# `miner/` and `cmd/qbitcoin-miner` — external PoW pipeline

qbitcoind has no built-in miner. Mining is an out-of-process task, matching Bitcoin Core's operational model: the node publishes BIP-22 templates and accepts submitted blocks; an external process does the grind.

- **`miner/`** — shared grinder (midstate + no-alloc parallel nonce scan) and coinbase helpers. Imported by both `cmd/qbitcoin-miner` and `cmd/qbitcoind`'s `generatetoaddress` handler.
- **`cmd/qbitcoin-miner`** — the external miner binary. Polls `getblocktemplate`, assembles the block, grinds, calls `submitblock`.

---

## 1. `miner.Grind` — parallel nonce scan

```go
func Grind(h *core.BlockHeader, threads int, quit <-chan struct{}) bool
```

Writes the winning nonce (and rarely a bumped timestamp) into `*h` on success. Returns false if `quit` closes first. `threads <= 1` runs a single-worker scan.

Each worker scans a disjoint nonce stride — worker `i` starts at nonce `i`, steps by `threads` — so no two workers ever test the same `(timestamp, nonce)` pair. If a worker's stride wraps `uint64` (unreachable at realistic hashrates) it bumps timestamp and restarts at its start nonce; the midstate stays valid because Timestamp lives in chunk 2.

### Midstate optimization

SHA-256 processes 64-byte chunks. The 88-byte PQBC header splits as:

| Byte range | Field | Mutable across nonces? |
|---|---|---|
| 0–3 | Version | no |
| 4–35 | PrevHash | no |
| 36–67 | MerkleRoot | no |
| 68–75 | Timestamp | no (within a stride) |
| 76–79 | Bits | no |
| 80–87 | Nonce | **yes** |

Chunk 1 (bytes 0–63) = Version + PrevHash + first 28 B of MerkleRoot — invariant across the whole template. Chunk 2 (bytes 64–87) = last 4 B of MerkleRoot + Timestamp + Bits + Nonce, 24 bytes.

Each worker precomputes the SHA-256 state after chunk 1 once via `hash.Hash.MarshalBinary()` — stable since Go 1.10. Per-nonce work is:

1. `UnmarshalBinary(midstate)` to restore post-chunk-1 state.
2. `Write(chunk2_24_bytes)` to hash the tail.
3. `Sum(firstHash[:0])` → 32-byte first hash (stack-resident).
4. `sha256.Sum256(firstHash[:])` → outer SHA wrap.

Two compression rounds per nonce instead of three on the naive path — roughly 33% off the hashing cost. Matches the classic Bitcoin ASIC midstate trick.

### No hot-path allocation

Each worker holds:

- one `*sha256.Hash` instance (reused every nonce)
- one `[88]byte` header buffer on the stack
- one marshaled midstate `[]byte` (~108 bytes, allocated once)

Per-nonce code touches none of those sizes. `sha.Sum(buf[:0])` appends into a `[32]byte` backing array — cap is sufficient, so no allocation. `sha256.Sum256(...)` returns `[32]byte` by value (stack). `bytes.Compare(hash[:], target[:])` doesn't allocate.

Channel polling is batched via `channelCheckEvery = 1 << 14` — each worker checks `quit`/`stop` every 16384 nonces (~1.6 ms at a per-core rate of ~10 MH/s), cheap insurance against the select-per-nonce runtime overhead that dominated the old in-process miner.

---

## 2. `miner.BuildCoinbase` + `miner.CoinbaseValue`

```go
func BuildCoinbase(height uint32, to address.P2MRAddress, value uint64) txn.Transaction
func CoinbaseValue(height uint32, fees uint64) uint64
```

`BuildCoinbase` constructs the coinbase tx paying `value` to `to` and embeds `height` as 4 big-endian bytes in the coinbase input's `Spend.Witness[0]` — a BIP-34 analog that keeps each block's coinbase txid unique (without this, back-to-back same-reward coinbases would collide on `UTXOKey{txid,0}`).

`CoinbaseValue` is `core.BlockReward(height) + fees`. Callers sum fees from the BIP-22 template's `transactions[].fee` and pass the total here.

---

## 3. `cmd/qbitcoin-miner` — the external binary

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `-rpc` | `http://127.0.0.1:8334` | qbitcoind RPC endpoint. |
| `-coinbase` | *(required)* | bech32 P2MR address to receive mining rewards. |
| `-threads` | `runtime.NumCPU()` | Parallel grinder workers. |
| `-rpcuser` | empty | Static HTTP Basic auth user (requires `-rpcpassword`). |
| `-rpcpassword` | empty | Static HTTP Basic auth password (requires `-rpcuser`). |
| `-rpccookiefile` | `<datadir>/.cookie` | RPC cookie path when `-rpcuser` not set. |
| `-datadir` | `~/.qbitcoin` | Cookie-file lookup root. |
| `-poll-interval` | `5s` | Tip-change poll cadence during a grind. |
| `-log` | `info` | Log spec — `"info,miner=debug"`. |
| `-log-json` | false | JSON log output. |

`--coinbase` is always required. The node doesn't resolve it any more — no `--coinbase` flag on qbitcoind, no wallet fallback.

### Main loop

```
for {
    tmpl = GET /mining/getblocktemplate
    block = assemble(tmpl, --coinbase)    // coinbase pays self, merkle root computed
    quit = make channel
    spawn watchdog:                       // stale-template guard
        tick every --poll-interval
        if GET /chain/info.bestblockhash != tmpl.previousblockhash: close(quit)
    solved = miner.Grind(&block.Header, --threads, quit)
    if solved:
        reason = POST /mining/submitblock {hexdata}
        log accept/reject
}
```

Stale-template abort is cheap because `Grind` polls `quit` every 16 k nonces. When the tip moves, the watchdog closes the channel, every worker exits on its next check, and the loop re-pulls a fresh template instead of burning cycles on a dead chain head.

### Auth resolution

Mirrors `qbitcoin-cli`:

1. `-rpcuser` + `-rpcpassword` pair (both required when either is set).
2. `-rpccookiefile` path (explicit).
3. `<datadir>/.cookie` default.

A missing cookie is not fatal — requests go out unauthenticated and the server's 401 surfaces cleanly.

---

## 4. BIP-22 wire format — deviations from Bitcoin

`/mining/getblocktemplate` returns a BIP-22 response with Bitcoin's field names. PQBC drops or adapts fields that don't apply:

| Bitcoin field | PQBC | Reason |
|---|---|---|
| `weight`, `weightlimit` | omitted | No segwit, no weight. |
| `transactions[].hash` | equals `txid` | No wtxid split (PQ signatures are deterministic, so wtxid would equal txid anyway). |
| `noncerange` | `"0000000000000000ffffffffffffffff"` | 64-bit nonce range vs Bitcoin's 32-bit `"00000000ffffffff"`. |
| `rules`, `vbavailable` | empty | No softfork deployments. |
| `default_witness_commitment` | omitted | No segwit. |
| `longpollid` | tip hash string | Server-side longpoll not implemented; miners poll on their own cadence. |
| `target`, `previousblockhash`, `transactions[].txid` | display-hex (reversed memory) | Matches qbitcoind's convention for all 32-byte RPC outputs. |
| `bits` | 8-char compact-hex | Same as Bitcoin (`"1e000fff"` etc.). |

`submitblock` response follows Bitcoin's convention:

| Value | Meaning |
|---|---|
| `null` | Accepted (main chain or valid side chain). |
| `"duplicate"` | Block already known. |
| `"inconclusive"` | Parent unknown (orphan). |
| `"<reason>"` | Validation error — the string is the server's reject reason. |

---

## 5. `generatetoaddress` — regtest convenience

`POST /mining/generatetoaddress {"nblocks": N, "address": "<bech32>"}` mines `N` blocks paying coinbase to the address and returns their hashes. Uses `miner.Grind` in-process with `threads=1` — same optimizations as the external miner, just without the RPC hop. Fees from template transactions are collected into the coinbase.

Bitcoin Core gates this under regtest; PQBC keeps it always-on because the PoC doesn't strictly separate chain types.
