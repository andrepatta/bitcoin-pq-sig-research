# `p2p/` — raw TCP and the qbitcoin wire protocol

The transport layer is plain TCP — one TCP connection per peer. There is **no libp2p, no peer-ID handshake, and no transport-layer encryption**. Anyone reachable at `ip:port` who speaks the qbitcoin wire protocol is a peer. This mirrors Bitcoin Core's native P2P exactly.

Framing follows Bitcoin Core's `CMessageHeader` layout; every qbitcoin message sits inside that envelope.

---

## 1. Files

| File | Owns |
|---|---|
| `messages.go` | Wire framing (magic + command + length + checksum) and every payload encoder/decoder. `NetAddr` helpers. |
| `bootnodes.go` | Hardcoded `DefaultBootnodes []string` of plain `host:port` entries. |
| `peer.go` | Per-peer state, `net.Conn` read/write loops, `txInvLoop` trickle, handshake watchdog. |
| `node.go` | TCP accept loop, outbound dialing, sync + relay, compact-block reconstruction, self-connection detection. |
| `banman.go` | Bitcoin Core-shaped misbehavior model with per-IP scoring and persisted bans. |

---

## 2. Identity — there isn't one

A node has no cryptographic identity at the transport layer. Dial strings are plain `host:port` — no `/p2p/<id>` suffix, no identity key on disk, no Noise handshake. Chain-level artifacts (blocks, transactions, wallet sigs) remain PQ-signed via SHRINCS/SHRIMPS; transport confidentiality and peer-identity unforgeability are explicitly out of scope for this PoC.

Self-connection detection is not identity — it's a nonce echo (see §6).

---

## 3. Wire format (Bitcoin-exact)

Every frame on the wire is:

```
[4 B magic = 0x51424354 ("QBCT"), LE]
[12 B command string, null-padded ASCII]
[4 B payload length, LE]
[4 B checksum = SHA256d(payload)[0:4]]
[N B payload]
```

This is Bitcoin Core's `CMessageHeader` to the byte, with a distinct magic so a Bitcoin node that dials us fails on the magic check instead of going down a cross-protocol parse path.

### Command strings

```
version        verack         getblocks      inv
getdata        block          tx             ping
pong           addr           reject         cmpctblock
getblocktxn    blocktxn
```

Every name is byte-identical to Bitcoin Core's, including the BIP-152 trio.

`ReadFrame` validates magic, cap-checks the length (`MaxFramePayload = 32 MiB`), reads the payload, recomputes SHA256d, and rejects on checksum mismatch.

---

## 4. Dial strings & bootnodes

`--connect` and `--bootnodes` accept plain `host:port`:

```
127.0.0.1:8333
node-0:8333
72.61.186.233:8333
```

`p2p/bootnodes.go` holds `DefaultBootnodes []string`, dialed in parallel with `--connect` at startup. `--bootnodes none` disables bootnodes entirely; any other value is a comma-separated override.

---

## 5. Connection caps & mesh formation

| Constant | Value | Notes |
|---|---|---|
| `MaxOutbound` | 8 | Matches Bitcoin Core's `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`. |
| `MaxInbound` | 117 | Matches Bitcoin Core's default inbound slots. |

**`MaxOutbound` only counts outbound dials**, not total peers — without this distinction, inbound traffic eats outbound dial slots and the node stops filling its mesh once 8 inbound peers attach.

---

## 6. Handshake + self-connection detection

`HandshakeTimeout = 60s` (Bitcoin Core parity). Per-peer `handshakeWatchdog` goroutine closes the stream if Version / VerAck haven't been exchanged within the window.

Every outbound version carries a random `uint64` nonce:

```
version payload = [4 B version][4 B height][18 B addr_from][8 B nonce]
```

Self-connection flow (Bitcoin Core's `pchMessageStart`-nonce trick):

1. On every peer add, the node mints a random nonce, adds it to `sentNonces`, and ships it in the version frame.
2. When handling an incoming version, the node checks the received nonce against `sentNonces`. A match means the peer is us — we dialed our own listen endpoint.
3. The connection is torn down and the target `host:port` goes into a `selfAddrs` set.
4. Future `Connect()` calls to any address in `selfAddrs` short-circuit before opening a socket.
5. `absorbAddrs` likewise skips known-self entries during gossip absorption so a peer's addr list can't trick us into repeatedly self-dialing.

A cheap loopback pre-guard in `Connect` also rejects `127.*:<self-port>` without a round trip.

`addr_from` (sender's self-reported listen `ip:port`) combined with the observed `RemoteAddr()` IP tells inbound receivers where to dial the sender back on — the accepted socket's remote port is the sender's ephemeral outbound port, not its listen port.

---

## 7. Tx-inv trickle scheduler

Per-peer `txInvLoop` buffers tx invs into a dedup set and flushes on a Poisson-distributed timer (`-mean·ln(rand)`):

| Constant | Value |
|---|---|
| `txInvMeanInbound` | 2 s |
| `txInvMeanOutbound` | 5 s |

Same parameters as Bitcoin Core. Block invs go out immediately via `Send(CmdInv, …)`; tx invs go through `QueueTxInv` so timing-side-channel attacks against tx origin don't trivially work.

---

## 8. Compact blocks (BIP-152)

When a peer requests a block via `CmdGetData`, the response is `CmdCmpctBlock` (header + 8-byte nonce + 6-byte short IDs for non-coinbase txs + prefilled coinbase) instead of the full `CmdBlock`. Short ID = SipHash-2-4 truncated to 6 bytes (LE), per BIP-152 exactly; per-block key derived as `SHA256(headerBytes || nonce_le)[0:16]` → `(k0, k1)`.

The `CmdBlock` handler is still wired for fallback: on cmpct merkle mismatch the node requests the full block via `CmdGetData` to the same peer. Reconstruction state lives in `cmpctPending` (TTL `CmpctReconstructTTL = 30s`, GC'd by the scheduler).

---

## 9. Ban manager (keyed by IP)

`BanManager` tracks per-IP score with linear decay, bans on threshold, persists to `BucketBans` for 24 h.

```go
BanThreshold         = 100
BanDuration          = 24 * time.Hour
BanScoreDecayPerHour = 1.0
```

Scoring is by IP, matching Bitcoin Core's `CAddrMan`/`CBanEntry` semantics — an attacker cycling through ephemeral outbound ports cannot reset their score. `BucketBans` keys are the canonical IP string bytes.

| Violation | Score |
|---|---|
| Bad payload (malformed message bytes) | 100 (immediate ban) |
| Pre-handshake non-Version traffic | 10 |
| Bad addr message | 10 |
| Missing slots after `BlockTxn` reply | 50 |
| Invalid block header / PoW failure | 100 |
| Invalid tx that passes mempool but fails block validation | 100 |

Inbound (`onInbound`) and outbound (`Connect`) both gate on `IsBanned(ip)`.

---

## 10. Graceful shutdown

`Stop()` is `sync.Once`-guarded:

1. Cancels node-lifetime ctx so any in-flight `chain.AddBlock` returns promptly.
2. Closes `n.quit` under `n.mu` (serializes with addPeer's quit-gate).
3. Closes the TCP listener (unblocks the accept loop).
4. Closes every connected peer.
5. Returns only once `n.wg.Wait()` drains every spawned goroutine.

Per-peer trackers registered inside `addPeer` hold an `n.wg` slot for each peer's full lifetime, so a `readLoop` mid-`handleMsg` mid-`AddBlock` can no longer race the caller's deferred `db.Close()`.

---

## 11. Storage (Pebble integration)

| Bucket | Key | Value |
|---|---|---|
| `peers` | 18-byte NetAddr (IPv4-mapped IPv6 + BE port) | 18 B addr + 8 B last-seen unix |
| `bans` | canonical IP string bytes | `BanEntry` (banned-until + reason) |

---

## 12. Wire-message safety hardening

`DecodeInv` / `DecodeGetBlocks` cap counts at `MaxInvItems = 50_000` and `MaxLocatorHashes = 500`, with size math in `uint64` to defeat `uint32`-wrap overflows. `ReadFrame` caps payloads at `MaxFramePayload = 32 MiB` and checksum-verifies before returning.

---

## 13. Discovery

- Bootstrap list (`DefaultBootnodes` or `--bootnodes`) for initial dialing.
- Addr gossip (`CmdAddr`) between connected peers — new nodes learn the mesh from what existing peers announce.
- No mDNS, no DHT, no NAT traversal. Bitcoin Core doesn't have those either.
