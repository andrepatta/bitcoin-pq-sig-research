# `core/` — block, PoW, blockchain, reorg, undo, orphan pool, genesis

The chain. Bitcoin-exact in every detail except the header layout (extended from 80 to 88 bytes for larger Timestamp + Nonce) and the block hash function (still SHA-256d, but applied to the larger header).

---

## 1. Files

| File | Owns |
|---|---|
| `block.go` | `BlockHeader`, `Block`, `Serialize` / `Deserialize`, `Hash`, `ComputeMerkleRoot`, mutation check. |
| `pow.go` | `Target`, `Bits ↔ Target`, `BigToBits`, `CheckProof`, `ComputeNextWorkRequired` (Bitcoin-exact 2016-block retarget). Nonce grinding lives in [`miner.md`](miner.md). |
| `genesis.go` | Hardcoded `GenesisBlock` + `GenesisBits`. |
| `blockchain.go` | The `Blockchain` type — `AddBlock`, `reorgTo`, undo records, orphan pool, callback hooks for mempool / fee-estimator. |
| `testhelpers.go` | Helper builders for tests. |

---

## 2. Block header (88 bytes)

```go
type BlockHeader struct {
    Version    uint32       //  4 B little-endian
    PrevHash   [32]byte     // 32 B
    MerkleRoot [32]byte     // 32 B
    Timestamp  uint64       //  8 B little-endian (vs Bitcoin's 4 B)
    Bits       uint32       //  4 B little-endian
    Nonce      uint64       //  8 B little-endian (vs Bitcoin's 4 B)
}                                  // 88 bytes total
```

Bitcoin's 80-byte header uses 32-bit Timestamp and Nonce. We extend both to 64 bits — Timestamp because we want headroom past 2106 (the 32-bit Unix overflow), Nonce because at SHA-256d hashrates beyond Bitcoin's, the 32-bit nonce wraps within seconds and forces extranonce twists in the coinbase. Otherwise: Bitcoin-exact little-endian layout, identical PoW formula.

```go
func (h BlockHeader) Hash() [32]byte {
    return crypto.Hash256(h.Serialize())     // SHA-256d
}
```

`Hash()` is the block's identity — used as the storage key, the PoW comparand, the `PrevHash` referent in the next block. Display via `crypto.DisplayHex` for the Bitcoin-style byte-reversed display.

---

## 3. PoW + difficulty

```go
type Target [32]byte

func CheckProof(h BlockHeader) bool {
    return bytes.Compare(h.Hash()[:], BitsToTarget(h.Bits)[:]) < 0
}
```

Nonce grinding lives in the `miner/` package — see [`miner.md`](miner.md) for the midstate + no-alloc parallel scanner and its callers (external `qbitcoin-miner` binary, in-process `generatetoaddress`).

### Bits encoding

Bitcoin-style compact: 1-byte exponent + 3-byte mantissa. `BigToBits` emits canonical form. Genesis `Bits = 0x1e001999` is non-canonical; after the first retarget round-trip it normalizes to `0x1e199900` (same target).

### Difficulty adjustment — Bitcoin-exact 2016-block retarget

Between retarget boundaries, `Bits` are inherited unchanged from the parent. At every `nextHeight % RetargetInterval == 0`:

```
actualTimespan := pindexLast.Timestamp - pindexFirst.Timestamp
actualTimespan = clamp(actualTimespan, TargetTimespan/4, TargetTimespan*4)
newTarget      = oldTarget * actualTimespan / TargetTimespan
newTarget      = min(newTarget, powLimit)
newBits        = BigToBits(newTarget)
```

Constants:

```go
const (
    RetargetInterval  = 2016
    TargetBlockTime   = 600                        // seconds
    TargetTimespanSec = RetargetInterval * 600     // 1_209_600 s = 14 days
    pindexLast        = chain.GetBlockAtHeight(nextHeight - 1)
    pindexFirst       = chain.GetBlockAtHeight(nextHeight - RetargetInterval)
)
```

The off-by-one (`pindexFirst = pindexLast - (RetargetInterval - 1)`, so 2015 intervals over 2016 blocks) is **part of Bitcoin consensus** — not a bug. `core.ComputeNextWorkRequired(nextHeight, parentBits, lastTimestamp, firstTimestamp)` is the public function. `Blockchain.CurrentBits()` walks the chain to locate `pindexFirst` only on boundary heights.

Calibration tools for picking `GenesisBits` for a new test network: see [`docs/research/calibration/`](../research/calibration/).

---

## 4. Block validation pipeline (`Blockchain.AddBlock`)

```
1. CheckProof(block.Header) — SHA-256d header < target.
2. PrevHash links to a known block (or → orphan pool, see §7).
3. Timestamp:
   - > median of last 11 timestamps
   - ≤ now + 7200 (2-hour future cap)
4. MerkleRoot matches Hash256-Merkle of block.Txns.
5. ComputeMerkleRootMutated == false  (CVE-2012-2459 defense — see crypto.md).
6. SigOpCost(all_txs) ≤ MaxBlockSigOpsCost (80_000).
7. First tx is coinbase:
   - exactly 1 input, no PrevTxID,
   - witness includes the BIP-34 height-as-4-BE bytes for txid uniqueness,
   - sum(coinbase outputs) ≤ BlockReward(height) + total_tx_fees.
8. For each non-coinbase tx:
   a. tx.IsFinal(height, header.Timestamp).
   b. All inputs reference existing UTXOs.
   c. No double-spend within the block.
   d. sum(input values) ≥ sum(output values).
   e. coinbase inputs respect CoinbaseMaturity = 100.
   f. spend.LeafScript exists in the address's Merkle tree (proof check).
   g. script.Execute returns true.
9. Apply UTXO mutations + undo record (atomic via overlay / Pebble batch — see §6).
10. Update tip if cumulative work increased; otherwise stash as side branch.
11. Fire OnBlockConnected callbacks (mempool eviction, fee-estimator).
```

Step 5 (mutation check) runs **before** the standard merkle-root comparison so the rejection log line is precise about *why* a malformed tree was rejected.

---

## 5. Block reward

```go
func BlockReward(height int) uint64 {
    const initial = uint64(5_000_000_000)
    halvings := height / 210_000
    if halvings >= 64 { return 0 }
    return initial >> halvings
}
```

5 BTC initial subsidy, halving every 210_000 blocks. Bitcoin-exact.

---

## 6. Reorg — atomicity contract

`Blockchain.reorgTo(targetTip)` runs the disconnect + connect pass under a single Pebble batch + an in-memory `utxoOverlay`:

```
1. Compute reorg path: disconnect (oldTip → ancestor), connect (ancestor → targetTip).
2. Stage all UTXO mutations + undo records + meta updates into utxoOverlay.
3. Validate every connect-side block against the overlay.
4. If any step fails: discard the overlay, no disk or in-memory mutation, no callbacks fire.
5. Otherwise: commit the Pebble batch atomically, then fire callbacks in order.
```

**Disconnect callbacks fire before connect callbacks** so subscribers see reorg events in the natural order: `old-tip-down → ancestor+1-up → new-tip`. The mempool's reorg interaction (`OnBlockDisconnected` re-injects disconnected non-coinbase txs via `pool.Add` after the estimator hook) depends on this ordering — see [`mempool.md`](mempool.md) §reorg.

The same overlay path is used by single-block extensions (the common case), not just reorgs. This guarantees no on-disk state ever sits in a half-applied state.

Test coverage: `core/reorg_atomicity_test.go` — 7 tests covering atomicity on invalid block, across restart, under commit-hook failure, success-matches-direct-apply, no-events-on-failed-reorg, event order, extension atomicity.

---

## 7. Orphan pool

`OrphanPool` (in `core/blockchain.go`) holds blocks whose parent isn't yet known.

```go
const (
    MaxOrphanBlocks   = 100
    OrphanBlockTTL    = 30 * time.Minute
)
```

When a parent arrives, every orphan child is retried via `AddBlock` in dependency order. `OrphanPool.GC()` runs periodically to drop expired entries.

Test coverage: `core/orphan_test.go`.

---

## 8. Median-of-11 timestamp + future cap

```
medianTimestamp := median(last 11 ancestor timestamps)
require header.Timestamp > medianTimestamp
require header.Timestamp ≤ time.Now().Unix() + 7200       // 2 h future cap
```

Bitcoin-matched. The future cap is inclusive (`≤`) per Bitcoin Core's `MAX_FUTURE_BLOCK_TIME`.

---

## 9. Undo records

For every connected block, `Blockchain` writes an undo record into `BucketUndo` keyed by block hash. The undo record contains:

- All UTXOs spent by the block (so they can be re-added on rollback).
- All UTXOs created by the block (so they can be removed on rollback).

`deserializeUndo` enforces `maxUndoEntries = 1_000_000` to harden the DB-corruption path.

Test coverage: `core/undo_caps_test.go`.

---

## 10. Genesis

Hardcoded in `core/genesis.go`. The genesis coinbase has empty `Spend` by construction (no input to validate), pays the initial block reward to a deterministic test address.

`GenesisBits` is the powLimit — the easiest target the chain accepts. To bring up a new test network with sane block times, use `docs/research/calibration/` (`pqbc-cal`) to benchmark the host hashrate and propose a tighter `Bits`. The mining-genesis tool (`cmd/mine-genesis`) re-mines the genesis block once `Bits` changes so the precomputed Nonce still satisfies `CheckProof`.

---

## 11. Coinbase BIP-34-style uniqueness

`buildCoinbase` (in `cmd/qbitcoind/main.go`) embeds the block height as 4 big-endian bytes in the coinbase input's `Spend.Witness[0]`. Coinbase inputs skip script verification, so this data is consensus-neutral — it exists solely to keep each block's coinbase txid distinct.

Without it, back-to-back blocks in the same reward tier serialize identically, collide on `UTXOKey{txid, 0}`, and each new coinbase silently overwrites the prior block's reward UTXO. Genesis has empty `Spend` and is unchanged.

---

## 12. Public API summary

```go
type BlockHeader struct { /* see §2 */ }
type Block struct { Header BlockHeader; Txns []txn.Transaction }
type Target [32]byte

func (h BlockHeader) Hash() [32]byte
func (b Block) ComputeMerkleRoot() [32]byte
func (b Block) ComputeMerkleRootMutated() (root [32]byte, mutated bool)

func BitsToTarget(bits uint32) Target
func TargetToBig(t Target) *big.Int
func BigToBits(b *big.Int) uint32
func CheckProof(h BlockHeader) bool
func ComputeNextWorkRequired(nextHeight int, parentBits uint32, lastTS, firstTS uint64) uint32

type Blockchain struct { /* unexported */ }
func NewBlockchain(ctx context.Context, db *storage.DB, opts ...Option) (*Blockchain, error)
func (bc *Blockchain) AddBlock(ctx context.Context, b Block) error
func (bc *Blockchain) GetBlock(ctx context.Context, hash [32]byte) (*Block, error)
func (bc *Blockchain) GetHeader(ctx context.Context, hash [32]byte) (*BlockHeader, error)
func (bc *Blockchain) Tip() (hash [32]byte, height uint32)
func (bc *Blockchain) CurrentBits() uint32
func (bc *Blockchain) FindTx(ctx context.Context, txid [32]byte) (*txn.Transaction, [32]byte, uint32, error)
func (bc *Blockchain) ListTxsForAddress(ctx context.Context, addr address.P2MRAddress) ([]AddrTxRecord, error)
func (bc *Blockchain) BlocksAfter(ctx context.Context, since [32]byte, limit int) ([]Block, error)

func (bc *Blockchain) OnBlockConnected(cb func(Block, uint32))
func (bc *Blockchain) OnBlockDisconnected(cb func(Block, uint32))
```

The `OnBlockConnected` / `OnBlockDisconnected` callbacks take `(Block, uint32)` (block + height) so subscribers can record exact heights even when many callbacks fire during a reorg burst.
