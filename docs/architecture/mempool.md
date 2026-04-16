# `mempool/` — relay policy, RBF, fee estimation

In-memory transaction pool with Bitcoin Core-shaped policy. Three policy gates at `Add` time on top of per-tx validity (UTXO existence, `IsFinal`, `MaxMoney`, inputs ≥ outputs):

1. **Conflict tracking** — no silent double-spends.
2. **Min-relay fee** — `fee >= MinRelayFeeRate · size_bytes`.
3. **BIP-125 RBF subset** — replace iff fee-rate strictly higher and absolute fee covers conflict-set + replacement size at the incremental relay rate.

Plus a Core-port **`BlockPolicyEstimator`** (`estimateSmartFee`) that tracks tx arrival-to-confirm samples across short / medium / long horizons.

---

## 1. Files

| File | Owns |
|---|---|
| `feerate.go` | `MinRelayFeeRate`, `IncrementalRelayFeeRate`, RBF helper math (cross-multiplication compare so no division). |
| `mempool.go` | `Mempool` type + `Add`, `Remove`, `Get`, `GetTemplate`, conflict index. |
| `estimator.go` | `BlockPolicyEstimator` — Bitcoin Core's `CBlockPolicyEstimator` ported to Go. `txConfirmStats` for short/med/long horizons. |
| `estimator_persist.go` | Save / Load `fee_estimates.dat`. |

---

## 2. Conflict tracking

`Mempool.spent map[txn.UTXOKey][32]byte` indexes every input consumed by an in-pool tx. A new tx whose inputs collide with this index is either replaced via RBF (rule 3) or rejected.

Without this index, two txs spending the same UTXO can both pass per-tx validation (each is valid against the chain UTXO set) and the miner's `GetTemplate` produces a block that fails `block: double spend within block`.

---

## 3. Min-relay fee

```go
require fee >= MinRelayFeeRate * size_bytes
```

Defaults:

| Constant | Default |
|---|---|
| `MinRelayFeeRate` | 1 sat/B |
| `IncrementalRelayFeeRate` | 1 sat/B |

Tests set `MinRelayFeeRate = 0` in `TestMain` to keep zero-fee fixtures working.

PQ-sig txs are large (~700 B SHRINCS, ~2.6 KB SHRIMPS), so absolute per-tx fees run higher than Bitcoin's at the same rate. Tune the rate down if relay economics need adjusting.

---

## 4. BIP-125 RBF (subset)

When a new tx conflicts with N in-pool txs, it's admitted iff:

- **Rule 5**: `N <= MaxRBFConflicts = 100`.
- **Rule 6**: replacement's fee-rate is **strictly higher** than every conflict's fee-rate (compared via cross-multiplication, no division).
- **Rule 4**: replacement's absolute fee ≥ `sum(conflict fees) + IncrementalRelayFeeRate * replacement_size`. The increment pays for the relay bandwidth of evicting the originals.

On accept, all conflicts are evicted in-place under `m.mu`, then the replacement is inserted.

**Skipped from BIP-125**:

- Rule 2 (no in-mempool tx chains yet → no descendant tracking).
- Rule 3 (no opt-in `nSequence` flag → this is full RBF, not opt-in RBF).

---

## 5. Why no segwit (and what we do instead)

Segwit's two motivations don't translate:

- **Tx malleability**: PQ sigs are deterministic (PRF-based randomness per paper §11), so byte-identical output for the same (key, message). No malleation surface to fix.
- **Capacity discount via 4× witness math**: qBitcoin isn't soft-fork-constrained — the limits are tunable knobs. To make PQ-sig-heavy txs cheap to relay, lower `MinRelayFeeRate`; same economic effect, no architectural cost.

The wtxid/txid split is pure Bitcoin legacy compat. See [`docs/invariants.md`](../invariants.md) §7: TxID = `Hash256(tx.Serialize())` with witness data included.

---

## 6. Fee estimator (`estimatesmartfee`)

Bitcoin Core's `CBlockPolicyEstimator` ported to Go. Three `txConfirmStats` horizons track (arrival → confirmation) samples with per-horizon decay constants:

| Horizon | decay | scale | periods | coverage |
|---|---|---|---|---|
| short  | 0.962   | 1  | 12 | 1–12 blocks |
| medium | 0.9952  | 2  | 24 | 1–48 blocks |
| long   | 0.99931 | 24 | 42 | 1–1008 blocks (~1 week) |

Bucket geometry: 1.05× geometric grid from `minBucketFeerate = 0.001 sat/B` up to `maxBucketFeerate = 1e4 sat/B`, plus a `+Inf` sentinel (skipped by queries).

### Observation hooks

Driven from `cmd/qbitcoind/main.go`:

| Hook | Source |
|---|---|
| `ProcessTransaction(txid, fee, size, validHeight)` | `Mempool.Add` |
| `RemoveTx(txid)` | mempool eviction (RBF replacement etc.) |
| `ProcessBlock(height, txids)` | `chain.OnBlockConnected` |
| `ProcessDisconnect(height, txids)` | `chain.OnBlockDisconnected` |

### Query

`EstimateFee(target, mode)` walks buckets from highest finite feerate down, accumulating `confAvg[target_period-1]`, `failAvg[target_period-1]`, `txCtAvg`, plus "extra fails" (currently-pending txs in `unconfTxs` older than `target` + everything in `oldUnconfTxs`).

The lowest passing range (total ≥ `sufficientFeeTxs`, success% ≥ threshold) is answered by the tx-weighted median feerate across that range.

Modes:

| Mode | Horizons | Threshold | How |
|---|---|---|---|
| `ModeEconomical` | short only | 60% | Optimistic. |
| `ModeConservative` | short / med / long | 95% / 85% / 85% | Takes max of the three. |
| `ModeUnset` | — | — | Conservative for `target ≤ 12`, Economical otherwise. |

### Sync-path coverage

| Scenario | Behavior |
|---|---|
| **IBD** (fresh node, no mempool) | `ProcessBlock` sees untracked txids → all silently skipped; `bestSeenHeight` advances. Estimator stays empty until live tx gossip arrives post-IBD. |
| **Post-load resume + sync gap** | On `Load`, live counters (`unconfTxs`, `oldUnconfTxs`) are cleared — they referenced no-longer-tracked txs. Historical `confAvg` / `failAvg` / `txCtAvg` survive. On `SetBestHeight(h)` with `h - bestSeenHeight > 1`, cumulative catch-up decay is applied so averages reflect their age. |
| **Reorg** | `OnBlockDisconnected` calls `ProcessDisconnect` per disconnected block, which forgets tracked txs and rolls `bestSeenHeight` back. Following Core, decayed stats are NOT reversed (one reorg-depth's worth of skew is in the decay noise). Txs reappearing in the mempool get tracked fresh. |
| **Orphan block drain** | Chain fires `OnBlockConnected` in ascending height order, the estimator's monotonic-height check enforces no double-processing. |
| **Compact blocks** | Reconstructed blocks flow through the same `AddBlock` → `OnBlockConnected` path, so the estimator sees identical txid lists regardless of whether the body came via `MsgBlock` or `MsgCmpctBlock` + `MsgBlockTxn`. |

### Persistence

`fee_estimates.dat` in the datadir. Hand-rolled big-endian binary layout (not Bitcoin-compat). Written on SIGINT / SIGTERM, plus a 10-minute periodic save. Atomic-rename pattern: write to `.tmp`, `Close`, then `Rename`.

### Chain callback API

`OnBlockConnected` / `OnBlockDisconnected` take `func(Block, uint32)` (block + height) so the estimator can record the exact height even when many callbacks fire in a burst during reorg. `fireConnected` and `fireDisconnected` queue `connectEvent{block, height}` pairs and are drained after the writer lock is released. `flushDisconnected` runs **before** `flushConnected` so subscribers see reorg events in the natural old-tip-down → ancestor+1-up → new-tip order.

---

## 7. Reorg interaction (mempool re-injection)

`OnBlockDisconnected` re-admits non-coinbase txs via `pool.Add` in block order (after the estimator hook). Fires post-commit so the new branch's UTXO view is authoritative; double-spent / RBF-losing re-inject attempts are silently rejected, matching Bitcoin Core semantics.

Test coverage: `mempool/reorg_interaction_test.go` (basic round-trip, double-spend drop, coinbase skip, multi-block disconnect survival, post-commit-only callback).

---

## 8. Pending-tx lifecycle (don't gossip rejected txs)

`Wallet.Send` / `Wallet.SendAtFeerate` **only build and sign** — they do NOT record the tx as wallet-pending. The caller is responsible for calling `Wallet.RecordPending(tx)` only AFTER `mempool.Add` succeeds locally.

Otherwise a tx rejected by our own policy (min-relay, RBF rule 6, etc.) would sit in the pending file and get re-gossiped to every peer by the 5-minute `WalletRebroadcastInterval` ticker.

Defense-in-depth: the rebroadcast ticker also checks `pool.Get(id) != nil` for each pending entry before broadcasting. If a pending tx isn't in our mempool (rebuilt after restart, RBF-evicted, policy-rejected at replay), it's cleared from pending and skipped.

The `/wallet/send` RPC handler enforces the contract: `pool.Add` first, `RecordPending` + `BroadcastTx` only on success.

---

## 9. Wallet integration — adaptive fee

`Wallet.SendAtFeerate(u, to, amount, feerate)` is **adaptive**:

1. **First pass**: build & sign with a conservative `EstimateTxSize`-based fee (900 B/input covers a fresh 2-leaf account's ~840 B actual).
2. Measure the signed tx's actual byte size.
3. **If real size > estimate** (happens as the SHRINCS leaf index grows — auth path is `~16·q B` per the paper, so heavily-used accounts produce bigger sigs): rebuild + re-sign once with the corrected fee. Logged as a warn-line since it consumes an extra SHRINCS slot.

`Wallet.EstimateTxSize(numInputs, numOutputs)` returns the first-pass prediction: 16 B base + 900 B/input + 40 B/output.

`/wallet/send` RPC fee-selection precedence:

1. Explicit absolute `fee > 0` → `Wallet.Send`.
2. Explicit `feerate > 0` → `Wallet.SendAtFeerate`.
3. Otherwise → query estimator (target default 6, mode default unset); floor to `MinRelayFeeRate` if estimator has no answer.

CLI: `qbitcoin-cli send <addr> <amount>` auto-estimates; adding a third arg overrides with an absolute fee. `qbitcoin-cli estimatesmartfee <target> [mode]` exposes the raw query.

---

## 10. Public API summary

```go
type Mempool struct { /* unexported */ }
func New(estimator *BlockPolicyEstimator) *Mempool
func (m *Mempool) Add(tx txn.Transaction, utxos txn.UTXOSet) error
func (m *Mempool) Remove(txids ...[32]byte)
func (m *Mempool) Get(txid [32]byte) *txn.Transaction
func (m *Mempool) GetTemplate(maxBytes int, maxSigOps int) []txn.Transaction

type BlockPolicyEstimator struct { /* unexported */ }
func (e *BlockPolicyEstimator) ProcessTransaction(txid [32]byte, fee uint64, size int, validHeight uint32)
func (e *BlockPolicyEstimator) RemoveTx(txid [32]byte)
func (e *BlockPolicyEstimator) ProcessBlock(height uint32, txids [][32]byte)
func (e *BlockPolicyEstimator) ProcessDisconnect(height uint32, txids [][32]byte)
func (e *BlockPolicyEstimator) EstimateFee(target int, mode Mode) (sat_per_byte float64, ok bool)
func (e *BlockPolicyEstimator) Save(path string) error
func (e *BlockPolicyEstimator) Load(path string) error
```

---

## 11. Out of scope

- Mempool size cap (`-maxmempool`) + dynamic min-fee under pressure.
- Ancestor / descendant fee scoring for richer eviction.

---

## 12. Tests

| Test file | Coverage |
|---|---|
| `mempool/mempool_test.go` | Add / remove / RBF eligibility / GetTemplate ordering. |
| `mempool/feerate_test.go` | Cross-multiplication compare correctness; min-relay floor. |
| `mempool/orphan_test.go` | Tx whose input UTXO is missing → orphan tx pool eviction. |
| `mempool/sigops_test.go` | Per-tx sigops cap rejection. |
| `mempool/reorg_interaction_test.go` | Reorg re-injection lifecycle. |
| `mempool/estimator_test.go` | Estimator math, IBD-skip, disconnect handling. |
