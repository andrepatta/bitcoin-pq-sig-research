# `storage/` — Pebble bucket layout

Single-file package wrapping `cockroachdb/pebble`. Pebble is a flat keyspace; "buckets" are emulated as key prefixes: on-disk keys are `bucket || 0x00 || key`. The `0x00` separator is safe because no bucket name contains it, so prefix scans over a bucket are well-bounded.

---

## Buckets

```go
const (
    BucketBlocks  = "blocks"   // [32]byte hash → serialized Block
    BucketHeaders = "headers"  // [32]byte hash → serialized BlockHeader
    BucketUTXOs   = "utxos"    // [32]byte txid || [4]byte index → serialized UTXOEntry
    BucketMeta    = "meta"     // "best_hash", "best_height", "total_work"
    BucketPeers   = "peers"    // peer_id_multihash → serialized PeerRecord
    BucketBans    = "bans"     // peer_id_multihash → serialized BanEntry
    BucketWallet  = "wallet"   // legacy single-wallet keys (multi-wallet uses files under <datadir>/wallets/)
    BucketWork    = "work"     // [32]byte block hash → cumulative work (big.Int bytes)
    BucketUndo    = "undo"     // [32]byte block hash → serialized undo record for reorgs
)
```

UTXO key construction:

```go
key := append(txid[:], binary.BigEndian.AppendUint32(nil, index)...)   // 36 B
```

---

## Public API

```go
type DB struct { /* unexported */ }

func Open(dir string) (*DB, error)
func (db *DB) Close() error

// Single-key ops
func (db *DB) Get(bucket, key []byte) ([]byte, error)        // returns ErrNotFound if absent
func (db *DB) Put(bucket, key, value []byte) error
func (db *DB) Delete(bucket, key []byte) error

// Atomic batch
type Batch struct { /* unexported */ }
func (db *DB) NewBatch() *Batch
func (b *Batch) Put(bucket, key, value []byte)
func (b *Batch) Delete(bucket, key []byte)
func (b *Batch) Commit() error                                // single Pebble write

// Prefix scan
func (db *DB) Scan(bucket, prefix []byte, fn func(k, v []byte) bool) error

var ErrNotFound = errors.New("storage: key not found")
```

`Batch.Commit()` is what gives `core.Blockchain.reorgTo` its atomicity — the entire disconnect + connect pass either lands as one Pebble write or is discarded with no on-disk effect. See [`core.md`](core.md) §6.

---

## Out of scope

- Snapshotting / `Checkpoint()` for warm-restart safety.
- Good-marker file or startup-side corruption truncation.
- UTXO pruning, snapshots, scheduled compaction.

These are flagged for follow-up. The current design relies on Pebble's native crash-safety (write-ahead log + checksummed sstables) plus the `core/` overlay → `Batch.Commit()` pattern for application-level atomicity.
