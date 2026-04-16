package storage

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cockroachdb/pebble"

	"qbitcoin/logging"
)

// pebbleLogger routes Pebble's internal logs through qbitcoin/logging as module
// "pebble". By default the global log level is INFO, so Pebble's chatty Infof
// output stays hidden unless a user passes -log=debug or -log=...,pebble=info.
type pebbleLogger struct{}

func (pebbleLogger) Infof(format string, args ...any) {
	logging.Module("pebble").Debug(fmt.Sprintf(format, args...))
}

func (pebbleLogger) Fatalf(format string, args ...any) {
	logging.Module("pebble").Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// Bucket names. Used as key prefixes in the flat Pebble keyspace.
const (
	BucketBlocks  = "blocks"
	BucketHeaders = "headers"
	BucketUTXOs   = "utxos"
	BucketMeta    = "meta"
	BucketPeers   = "peers"
	BucketWallet  = "wallet"
	BucketWork    = "work"
	BucketUndo    = "undo"
	BucketBans    = "bans"
)

// bucketSep separates bucket prefix from the key. Chosen as 0x00 because no
// bucket name contains it, so prefix scans over a bucket are well-bounded.
const bucketSep = 0x00

// composeKey builds the on-disk key: bucket || 0x00 || key.
func composeKey(bucket, key []byte) []byte {
	out := make([]byte, 0, len(bucket)+1+len(key))
	out = append(out, bucket...)
	out = append(out, bucketSep)
	out = append(out, key...)
	return out
}

// bucketBounds returns [lower, upper) scan bounds for a bucket.
func bucketBounds(bucket []byte) (lower, upper []byte) {
	lower = make([]byte, 0, len(bucket)+1)
	lower = append(lower, bucket...)
	lower = append(lower, bucketSep)
	// upper = bucket || 0x01 — the next byte after the separator, which
	// excludes every key in this bucket while including none beyond it.
	upper = make([]byte, 0, len(bucket)+1)
	upper = append(upper, bucket...)
	upper = append(upper, bucketSep+1)
	return lower, upper
}

// DB is a Pebble-backed KV store with bucket-prefixed keys.
type DB struct {
	pdb *pebble.DB
}

// Open opens/creates a Pebble database at filepath.Join(dir, "qbitcoin").
func Open(dir string) (*DB, error) {
	path := filepath.Join(dir, "qbitcoin")
	p, err := pebble.Open(path, &pebble.Options{Logger: pebbleLogger{}})
	if err != nil {
		return nil, err
	}
	return &DB{pdb: p}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.pdb.Close() }

// Get retrieves a value from bucket. Returns (nil, nil) on miss.
// The returned slice is owned by the caller.
func (d *DB) Get(bucket, key []byte) ([]byte, error) {
	v, closer, err := d.pdb.Get(composeKey(bucket, key))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(v))
	copy(out, v)
	_ = closer.Close()
	return out, nil
}

// Put stores a value.
func (d *DB) Put(bucket, key, value []byte) error {
	return d.pdb.Set(composeKey(bucket, key), value, pebble.Sync)
}

// Delete removes a key.
func (d *DB) Delete(bucket, key []byte) error {
	return d.pdb.Delete(composeKey(bucket, key), pebble.Sync)
}

// ForEach iterates all keys in a bucket. The (k, v) passed to fn are the
// bucket-local key and value; both are valid only for the duration of the
// callback — callers that need to retain them must copy.
func (d *DB) ForEach(bucket []byte, fn func(k, v []byte) error) error {
	lower, upper := bucketBounds(bucket)
	it, err := d.pdb.NewIter(&pebble.IterOptions{LowerBound: lower, UpperBound: upper})
	if err != nil {
		return err
	}
	defer it.Close()
	prefixLen := len(bucket) + 1
	for it.First(); it.Valid(); it.Next() {
		k := it.Key()
		if len(k) < prefixLen || !bytes.Equal(k[:prefixLen-1], bucket) || k[prefixLen-1] != bucketSep {
			continue
		}
		if err := fn(k[prefixLen:], it.Value()); err != nil {
			return err
		}
	}
	return it.Error()
}

// Batch is an atomic multi-key write. Commit is all-or-nothing.
type Batch struct {
	b *pebble.Batch
}

// NewBatch starts an atomic batch.
func (d *DB) NewBatch() *Batch { return &Batch{b: d.pdb.NewBatch()} }

// Put stages a write.
func (b *Batch) Put(bucket, key, value []byte) error {
	return b.b.Set(composeKey(bucket, key), value, nil)
}

// Delete stages a delete.
func (b *Batch) Delete(bucket, key []byte) error {
	return b.b.Delete(composeKey(bucket, key), nil)
}

// Commit applies the batch atomically with a synchronous fsync.
func (b *Batch) Commit() error {
	return b.b.Commit(pebble.Sync)
}

// Close releases batch resources. Safe to call after Commit.
func (b *Batch) Close() error { return b.b.Close() }
