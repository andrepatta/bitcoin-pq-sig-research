package core

import (
	"bytes"
	"testing"

	"qbitcoin/txn"
)

// FuzzDeserializeHeader asserts the 88-byte header decoder never panics on
// arbitrary input and round-trips on every output it accepts.
func FuzzDeserializeHeader(f *testing.F) {
	seed := BlockHeader{Version: 1, Timestamp: 1700000000, Bits: 0x1e001999, Nonce: 42}
	f.Add(seed.Serialize())
	f.Add(make([]byte, HeaderSize))
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize-1))

	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := DeserializeHeader(data)
		if err != nil {
			return
		}
		// Round-trip: re-serialize and compare. DeserializeHeader accepts
		// any len >= HeaderSize and reads exactly the first HeaderSize bytes,
		// so the expected round-trip is against data[:HeaderSize].
		if got := h.Serialize(); !bytes.Equal(got, data[:HeaderSize]) {
			t.Fatalf("header round-trip mismatch:\n got: %x\n want: %x", got, data[:HeaderSize])
		}
	})
}

// FuzzDeserializeBlock asserts DeserializeBlock never panics and round-trips
// on accepted inputs. Bounded allocations (MaxBlockSize, MaxBlockTxCount) are
// enforced by the decoder; the fuzzer hammers the count-vs-bytes interactions.
func FuzzDeserializeBlock(f *testing.F) {
	// Seed 1: empty block (no txs, just a header).
	empty := &Block{Header: BlockHeader{Version: 1, Bits: 0x1e001999}}
	f.Add(empty.Serialize())

	// Seed 2: block with one minimal transaction.
	tx := txn.Transaction{Version: 1}
	withTx := &Block{Header: BlockHeader{Version: 1, Bits: 0x1e001999}, Txns: []txn.Transaction{tx}}
	f.Add(withTx.Serialize())

	// Seed 3: truncated header.
	f.Add(make([]byte, HeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		blk, err := DeserializeBlock(data)
		if err != nil {
			return
		}
		if blk == nil {
			t.Fatal("nil block with nil error")
		}
		if len(blk.Txns) > MaxBlockTxCount {
			t.Fatalf("tx count %d exceeds MaxBlockTxCount", len(blk.Txns))
		}
		// Round-trip assertion: re-serialize and redecode. We don't compare
		// to `data` because the input may carry trailing bytes we ignore.
		round := blk.Serialize()
		if _, err := DeserializeBlock(round); err != nil {
			t.Fatalf("serialized form of decoded block fails to re-decode: %v", err)
		}
	})
}
