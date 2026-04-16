package txn

import (
	"bytes"
	"testing"

	"qbitcoin/address"
)

// FuzzDeserializeTx asserts DeserializeTx never panics on arbitrary input and
// that accepted transactions round-trip byte-exactly.
func FuzzDeserializeTx(f *testing.F) {
	// Seed 1: minimal tx, no inputs, no outputs.
	empty := &Transaction{Version: 1}
	f.Add(empty.Serialize())

	// Seed 2: tx with one tiny output.
	withOut := &Transaction{
		Version: 1,
		Outputs: []TxOutput{{Value: 5000, Address: address.P2MRAddress{}}},
	}
	f.Add(withOut.Serialize())

	// Seed 3: tx with one input carrying a minimal spend.
	withIn := &Transaction{
		Version: 1,
		Inputs: []TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0,
			Spend:     address.P2MRSpend{LeafIndex: 0},
		}},
	}
	f.Add(withIn.Serialize())

	// Seed 4: short/empty buffer.
	f.Add([]byte{})
	f.Add(make([]byte, 4))

	f.Fuzz(func(t *testing.T, data []byte) {
		tx, n, err := DeserializeTx(data)
		if err != nil {
			return
		}
		if tx == nil {
			t.Fatal("nil tx with nil error")
		}
		if n < 0 || n > len(data) {
			t.Fatalf("bytes consumed %d outside [0, %d]", n, len(data))
		}
		if len(tx.Inputs) > MaxTxInputs {
			t.Fatalf("input count %d exceeds cap", len(tx.Inputs))
		}
		if len(tx.Outputs) > MaxTxOutputs {
			t.Fatalf("output count %d exceeds cap", len(tx.Outputs))
		}
		round := tx.Serialize()
		if !bytes.Equal(round, data[:n]) {
			t.Fatalf("tx round-trip mismatch:\n got:  %x\n want: %x", round, data[:n])
		}
	})
}
