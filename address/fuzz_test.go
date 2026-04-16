package address

import (
	"bytes"
	"testing"
)

// FuzzDeserializeSpend asserts DeserializeSpend never panics on arbitrary
// input and that accepted spends round-trip byte-exactly.
func FuzzDeserializeSpend(f *testing.F) {
	// Seed 1: empty-everything spend.
	empty := P2MRSpend{}
	f.Add(SerializeSpend(empty))

	// Seed 2: spend with a trivial leaf script + one proof node + one
	// witness item. Does not have to be consensus-valid, only shape-valid.
	shaped := P2MRSpend{
		LeafScript:  LeafScript{0x51}, // OP_1
		LeafIndex:   0,
		MerkleProof: [][32]byte{{}},
		Witness:     [][]byte{{0x00, 0x01, 0x02}},
	}
	f.Add(SerializeSpend(shaped))

	// Seed 3: short/empty input.
	f.Add([]byte{})
	f.Add(make([]byte, 4))

	f.Fuzz(func(t *testing.T, data []byte) {
		s, n, err := DeserializeSpend(data)
		if err != nil {
			return
		}
		if n < 0 || n > len(data) {
			t.Fatalf("bytes consumed %d outside [0, %d]", n, len(data))
		}
		if len(s.LeafScript) > MaxLeafScriptSize {
			t.Fatalf("leaf script len %d exceeds cap", len(s.LeafScript))
		}
		if len(s.MerkleProof) > MaxMerkleProofDepth {
			t.Fatalf("proof depth %d exceeds cap", len(s.MerkleProof))
		}
		if len(s.Witness) > MaxWitnessItemCount {
			t.Fatalf("witness item count %d exceeds cap", len(s.Witness))
		}
		for i, w := range s.Witness {
			if len(w) > MaxWitnessItemSize {
				t.Fatalf("witness item %d len %d exceeds cap", i, len(w))
			}
		}
		round := SerializeSpend(s)
		if !bytes.Equal(round, data[:n]) {
			t.Fatalf("spend round-trip mismatch:\n got:  %x\n want: %x", round, data[:n])
		}
	})
}

// FuzzDecodeBech32 asserts the address decoder never panics on arbitrary
// strings.
func FuzzDecodeBech32(f *testing.F) {
	// Seed: valid encoding of the zero-root address.
	if s, err := EncodeBech32(P2MRAddress{}); err == nil {
		f.Add(s)
	}
	f.Add("")
	f.Add("qbc")
	f.Add("qbc1invalid")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = DecodeBech32(s)
	})
}
