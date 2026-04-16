package address

import (
	"encoding/binary"
	"testing"
)

// TestDeserializeSpend_LeafScriptCap rejects spend bytes claiming an
// over-cap leaf script length.
func TestDeserializeSpend_LeafScriptCap(t *testing.T) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], MaxLeafScriptSize+1)
	if _, _, err := DeserializeSpend(b[:]); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}

// TestDeserializeSpend_ProofDepthCap rejects an over-cap proof count.
func TestDeserializeSpend_ProofDepthCap(t *testing.T) {
	b := make([]byte, 4+4+4)
	binary.BigEndian.PutUint32(b[0:4], 0)                      // leafscript len
	binary.BigEndian.PutUint32(b[4:8], 0)                      // leaf index
	binary.BigEndian.PutUint32(b[8:12], MaxMerkleProofDepth+1) // proof count
	if _, _, err := DeserializeSpend(b); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}

// TestDeserializeSpend_WitnessCountCap rejects an over-cap witness item count.
func TestDeserializeSpend_WitnessCountCap(t *testing.T) {
	b := make([]byte, 4+4+4+4)
	binary.BigEndian.PutUint32(b[0:4], 0)                       // leafscript len
	binary.BigEndian.PutUint32(b[4:8], 0)                       // leaf index
	binary.BigEndian.PutUint32(b[8:12], 0)                      // proof count
	binary.BigEndian.PutUint32(b[12:16], MaxWitnessItemCount+1) // witness count
	if _, _, err := DeserializeSpend(b); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}

// TestDeserializeSpend_WitnessItemSizeCap rejects an over-cap individual
// witness item.
func TestDeserializeSpend_WitnessItemSizeCap(t *testing.T) {
	b := make([]byte, 4+4+4+4+4)
	binary.BigEndian.PutUint32(b[0:4], 0)                      // leafscript len
	binary.BigEndian.PutUint32(b[4:8], 0)                      // leaf index
	binary.BigEndian.PutUint32(b[8:12], 0)                     // proof count
	binary.BigEndian.PutUint32(b[12:16], 1)                    // 1 witness item
	binary.BigEndian.PutUint32(b[16:20], MaxWitnessItemSize+1) // witness item len
	if _, _, err := DeserializeSpend(b); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}

// TestDeserializeSpend_RoundTrip ensures a real-shaped spend still parses.
func TestDeserializeSpend_RoundTrip(t *testing.T) {
	in := P2MRSpend{
		LeafScript:  NewP2PKLeaf([]byte{1, 2, 3, 4}),
		LeafIndex:   0,
		MerkleProof: [][32]byte{{0xAA}},
		Witness:     [][]byte{{0xBB, 0xCC}, {0xDD}},
	}
	bytes := SerializeSpend(in)
	out, n, err := DeserializeSpend(bytes)
	if err != nil {
		t.Fatalf("round-trip parse: %v", err)
	}
	if n != len(bytes) {
		t.Fatalf("consumed %d, want %d", n, len(bytes))
	}
	if string(out.LeafScript) != string(in.LeafScript) ||
		out.LeafIndex != in.LeafIndex ||
		len(out.MerkleProof) != 1 || out.MerkleProof[0] != in.MerkleProof[0] ||
		len(out.Witness) != 2 {
		t.Fatalf("mismatch: %+v", out)
	}
}
