package crypto

import "testing"

func leaf(b byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// TestMerkleMutationSecondPreimage demonstrates CVE-2012-2459.
// A 3-leaf honest tree [A,B,C] and a 4-leaf crafted tree [A,B,C,C]
// produce the same root under Bitcoin's odd-level duplicate-last rule.
// MerkleRoot itself yields the matching value; MerkleRootMutated flags
// the 4-leaf variant so block validators can reject it.
func TestMerkleMutationSecondPreimage(t *testing.T) {
	a, b, c := leaf(0xAA), leaf(0xBB), leaf(0xCC)

	honest := [][32]byte{a, b, c}
	crafted := [][32]byte{a, b, c, c}

	honestRoot, honestMut := MerkleRootMutated(honest)
	craftedRoot, craftedMut := MerkleRootMutated(crafted)

	if honestRoot != craftedRoot {
		t.Fatalf("expected identical roots (CVE-2012-2459 precondition): honest=%x crafted=%x", honestRoot, craftedRoot)
	}
	if honestMut {
		t.Fatalf("honest 3-leaf tree should not be flagged mutated")
	}
	if !craftedMut {
		t.Fatalf("crafted 4-leaf tree with C==C must be flagged mutated")
	}
}

// TestMerkleMutationDeepLevel checks that mutation is detected at a
// non-leaf level, where the duplicate siblings are hashes of larger
// subtrees rather than literal leaves.
func TestMerkleMutationDeepLevel(t *testing.T) {
	a, b := leaf(0x01), leaf(0x02)
	sub := Hash256Concat(a, b)

	// 6 leaves: [a,b,a,b,x,y]. Level 0 pairs → [sub, sub, H(xy)].
	// Level 1 consecutive siblings equal sub → flagged mutated.
	leaves := [][32]byte{a, b, a, b, leaf(0x03), leaf(0x04)}
	_, mutated := MerkleRootMutated(leaves)
	if !mutated {
		t.Fatalf("expected mutation at internal level where sub==sub")
	}
	_ = sub
}

func TestMerkleMutationCleanTrees(t *testing.T) {
	cases := [][][32]byte{
		{leaf(1)},
		{leaf(1), leaf(2)},
		{leaf(1), leaf(2), leaf(3)},
		{leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)},
	}
	for i, leaves := range cases {
		if _, m := MerkleRootMutated(leaves); m {
			t.Fatalf("case %d: distinct leaves wrongly flagged mutated", i)
		}
	}
}

func TestMerkleRootWrapperMatchesMutated(t *testing.T) {
	leaves := [][32]byte{leaf(7), leaf(8), leaf(9)}
	r1 := MerkleRoot(leaves)
	r2, _ := MerkleRootMutated(leaves)
	if r1 != r2 {
		t.Fatalf("MerkleRoot wrapper diverged from MerkleRootMutated: %x vs %x", r1, r2)
	}
}
