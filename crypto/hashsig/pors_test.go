package hashsig

import (
	"bytes"
	"testing"
)

// --- Octopus KAT against paper §C Fig 21 example --------------------

// The paper's Fig 21 traces the Octopus algorithm for leaves {000, 011,
// 110} in a height-3 tree. The resulting minimal auth set must contain
// the four sibling nodes the algorithm discovers in its canonical
// output order. Levels use the paper's convention: root = 0, leaves = h.
func TestOctopusPaperExample(t *testing.T) {
	got := Octopus([]uint32{0, 3, 6}, 3)
	want := []OctopusNode{
		{Level: 3, Index: 1}, // sibling of leaf 000 at leaf level
		{Level: 3, Index: 2}, // sibling of leaf 011
		{Level: 3, Index: 7}, // sibling of leaf 110
		{Level: 2, Index: 2}, // parent of {110,111} has no neighbor in the working set
	}
	if len(got) != len(want) {
		t.Fatalf("auth size: got %d want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("auth[%d]: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestOctopusFullLeafSetEmpty(t *testing.T) {
	// Revealing every leaf means every sibling is already present — the
	// auth set must be empty at every level.
	h := 3
	all := make([]uint32, 1<<uint(h))
	for i := range all {
		all[i] = uint32(i)
	}
	got := Octopus(all, h)
	if len(got) != 0 {
		t.Fatalf("expected empty auth set, got %d entries: %v", len(got), got)
	}
}

func TestOctopusSingleLeafGivesHSiblings(t *testing.T) {
	// A single leaf in a height-h tree needs exactly h siblings (the
	// full auth path). Octopus cannot compress a lone leaf further.
	h := 4
	got := Octopus([]uint32{5}, h)
	if len(got) != h {
		t.Fatalf("auth size for single leaf: got %d want %d", len(got), h)
	}
}

// --- HashToSubset ---------------------------------------------------

func TestHashToSubsetExtractsTau(t *testing.T) {
	// Craft a digest whose first 8 bits are 0b10110010 = 0xB2, then
	// three 4-bit blocks of distinct values. t = 16 accepts any 4-bit value.
	digest := []byte{0xB2, 0x12, 0x34, 0x00, 0x00}
	tau, idx, ok := HashToSubset(digest, 8, 3, 4, 16)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if tau != 0xB2 {
		t.Fatalf("tau: got 0x%X want 0xB2", tau)
	}
	// Blocks: 0x1, 0x2, 0x3, 0x4 (first three distinct are 1,2,3; sorted).
	want := []uint32{1, 2, 3}
	if !equalU32(idx, want) {
		t.Fatalf("indices: got %v want %v", idx, want)
	}
}

func TestHashToSubsetInsufficientDistinctFails(t *testing.T) {
	// All blocks are 0x1 — duplicates, so fewer than k=3 distinct values.
	digest := []byte{0x11, 0x11, 0x11, 0x00, 0x00}
	if _, _, ok := HashToSubset(digest, 0, 3, 4, 16); ok {
		t.Fatal("expected ok=false when digest lacks enough distinct blocks")
	}
}

// HashToSubset must reject blocks whose value is ≥ t (the non-power-of-2 case).
func TestHashToSubsetRejectsOutOfRange(t *testing.T) {
	// Blocks 0xA, 0xB, 0xC, 0xD, 0xE — with t=11, values ≥ 11 (0xB..0xE)
	// are rejected; only 0xA=10 is accepted, so k=3 distinct should fail.
	digest := []byte{0xAB, 0xCD, 0xE0, 0x00}
	if _, _, ok := HashToSubset(digest, 0, 3, 4, 11); ok {
		t.Fatal("expected ok=false when most blocks are ≥ t")
	}
	// Sanity: with t=16 all blocks are accepted — 0xA, 0xB, 0xC succeed.
	_, idx, ok := HashToSubset(digest, 0, 3, 4, 16)
	if !ok {
		t.Fatal("expected ok=true at t=16")
	}
	if !equalU32(idx, []uint32{0xA, 0xB, 0xC}) {
		t.Fatalf("indices at t=16: got %v want [10 11 12]", idx)
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- PORS+FP round-trip and tamper detection ------------------------

func porsTestParams() PORSParams {
	// Balanced small params: K=2 power of 2 → t = 2·2^3 = 16 leaves,
	// h=4, standard balanced Merkle. Generous MMax so counter grinding
	// succeeds quickly.
	return PORSParams{N: 16, K: 2, ALog2: 3, RBits: 16, MMax: 8}
}

// porsUnbalancedTestParams exercises the non-power-of-2 tree path:
// K=3, ALog2=2 → t = 12 leaves (not a power of 2). The left-filled
// layout has x = 2L = 2·(12-8) = 8 bottom leaves at level 4 and 4 upper
// direct leaves at level 3. Every Octopus walk mixes depths.
func porsUnbalancedTestParams() PORSParams {
	return PORSParams{N: 16, K: 3, ALog2: 2, RBits: 20, MMax: 10}
}

func porsTestBase() ADRS {
	var a ADRS
	a.SetLayer(0)
	a.SetTree(0xABCD)
	a.SetKeyPair(7)
	return a
}

func TestPORSRoundTrip(t *testing.T) {
	p := testParams()
	pp := porsTestParams()
	sk := bytes.Repeat([]byte{0x42}, 16)
	base := porsTestBase()

	root, err := pp.GenPK(p, sk, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != pp.N {
		t.Fatalf("root size: got %d want %d", len(root), pp.N)
	}

	msg := bytes.Repeat([]byte{0x5C}, 32)
	sig, err := pp.Sign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != pp.SigSize() {
		t.Fatalf("sig size: got %d want %d", len(sig), pp.SigSize())
	}

	got, err := pp.PKFromSig(p, msg, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("recovered root != GenPK root")
	}
}

func TestPORSTamperedCounterFails(t *testing.T) {
	p := testParams()
	pp := porsTestParams()
	sk := bytes.Repeat([]byte{0x42}, 16)
	base := porsTestBase()
	msg := bytes.Repeat([]byte{0x5C}, 32)

	root, _ := pp.GenPK(p, sk, base)
	sig, err := pp.Sign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff // flip counter bit
	got, err := pp.PKFromSig(p, msg, bad, base)
	if err != nil {
		return // acceptable: counter-rotated digest fails hash-to-subset
	}
	if bytes.Equal(got, root) {
		t.Fatal("tampered counter yielded original root")
	}
}

func TestPORSTamperedSkFails(t *testing.T) {
	p := testParams()
	pp := porsTestParams()
	sk := bytes.Repeat([]byte{0x42}, 16)
	base := porsTestBase()
	msg := bytes.Repeat([]byte{0x5C}, 32)

	root, _ := pp.GenPK(p, sk, base)
	sig, err := pp.Sign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	// Flip inside the first revealed sk (after the counter bytes).
	bad := append([]byte(nil), sig...)
	bad[pp.CounterBytes()+2] ^= 0xff
	got, err := pp.PKFromSig(p, msg, bad, base)
	if err != nil {
		return
	}
	if bytes.Equal(got, root) {
		t.Fatal("tampered sk yielded original root")
	}
}

func TestPORSTamperedAuthFails(t *testing.T) {
	p := testParams()
	pp := porsTestParams()
	sk := bytes.Repeat([]byte{0x42}, 16)
	base := porsTestBase()
	msg := bytes.Repeat([]byte{0x5C}, 32)

	root, _ := pp.GenPK(p, sk, base)
	sig, err := pp.Sign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the auth-set region (after counter + k·N sks).
	authOff := pp.CounterBytes() + pp.K*pp.N
	bad := append([]byte(nil), sig...)
	bad[authOff+1] ^= 0xff
	got, err := pp.PKFromSig(p, msg, bad, base)
	if err != nil {
		return
	}
	if bytes.Equal(got, root) {
		t.Fatal("tampered auth value yielded original root")
	}
}

// --- Parameter validation -------------------------------------------

func TestPORSValidateRejectsBadParams(t *testing.T) {
	cases := map[string]PORSParams{
		"k-zero":       {N: 16, K: 0, ALog2: 3, RBits: 16, MMax: 5},
		"m-below-k":    {N: 16, K: 3, ALog2: 3, RBits: 16, MMax: 2},
		"alog2-zero":   {N: 16, K: 3, ALog2: 0, RBits: 16, MMax: 5},
		"rbits-zero":   {N: 16, K: 3, ALog2: 3, RBits: 0, MMax: 5},
		"bit-overflow": {N: 16, K: 100, ALog2: 20, RBits: 16, MMax: 100},
	}
	for name, pp := range cases {
		if err := pp.Validate(); err == nil {
			t.Fatalf("case %q: expected validation error", name)
		}
	}
}

// --- Tree shape invariants -----------------------------------------

func TestPORSTreeShapeBalanced(t *testing.T) {
	pp := PORSParams{N: 16, K: 8, ALog2: 4, RBits: 16, MMax: 32}
	// t = 128, h = 7, balanced.
	if pp.TotalLeaves() != 128 {
		t.Fatalf("TotalLeaves: got %d want 128", pp.TotalLeaves())
	}
	if pp.TreeHeight() != 7 {
		t.Fatalf("TreeHeight: got %d want 7", pp.TreeHeight())
	}
	if !pp.IsBalanced() {
		t.Fatal("expected IsBalanced")
	}
	// All leaves should map to level h.
	for i := 0; i < pp.TotalLeaves(); i++ {
		lvl, pos := pp.leafCoords(uint32(i))
		if int(lvl) != pp.TreeHeight() || int(pos) != i {
			t.Fatalf("leaf %d: got (%d, %d) want (%d, %d)", i, lvl, pos, pp.TreeHeight(), i)
		}
	}
}

func TestPORSTreeShapeUnbalanced(t *testing.T) {
	pp := PORSParams{N: 16, K: 3, ALog2: 2, RBits: 20, MMax: 10}
	// t = 12, h = 4, p = 8, L = 4, x = 8. Bottom leaves [0,8) at level 4;
	// upper leaves [8,12) at level 3 positions [4,8).
	if pp.TotalLeaves() != 12 || pp.TreeHeight() != 4 {
		t.Fatalf("shape: t=%d h=%d (want t=12 h=4)", pp.TotalLeaves(), pp.TreeHeight())
	}
	if pp.IsBalanced() {
		t.Fatal("expected NOT balanced")
	}
	// Bottom leaves.
	for i := 0; i < 8; i++ {
		lvl, pos := pp.leafCoords(uint32(i))
		if lvl != 4 || int(pos) != i {
			t.Fatalf("bottom leaf %d: (%d,%d)", i, lvl, pos)
		}
	}
	// Upper leaves — user indices 8..11 map to level-3 positions 4..7.
	for i := 8; i < 12; i++ {
		lvl, pos := pp.leafCoords(uint32(i))
		if lvl != 3 || int(pos) != i-4 {
			t.Fatalf("upper leaf %d: got (%d,%d) want (3,%d)", i, lvl, pos, i-4)
		}
	}
}

// Round-trip on the unbalanced path.
func TestPORSUnbalancedRoundTrip(t *testing.T) {
	p := testParams()
	pp := porsUnbalancedTestParams()
	sk := bytes.Repeat([]byte{0x42}, 16)
	base := porsTestBase()

	root, err := pp.GenPK(p, sk, base)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte{0x5C}, 32)
	sig, err := pp.Sign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pp.PKFromSig(p, msg, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("unbalanced: recovered root != GenPK root")
	}
}

// Octopus should handle mixed-depth leaves (some at h, some at h-1)
// identically to the balanced case algorithmically — both collapse to
// the single sorted left-filled walk.
func TestOctopusMixedDepth(t *testing.T) {
	// Tiny unbalanced tree: t=3, h=2, L=1, x=2.
	// Leaf 0 → (2, 0); leaf 1 → (2, 1); leaf 2 → (1, 1).
	// Revealing all 3 should require 0 auth nodes.
	leaves := []OctopusNode{{Level: 2, Index: 0}, {Level: 2, Index: 1}, {Level: 1, Index: 1}}
	if got := OctopusMixed(leaves, 2); len(got) != 0 {
		t.Fatalf("full-leaf Octopus should be empty, got %+v", got)
	}
	// Revealing just leaf 0: needs sibling (2,1), then (1,1) at the upper level.
	got := OctopusMixed([]OctopusNode{{Level: 2, Index: 0}}, 2)
	want := []OctopusNode{{Level: 2, Index: 1}, {Level: 1, Index: 1}}
	if len(got) != len(want) {
		t.Fatalf("mixed: got %+v want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mixed auth[%d]: got %+v want %+v", i, got[i], want[i])
		}
	}
}
