package hashsig

import (
	"bytes"
	"testing"
)

// Structural tests for unbalanced XMSS (§B.3). Known-answer validation
// against costs.sage / reference implementations lives in separate KAT fixtures.
//
// The WOTS+C parameters used below are from docs/parameters/ (SHRINCS
// OTS at L1): n=16, w=16, z=14, ℓ=18. S is a representative in-range
// value; any value in [0, len1·(w-1)] suffices for structural
// round-tripping. Keep RBits generous so the counter search always
// terminates in tests.

func uxmssTestParams(n int) UXMSSParams {
	// Use z=0, S=240 (the same fast-grinding parameters as
	// TestWOTSPlusCRoundTrip). A z>0 test would require running
	// security.sage to pick a feasible S; structural round-trip
	// is what we're validating here.
	wp, err := NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	if err != nil {
		panic(err)
	}
	return UXMSSParams{NumLeaves: n, WOTS: wp}
}

func TestUXMSSRoundTrip(t *testing.T) {
	p := testParams()
	xp := uxmssTestParams(5) // small tree — every leaf exercised
	sk := bytes.Repeat([]byte{0x77}, 16)
	var base ADRS
	base.SetLayer(0)
	base.SetTree(0)

	root, err := xp.GenPK(p, sk, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 16 {
		t.Fatalf("root size: got %d want 16", len(root))
	}

	msg := bytes.Repeat([]byte{0xA5}, 16)
	for q := range xp.NumLeaves {
		sig, err := xp.Sign(p, sk, msg, q, base)
		if err != nil {
			t.Fatalf("sign q=%d: %v", q, err)
		}
		if len(sig) != xp.SigSize(q) {
			t.Fatalf("sig size q=%d: got %d want %d", q, len(sig), xp.SigSize(q))
		}
		got, err := xp.PKFromSig(p, msg, q, sig, base)
		if err != nil {
			t.Fatalf("verify q=%d: %v", q, err)
		}
		if !bytes.Equal(got, root) {
			t.Fatalf("verify q=%d: recovered root != GenPK root", q)
		}
	}
}

func TestUXMSSAuthPathLen(t *testing.T) {
	xp := uxmssTestParams(6)
	// Per §B.3: leaf q<N-1 gets auth path of length q+1; deepest two
	// leaves share depth N-1, each with path length N-1.
	cases := map[int]int{0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 5}
	for q, want := range cases {
		if got := xp.AuthPathLen(q); got != want {
			t.Fatalf("AuthPathLen(q=%d): got %d want %d", q, got, want)
		}
	}
}

func TestUXMSSWrongIndexFails(t *testing.T) {
	p := testParams()
	xp := uxmssTestParams(5)
	sk := bytes.Repeat([]byte{0x77}, 16)
	var base ADRS
	msg := bytes.Repeat([]byte{0xA5}, 16)

	root, _ := xp.GenPK(p, sk, base)
	// Sign at q=2, attempt to verify at q=1. Signature length mismatch
	// is the primary defense: a q=2 sig has a longer auth path than a
	// q=1 sig expects, so verification must reject on size alone.
	sig, err := xp.Sign(p, sk, msg, 2, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xp.PKFromSig(p, msg, 1, sig, base); err == nil {
		t.Fatal("expected size-mismatch error when verifying q=2 sig at q=1")
	}

	// Same-length case: q=3 sig (len 4) re-submitted at q=2 (also len 3)? no, different lengths.
	// Use deepest pair (q=N-2 vs q=N-1) which share path length N-1.
	sigDeep, err := xp.Sign(p, sk, msg, xp.NumLeaves-2, base)
	if err != nil {
		t.Fatal(err)
	}
	// Verifying a q=N-2 sig under q=N-1 should either error at the WOTS+C
	// layer (keypair ADRS differs, so counter predicate fails) or recover
	// a root distinct from the tree's actual root. Both are acceptable
	// rejections — a silent accept would be a bug.
	got, err := xp.PKFromSig(p, msg, xp.NumLeaves-1, sigDeep, base)
	if err == nil && bytes.Equal(got, root) {
		t.Fatal("sig at leaf N-2 verified under leaf N-1")
	}
}

func TestUXMSSTamperedAuthPathFails(t *testing.T) {
	p := testParams()
	xp := uxmssTestParams(5)
	sk := bytes.Repeat([]byte{0x77}, 16)
	var base ADRS
	msg := bytes.Repeat([]byte{0xA5}, 16)

	root, _ := xp.GenPK(p, sk, base)
	sig, err := xp.Sign(p, sk, msg, 3, base)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sig...)
	// Flip a byte inside the auth-path region.
	bad[xp.WOTS.SigSize()+1] ^= 0xff
	got, err := xp.PKFromSig(p, msg, 3, bad, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, root) {
		t.Fatal("tampered auth path recovered the original root")
	}
}

func TestUXMSSRejectsWOTSTWParams(t *testing.T) {
	wp := NewWOTSTWParams(16, 16, 16)
	xp := UXMSSParams{NumLeaves: 4, WOTS: wp}
	if err := xp.Validate(); err == nil {
		t.Fatal("expected rejection of WOTS-TW params in unbalanced XMSS")
	}
}

func TestUXMSSRejectsTinyTree(t *testing.T) {
	wp, _ := NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	xp := UXMSSParams{NumLeaves: 1, WOTS: wp}
	if err := xp.Validate(); err == nil {
		t.Fatal("expected rejection of NumLeaves < 2")
	}
}
