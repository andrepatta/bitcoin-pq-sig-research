package hashsig

import (
	"bytes"
	"testing"
)

// Structural tests for the SPHINCS+ (W+C P+FP) composition. Parameters
// are intentionally tiny so keygen (O(2^h · t_PORS) hash evaluations)
// completes in milliseconds. Production-shaped parameters are
// validated against costs.sage by separate KAT fixtures.
//
// Test geometry:
//
//	h = 4, d = 2         → per-layer XMSS height 2, 16 hypertree leaves
//	PORS: k=3, ALog2=3   → 8 leaves per PORS+FP instance
//	WOTS+C: w=16, z=0    → 32 chains per WOTS+C pk, fast grinding
//
// Total hash cost for keygen: 16 hypertree leaves × (WOTS+C keygen +
// one PORS+FP tree of 8 leaves) ≈ a few thousand SHA-256 calls — fast.

func spTestParams(t *testing.T) SPHINCSParams {
	t.Helper()
	wp, err := NewWOTSPlusCParams(16, 16, 16, 0, 240, 24)
	if err != nil {
		t.Fatal(err)
	}
	return SPHINCSParams{
		N:     16,
		H:     4,
		D:     2,
		WOTS:  wp,
		PORS:  PORSParams{N: 16, K: 3, ALog2: 3, RBits: 16, MMax: 5},
		RBits: 16,
	}
}

func TestSPHINCSRoundTrip(t *testing.T) {
	p := testParams()
	sp := spTestParams(t)
	sk := bytes.Repeat([]byte{0x42}, 16)
	skPRF := bytes.Repeat([]byte{0x13}, 16)
	opt := bytes.Repeat([]byte{0x00}, 16)
	msg := []byte("sphincs+ W+C P+FP round-trip payload")

	pkRoot, err := sp.GenPK(p, sk)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkRoot) != sp.N {
		t.Fatalf("pk size: got %d want %d", len(pkRoot), sp.N)
	}

	sig, err := sp.Sign(p, sk, skPRF, opt, msg, pkRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != sp.SigSize() {
		t.Fatalf("sig size: got %d want %d", len(sig), sp.SigSize())
	}
	if !sp.Verify(p, msg, sig, pkRoot) {
		t.Fatal("verify returned false for a freshly-produced signature")
	}
}

func TestSPHINCSWrongMessageFails(t *testing.T) {
	p := testParams()
	sp := spTestParams(t)
	sk := bytes.Repeat([]byte{0x42}, 16)
	skPRF := bytes.Repeat([]byte{0x13}, 16)
	opt := bytes.Repeat([]byte{0x00}, 16)
	msg := []byte("original message")

	pkRoot, _ := sp.GenPK(p, sk)
	sig, err := sp.Sign(p, sk, skPRF, opt, msg, pkRoot)
	if err != nil {
		t.Fatal(err)
	}
	if sp.Verify(p, []byte("tampered message"), sig, pkRoot) {
		t.Fatal("verify accepted signature over a different message")
	}
}

func TestSPHINCSWrongPKFails(t *testing.T) {
	p := testParams()
	sp := spTestParams(t)
	sk := bytes.Repeat([]byte{0x42}, 16)
	skPRF := bytes.Repeat([]byte{0x13}, 16)
	opt := bytes.Repeat([]byte{0x00}, 16)
	msg := []byte("m")

	pkRoot, _ := sp.GenPK(p, sk)
	sig, err := sp.Sign(p, sk, skPRF, opt, msg, pkRoot)
	if err != nil {
		t.Fatal(err)
	}
	// Generate a distinct pk from a different seed.
	otherPK, _ := sp.GenPK(p, bytes.Repeat([]byte{0x99}, 16))
	if sp.Verify(p, msg, sig, otherPK) {
		t.Fatal("verify accepted signature under a different public key")
	}
}

func TestSPHINCSTamperedRFails(t *testing.T) {
	p := testParams()
	sp := spTestParams(t)
	sk := bytes.Repeat([]byte{0x42}, 16)
	skPRF := bytes.Repeat([]byte{0x13}, 16)
	opt := bytes.Repeat([]byte{0x00}, 16)
	msg := []byte("m")

	pkRoot, _ := sp.GenPK(p, sk)
	sig, err := sp.Sign(p, sk, skPRF, opt, msg, pkRoot)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01 // flip a bit in R
	if sp.Verify(p, msg, bad, pkRoot) {
		t.Fatal("verify accepted signature with tampered R")
	}
}

func TestSPHINCSTamperedPORSFails(t *testing.T) {
	p := testParams()
	sp := spTestParams(t)
	sk := bytes.Repeat([]byte{0x42}, 16)
	skPRF := bytes.Repeat([]byte{0x13}, 16)
	opt := bytes.Repeat([]byte{0x00}, 16)
	msg := []byte("m")

	pkRoot, _ := sp.GenPK(p, sk)
	sig, err := sp.Sign(p, sk, skPRF, opt, msg, pkRoot)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sig...)
	// First revealed PORS+FP sk sits at offset N (after R).
	bad[sp.N+2] ^= 0xff
	if sp.Verify(p, msg, bad, pkRoot) {
		t.Fatal("verify accepted tampered PORS+FP sk")
	}
}

func TestSPHINCSTamperedHTFails(t *testing.T) {
	p := testParams()
	sp := spTestParams(t)
	sk := bytes.Repeat([]byte{0x42}, 16)
	skPRF := bytes.Repeat([]byte{0x13}, 16)
	opt := bytes.Repeat([]byte{0x00}, 16)
	msg := []byte("m")

	pkRoot, _ := sp.GenPK(p, sk)
	sig, err := sp.Sign(p, sk, skPRF, opt, msg, pkRoot)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), sig...)
	// Flip the last byte (inside the hypertree auth path of the top layer).
	bad[len(bad)-1] ^= 0x01
	if sp.Verify(p, msg, bad, pkRoot) {
		t.Fatal("verify accepted tampered hypertree signature")
	}
}

func TestSPHINCSSigSizeArithmetic(t *testing.T) {
	sp := spTestParams(t)
	wantPORS := sp.PORS.EmbeddedSigSize()
	wantHT := sp.HT().SigSize()
	wantTotal := sp.RSize() + wantPORS + wantHT
	if sp.SigSize() != wantTotal {
		t.Fatalf("SigSize: got %d want %d (R=%d + PORS=%d + HT=%d)",
			sp.SigSize(), wantTotal, sp.RSize(), wantPORS, wantHT)
	}
}

func TestSPHINCSValidateRejects(t *testing.T) {
	wp, _ := NewWOTSPlusCParams(16, 16, 16, 0, 240, 24)
	pors := PORSParams{N: 16, K: 3, ALog2: 3, RBits: 16, MMax: 5}
	cases := map[string]SPHINCSParams{
		"d-does-not-divide-h": {N: 16, H: 5, D: 2, WOTS: wp, PORS: pors, RBits: 16},
		"wots-tw-not-accepted": {
			N: 16, H: 4, D: 2,
			WOTS:  NewWOTSTWParams(16, 16, 16),
			PORS:  pors,
			RBits: 16,
		},
		"n-mismatch": {N: 16, H: 4, D: 2, WOTS: wp,
			PORS:  PORSParams{N: 8, K: 3, ALog2: 3, RBits: 16, MMax: 5},
			RBits: 16,
		},
	}
	for name, sp := range cases {
		if err := sp.Validate(); err == nil {
			t.Fatalf("case %q: expected validation error", name)
		}
	}
}
