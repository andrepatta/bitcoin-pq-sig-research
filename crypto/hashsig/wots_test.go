package hashsig

import (
	"bytes"
	"testing"
)

// Structural tests for WOTS-TW and WOTS+C. Cover the invariants a
// correct implementation must satisfy: sign/verify round-trip,
// tamper-detection, and signature size matching the paper's arithmetic.

func wotsBase() ADRS {
	var a ADRS
	a.SetLayer(0)
	a.SetTree(0x1234567890abcdef)
	a.SetKeyPair(42)
	return a
}

func TestWOTSTWRoundTrip(t *testing.T) {
	p := testParams()
	wp := NewWOTSTWParams(16, 16, 16)
	if wp.Ell != wp.Len1+wp.Len2 {
		t.Fatalf("ell mismatch: got %d want %d", wp.Ell, wp.Len1+wp.Len2)
	}
	sk := bytes.Repeat([]byte{0xCC}, 16)
	msg := bytes.Repeat([]byte{0x5A}, 16)
	base := wotsBase()

	pk := wp.WOTSGenPK(p, sk, base)
	if len(pk) != wp.N {
		t.Fatalf("pk size: got %d want %d", len(pk), wp.N)
	}
	sig, err := wp.WOTSSign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != wp.Ell*wp.N {
		t.Fatalf("sig size: got %d want %d", len(sig), wp.Ell*wp.N)
	}
	pk2, err := wp.WOTSPKFromSig(p, msg, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk, pk2) {
		t.Fatal("WOTS-TW: recovered pk != generated pk")
	}
}

func TestWOTSTWTamperDetected(t *testing.T) {
	p := testParams()
	wp := NewWOTSTWParams(16, 16, 16)
	sk := bytes.Repeat([]byte{0xCC}, 16)
	msg := bytes.Repeat([]byte{0x5A}, 16)
	base := wotsBase()
	pk := wp.WOTSGenPK(p, sk, base)
	sig, err := wp.WOTSSign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	// Flipping a bit in the message produces a different pk (verify fails).
	msg2 := append([]byte(nil), msg...)
	msg2[0] ^= 0x01
	pk2, err := wp.WOTSPKFromSig(p, msg2, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pk, pk2) {
		t.Fatal("WOTS-TW: tampered message yielded identical pk")
	}
}

func TestWOTSPlusCRoundTrip(t *testing.T) {
	p := testParams()
	// Small-grind parameters so the counter search terminates quickly:
	// n=m=16, w=16, len1=32. Pick z=0, S = 32·(16-1)/2 = 240 (the
	// expected value for uniform random digits). rBits=32.
	wp, err := NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	if err != nil {
		t.Fatal(err)
	}
	if wp.SigSize() != wp.Ell*wp.N+4 {
		t.Fatalf("sig size: got %d want %d", wp.SigSize(), wp.Ell*wp.N+4)
	}
	sk := bytes.Repeat([]byte{0xAB}, 16)
	msg := bytes.Repeat([]byte{0x33}, 16)
	base := wotsBase()

	sig, err := wp.WOTSPlusCSign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != wp.SigSize() {
		t.Fatalf("sig size: got %d want %d", len(sig), wp.SigSize())
	}
	// PK recovered from a valid sig under the same base ADRS must be
	// stable across re-verification.
	pk1, err := wp.WOTSPlusCPKFromSig(p, msg, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	pk2, err := wp.WOTSPlusCPKFromSig(p, msg, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pk1, pk2) {
		t.Fatal("WOTS+C: verify is non-deterministic")
	}
}

func TestWOTSPlusCTamperDetected(t *testing.T) {
	p := testParams()
	wp, err := NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	if err != nil {
		t.Fatal(err)
	}
	sk := bytes.Repeat([]byte{0xAB}, 16)
	msg := bytes.Repeat([]byte{0x33}, 16)
	base := wotsBase()
	sig, err := wp.WOTSPlusCSign(p, sk, msg, base)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupting the counter must cause verify to fail (predicate fails
	// or digits differ in the first positions).
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xff
	if _, err := wp.WOTSPlusCPKFromSig(p, msg, bad, base); err == nil {
		// It is possible (astronomically unlikely at rBits=32) that the
		// flipped counter still satisfies the predicate, in which case
		// the recovered pk just differs. Accept either outcome.
		pkOrig, _ := wp.WOTSPlusCPKFromSig(p, msg, sig, base)
		pkBad, _ := wp.WOTSPlusCPKFromSig(p, msg, bad, base)
		if bytes.Equal(pkOrig, pkBad) {
			t.Fatal("WOTS+C: counter flip produced identical pk")
		}
	}
}

func TestWOTSPlusCSHRINCSSizeTarget(t *testing.T) {
	// SHRINCS OTS per paper §B.3: m=9, w=16, len1=18, z=0, ell=18,
	// rBits=32 → 18·16 + 4 = 292 B. S=135 is the centered target where
	// ν is maximal; counter grinding converges in ~50 tries on average.
	wp, err := NewWOTSPlusCParams(16, 9, 16, 0, 135, 32)
	if err != nil {
		t.Fatal(err)
	}
	if wp.Ell != 18 {
		t.Fatalf("ell: got %d want 18", wp.Ell)
	}
	if wp.SigSize() != 292 {
		t.Fatalf("SHRINCS OTS sig size: got %d want 292", wp.SigSize())
	}
}

func TestBaseWRoundsTripW16(t *testing.T) {
	// 16-byte input at w=16 decodes to 32 nibbles, MSN first.
	in := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	got := baseW(in, 16, 32)
	want := []uint8{
		0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
		0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0,
		0x0, 0x0, 0x1, 0x1, 0x2, 0x2, 0x3, 0x3,
		0x4, 0x4, 0x5, 0x5, 0x6, 0x6, 0x7, 0x7,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("baseW[%d]: got %x want %x", i, got[i], want[i])
		}
	}
}
