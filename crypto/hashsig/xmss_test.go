package hashsig

import (
	"bytes"
	"testing"
)

// Structural tests for balanced XMSS. Correctness against known-answer
// test vectors from SPHINCS+ reference lives in separate KAT fixtures.

func xmssTestParams(height int) XMSSParams {
	return XMSSParams{
		Height: height,
		WOTS:   NewWOTSTWParams(16, 16, 16),
	}
}

func TestXMSSRoundTrip(t *testing.T) {
	p := testParams()
	xp := xmssTestParams(4) // 16 leaves — fast, exercises tree arithmetic
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

	// Sign with every leaf index and verify round-trip.
	msg := bytes.Repeat([]byte{0xA5}, 16)
	for idx := range xp.NumLeaves() {
		sig, err := xp.Sign(p, sk, msg, uint32(idx), base)
		if err != nil {
			t.Fatalf("sign idx=%d: %v", idx, err)
		}
		if len(sig) != xp.SigSize() {
			t.Fatalf("sig size: got %d want %d", len(sig), xp.SigSize())
		}
		got, err := xp.PKFromSig(p, msg, uint32(idx), sig, base)
		if err != nil {
			t.Fatalf("verify idx=%d: %v", idx, err)
		}
		if !bytes.Equal(got, root) {
			t.Fatalf("verify idx=%d: recovered root != genPK root", idx)
		}
	}
}

func TestXMSSWrongIndexFails(t *testing.T) {
	p := testParams()
	xp := xmssTestParams(3)
	sk := bytes.Repeat([]byte{0x77}, 16)
	var base ADRS
	msg := bytes.Repeat([]byte{0xA5}, 16)

	root, _ := xp.GenPK(p, sk, base)
	sig, err := xp.Sign(p, sk, msg, 3, base)
	if err != nil {
		t.Fatal(err)
	}
	// Submit the same sig under a different idx — root must differ.
	got, err := xp.PKFromSig(p, msg, 5, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, root) {
		t.Fatal("xmss: sig verified under wrong leaf index")
	}
}

func TestXMSSTamperedAuthPathFails(t *testing.T) {
	p := testParams()
	xp := xmssTestParams(3)
	sk := bytes.Repeat([]byte{0x77}, 16)
	var base ADRS
	msg := bytes.Repeat([]byte{0xA5}, 16)

	root, _ := xp.GenPK(p, sk, base)
	sig, err := xp.Sign(p, sk, msg, 2, base)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the auth-path region (after the WOTS sig).
	bad := append([]byte(nil), sig...)
	bad[xp.WOTS.SigSize()] ^= 0xff
	got, err := xp.PKFromSig(p, msg, 2, bad, base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, root) {
		t.Fatal("xmss: tampered auth path yielded original root")
	}
}

// Balanced XMSS must accept WOTS+C leaves for the W+C P+FP SPHINCS+
// variant — signing dispatches on RBits. This test exercises a full
// round-trip at one leaf, confirming both the keygen pk-compression
// path and the WOTS+C sign/verify dispatch agree.
func TestXMSSAcceptsWOTSPlusC(t *testing.T) {
	p := testParams()
	wp, err := NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	if err != nil {
		t.Fatal(err)
	}
	xp := XMSSParams{Height: 3, WOTS: wp}
	if err := xp.Validate(); err != nil {
		t.Fatalf("WOTS+C params rejected: %v", err)
	}
	sk := bytes.Repeat([]byte{0x77}, 16)
	var base ADRS
	root, err := xp.GenPK(p, sk, base)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte{0xA5}, 16)
	sig, err := xp.Sign(p, sk, msg, 2, base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := xp.PKFromSig(p, msg, 2, sig, base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, root) {
		t.Fatal("WOTS+C XMSS: recovered root != generated root")
	}
}
