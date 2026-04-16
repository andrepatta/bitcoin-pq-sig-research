package hashsig

import (
	"bytes"
	"testing"
)

func htTestParams(totalH, layerH int) HTParams {
	return HTParams{
		TotalHeight: totalH,
		LayerHeight: layerH,
		D:           totalH / layerH,
		WOTS:        NewWOTSTWParams(16, 16, 16),
	}
}

func TestHTSingleLayerEqualsXMSS(t *testing.T) {
	// With D=1 the hypertree degenerates to a single XMSS tree; root
	// and verification must match the XMSS implementation exactly.
	p := testParams()
	sk := bytes.Repeat([]byte{0x33}, 16)
	msg := bytes.Repeat([]byte{0x77}, 16)

	hp := htTestParams(3, 3)
	xp := XMSSParams{Height: 3, WOTS: hp.WOTS}

	htRoot, err := hp.GenPK(p, sk)
	if err != nil {
		t.Fatal(err)
	}
	var base ADRS
	base.SetLayer(0)
	base.SetTree(0)
	xRoot, err := xp.GenPK(p, sk, base)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(htRoot, xRoot) {
		t.Fatal("ht D=1 root != xmss root")
	}
	sig, err := hp.Sign(p, sk, msg, 5)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hp.PKFromSig(p, msg, 5, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, htRoot) {
		t.Fatal("ht D=1 round-trip failed")
	}
}

func TestHTMultiLayerRoundTrip(t *testing.T) {
	// Total height 4 split into 2 layers of height 2 each. Small
	// enough to run but exercises cross-layer signing.
	p := testParams()
	hp := htTestParams(4, 2)
	sk := bytes.Repeat([]byte{0x11}, 16)
	msg := bytes.Repeat([]byte{0xEE}, 16)

	root, err := hp.GenPK(p, sk)
	if err != nil {
		t.Fatal(err)
	}
	// Verify a handful of leaf indices across the ht range.
	for _, idx := range []uint64{0, 1, 3, 7, 11, 15} {
		sig, err := hp.Sign(p, sk, msg, idx)
		if err != nil {
			t.Fatalf("sign idx=%d: %v", idx, err)
		}
		if len(sig) != hp.SigSize() {
			t.Fatalf("sig size: got %d want %d", len(sig), hp.SigSize())
		}
		got, err := hp.PKFromSig(p, msg, idx, sig)
		if err != nil {
			t.Fatalf("verify idx=%d: %v", idx, err)
		}
		if !bytes.Equal(got, root) {
			t.Fatalf("idx=%d: recovered root != hp root", idx)
		}
	}
}

func TestHTTamperedLayerFails(t *testing.T) {
	p := testParams()
	hp := htTestParams(4, 2)
	sk := bytes.Repeat([]byte{0x11}, 16)
	msg := bytes.Repeat([]byte{0xEE}, 16)

	root, _ := hp.GenPK(p, sk)
	sig, err := hp.Sign(p, sk, msg, 9)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt a byte inside the upper-layer XMSS signature.
	bad := append([]byte(nil), sig...)
	perLayer := hp.xmssAt().SigSize()
	bad[perLayer+10] ^= 0xff
	got, err := hp.PKFromSig(p, msg, 9, bad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, root) {
		t.Fatal("ht: tampered upper-layer sig verified as original root")
	}
}

func TestHTValidationRejectsBadGeometry(t *testing.T) {
	hp := HTParams{TotalHeight: 5, LayerHeight: 2, D: 2, WOTS: NewWOTSTWParams(16, 16, 16)}
	if err := hp.Validate(); err == nil {
		t.Fatal("expected validation error: 2·2 != 5")
	}
}
