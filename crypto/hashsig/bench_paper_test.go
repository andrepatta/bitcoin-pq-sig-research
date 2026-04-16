package hashsig

import (
	"testing"
	"time"
)

// Isolated timings for the hot loops at paper-compact SPHINCS+ params
// (t=2^20 PORS leaves, h=12 hypertree).
func TestPaperCompactBuildTimes(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	pkSeed := make([]byte, 16)
	p := &Params{N: 16, PKSeed: pkSeed}
	sk := make([]byte, 16)
	for i := range sk {
		sk[i] = byte(i)
	}
	var base ADRS

	// PORS tree at paper compact: K=8, ALog2=17, t=2^20 balanced.
	pp := PORSParams{N: 16, K: 8, ALog2: 17, RBits: 32, MMax: 105}
	start := time.Now()
	root, _ := pp.buildTree(p, sk, base)
	t.Logf("PORS buildTree (t=%d): %s (root %d B)", pp.TotalLeaves(), time.Since(start), len(root))

	// XMSS at h'=12 (compact hypertree top layer).
	wp, _ := NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	xp := XMSSParams{Height: 12, WOTS: wp}
	start = time.Now()
	_, _ = xp.GenPK(p, sk, base)
	t.Logf("XMSS GenPK (h=12): %s", time.Since(start))

	// XMSS at h'=8, w=256 (fallback hypertree layer).
	wpF, _ := NewWOTSPlusCParams(16, 16, 256, 0, 2040, 32)
	xpF := XMSSParams{Height: 8, WOTS: wpF}
	start = time.Now()
	_, _ = xpF.GenPK(p, sk, base)
	t.Logf("XMSS GenPK (h=8 w=256): %s", time.Since(start))
}
