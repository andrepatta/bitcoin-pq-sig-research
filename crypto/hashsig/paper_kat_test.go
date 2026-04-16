package hashsig

import (
	"encoding/json"
	"os"
	"testing"
)

// katFixture mirrors the schema of testdata/paper_kat.json produced by
// SPHINCS-Parameters/dump_katfixtures.sage. Field names are chosen to
// match sage's JSON keys.
type katParams struct {
	Name               string  `json:"name"`
	Scheme             string  `json:"scheme"`
	QsLog2             int     `json:"q_s_log2"`
	H                  int     `json:"h"`
	D                  int     `json:"d"`
	A                  int     `json:"a"`
	K                  int     `json:"k"`
	W                  int     `json:"w"`
	Swn                int     `json:"swn"`
	L                  int     `json:"l"`
	T                  int     `json:"t"`
	MMax               int     `json:"mmax"`
	SigSizeBytes       int     `json:"sig_size_bytes"`
	SecurityBits       float64 `json:"security_bits"`
	SignCompressions   int     `json:"sign_compressions"`
	VerifyCompressions int     `json:"verify_compressions"`
}

type katFile struct {
	NBytes        int         `json:"n_bytes"`
	ParameterSets []katParams `json:"parameter_sets"`
}

// loadKAT loads the sage-generated fixture at testdata/paper_kat.json.
func loadKAT(t *testing.T) katFile {
	t.Helper()
	data, err := os.ReadFile("testdata/paper_kat.json")
	if err != nil {
		t.Fatalf("read KAT: %v", err)
	}
	var k katFile
	if err := json.Unmarshal(data, &k); err != nil {
		t.Fatalf("parse KAT: %v", err)
	}
	return k
}

// Paper-vs-ours sig-size delta:
//
//	ours = paper + pors.CounterBytes()  (PORS+FP grind salt = 4 bytes at L1)
//
// The counter is the "salt s" returned by §10 Algorithm 1: without it,
// a verifier cannot reproduce the (τ-fixed) inner grinding that keeps
// the PORS tree build off the grind hot path. Sage's `compute_size`
// omits this byte cost — the expected value is small and the authors
// seem to treat it as negligible vs the ~1.8 KB auth set — but the
// construction itself needs it. Accepting it as a documented overhead.
//
// R size is 2N = 32 bytes per paper §11 / sage `randomness_size = 32`,
// matched exactly by SPHINCSParams.RSize().

// TestKATPaperSigSizes asserts that our Go types produce SigSize()
// matching the paper oracle modulo the documented delta. This catches
// accidental regressions in SigSize()/Validate() arithmetic that would
// silently desync with costs.sage.
func TestKATPaperSigSizes(t *testing.T) {
	kat := loadKAT(t)
	if kat.NBytes != 16 {
		t.Fatalf("fixture N mismatch: %d", kat.NBytes)
	}

	for _, pset := range kat.ParameterSets {
		t.Run(pset.Name, func(t *testing.T) {
			if pset.Scheme != "W+C_P+FP" {
				t.Skipf("unsupported scheme %q", pset.Scheme)
			}
			// Build the equivalent Go SPHINCS+ param set.
			wp, err := NewWOTSPlusCParams(16, 16, pset.W, 0, pset.Swn, 32)
			if err != nil {
				t.Fatal(err)
			}
			if wp.Ell != pset.L {
				t.Fatalf("WOTS ℓ mismatch: got %d want %d", wp.Ell, pset.L)
			}
			pors := PORSParams{N: 16, K: pset.K, ALog2: pset.A, RBits: 32, MMax: pset.MMax}
			if pors.TotalLeaves() != pset.T {
				t.Fatalf("PORS t mismatch: got %d want %d", pors.TotalLeaves(), pset.T)
			}
			sp := SPHINCSParams{
				N: 16, H: pset.H, D: pset.D,
				WOTS: wp, PORS: pors, RBits: 32,
			}
			if err := sp.Validate(); err != nil {
				t.Fatalf("SPHINCSParams.Validate: %v", err)
			}
			// Expected size under our layout — exactly paper + grind salt.
			expect := pset.SigSizeBytes + pors.CounterBytes()
			if sp.SigSize() != expect {
				t.Fatalf("SigSize: got %d want %d (paper %d + %d-byte PORS grind salt)",
					sp.SigSize(), expect, pset.SigSizeBytes, pors.CounterBytes())
			}
		})
	}
}

// TestKATBalancedTreeHeight cross-checks that our PORSParams.TreeHeight
// matches the ceil(log2(t)) implied by the paper's (k, a).
func TestKATBalancedTreeHeight(t *testing.T) {
	kat := loadKAT(t)
	for _, pset := range kat.ParameterSets {
		t.Run(pset.Name, func(t *testing.T) {
			pors := PORSParams{N: 16, K: pset.K, ALog2: pset.A, RBits: 32, MMax: pset.MMax}
			// Paper's PORS tree has h = ceil(log2(k·2^a)).
			// For power-of-2 k: h = log2(k) + a; otherwise h = log2(k) rounded up + a.
			wantH := 0
			for x := pset.T - 1; x > 0; x >>= 1 {
				wantH++
			}
			if pors.TreeHeight() != wantH {
				t.Fatalf("TreeHeight: got %d want %d", pors.TreeHeight(), wantH)
			}
		})
	}
}
