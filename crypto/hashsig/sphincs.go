// SPHINCS+ (W+C P+FP) — the stateless hash-based signature scheme §11
// of Kudinov & Nick, "Hash-based Signature Schemes for Bitcoin" (IACR
// eprint 2025/2203, Revision 2025-12-05), instantiated with:
//
//   - WOTS+C (§5) at every hypertree layer (one-time signatures)
//   - PORS+FP (§10) at the bottom, replacing FORS as the few-time
//     signature whose root is signed by the hypertree's leaf at τ
//
// Construction:
//
//	           R ── PRFmsg(SK.prf, opt, m, counter)
//	           │
//	           ▼
//	   Hmsg(R, PK.seed, PK.root, m) ── 64-byte digest
//	           │
//	   HashToSubset(digest, h, k, a+log₂k)
//	           │
//	   (τ: hypertree leaf, I = {i_1,…,i_k}: PORS+FP indices)
//	           │
//	           ▼
//	   PORS+FP at ADRS(layer=0, tree=τ):
//	     • sks for indices I
//	     • Octopus auth set ≤ m_max siblings
//	           │
//	           ▼
//	   HT sign of PORS+FP root at hypertree leaf τ:
//	     • D × XMSS(WOTS+C) layers up to PK.root
//
// Signature layout on the wire:
//
//	R (n bytes) ∥ PORS+FP embedded body ∥ hypertree signature
//
// The outer grinding counter is folded into PRFmsg — it is NOT stored
// in the signature. The verifier reconstructs R from msg + sig (R is
// the first n bytes), so counter resampling is invisible to verify.

package hashsig

import (
	"errors"
)

// SPHINCSParams binds the hypertree and PORS+FP parameterization for a
// SPHINCS+ (W+C P+FP) instance.
//
//   - N:     hash output size in bytes (= PORS.N = WOTS.N)
//   - H:     total hypertree height (must equal PORS tauBits consumed)
//   - D:     hypertree layer count (H/D must be integral)
//   - WOTS:  WOTS+C parameters for every hypertree leaf (RBits > 0)
//   - PORS:  bottom-layer PORS+FP params (N, K, ALog2, MMax, RBits)
//   - RBits: SPHINCS+ grinding counter width in bits (drives R resampling)
type SPHINCSParams struct {
	N     int
	H     int
	D     int
	WOTS  WOTSParams
	PORS  PORSParams
	RBits int
}

// Validate checks internal consistency. Cryptographic adequacy of the
// individual parameters is the caller's responsibility (costs.sage).
func (sp SPHINCSParams) Validate() error {
	if sp.N < 1 {
		return errors.New("sphincs+: N must be ≥ 1")
	}
	if sp.N != sp.PORS.N || sp.N != sp.WOTS.N {
		return errors.New("sphincs+: N must match both PORS.N and WOTS.N")
	}
	if sp.H < 1 {
		return errors.New("sphincs+: H must be ≥ 1")
	}
	if sp.D < 1 || sp.H%sp.D != 0 {
		return errors.New("sphincs+: D must divide H")
	}
	if sp.WOTS.RBits == 0 {
		return errors.New("sphincs+: WOTS must be WOTS+C (RBits > 0) for W+C P+FP")
	}
	if sp.RBits < 1 || sp.RBits > 64 {
		return errors.New("sphincs+: RBits must be in [1, 64]")
	}
	// Hash-to-subset must fit in a single H_msg digest.
	if sp.H+sp.PORS.K*sp.PORS.TreeHeight() > HmsgDigestSize*8 {
		return errors.New("sphincs+: H + K·h exceeds Hmsg output bits")
	}
	return sp.PORS.Validate()
}

// HT returns the hypertree parameters derived from this SPHINCS+ config.
func (sp SPHINCSParams) HT() HTParams {
	return HTParams{
		TotalHeight: sp.H,
		LayerHeight: sp.H / sp.D,
		D:           sp.D,
		WOTS:        sp.WOTS,
	}
}

// RSize returns the on-wire byte size of the per-signature randomness R
// per paper §11 / costs.sage: fixed at 2N regardless of hash output size.
func (sp SPHINCSParams) RSize() int { return 2 * sp.N }

// SigSize returns the total on-wire signature size:
// R (2N bytes) + PORS+FP embedded body + hypertree D-layer signature.
func (sp SPHINCSParams) SigSize() int {
	return sp.RSize() + sp.PORS.EmbeddedSigSize() + sp.HT().SigSize()
}

// GenPK returns the SPHINCS+ public root (N bytes). Equals the
// hypertree's top-layer XMSS root.
func (sp SPHINCSParams) GenPK(p *Params, skSeed []byte) ([]byte, error) {
	if err := sp.Validate(); err != nil {
		return nil, err
	}
	return sp.HT().GenPK(p, skSeed)
}

// porsBase returns the ADRS identifying the PORS+FP instance at
// hypertree leaf τ. Layer 0 / tree τ / type later set by PORS+FP.
func (sp SPHINCSParams) porsBase(tau uint64) ADRS {
	var a ADRS
	a.SetLayer(0)
	a.SetTree(tau)
	return a
}

// Sign produces a SPHINCS+ (W+C P+FP) signature over msg. pkRoot must
// be the caller's cached GenPK result — H_msg binds the signature to
// it, so it MUST match what a verifier will supply.
//
// Per paper §11 Algorithm 5 + §10 Algorithm 4, the outer SPHINCS+ layer
// is deterministic: R = PRFmsg(SK.prf, opt, m), no counter. τ is
// extracted from H_msg(R, PK, m) and fixed for this signature. PORS+FP
// does its own grinding internally — see `PORS.SignEmbedded`. This
// keeps the expensive `buildTree` call outside the grind loop, which is
// exactly the cost model the authors' costs.sage assumes.
//
// `opt` may be empty; it corresponds to the OPT_RAND parameter in the
// spec and is mixed into PRFmsg for domain separation.
func (sp SPHINCSParams) Sign(p *Params, skSeed, skPRF, opt, msg, pkRoot []byte) ([]byte, error) {
	if err := sp.Validate(); err != nil {
		return nil, err
	}
	if len(pkRoot) != sp.N {
		return nil, errors.New("sphincs+: pkRoot must be N bytes")
	}

	r := p.PRFmsgR(skPRF, opt, msg)
	digest := Hmsg(r, p.PKSeed, pkRoot, msg)
	tau := readTauFromDigest(digest, sp.H)

	porsBase := sp.porsBase(tau)
	porsBody, err := sp.PORS.SignEmbedded(p, skSeed, digest, porsBase)
	if err != nil {
		return nil, err
	}
	porsRoot, err := sp.PORS.PKFromSigEmbedded(p, digest, porsBody, porsBase)
	if err != nil {
		return nil, err
	}
	htSig, err := sp.HT().Sign(p, skSeed, porsRoot, tau)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, sp.SigSize())
	out = append(out, r...)
	out = append(out, porsBody...)
	out = append(out, htSig...)
	return out, nil
}

// readTauFromDigest reads the leading `hBits` of `digest` as the
// hypertree leaf index τ (big-endian, MSB-first).
func readTauFromDigest(digest []byte, hBits int) uint64 {
	var tau uint64
	for i := range hBits {
		bit := (digest[i>>3] >> (7 - uint(i&7))) & 1
		tau = (tau << 1) | uint64(bit)
	}
	return tau
}

// Verify returns true iff sig authenticates msg under pkRoot. Returns
// false on any structural or cryptographic failure; the caller gets no
// error detail so as not to leak verifier state.
func (sp SPHINCSParams) Verify(p *Params, msg, sig, pkRoot []byte) bool {
	if err := sp.Validate(); err != nil {
		return false
	}
	if len(pkRoot) != sp.N || len(sig) != sp.SigSize() {
		return false
	}
	rSize := sp.RSize()
	r := sig[:rSize]
	embSize := sp.PORS.EmbeddedSigSize()
	porsBody := sig[rSize : rSize+embSize]
	htSig := sig[rSize+embSize:]

	digest := Hmsg(r, p.PKSeed, pkRoot, msg)
	tau := readTauFromDigest(digest, sp.H)
	porsBase := sp.porsBase(tau)
	porsRoot, err := sp.PORS.PKFromSigEmbedded(p, digest, porsBody, porsBase)
	if err != nil {
		return false
	}
	cand, err := sp.HT().PKFromSig(p, porsRoot, tau, htSig)
	if err != nil {
		return false
	}
	return constantTimeEqual(cand, pkRoot)
}

// constantTimeEqual is bytes.Equal semantically but avoids the obvious
// early-exit timing leak. Not cryptographically critical for SPHINCS+
// verify (the attacker already knows pkRoot), but costs nothing.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
