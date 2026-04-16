// XMSS^MT hypertree (§8) — a stack of `D` XMSS layers where the root
// of each lower-layer tree is signed by a leaf of the next-higher-layer
// tree. Per Kudinov & Nick, IACR eprint 2025/2203.
//
// A hypertree signature chains D balanced-XMSS signatures:
//
//	msg ──layer 0──▶ root₀ ──layer 1──▶ root₁ ──▶ … ──▶ rootₐ (= HT pk)
//
// The ht-leaf index has TotalHeight bits; the low LayerHeight bits
// select the leaf within layer 0's tree, the next LayerHeight bits
// select the tree within layer 1 (and the leaf inside it), and so on.

package hashsig

import "errors"

// HTParams binds hypertree geometry to WOTS-TW parameters.
//
//   - TotalHeight: total ht height h = LayerHeight · D
//   - LayerHeight: height h' of each per-layer XMSS tree
//   - D: number of stacked layers
type HTParams struct {
	TotalHeight int
	LayerHeight int
	D           int
	WOTS        WOTSParams
}

// Validate checks geometry invariants.
func (hp HTParams) Validate() error {
	if hp.D < 1 {
		return errors.New("hypertree: D < 1")
	}
	if hp.LayerHeight < 1 {
		return errors.New("hypertree: LayerHeight < 1")
	}
	if hp.LayerHeight*hp.D != hp.TotalHeight {
		return errors.New("hypertree: LayerHeight · D != TotalHeight")
	}
	// Both WOTS-TW and WOTS+C are accepted; the per-layer XMSS dispatches
	// on WOTS.RBits. W+C is required for the "W+C P+FP" SPHINCS+ variant.
	return nil
}

// xmssAt returns the XMSSParams governing one layer of this hypertree.
func (hp HTParams) xmssAt() XMSSParams {
	return XMSSParams{Height: hp.LayerHeight, WOTS: hp.WOTS}
}

// SigSize returns the total hypertree signature size in bytes:
// D × (WOTS-TW sig + layer-height auth path).
func (hp HTParams) SigSize() int {
	return hp.D * hp.xmssAt().SigSize()
}

// layerMask returns the bit mask that selects the leaf index within
// one layer's tree (2^LayerHeight − 1).
func (hp HTParams) layerMask() uint64 {
	return (uint64(1) << uint(hp.LayerHeight)) - 1
}

// GenPK computes the hypertree public key (top-layer root). O(D · 2^LayerHeight)
// WOTS keypairs generated.
func (hp HTParams) GenPK(p *Params, skSeed []byte) ([]byte, error) {
	if err := hp.Validate(); err != nil {
		return nil, err
	}
	xp := hp.xmssAt()
	// Build the top-layer tree at layer = D-1, tree = 0.
	var base ADRS
	base.SetLayer(uint32(hp.D - 1))
	base.SetTree(0)
	return xp.GenPK(p, skSeed, base)
}

// Sign produces a D-layer hypertree signature over msg. `idx` is the
// ht-leaf index, with TotalHeight significant low bits.
func (hp HTParams) Sign(p *Params, skSeed, msg []byte, idx uint64) ([]byte, error) {
	if err := hp.Validate(); err != nil {
		return nil, err
	}
	if hp.TotalHeight < 64 && idx >= (uint64(1)<<uint(hp.TotalHeight)) {
		return nil, errors.New("hypertree: leaf index out of range")
	}
	xp := hp.xmssAt()
	mask := hp.layerMask()

	sig := make([]byte, 0, hp.SigSize())
	curMsg := msg
	treeIdx := idx >> uint(hp.LayerHeight)
	leafIdx := uint32(idx & mask)

	for layer := range hp.D {
		var base ADRS
		base.SetLayer(uint32(layer))
		base.SetTree(treeIdx)
		ls, err := xp.Sign(p, skSeed, curMsg, leafIdx, base)
		if err != nil {
			return nil, err
		}
		sig = append(sig, ls...)
		if layer == hp.D-1 {
			break
		}
		// Next layer signs the root of this layer's tree.
		root, err := xp.GenPK(p, skSeed, base)
		if err != nil {
			return nil, err
		}
		curMsg = root
		leafIdx = uint32(treeIdx & mask)
		treeIdx >>= uint(hp.LayerHeight)
	}
	return sig, nil
}

// PKFromSig recovers the candidate hypertree public key from a
// signature. The caller compares it to the trusted root.
func (hp HTParams) PKFromSig(p *Params, msg []byte, idx uint64, sig []byte) ([]byte, error) {
	if err := hp.Validate(); err != nil {
		return nil, err
	}
	if hp.TotalHeight < 64 && idx >= (uint64(1)<<uint(hp.TotalHeight)) {
		return nil, errors.New("hypertree: leaf index out of range")
	}
	if len(sig) != hp.SigSize() {
		return nil, errors.New("hypertree: wrong signature length")
	}
	xp := hp.xmssAt()
	mask := hp.layerMask()
	perLayer := xp.SigSize()

	curMsg := msg
	treeIdx := idx >> uint(hp.LayerHeight)
	leafIdx := uint32(idx & mask)

	var node []byte
	for layer := range hp.D {
		var base ADRS
		base.SetLayer(uint32(layer))
		base.SetTree(treeIdx)
		slice := sig[layer*perLayer : (layer+1)*perLayer]
		root, err := xp.PKFromSig(p, curMsg, leafIdx, slice, base)
		if err != nil {
			return nil, err
		}
		node = root
		if layer == hp.D-1 {
			break
		}
		curMsg = root
		leafIdx = uint32(treeIdx & mask)
		treeIdx >>= uint(hp.LayerHeight)
	}
	return node, nil
}
