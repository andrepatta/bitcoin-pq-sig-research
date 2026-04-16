// XMSS (§7) — balanced Merkle tree of WOTS public keys.
//
// Per Kudinov & Nick, "Hash-based Signature Schemes for Bitcoin"
// (IACR eprint 2025/2203, Revision 2025-12-05). An XMSS tree has
// 2^Height leaves, each a compressed WOTS public key; internal
// nodes are H(left, right) under Tree-type ADRS carrying the node's
// height and index. The tree root is the XMSS public key.
//
// This file implements ONLY balanced XMSS with WOTS-TW leaves — the
// flavor used by SPHINCS+ hypertrees and by SHRIMPS's compact /
// fallback instances. The caterpillar-shaped unbalanced XMSS used
// by SHRINCS (paper §B.3) is implemented separately in
// `unbalanced_xmss.go` because it uses WOTS+C leaves and a different
// auth-path geometry.

package hashsig

import "errors"

// XMSSParams binds a Merkle tree height to a WOTS parameter set.
// Either WOTS-TW or WOTS+C is accepted; Sign and PKFromSig dispatch on
// the WOTS.RBits flag. The unbalanced-caterpillar XMSS (§B.3) lives in
// a separate type (UXMSSParams) because its auth-path geometry differs.
type XMSSParams struct {
	Height int
	WOTS   WOTSParams
}

// Validate returns an error if the params are internally inconsistent.
func (xp XMSSParams) Validate() error {
	if xp.Height < 1 || xp.Height > 32 {
		return errors.New("xmss: height out of range [1, 32]")
	}
	return nil
}

// usesWOTSPlusC reports whether this instance signs leaves with WOTS+C.
func (xp XMSSParams) usesWOTSPlusC() bool { return xp.WOTS.RBits != 0 }

// NumLeaves returns 2^Height.
func (xp XMSSParams) NumLeaves() int {
	return 1 << uint(xp.Height)
}

// AuthPathSize returns the on-wire size in bytes of an XMSS auth path
// (Height sibling hashes, each N bytes).
func (xp XMSSParams) AuthPathSize() int {
	return xp.Height * xp.WOTS.N
}

// SigSize is the total XMSS signature size: one WOTS-TW signature plus
// a Height-long auth path.
func (xp XMSSParams) SigSize() int {
	return xp.WOTS.SigSize() + xp.AuthPathSize()
}

// leafPK builds the compressed WOTS-TW public key that lives at leaf
// index `idx` of this XMSS tree, under the supplied tree `base` ADRS.
func (xp XMSSParams) leafPK(p *Params, skSeed []byte, base ADRS, idx uint32) []byte {
	leafBase := base.Clone()
	leafBase.SetType(AddrTypeWOTSHash)
	leafBase.SetKeyPair(idx)
	return xp.WOTS.WOTSGenPK(p, skSeed, leafBase)
}

// GenPK computes the XMSS root (n bytes). `base` carries the hypertree
// layer and tree index; this function overwrites type and per-node
// fields. Time/space are O(2^Height) — acceptable at Height ≤ 16.
func (xp XMSSParams) GenPK(p *Params, skSeed []byte, base ADRS) ([]byte, error) {
	if err := xp.Validate(); err != nil {
		return nil, err
	}
	nLeaves := xp.NumLeaves()
	level := make([][]byte, nLeaves)
	parallelFill(nLeaves, func(i int) {
		level[i] = xp.leafPK(p, skSeed, base, uint32(i))
	})
	for h := 1; h <= xp.Height; h++ {
		half := len(level) / 2
		next := make([][]byte, half)
		for j := range half {
			a := base.Clone()
			a.SetType(AddrTypeTree)
			a.SetTreeHeight(uint32(h))
			a.SetTreeIndex(uint32(j))
			next[j] = p.H(a, level[2*j], level[2*j+1])
		}
		level = next
	}
	return level[0], nil
}

// Sign produces (WOTS-TW signature || auth path). The message is the
// m-byte leaf payload to sign; idx selects the leaf.
func (xp XMSSParams) Sign(p *Params, skSeed, msg []byte, idx uint32, base ADRS) ([]byte, error) {
	if err := xp.Validate(); err != nil {
		return nil, err
	}
	if int(idx) >= xp.NumLeaves() {
		return nil, errors.New("xmss: leaf index out of range")
	}
	nLeaves := xp.NumLeaves()
	leaves := make([][]byte, nLeaves)
	parallelFill(nLeaves, func(i int) {
		leaves[i] = xp.leafPK(p, skSeed, base, uint32(i))
	})
	// Extract auth path while walking up.
	auth := make([]byte, xp.AuthPathSize())
	level := leaves
	cur := idx
	for h := range xp.Height {
		sibling := cur ^ 1
		copy(auth[h*xp.WOTS.N:], level[sibling])
		half := len(level) / 2
		next := make([][]byte, half)
		for j := range half {
			a := base.Clone()
			a.SetType(AddrTypeTree)
			a.SetTreeHeight(uint32(h + 1))
			a.SetTreeIndex(uint32(j))
			next[j] = p.H(a, level[2*j], level[2*j+1])
		}
		level = next
		cur >>= 1
	}
	// Leaf signature at idx — dispatch WOTS-TW vs WOTS+C on RBits.
	leafBase := base.Clone()
	leafBase.SetType(AddrTypeWOTSHash)
	leafBase.SetKeyPair(idx)
	var wsig []byte
	var err error
	if xp.usesWOTSPlusC() {
		wsig, err = xp.WOTS.WOTSPlusCSign(p, skSeed, msg, leafBase)
	} else {
		wsig, err = xp.WOTS.WOTSSign(p, skSeed, msg, leafBase)
	}
	if err != nil {
		return nil, err
	}
	return append(wsig, auth...), nil
}

// PKFromSig recovers the candidate XMSS root from a signature. The
// caller compares the returned value against the trusted public root.
func (xp XMSSParams) PKFromSig(p *Params, msg []byte, idx uint32, sig []byte, base ADRS) ([]byte, error) {
	if err := xp.Validate(); err != nil {
		return nil, err
	}
	if int(idx) >= xp.NumLeaves() {
		return nil, errors.New("xmss: leaf index out of range")
	}
	if len(sig) != xp.SigSize() {
		return nil, errors.New("xmss: wrong signature length")
	}
	wotsLen := xp.WOTS.SigSize()
	wsig := sig[:wotsLen]
	auth := sig[wotsLen:]
	leafBase := base.Clone()
	leafBase.SetType(AddrTypeWOTSHash)
	leafBase.SetKeyPair(idx)
	var leaf []byte
	var err error
	if xp.usesWOTSPlusC() {
		leaf, err = xp.WOTS.WOTSPlusCPKFromSig(p, msg, wsig, leafBase)
	} else {
		leaf, err = xp.WOTS.WOTSPKFromSig(p, msg, wsig, leafBase)
	}
	if err != nil {
		return nil, err
	}
	node := leaf
	cur := idx
	for h := range xp.Height {
		a := base.Clone()
		a.SetType(AddrTypeTree)
		a.SetTreeHeight(uint32(h + 1))
		a.SetTreeIndex(uint32(cur >> 1))
		sib := auth[h*xp.WOTS.N : (h+1)*xp.WOTS.N]
		if cur&1 == 0 {
			node = p.H(a, node, sib)
		} else {
			node = p.H(a, sib, node)
		}
		cur >>= 1
	}
	return node, nil
}
