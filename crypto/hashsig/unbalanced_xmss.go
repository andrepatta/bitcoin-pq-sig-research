// Unbalanced XMSS (§B.3, Fig 20) — the caterpillar-shaped Merkle tree
// SHRINCS uses as its stateful signing branch. Leaves are WOTS+C one-time
// public keys; the tree is strictly right-heavy so the q-th leaf sits at
// a depth linear in q, keeping early signatures small.
//
// Paper reference: Kudinov & Nick, "Hash-based Signature Schemes for
// Bitcoin" (IACR eprint 2025/2203, Revision 2025-12-05), §B.3.
//
// Tree shape for NumLeaves = N (leaves indexed 0..N-1):
//
//	                S_0 (root)
//	               /   \
//	             L_0    S_1
//	                   /   \
//	                 L_1    S_2
//	                       /   \
//	                     L_2   ...
//	                             \
//	                             S_{N-2}
//	                             /    \
//	                          L_{N-2}  L_{N-1}
//
// Auth-path geometry:
//   - for q ∈ [0, N-2): path = [S_{q+1}, L_{q-1}, L_{q-2}, ..., L_0] (len q+1)
//   - for q == N-2:     path = [L_{N-1},  L_{N-3}, L_{N-4}, ..., L_0] (len N-1)
//   - for q == N-1:     path = [L_{N-2},  L_{N-3}, L_{N-4}, ..., L_0] (len N-1)
//
// At the leaf step the signing leaf is LEFT of its parent except for
// L_{N-1}, which is RIGHT. Every subsequent spine step the running node
// is RIGHT of the parent spine node, so its sibling is the left-hand
// leaf L_{d-1} at that spine depth d.
//
// Tree-ADRS encoding for internal-node hashes uses the SPHINCS+ Tree
// type with TreeHeight = N-1-spine_index and TreeIndex = 0 (each spine
// level carries exactly one internal node, so an index is unnecessary
// but the field must be deterministic).

package hashsig

import "errors"

// UXMSSParams parameterizes an unbalanced XMSS. NumLeaves must be ≥ 2;
// WOTS must carry WOTS+C configuration (RBits > 0) per §B.3.
type UXMSSParams struct {
	NumLeaves int
	WOTS      WOTSParams
}

// Validate returns an error if the params are internally inconsistent.
func (xp UXMSSParams) Validate() error {
	if xp.NumLeaves < 2 {
		return errors.New("unbalanced xmss: NumLeaves must be ≥ 2")
	}
	if xp.WOTS.RBits == 0 {
		return errors.New("unbalanced xmss: leaves require WOTS+C params (RBits > 0)")
	}
	return nil
}

// AuthPathLen returns the number of sibling hashes carried in an auth
// path for leaf q.
func (xp UXMSSParams) AuthPathLen(q int) int {
	if q < 0 || q >= xp.NumLeaves {
		return 0
	}
	if q == xp.NumLeaves-1 {
		return xp.NumLeaves - 1
	}
	return q + 1
}

// SigSize returns the total signature size at leaf q: one WOTS+C
// signature plus AuthPathLen(q) sibling hashes of N bytes each.
func (xp UXMSSParams) SigSize(q int) int {
	return xp.WOTS.SigSize() + xp.AuthPathLen(q)*xp.WOTS.N
}

// leafPK derives the compressed WOTS+C public key at leaf idx. The
// caller supplies a base ADRS with layer/tree already set; this routine
// overwrites type and per-keypair fields.
func (xp UXMSSParams) leafPK(p *Params, skSeed []byte, base ADRS, idx uint32) []byte {
	a := base.Clone()
	a.SetType(AddrTypeWOTSHash)
	a.SetKeyPair(idx)
	return xp.WOTS.WOTSGenPK(p, skSeed, a)
}

// spineHashADRS returns the Tree-type ADRS to use when hashing a spine
// node at `spineIdx` (0 = root, N-2 = deepest spine node).
func (xp UXMSSParams) spineHashADRS(base ADRS, spineIdx int) ADRS {
	a := base.Clone()
	a.SetType(AddrTypeTree)
	a.SetTreeHeight(uint32(xp.NumLeaves - 1 - spineIdx))
	a.SetTreeIndex(0)
	return a
}

// computeTree materializes all leaves and the N-1 spine node values.
// spine[i] is the value of internal node S_i; spine[0] is the root.
func (xp UXMSSParams) computeTree(p *Params, skSeed []byte, base ADRS) (leaves [][]byte, spine [][]byte) {
	n := xp.NumLeaves
	leaves = make([][]byte, n)
	parallelFill(n, func(i int) {
		leaves[i] = xp.leafPK(p, skSeed, base, uint32(i))
	})
	spine = make([][]byte, n-1)
	// Bottom spine node: H(L_{n-2}, L_{n-1}).
	spine[n-2] = p.H(xp.spineHashADRS(base, n-2), leaves[n-2], leaves[n-1])
	for i := n - 3; i >= 0; i-- {
		spine[i] = p.H(xp.spineHashADRS(base, i), leaves[i], spine[i+1])
	}
	return leaves, spine
}

// GenPK returns the tree root (n bytes). Cost: O(N · WOTS keygen).
func (xp UXMSSParams) GenPK(p *Params, skSeed []byte, base ADRS) ([]byte, error) {
	if err := xp.Validate(); err != nil {
		return nil, err
	}
	_, spine := xp.computeTree(p, skSeed, base)
	return spine[0], nil
}

// Sign produces (WOTS+C sig || auth path) for leaf q. The message is
// the m-byte payload to sign with this OTS leaf.
func (xp UXMSSParams) Sign(p *Params, skSeed, msg []byte, q int, base ADRS) ([]byte, error) {
	if err := xp.Validate(); err != nil {
		return nil, err
	}
	if q < 0 || q >= xp.NumLeaves {
		return nil, errors.New("unbalanced xmss: leaf index out of range")
	}
	leaves, spine := xp.computeTree(p, skSeed, base)

	// Leaf signature with WOTS+C.
	leafBase := base.Clone()
	leafBase.SetType(AddrTypeWOTSHash)
	leafBase.SetKeyPair(uint32(q))
	wsig, err := xp.WOTS.WOTSPlusCSign(p, skSeed, msg, leafBase)
	if err != nil {
		return nil, err
	}

	// Assemble auth path.
	authLen := xp.AuthPathLen(q)
	auth := make([]byte, authLen*xp.WOTS.N)
	n := xp.NumLeaves
	idx := 0
	writeNode := func(src []byte) {
		copy(auth[idx*xp.WOTS.N:(idx+1)*xp.WOTS.N], src)
		idx++
	}

	switch q {
	case n - 1:
		// First sibling is L_{n-2}; then L_{n-3}, ..., L_0.
		writeNode(leaves[n-2])
		for i := n - 3; i >= 0; i-- {
			writeNode(leaves[i])
		}
	case n - 2:
		// First sibling is L_{n-1}; then L_{n-3}, ..., L_0.
		writeNode(leaves[n-1])
		for i := n - 3; i >= 0; i-- {
			writeNode(leaves[i])
		}
	default:
		// q < n-2: first sibling is S_{q+1}; then L_{q-1}, ..., L_0.
		writeNode(spine[q+1])
		for i := q - 1; i >= 0; i-- {
			writeNode(leaves[i])
		}
	}

	return append(wsig, auth...), nil
}

// PKFromSig recovers the candidate root from a leaf-q signature. The
// caller compares the returned value against the trusted public root.
func (xp UXMSSParams) PKFromSig(p *Params, msg []byte, q int, sig []byte, base ADRS) ([]byte, error) {
	if err := xp.Validate(); err != nil {
		return nil, err
	}
	if q < 0 || q >= xp.NumLeaves {
		return nil, errors.New("unbalanced xmss: leaf index out of range")
	}
	expected := xp.SigSize(q)
	if len(sig) != expected {
		return nil, errors.New("unbalanced xmss: wrong signature length")
	}
	wotsLen := xp.WOTS.SigSize()
	wsig := sig[:wotsLen]
	auth := sig[wotsLen:]

	leafBase := base.Clone()
	leafBase.SetType(AddrTypeWOTSHash)
	leafBase.SetKeyPair(uint32(q))
	leaf, err := xp.WOTS.WOTSPlusCPKFromSig(p, msg, wsig, leafBase)
	if err != nil {
		return nil, err
	}

	n := xp.NumLeaves
	N := xp.WOTS.N
	readNode := func(i int) []byte { return auth[i*N : (i+1)*N] }

	var node []byte
	ai := 0

	// First combine at the leaf's parent.
	if q == n-1 {
		// Leaf is right child of S_{n-2}; sibling L_{n-2} is left.
		node = p.H(xp.spineHashADRS(base, n-2), readNode(ai), leaf)
		ai++
		// Now at S_{n-2}; walk up to root, always right-of-parent.
		for i := n - 3; i >= 0; i-- {
			node = p.H(xp.spineHashADRS(base, i), readNode(ai), node)
			ai++
		}
		return node, nil
	}

	// q < n-1: leaf is LEFT child of S_q; sibling is on the right.
	node = p.H(xp.spineHashADRS(base, q), leaf, readNode(ai))
	ai++
	// Now at S_q. S_q is right child of S_{q-1}, and so on up to S_0.
	for i := q - 1; i >= 0; i-- {
		node = p.H(xp.spineHashADRS(base, i), readNode(ai), node)
		ai++
	}
	return node, nil
}
