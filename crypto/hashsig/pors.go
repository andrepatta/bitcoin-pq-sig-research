// PORS+FP — "PRNG to Obtain a Random Subset with Forced Pruning" — the
// few-time signature scheme that replaces FORS inside our SPHINCS+
// variant ("W+C P+FP"). Paper reference: Kudinov & Nick, "Hash-based
// Signature Schemes for Bitcoin" (IACR eprint 2025/2203, Revision
// 2025-12-05), §10 and §C.
//
// Per paper §10, PORS+FP uses ONE Merkle tree with t = k · 2^a leaves.
// When k is a power of two, t is a power of two and the tree is balanced.
// Otherwise the tree is "left-filled" per BlockstreamResearch's
// octopus_pmf.py `pmf_leftfilled` (which is what the authors' costs.sage
// uses to score the bold q_s=2^40 W+C P+FP row): with h = ⌈log₂ t⌉,
// p = 2^(h-1), L = t − p, x = 2L — the first x leaves sit at the bottom
// level h (sharing full sibling pairs) and the remaining p − L leaves
// sit one level up at h − 1 (as "direct" leaves without children of
// their own).
//
// A message hash selects k distinct leaves to reveal; their authentication
// paths share internal nodes, so the signer runs the Octopus algorithm
// (§C) — generalized here to handle leaves at mixed depths — and grinds
// a counter until the set size fits under a bound m_max. The signature
// carries the grinding counter, the k revealed secrets, and the
// m_max-padded Octopus set of sibling node values.
//
// Outer hash (H_msg) is SHA-512 per §13.3. The digest must hold at least
// h + k·⌈log₂ t⌉ bits when PORS+FP runs inside a SPHINCS+ hypertree; 64
// bytes is comfortable for every parameter set we target.

package hashsig

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// PORSParams parameterizes a PORS+FP instance.
//
//   - N:       hash output size in bytes (16 at L1).
//   - K:       paper's "k" — both the number of indices revealed per
//     signature AND the PORS tree width (t = K · 2^ALog2).
//   - ALog2:   paper's "a". Together with K determines t. When K is
//     non-power-of-2, t is non-power-of-2 (unbalanced tree).
//   - RBits:   grinding counter width (≤ 64); signature carries ⌈RBits/8⌉
//     bytes.
//   - MMax:    Octopus authentication-set size bound (signer grinds
//     until |Octopus set| ≤ MMax; signature is padded to MMax
//     entries).
type PORSParams struct {
	N, K, ALog2, RBits, MMax int
}

// Validate rejects internally inconsistent parameters. Does not validate
// cryptographic adequacy — that requires running costs.sage.
func (pp PORSParams) Validate() error {
	if pp.N < 1 {
		return errors.New("pors+fp: N must be ≥ 1")
	}
	if pp.K < 1 {
		return errors.New("pors+fp: K must be ≥ 1")
	}
	if pp.ALog2 < 1 || pp.ALog2 > 30 {
		return errors.New("pors+fp: ALog2 must be in [1, 30]")
	}
	if pp.RBits < 1 || pp.RBits > 64 {
		return errors.New("pors+fp: RBits must be in [1, 64]")
	}
	if pp.MMax < pp.K {
		return errors.New("pors+fp: MMax must be ≥ K")
	}
	if pp.K*pp.TreeHeight() > HmsgDigestSize*8 {
		return errors.New("pors+fp: K·h exceeds Hmsg output bits")
	}
	return nil
}

// TotalLeaves returns t = K · 2^ALog2.
func (pp PORSParams) TotalLeaves() int { return pp.K << uint(pp.ALog2) }

// TreeHeight returns h = ⌈log₂ t⌉ — the depth of the deepest leaf from
// the root. For balanced t (K a power of 2), h = log₂ K + ALog2.
func (pp PORSParams) TreeHeight() int {
	t := pp.TotalLeaves()
	if t <= 1 {
		return 0
	}
	return bits.Len(uint(t - 1))
}

// IsBalanced reports whether t is a power of two (⇔ K is a power of two).
func (pp PORSParams) IsBalanced() bool {
	t := pp.TotalLeaves()
	return t > 0 && t&(t-1) == 0
}

// treeShape returns (h, p, L, x) for the left-filled layout:
//   - h = ⌈log₂ t⌉
//   - p = 2^(h-1)
//   - L = t − p  (number of internal nodes at level h-1 that have bottom
//     children; equivalently, half the bottom-layer leaf count)
//   - x = 2L (bottom-layer leaf count)
//
// For balanced t = 2^h: L = p = t/2 and x = t — all leaves sit at level h.
func (pp PORSParams) treeShape() (h, p, L, x int) {
	t := pp.TotalLeaves()
	if t <= 1 {
		return 0, 1, 0, 0
	}
	h = pp.TreeHeight()
	p = 1 << uint(h-1)
	L = t - p
	x = 2 * L
	return
}

// leafCoords maps a user leaf index i ∈ [0, t) to the (level, pos)
// coordinates of its node in the left-filled tree. level counts from the
// root (root = 0, deepest leaves = h).
func (pp PORSParams) leafCoords(i uint32) (level, pos uint32) {
	h, _, L, x := pp.treeShape()
	if int(i) < x {
		return uint32(h), i
	}
	return uint32(h - 1), i - uint32(L)
}

// CounterBytes returns the on-wire width of the grinding counter.
func (pp PORSParams) CounterBytes() int { return (pp.RBits + 7) / 8 }

// SigSize returns the standalone PORS+FP signature size in bytes
// (counter + revealed sks + padded Octopus auth set).
func (pp PORSParams) SigSize() int {
	return pp.CounterBytes() + pp.K*pp.N + pp.MMax*pp.N
}

// EmbeddedSigSize returns the signature size when PORS+FP runs inside a
// SPHINCS+ hypertree. The embedded body carries a grinding counter
// (PORS+FP's own, distinct from the outer SPHINCS+ randomness), the k
// revealed sks, and the m_max-padded Octopus auth set. Per paper §10
// Algorithm 4 / §11, the PORS+FP layer owns its own Octopus-fit grind —
// NOT the outer SPHINCS+ layer — so that the tree is built exactly once
// per signature instead of once per outer-grind attempt.
func (pp PORSParams) EmbeddedSigSize() int {
	return pp.CounterBytes() + pp.K*pp.N + pp.MMax*pp.N
}

// --- Algorithm 1: hash-to-subset (§10) ------------------------------------

// HashToSubset parses `digest` per §10 Algorithm 1, extracting a
// hypertree index τ of width `tauBits` bits (0 for standalone PORS+FP)
// followed by k distinct leaf indices in [0, t).
//
// Each index is read as an indexBits-wide big-endian block. Blocks
// yielding values ≥ t are rejected (required when t is non-power-of-2,
// ignored when t = 2^indexBits).
//
// Returns (τ, sorted distinct indices, ok=true) on success. Returns
// ok=false if the digest yields fewer than k distinct valid indices —
// the caller must re-sample (grind) and retry.
//
// Bit extraction is MSB-first: byte 0 bit 7 is the most significant bit
// of τ. Signer and verifier MUST agree on this ordering, which they do
// by both going through this function.
func HashToSubset(digest []byte, tauBits, k, indexBits, t int) (uint64, []uint32, bool) {
	totalBits := len(digest) * 8
	if totalBits < tauBits+k*indexBits {
		return 0, nil, false
	}
	var tau uint64
	for i := range tauBits {
		tau = (tau << 1) | uint64(readBit(digest, i))
	}
	seen := make(map[uint32]bool, k)
	out := make([]uint32, 0, k)
	bitPos := tauBits
	for bitPos+indexBits <= totalBits && len(out) < k {
		var v uint32
		for j := range indexBits {
			v = (v << 1) | uint32(readBit(digest, bitPos+j))
		}
		bitPos += indexBits
		if int(v) >= t {
			continue // reject out-of-range block
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) < k {
		return 0, nil, false
	}
	sortAscUint32(out)
	return tau, out, true
}

func readBit(b []byte, i int) uint8 {
	return (b[i>>3] >> (7 - uint(i&7))) & 1
}

func sortAscUint32(a []uint32) {
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}

// --- Algorithm 2: Octopus (§C), generalized to mixed-depth leaves ----------

// OctopusNode names a node in the Merkle tree. Level counts from the
// root (level 0 = root, level h = deepest leaves). Index is the node's
// position within its level.
type OctopusNode struct {
	Level uint32
	Index uint32
}

// Octopus returns the minimal authentication set for a set of leaf
// indices in a balanced Merkle tree of height `h` — compatibility
// wrapper preserving the pre-unbalanced API signature.
//
// Internally dispatches to OctopusMixed after mapping each leaf to
// (level=h, pos=i).
//
// Panics if `indices` is not strictly ascending.
func Octopus(indices []uint32, h int) []OctopusNode {
	for i := 1; i < len(indices); i++ {
		if indices[i] <= indices[i-1] {
			panic("octopus: indices must be strictly ascending")
		}
	}
	coords := make([]OctopusNode, len(indices))
	for i, idx := range indices {
		coords[i] = OctopusNode{Level: uint32(h), Index: idx}
	}
	return OctopusMixed(coords, h)
}

// OctopusMixed returns the minimal authentication set for a set of
// leaves living at possibly-different depths in an unbalanced Merkle
// tree of height `h`. `leaves` is a list of (level, pos) entries — the
// caller must supply them from PORSParams.leafCoords. The output has
// the paper's canonical order: first the siblings discovered at the
// deepest level (ascending by position), then at the next level up, etc.
//
// Panics if `leaves` contains duplicates or non-leaf entries at levels
// outside [0, h].
func OctopusMixed(leaves []OctopusNode, h int) []OctopusNode {
	if len(leaves) == 0 {
		return nil
	}

	// Working set: (level, pos) pairs currently known. Invariant: sorted
	// by (level desc, pos asc) and deduped.
	cur := make([]OctopusNode, len(leaves))
	copy(cur, leaves)
	sortNodesDeepFirst(cur)
	cur = dedupeNodes(cur)

	var auth []OctopusNode

	// Process each level from deepest down to 1; at each step, pair-merge
	// all nodes currently at that level into parents one level shallower.
	for level := h; level >= 1; level-- {
		var atLevel, above []OctopusNode
		for _, n := range cur {
			if int(n.Level) == level {
				atLevel = append(atLevel, n)
			} else {
				above = append(above, n)
			}
		}
		// atLevel is already ascending by position (inherited from cur's
		// sort order: within a given level, positions appear ascending).

		var parents []OctopusNode
		i := 0
		for i < len(atLevel) {
			x := atLevel[i]
			sibPos := x.Index ^ 1
			parent := OctopusNode{Level: uint32(level - 1), Index: x.Index / 2}
			if i+1 < len(atLevel) && atLevel[i+1].Index == sibPos {
				parents = append(parents, parent)
				i += 2
			} else {
				auth = append(auth, OctopusNode{Level: uint32(level), Index: sibPos})
				parents = append(parents, parent)
				i++
			}
		}
		// Merge parents into above, then re-sort+dedupe for next iteration.
		merged := append(above, parents...)
		sortNodesDeepFirst(merged)
		cur = dedupeNodes(merged)
	}
	return auth
}

// sortNodesDeepFirst sorts ascending by (h - level) — i.e. deepest
// nodes first — ties broken by Index ascending.
func sortNodesDeepFirst(a []OctopusNode) {
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && nodeLess(v, a[j]) {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}

// nodeLess returns true if a should precede b in our canonical order:
// deeper (higher Level) first; within the same level, lower Index first.
func nodeLess(a, b OctopusNode) bool {
	if a.Level != b.Level {
		return a.Level > b.Level
	}
	return a.Index < b.Index
}

func dedupeNodes(a []OctopusNode) []OctopusNode {
	if len(a) <= 1 {
		return a
	}
	out := a[:1]
	for i := 1; i < len(a); i++ {
		if a[i] != a[i-1] {
			out = append(out, a[i])
		}
	}
	return out
}

// --- PORS+FP Merkle tree and keygen ---------------------------------------

// porsLeafPRFADRS returns the PRF-ADRS used to derive the secret at a
// leaf living at tree coordinates (level, pos). A leaf encodes its
// height-from-bottom as `h - level` in TreeHeight: bottom leaves have
// TreeHeight=0, upper direct leaves have TreeHeight=1.
func porsLeafPRFADRS(base ADRS, h int, level, pos uint32) ADRS {
	a := base.Clone()
	a.SetType(AddrTypeFORSPRF)
	a.SetTreeHeight(uint32(h) - level)
	a.SetTreeIndex(pos)
	return a
}

// porsLeafHashADRS returns the ADRS used to hash the leaf secret into
// its hash commitment.
func porsLeafHashADRS(base ADRS, h int, level, pos uint32) ADRS {
	a := base.Clone()
	a.SetType(AddrTypeFORSTree)
	a.SetTreeHeight(uint32(h) - level)
	a.SetTreeIndex(pos)
	return a
}

// porsInternalADRS returns the ADRS used to hash a pair of children at
// internal node (level, index). Tree-height field is (h - level) to
// match the height-from-bottom convention used elsewhere.
func porsInternalADRS(base ADRS, h int, level, index uint32) ADRS {
	a := base.Clone()
	a.SetType(AddrTypeFORSTree)
	a.SetTreeHeight(uint32(h) - level)
	a.SetTreeIndex(index)
	return a
}

// skLeaf derives the secret for leaf i ∈ [0, t).
func (pp PORSParams) skLeaf(p *Params, skSeed []byte, base ADRS, i uint32) []byte {
	h := pp.TreeHeight()
	level, pos := pp.leafCoords(i)
	return p.PRF(skSeed, porsLeafPRFADRS(base, h, level, pos))
}

// leafValue returns F(adrs_i, sk_i) — the hashed leaf commitment for
// leaf i ∈ [0, t).
func (pp PORSParams) leafValue(p *Params, skSeed []byte, base ADRS, i uint32) []byte {
	h := pp.TreeHeight()
	level, pos := pp.leafCoords(i)
	return p.F(porsLeafHashADRS(base, h, level, pos), pp.skLeaf(p, skSeed, base, i))
}

// buildTree constructs the full left-filled Merkle tree and returns the
// root plus a nodeStore indexed by (level, position). Cost: O(t) hashes.
func (pp PORSParams) buildTree(p *Params, skSeed []byte, base ADRS) (root []byte, nodes nodeStore) {
	h, pp2, L, x := pp.treeShape()
	t := pp.TotalLeaves()
	nodes = makeNodeStore(h)

	// Bottom level (level h): the first x leaves live here. Parallel:
	// each leaf is an independent PRF+F pair; writes go to distinct slots.
	parallelFill(x, func(i int) {
		nodes.put(uint32(h), uint32(i), pp.leafValue(p, skSeed, base, uint32(i)))
	})

	// Level h-1: L internal nodes (children of level-h pairs) followed by
	// p-L direct leaves. Skip if h == 0 (t==1, degenerate).
	if h >= 1 {
		// Internal nodes at positions [0, L) — parallel H() calls.
		parallelFill(L, func(j int) {
			left := nodes.get(uint32(h), uint32(2*j))
			right := nodes.get(uint32(h), uint32(2*j+1))
			adrs := porsInternalADRS(base, h, uint32(h-1), uint32(j))
			nodes.put(uint32(h-1), uint32(j), p.H(adrs, left, right))
		})
		// Direct leaves at positions [L, p) — parallel PRF+F.
		parallelFill(pp2-L, func(off int) {
			j := L + off
			leafIdx := uint32(L + j) // equals 2L + off
			if int(leafIdx) >= t {
				return
			}
			nodes.put(uint32(h-1), uint32(j), pp.leafValue(p, skSeed, base, leafIdx))
		})
	}

	// Levels h-2 down to 0: standard internal nodes. Each level depends
	// on the one below but is internally parallel.
	for level := h - 2; level >= 0; level-- {
		width := 1 << uint(level)
		lvl := level
		parallelFill(width, func(j int) {
			left := nodes.get(uint32(lvl+1), uint32(2*j))
			right := nodes.get(uint32(lvl+1), uint32(2*j+1))
			adrs := porsInternalADRS(base, h, uint32(lvl), uint32(j))
			nodes.put(uint32(lvl), uint32(j), p.H(adrs, left, right))
		})
	}

	root = nodes.get(0, 0)
	return root, nodes
}

// nodeStore is a packed-by-level store of tree node hash values.
type nodeStore struct {
	levels [][][]byte // levels[level][pos] → hash bytes (nil if absent)
}

func makeNodeStore(h int) nodeStore {
	ns := nodeStore{levels: make([][][]byte, h+1)}
	for level := 0; level <= h; level++ {
		// Maximum possible width at each level (upper-bound allocation):
		// width at level ℓ (from root) is 2^ℓ.
		ns.levels[level] = make([][]byte, 1<<uint(level))
	}
	return ns
}

func (ns nodeStore) put(level, pos uint32, val []byte) {
	ns.levels[level][pos] = val
}

func (ns nodeStore) get(level, pos uint32) []byte {
	if int(level) >= len(ns.levels) || int(pos) >= len(ns.levels[level]) {
		return nil
	}
	return ns.levels[level][pos]
}

// GenPK returns the PORS+FP root (n bytes). Cost: O(t) hash evaluations.
func (pp PORSParams) GenPK(p *Params, skSeed []byte, base ADRS) ([]byte, error) {
	if err := pp.Validate(); err != nil {
		return nil, err
	}
	root, _ := pp.buildTree(p, skSeed, base)
	return root, nil
}

// --- Sign / Verify --------------------------------------------------------

// porsMsgDigest produces a 64-byte digest for hash-to-subset. Salt is
// the grinding counter (big-endian). `base` domain-separates this
// instance; `msg` is the caller's payload.
func (pp PORSParams) porsMsgDigest(p *Params, base ADRS, counter uint64, msg []byte) []byte {
	ctr := ToByteBE(counter, 8)
	bb := base.Bytes()
	return Hmsg(ctr, p.PKSeed, bb[:], msg)
}

// ErrOctopusOverflow indicates the auth set exceeds MMax; when PORS+FP
// is embedded in SPHINCS+, the caller retries with fresh randomness.
var ErrOctopusOverflow = errors.New("pors+fp: Octopus auth set exceeds MMax")

// leafCoordsList maps a sorted []uint32 of leaf indices to their
// (level, pos) coordinates in the left-filled tree.
func (pp PORSParams) leafCoordsList(indices []uint32) []OctopusNode {
	out := make([]OctopusNode, len(indices))
	for i, idx := range indices {
		level, pos := pp.leafCoords(idx)
		out[i] = OctopusNode{Level: level, Index: pos}
	}
	return out
}

// innerDigest is PORS+FP's private grinding oracle (paper §10 Algorithm
// 4 and §11). `outer` is the SPHINCS+ message digest — the caller has
// already extracted τ from its prefix; PORS+FP only needs the k
// subsequent indices, and grinds `counter` to re-sample them without
// perturbing τ. The inner hash is `Hmsg(counter || base_bytes || outer,
// PK.seed, ...)` — the counter + base embed the PORS tree identity, and
// the outer digest binds the grind to this specific signature.
func (pp PORSParams) innerDigest(p *Params, base ADRS, outer []byte, counter uint64) []byte {
	ctr := ToByteBE(counter, 8)
	bb := base.Bytes()
	// Hmsg signature: Hmsg(R_like, PKSeed, ctx, msg)
	//   - R_like = counter bytes (acts as a fresh salt per grind)
	//   - ctx    = base ADRS bytes (PORS+FP instance identity)
	//   - msg    = outer digest (the SPHINCS+ H_msg output that fixes τ)
	return Hmsg(ctr, p.PKSeed, bb[:], outer)
}

// SignEmbedded grinds PORS+FP's internal counter against `outer` (the
// SPHINCS+ H_msg digest) until Algorithm 1 yields k distinct indices
// and Octopus produces ≤ m_max siblings. Builds the PORS tree once
// and reuses it across every grinding attempt — this is the key
// cost-model property from the paper: PORS fixed work is O(t), not
// O(t · grind_attempts).
//
// The embedded sig layout is [counterBytes || K·N sks || MMax·N auth].
func (pp PORSParams) SignEmbedded(p *Params, skSeed []byte, outer []byte, base ADRS) ([]byte, error) {
	if err := pp.Validate(); err != nil {
		return nil, err
	}
	_, nodes := pp.buildTree(p, skSeed, base)
	h := pp.TreeHeight()
	t := pp.TotalLeaves()

	limit := uint64(1) << uint(pp.RBits)
	if pp.RBits == 64 {
		limit = ^uint64(0)
	}
	for counter := uint64(0); counter < limit; counter++ {
		salted := pp.innerDigest(p, base, outer, counter)
		_, indices, ok := HashToSubset(salted, 0, pp.K, h, t)
		if !ok {
			continue
		}
		leaves := pp.leafCoordsList(indices)
		auth := OctopusMixed(leaves, h)
		if len(auth) > pp.MMax {
			continue
		}
		return pp.assembleEmbedded(skSeed, base, nodes, counter, indices, auth, p), nil
	}
	return nil, errors.New("pors+fp: embedded counter space exhausted")
}

// assembleEmbedded lays out the embedded-mode signature body.
func (pp PORSParams) assembleEmbedded(
	skSeed []byte, base ADRS, nodes nodeStore,
	counter uint64, indices []uint32, auth []OctopusNode, p *Params,
) []byte {
	out := make([]byte, pp.EmbeddedSigSize())
	off := 0
	ctrBuf := ToByteBE(counter, 8)
	copy(out[off:], ctrBuf[8-pp.CounterBytes():])
	off += pp.CounterBytes()
	for _, idx := range indices {
		copy(out[off:], pp.skLeaf(p, skSeed, base, idx))
		off += pp.N
	}
	for _, node := range auth {
		copy(out[off:], nodes.get(node.Level, node.Index))
		off += pp.N
	}
	return out
}

// PKFromSigEmbedded reconstructs the candidate PORS+FP root from an
// embedded-mode signature body plus the SPHINCS+ outer digest. Mirrors
// SignEmbedded: parses the counter, re-derives indices via innerDigest,
// checks Octopus fit, and walks the tree back to a root.
func (pp PORSParams) PKFromSigEmbedded(p *Params, outer []byte, sig []byte, base ADRS) ([]byte, error) {
	if err := pp.Validate(); err != nil {
		return nil, err
	}
	if len(sig) != pp.EmbeddedSigSize() {
		return nil, errors.New("pors+fp: embedded sig wrong length")
	}
	off := 0
	ctrBuf := make([]byte, 8)
	copy(ctrBuf[8-pp.CounterBytes():], sig[off:off+pp.CounterBytes()])
	counter := binary.BigEndian.Uint64(ctrBuf)
	off += pp.CounterBytes()

	h := pp.TreeHeight()
	t := pp.TotalLeaves()
	salted := pp.innerDigest(p, base, outer, counter)
	_, indices, ok := HashToSubset(salted, 0, pp.K, h, t)
	if !ok {
		return nil, errors.New("pors+fp: hash-to-subset failed at embedded verify")
	}

	skVals := make([][]byte, pp.K)
	for i := range pp.K {
		skVals[i] = sig[off : off+pp.N]
		off += pp.N
	}
	authVals := make([][]byte, pp.MMax)
	for i := range pp.MMax {
		authVals[i] = sig[off : off+pp.N]
		off += pp.N
	}
	leaves := pp.leafCoordsList(indices)
	auth := OctopusMixed(leaves, h)
	if len(auth) > pp.MMax {
		return nil, errors.New("pors+fp: auth set exceeds MMax at embedded verify")
	}
	return pp.walkToRoot(p, base, indices, skVals, auth, authVals)
}

// walkToRoot reconstructs a candidate root from revealed leaves + the
// Octopus auth set. Shared by the standalone and embedded verify paths.
func (pp PORSParams) walkToRoot(
	p *Params, base ADRS, indices []uint32,
	skVals [][]byte, auth []OctopusNode, authVals [][]byte,
) ([]byte, error) {
	h := pp.TreeHeight()
	known := make([]map[uint32][]byte, h+1)
	for i := range known {
		known[i] = map[uint32][]byte{}
	}
	// Hash each revealed sk into its leaf value.
	for i, idx := range indices {
		level, pos := pp.leafCoords(idx)
		known[level][pos] = p.F(porsLeafHashADRS(base, h, level, pos), skVals[i])
	}
	// Insert auth values at their coordinates.
	for i, node := range auth {
		known[node.Level][node.Index] = authVals[i]
	}
	// Walk up: for each level ℓ from h down to 1, try to combine any
	// known pair (ℓ, 2j), (ℓ, 2j+1) into parent (ℓ-1, j).
	for level := h; level >= 1; level-- {
		for pos := range known[level] {
			// Only handle left-of-pair entries to avoid double work.
			if pos&1 != 0 {
				continue
			}
			left := known[level][pos]
			right, ok := known[level][pos+1]
			if !ok {
				continue
			}
			parent := p.H(
				porsInternalADRS(base, h, uint32(level-1), pos/2),
				left, right,
			)
			known[level-1][pos/2] = parent
		}
	}
	root, ok := known[0][0]
	if !ok {
		return nil, errors.New("pors+fp: unable to recover root from sig")
	}
	return root, nil
}

// Sign produces a PORS+FP signature over msg using a fresh secret tree
// derived from skSeed under `base`. The signer grinds a counter until
// (i) Algorithm 1 yields k distinct indices AND (ii) Octopus of those
// indices produces at most MMax sibling nodes.
//
// Signature layout:
//
//	[counterBytes BE]  [K · N bytes sk values, in sorted-index order]
//	[MMax · N bytes auth node values, in Octopus output order padded
//	 with zero-byte entries if the set is smaller than MMax]
func (pp PORSParams) Sign(p *Params, skSeed, msg []byte, base ADRS) ([]byte, error) {
	if err := pp.Validate(); err != nil {
		return nil, err
	}
	_, nodes := pp.buildTree(p, skSeed, base)
	h := pp.TreeHeight()
	t := pp.TotalLeaves()

	limit := uint64(1) << uint(pp.RBits)
	if pp.RBits == 64 {
		limit = ^uint64(0)
	}
	for counter := uint64(0); counter < limit; counter++ {
		digest := pp.porsMsgDigest(p, base, counter, msg)
		_, indices, ok := HashToSubset(digest, 0, pp.K, h, t)
		if !ok {
			continue
		}
		leaves := pp.leafCoordsList(indices)
		auth := OctopusMixed(leaves, h)
		if len(auth) > pp.MMax {
			continue
		}
		return pp.assembleSig(skSeed, base, nodes, counter, indices, auth, p), nil
	}
	return nil, errors.New("pors+fp: counter space exhausted without finding a witness")
}

// assembleSig builds the on-wire byte layout.
func (pp PORSParams) assembleSig(
	skSeed []byte, base ADRS, nodes nodeStore,
	counter uint64, indices []uint32, auth []OctopusNode, p *Params,
) []byte {
	out := make([]byte, pp.SigSize())
	off := 0

	// Counter.
	ctrBuf := ToByteBE(counter, 8)
	copy(out[off:], ctrBuf[8-pp.CounterBytes():])
	off += pp.CounterBytes()

	// Revealed secrets — one per selected leaf index, in sorted order.
	for _, idx := range indices {
		sk := pp.skLeaf(p, skSeed, base, idx)
		copy(out[off:], sk)
		off += pp.N
	}

	// Auth set values, in Octopus output order, then zero-padded.
	for _, node := range auth {
		copy(out[off:], nodes.get(node.Level, node.Index))
		off += pp.N
	}
	return out
}

// PKFromSig reconstructs the candidate Merkle root from a PORS+FP
// signature. The caller compares the returned value against the trusted
// public key.
func (pp PORSParams) PKFromSig(p *Params, msg, sig []byte, base ADRS) ([]byte, error) {
	if err := pp.Validate(); err != nil {
		return nil, err
	}
	if len(sig) != pp.SigSize() {
		return nil, errors.New("pors+fp: wrong signature length")
	}
	h := pp.TreeHeight()
	t := pp.TotalLeaves()
	off := 0
	// Counter.
	ctrBuf := make([]byte, 8)
	copy(ctrBuf[8-pp.CounterBytes():], sig[off:off+pp.CounterBytes()])
	counter := binary.BigEndian.Uint64(ctrBuf)
	off += pp.CounterBytes()

	// Re-derive indices from (counter, msg) via Algorithm 1.
	digest := pp.porsMsgDigest(p, base, counter, msg)
	_, indices, ok := HashToSubset(digest, 0, pp.K, h, t)
	if !ok {
		return nil, errors.New("pors+fp: hash-to-subset failed at verify")
	}

	// Slice out revealed secrets and auth values.
	skVals := make([][]byte, pp.K)
	for i := range pp.K {
		skVals[i] = sig[off : off+pp.N]
		off += pp.N
	}
	authVals := make([][]byte, pp.MMax)
	for i := range pp.MMax {
		authVals[i] = sig[off : off+pp.N]
		off += pp.N
	}

	leaves := pp.leafCoordsList(indices)
	auth := OctopusMixed(leaves, h)
	if len(auth) > pp.MMax {
		return nil, errors.New("pors+fp: auth set exceeds MMax at verify")
	}
	return pp.walkToRoot(p, base, indices, skVals, auth, authVals)
}
