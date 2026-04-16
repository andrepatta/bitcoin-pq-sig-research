// Package hashsig implements the hash-based signature primitives specified in
// Kudinov & Nick, "Hash-based Signature Schemes for Bitcoin" (IACR eprint
// 2025/2203, Revision 2025-12-05) — WOTS-TW, WOTS+C, FORS, FORS+C, PORS+FP,
// XMSS, XMSS^MT, and SPHINCS+ — faithful to the paper's parameterization so
// signature sizes match `costs.sage` from BlockstreamResearch/SPHINCS-Parameters.
//
// This is the ONLY place in the repository that imports crypto/sha256 and
// crypto/sha512.
package hashsig

import "encoding/binary"

// Address type constants per the SPHINCS+ specification. ADRS.typ selects
// which portion of the type-specific fields is meaningful.
const (
	AddrTypeWOTSHash  uint32 = 0
	AddrTypeWOTSPK    uint32 = 1
	AddrTypeTree      uint32 = 2
	AddrTypeFORSTree  uint32 = 3
	AddrTypeFORSRoots uint32 = 4
	AddrTypeWOTSPRF   uint32 = 5
	AddrTypeFORSPRF   uint32 = 6
)

// ADRS is the SPHINCS+ address structure. We carry the full 32-byte layout
// internally for clarity and expose the 22-byte compressed form via Bytes()
// for consumption by the SHA-256 tweakable hashes — matching the SHA-256
// instantiation in the SPHINCS+ specification.
//
// Internal layout (32 bytes):
//
//	[0..3]   layer      uint32 BE
//	[4..11]  tree       uint64 BE
//	[12..15] type       uint32 BE
//	[16..31] type-specific fields (four uint32 BE slots)
type ADRS struct {
	layer uint32
	tree  uint64
	typ   uint32
	// type-specific fields (meaning varies by typ)
	f1, f2, f3 uint32
}

// SetLayer sets the hypertree layer index.
func (a *ADRS) SetLayer(l uint32) { a.layer = l }

// SetTree sets the tree index within the current layer.
func (a *ADRS) SetTree(t uint64) { a.tree = t }

// SetType sets the address type. All type-specific fields are zeroed.
func (a *ADRS) SetType(t uint32) {
	a.typ = t
	a.f1, a.f2, a.f3 = 0, 0, 0
}

// WOTS-family setters.
func (a *ADRS) SetKeyPair(i uint32) { a.f1 = i }
func (a *ADRS) SetChain(i uint32)   { a.f2 = i }
func (a *ADRS) SetHash(i uint32)    { a.f3 = i }

// XMSS auth-path / tree hash setters.
func (a *ADRS) SetTreeHeight(h uint32) { a.f2 = h }
func (a *ADRS) SetTreeIndex(i uint32)  { a.f3 = i }

// FORS setters.
func (a *ADRS) SetFORSTreeIndex(i uint32) { a.f3 = i }

// Clone returns a value copy. Useful when a hash call needs a variant.
func (a ADRS) Clone() ADRS { return a }

// Bytes returns the 22-byte compressed address used by the SHA-256 tweakable
// hash family (SPHINCS+ SHA-256 instantiation).
//
// Layout (22 bytes):
//
//	[0]      layer (1 byte — low byte of layer; SPHINCS+ caps layers at 255)
//	[1..8]   tree (8 bytes BE — low 8 bytes of tree)
//	[9]      type (1 byte — low byte of typ)
//	[10..13] f1   (4 bytes BE)
//	[14..17] f2   (4 bytes BE)
//	[18..21] f3   (4 bytes BE)
func (a ADRS) Bytes() [22]byte {
	var b [22]byte
	b[0] = byte(a.layer)
	binary.BigEndian.PutUint64(b[1:9], a.tree)
	b[9] = byte(a.typ)
	binary.BigEndian.PutUint32(b[10:14], a.f1)
	binary.BigEndian.PutUint32(b[14:18], a.f2)
	binary.BigEndian.PutUint32(b[18:22], a.f3)
	return b
}
