package address

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/bech32"

	"qbitcoin/crypto"
	"qbitcoin/script"
)

// Deserializer sanity caps for spend payloads. A real 2-leaf P2MR spend
// uses one proof entry, one witness item (the scheme-tagged signature),
// and a ~35 B leaf script. These caps leave large headroom while
// bounding any attacker-controlled allocation.
const (
	MaxLeafScriptSize   = 1024
	MaxMerkleProofDepth = 32
	MaxWitnessItemCount = 16
	MaxWitnessItemSize  = 32 * 1024
)

// HRP is the bech32 human-readable prefix.
const HRP = "qbc"

// Leaf scheme tags. Each leaf of a 2-leaf P2MR address signs with one
// PQ scheme; the tag distinguishes the two leaves from the index side
// and drives the wallet layer's choice of scheme-tag byte (see
// crypto.SchemeShrincs / SchemeShrimps) when building a witness.
const (
	LeafIndexShrincs uint32 = 0
	LeafIndexShrimps uint32 = 1
)

// LeafScript is a Bitcoin-shaped script: [push_pubkey][OP_CHECKSIG].
// Arbitrary scripts are permitted (the interpreter runs the full opset)
// but BuildTwoLeafAddress always emits this canonical P2PK template.
type LeafScript []byte

// P2MRAddress is the 32-byte Merkle root on-chain representation.
type P2MRAddress struct {
	MerkleRoot [32]byte
}

// P2MRSpend is the witness + path data committed to by the root.
type P2MRSpend struct {
	LeafScript  LeafScript
	LeafIndex   uint32
	MerkleProof [][32]byte
	Witness     [][]byte // typically [scheme_tagged_signature_bytes]
}

// NewP2PKLeaf builds a `<pubkey> OP_CHECKSIG` leaf script. This is the
// only template BuildTwoLeafAddress uses, but it's exposed for tests
// and future address variants.
func NewP2PKLeaf(pubkey []byte) LeafScript {
	s := script.NewScript(pubkey, script.OP_CHECKSIG)
	return LeafScript(s)
}

// BuildTwoLeafAddress constructs the 2-leaf P2MR address = Merkle over
// (leaf 0: SHRINCS P2PK, leaf 1: SHRIMPS P2PK). Each leaf is an
// independent spending path: SHRINCS for normal daily signing (~324 B
// stateful sigs, auto-falls-back to a stateless SPHINCS+ internally
// once its slots drain) and SHRIMPS for multi-device signing (~2564 B).
// Both leaves share the same template — `<pubkey> OP_CHECKSIG` —
// because OP_CHECKSIG dispatches SHRINCS vs SHRIMPS polymorphically on
// the signature's scheme-tag byte (see crypto.CheckSig).
//
// Users pick one pubkey forever; no on-chain rotation protocol exists
// in this design. Fresh receive addresses come from advancing the
// wallet account index.
func BuildTwoLeafAddress(shrincsPK, shrimpsPK []byte) (P2MRAddress, []LeafScript) {
	l0 := NewP2PKLeaf(shrincsPK)
	l1 := NewP2PKLeaf(shrimpsPK)
	leaves := []LeafScript{l0, l1}
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = crypto.Hash256(l)
	}
	root := crypto.MerkleRoot(hashes)
	return P2MRAddress{MerkleRoot: root}, leaves
}

// LeafHash returns H(leafScript).
func LeafHash(l LeafScript) [32]byte { return crypto.Hash256(l) }

// VerifyInclusion verifies the leaf is committed to by the root.
func VerifyInclusion(addr P2MRAddress, leaf LeafScript, index uint32, proof [][32]byte) bool {
	lh := LeafHash(leaf)
	return crypto.VerifyProof(addr.MerkleRoot, lh, proof, int(index))
}

// EncodeBech32 encodes the 32-byte root as a bech32 string with HRP "qbc".
func EncodeBech32(a P2MRAddress) (string, error) {
	conv, err := bech32.ConvertBits(a.MerkleRoot[:], 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(HRP, conv)
}

// DecodeBech32 parses a bech32 P2MR address string.
func DecodeBech32(s string) (P2MRAddress, error) {
	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return P2MRAddress{}, err
	}
	if hrp != HRP {
		return P2MRAddress{}, fmt.Errorf("bad hrp: %s", hrp)
	}
	conv, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return P2MRAddress{}, err
	}
	if len(conv) != 32 {
		return P2MRAddress{}, errors.New("address: wrong length")
	}
	var out P2MRAddress
	copy(out.MerkleRoot[:], conv)
	return out, nil
}

// --- serialization helpers used by tx.go ---

// SerializeSpend writes a P2MRSpend deterministically.
// [4-byte leafscript_len][leafscript]
// [4-byte leaf_index]
// [4-byte proof_count][proof_count * 32-byte hashes]
// [4-byte witness_count] then for each witness: [4-byte len][bytes]
func SerializeSpend(s P2MRSpend) []byte {
	var buf []byte
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(len(s.LeafScript)))
	buf = append(buf, tmp[:]...)
	buf = append(buf, s.LeafScript...)
	binary.BigEndian.PutUint32(tmp[:], s.LeafIndex)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:], uint32(len(s.MerkleProof)))
	buf = append(buf, tmp[:]...)
	for _, p := range s.MerkleProof {
		buf = append(buf, p[:]...)
	}
	binary.BigEndian.PutUint32(tmp[:], uint32(len(s.Witness)))
	buf = append(buf, tmp[:]...)
	for _, w := range s.Witness {
		binary.BigEndian.PutUint32(tmp[:], uint32(len(w)))
		buf = append(buf, tmp[:]...)
		buf = append(buf, w...)
	}
	return buf
}

// DeserializeSpend parses SerializeSpend output. Returns bytes consumed.
func DeserializeSpend(b []byte) (P2MRSpend, int, error) {
	var s P2MRSpend
	off := 0
	readU32 := func() (uint32, error) {
		if off+4 > len(b) {
			return 0, errors.New("spend: truncated")
		}
		v := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		return v, nil
	}
	n, err := readU32()
	if err != nil {
		return s, 0, err
	}
	if n > MaxLeafScriptSize {
		return s, 0, errors.New("spend: leafscript exceeds cap")
	}
	if off+int(n) > len(b) {
		return s, 0, errors.New("spend: leafscript truncated")
	}
	s.LeafScript = make(LeafScript, n)
	copy(s.LeafScript, b[off:off+int(n)])
	off += int(n)
	if s.LeafIndex, err = readU32(); err != nil {
		return s, 0, err
	}
	pc, err := readU32()
	if err != nil {
		return s, 0, err
	}
	if pc > MaxMerkleProofDepth {
		return s, 0, errors.New("spend: proof depth exceeds cap")
	}
	if off+32*int(pc) > len(b) {
		return s, 0, errors.New("spend: proof truncated")
	}
	s.MerkleProof = make([][32]byte, pc)
	for i := uint32(0); i < pc; i++ {
		copy(s.MerkleProof[i][:], b[off:off+32])
		off += 32
	}
	wc, err := readU32()
	if err != nil {
		return s, 0, err
	}
	if wc > MaxWitnessItemCount {
		return s, 0, errors.New("spend: witness count exceeds cap")
	}
	s.Witness = make([][]byte, wc)
	for i := uint32(0); i < wc; i++ {
		wn, err := readU32()
		if err != nil {
			return s, 0, err
		}
		if wn > MaxWitnessItemSize {
			return s, 0, errors.New("spend: witness item exceeds cap")
		}
		if off+int(wn) > len(b) {
			return s, 0, errors.New("spend: witness truncated")
		}
		s.Witness[i] = make([]byte, wn)
		copy(s.Witness[i], b[off:off+int(wn)])
		off += int(wn)
	}
	return s, off, nil
}
