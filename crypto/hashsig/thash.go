package hashsig

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
)

// Params holds the public parameters needed by the tweakable hash family.
// For our L1 instantiation: N = 16.
type Params struct {
	N      int    // hash output size in bytes (16 for L1)
	PKSeed []byte // public parameter P, length N
}

// F is the single-input tweakable hash (SPHINCS+ SHA-256 "simple" variant).
//
//	F(P, ADRS, M1) = SHA256(P || ADRS_c || M1)[:N]
//
// Used for chaining steps in WOTS-TW / WOTS+C and for hashing leaves
// (the pk compression of a single WOTS chain end value).
func (p *Params) F(adrs ADRS, m1 []byte) []byte {
	h := sha256.New()
	h.Write(p.PKSeed)
	ab := adrs.Bytes()
	h.Write(ab[:])
	h.Write(m1)
	sum := h.Sum(nil)
	return sum[:p.N]
}

// H is the two-input tweakable hash, used to hash two n-byte children into a
// Merkle node.
//
//	H(P, ADRS, M1 || M2) = SHA256(P || ADRS_c || M1 || M2)[:N]
func (p *Params) H(adrs ADRS, m1, m2 []byte) []byte {
	h := sha256.New()
	h.Write(p.PKSeed)
	ab := adrs.Bytes()
	h.Write(ab[:])
	h.Write(m1)
	h.Write(m2)
	sum := h.Sum(nil)
	return sum[:p.N]
}

// Tl is the l-input (variable-arity) tweakable hash, used for compressing the
// ell chain tops of a WOTS+ public key down to a single n-byte commitment.
//
//	T_l(P, ADRS, M1 || ... || Ml) = SHA256(P || ADRS_c || M1 || ... || Ml)[:N]
func (p *Params) Tl(adrs ADRS, inputs ...[]byte) []byte {
	h := sha256.New()
	h.Write(p.PKSeed)
	ab := adrs.Bytes()
	h.Write(ab[:])
	for _, m := range inputs {
		h.Write(m)
	}
	sum := h.Sum(nil)
	return sum[:p.N]
}

// PRF derives a secret key element from SK.seed and an address. This is the
// "simple" SPHINCS+ variant — no additional masking.
//
//	PRF(P, SK.seed, ADRS) = SHA256(P || ADRS_c || SK.seed)[:N]
func (p *Params) PRF(skSeed []byte, adrs ADRS) []byte {
	h := sha256.New()
	h.Write(p.PKSeed)
	ab := adrs.Bytes()
	h.Write(ab[:])
	h.Write(skSeed)
	sum := h.Sum(nil)
	return sum[:p.N]
}

// PRFmsg derives the per-signature randomness R used to salt message hashing.
//
//	PRFmsg(SK.prf, opt, M) = SHA256(SK.prf || opt || M)[:N]
//
// `opt` is typically n zero bytes for deterministic signing; feeding external
// randomness into opt yields probabilistic signatures.
func (p *Params) PRFmsg(skPRF, opt, msg []byte) []byte {
	h := sha256.New()
	h.Write(skPRF)
	h.Write(opt)
	h.Write(msg)
	sum := h.Sum(nil)
	return sum[:p.N]
}

// PRFmsgR derives the SPHINCS+ per-signature randomness R, which the
// paper (§11 + costs.sage `randomness_size = 32`) fixes at 2N bytes
// regardless of hash output size. Distinct from PRFmsg so chain-layer
// callers who only need N-byte outputs aren't accidentally paying the
// wider size. At N=16, 2N=32 fits inside a single SHA-256 evaluation.
func (p *Params) PRFmsgR(skPRF, opt, msg []byte) []byte {
	h := sha256.New()
	h.Write(skPRF)
	h.Write(opt)
	h.Write(msg)
	sum := h.Sum(nil)
	return sum[:2*p.N]
}

// HmsgDigestSize is the raw digest size produced by Hmsg prior to subset
// extraction. SHA-512 gives 64 bytes = 512 bits, which comfortably covers
// h + k·⌈log₂ t⌉ for all parameter sets we target (§13.3).
const HmsgDigestSize = sha512.Size

// Hmsg produces a 64-byte digest binding the message to the per-signature
// randomness R and the wallet's public key (PK.seed || PK.root). Callers
// then slice this digest to extract (hypertree index, k distinct leaf
// indices) per §10 Algorithm 1. Because SHA-512 outputs 512 bits, a single
// evaluation typically suffices; if not, Algorithm 1 resamples R and retries.
//
//	Hmsg(R, PK.seed, PK.root, M) = SHA512(R || PK.seed || PK.root || M)
func Hmsg(r, pkSeed, pkRoot, msg []byte) []byte {
	h := sha512.New()
	h.Write(r)
	h.Write(pkSeed)
	h.Write(pkRoot)
	h.Write(msg)
	return h.Sum(nil)
}

// ToByteBE is a small helper matching the SPHINCS+ spec's toByte function,
// converting an integer to a big-endian byte slice of fixed length. Used
// inside chain index and tree index encodings that feed into tweaks.
func ToByteBE(x uint64, length int) []byte {
	out := make([]byte, length)
	switch length {
	case 1:
		out[0] = byte(x)
	case 2:
		binary.BigEndian.PutUint16(out, uint16(x))
	case 4:
		binary.BigEndian.PutUint32(out, uint32(x))
	case 8:
		binary.BigEndian.PutUint64(out, x)
	default:
		for i := length - 1; i >= 0; i-- {
			out[i] = byte(x & 0xff)
			x >>= 8
		}
	}
	return out
}
