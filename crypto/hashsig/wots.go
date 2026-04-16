// WOTS-TW (§4) and WOTS+C (§5) one-time signature schemes from
// Kudinov & Nick, "Hash-based Signature Schemes for Bitcoin"
// (IACR eprint 2025/2203, Revision 2025-12-05).
//
// WOTS-TW is the tweakable-hash Winternitz OTS used as a building block
// inside XMSS / SPHINCS+. WOTS+C replaces WOTS-TW's explicit checksum
// chains with a trial-counter that forces the message digest's base-w
// digits to sum to a fixed target S and to end in z zero digits — saving
// `z` chains of signature material at the cost of per-signature grinding.
//
// Both are parameterized: S, z, r (counter bits) and w are caller-supplied
// so downstream code can instantiate SHRINCS OTS (n=16, m=9, w=16, z=0,
// ℓ=18 — len1 shrunk via m) and SHRIMPS compact (n=16, m=16, w=16, z=0,
// ℓ=32) without source edits.

package hashsig

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// AddrTypeWOTSCMsg is a local extension used to domain-separate the
// counter-grinding message hash of WOTS+C from every other tweakable
// hash call. The SPHINCS+ spec reserves address types 0..6; we use 7
// for the WOTS+C message tweak. Signer and verifier must agree, which
// they do by construction since both go through `wotsCMsgHash`.
const AddrTypeWOTSCMsg uint32 = 7

// WOTSParams captures the Winternitz parameters of a WOTS-TW or WOTS+C
// instance. Field semantics follow the paper:
//
//   - N: tweakable-hash output size in bytes (n; = 16 at L1)
//   - M: message length in bytes signed by the OTS (m)
//   - W: Winternitz base (w)
//   - Len1: ⌈M·8 / log₂ W⌉ base-w digits covering the message
//   - Len2: WOTS-TW checksum digits (0 for WOTS+C)
//   - Ell:  number of chains actually signed (Len1+Len2 for WOTS-TW,
//     Len1-Z for WOTS+C)
//   - Z:    zero-chain reduction (WOTS+C only; 0 for WOTS-TW)
//   - S:    target digit sum S_{w,n} (WOTS+C only)
//   - RBits:counter width in bits (WOTS+C only); signature carries
//     ⌈RBits/8⌉ bytes of counter
type WOTSParams struct {
	N, M, W         int
	Len1, Len2, Ell int
	Z, S            int
	RBits           int
}

// NewWOTSTWParams returns parameters for the checksum-variant WOTS-TW
// used inside XMSS / SPHINCS+ hypertrees. n, m, w must be caller-chosen.
// Panics on invalid w (must be a power of two with log2(w) ∈ {1..8}).
func NewWOTSTWParams(n, m, w int) WOTSParams {
	logW := log2Exact(w)
	len1 := (m * 8) / logW
	if (m*8)%logW != 0 {
		len1++
	}
	// Max unsigned checksum value = len1·(w-1); encoded in len2 base-w digits.
	maxCsum := len1 * (w - 1)
	len2 := 1
	for v := maxCsum; v >= w; v /= w {
		len2++
	}
	return WOTSParams{
		N: n, M: m, W: w,
		Len1: len1, Len2: len2, Ell: len1 + len2,
	}
}

// NewWOTSPlusCParams returns parameters for the counter-variant WOTS+C
// (§5). `z` zero-chains are dropped from the signature, `s` is the
// target digit sum over the first `len1` digits, and `rBits` is the
// counter width (≤ 32 in every parameter set we target).
//
// Callers must pick (z, s, rBits) consistent with the security bound in
// §5.1; values come from `security.sage`. This constructor performs only
// arithmetic sanity checks — it does NOT verify cryptographic adequacy.
func NewWOTSPlusCParams(n, m, w, z, s, rBits int) (WOTSParams, error) {
	logW := log2Exact(w)
	len1 := (m * 8) / logW
	if (m*8)%logW != 0 {
		len1++
	}
	if z < 0 || z >= len1 {
		return WOTSParams{}, errors.New("wotsplusc: z out of range [0, len1)")
	}
	if s < 0 || s > len1*(w-1) {
		return WOTSParams{}, errors.New("wotsplusc: s out of range [0, len1·(w-1)]")
	}
	if rBits <= 0 || rBits > 64 {
		return WOTSParams{}, errors.New("wotsplusc: rBits out of range (0, 64]")
	}
	return WOTSParams{
		N: n, M: m, W: w,
		Len1: len1, Len2: 0, Ell: len1 - z,
		Z: z, S: s, RBits: rBits,
	}, nil
}

// SigSize returns the WOTS signature size in bytes: ℓ chain tops plus
// the WOTS+C counter (0 for WOTS-TW).
func (p WOTSParams) SigSize() int {
	return p.Ell*p.N + p.counterBytes()
}

func (p WOTSParams) counterBytes() int {
	if p.RBits == 0 {
		return 0
	}
	return (p.RBits + 7) / 8
}

// chain applies the tweakable hash F in sequence, advancing the
// chain-index inside ADRS. steps may be zero (returns a copy of x).
func (wp *WOTSParams) chain(p *Params, adrs ADRS, x []byte, start, steps int) []byte {
	tmp := make([]byte, len(x))
	copy(tmp, x)
	for j := range steps {
		adrs.SetHash(uint32(start + j))
		tmp = p.F(adrs, tmp)
	}
	return tmp
}

// baseW decodes `out` base-w digits from the most significant side of
// msg. Matches the SPHINCS+ reference base_w routine bit-packed for
// w ∈ {4, 16, 256}.
func baseW(msg []byte, w, out int) []uint8 {
	logW := log2Exact(w)
	digits := make([]uint8, out)
	var total uint16
	bitsLeft := 0
	in := 0
	for i := range out {
		if bitsLeft == 0 {
			total = uint16(msg[in])
			in++
			bitsLeft = 8
		}
		bitsLeft -= logW
		digits[i] = uint8((total >> uint(bitsLeft)) & uint16(w-1))
	}
	return digits
}

// wotsChecksum computes the base-w checksum digits used by WOTS-TW.
// The paper shifts the checksum left so its total bit length is a
// multiple of logW — same as SPHINCS+ reference.
func wotsChecksum(digits []uint8, w, len2 int) []uint8 {
	logW := log2Exact(w)
	var csum uint64
	for _, d := range digits {
		csum += uint64(w-1) - uint64(d)
	}
	// Pad up so len2·logW bits fit.
	pad := (len2 * logW) % 8
	if pad != 0 {
		csum <<= uint(8 - pad)
	}
	csBytes := len2 * logW
	csBytes = (csBytes + 7) / 8
	buf := make([]byte, csBytes)
	for i := csBytes - 1; i >= 0; i-- {
		buf[i] = byte(csum & 0xff)
		csum >>= 8
	}
	return baseW(buf, w, len2)
}

// secretFor returns sk_i = PRF(SK.seed, WOTSPRF-ADRS) for chain i under
// the WOTS keypair addressed by `kp` inside `tree`/`layer`.
func (wp *WOTSParams) secretFor(p *Params, skSeed []byte, base ADRS, i int) []byte {
	a := base.Clone()
	a.SetType(AddrTypeWOTSPRF)
	a.SetKeyPair(base.f1) // carry keypair from caller's ADRS
	a.SetChain(uint32(i))
	a.SetHash(0)
	return p.PRF(skSeed, a)
}

// WOTSGenPK derives the compressed WOTS public key (n bytes) for the
// keypair addressed by `base`. `base.type`/`f1` are used for keypair
// identity; this function overrides the other slots.
func (wp *WOTSParams) WOTSGenPK(p *Params, skSeed []byte, base ADRS) []byte {
	chainEnds := make([][]byte, wp.Ell)
	for i := range wp.Ell {
		sk := wp.secretFor(p, skSeed, base, i)
		adrs := base.Clone()
		adrs.SetType(AddrTypeWOTSHash)
		adrs.SetKeyPair(base.f1)
		adrs.SetChain(uint32(i))
		chainEnds[i] = wp.chain(p, adrs, sk, 0, wp.W-1)
	}
	pkADRS := base.Clone()
	pkADRS.SetType(AddrTypeWOTSPK)
	pkADRS.SetKeyPair(base.f1)
	return p.Tl(pkADRS, chainEnds...)
}

// --- WOTS-TW (§4) ---------------------------------------------------

// WOTSSign signs an `M`-byte message with WOTS-TW. The signature
// consists of Ell = Len1+Len2 chain elements, each N bytes.
func (wp *WOTSParams) WOTSSign(p *Params, skSeed, msg []byte, base ADRS) ([]byte, error) {
	if wp.RBits != 0 || wp.Z != 0 {
		return nil, errors.New("wots-tw: params carry WOTS+C configuration; use WOTSPlusCSign")
	}
	if len(msg) != wp.M {
		return nil, errors.New("wots-tw: wrong message length")
	}
	digits := baseW(msg, wp.W, wp.Len1)
	csum := wotsChecksum(digits, wp.W, wp.Len2)
	digits = append(digits, csum...)

	sig := make([]byte, wp.Ell*wp.N)
	for i := range wp.Ell {
		sk := wp.secretFor(p, skSeed, base, i)
		a := base.Clone()
		a.SetType(AddrTypeWOTSHash)
		a.SetKeyPair(base.f1)
		a.SetChain(uint32(i))
		out := wp.chain(p, a, sk, 0, int(digits[i]))
		copy(sig[i*wp.N:], out)
	}
	return sig, nil
}

// WOTSPKFromSig recovers a candidate compressed pk from a WOTS-TW sig.
// Verifiers compare the returned pk against the expected leaf value.
func (wp *WOTSParams) WOTSPKFromSig(p *Params, msg, sig []byte, base ADRS) ([]byte, error) {
	if wp.RBits != 0 || wp.Z != 0 {
		return nil, errors.New("wots-tw: params carry WOTS+C configuration; use WOTSPlusCPKFromSig")
	}
	if len(msg) != wp.M {
		return nil, errors.New("wots-tw: wrong message length")
	}
	if len(sig) != wp.Ell*wp.N {
		return nil, errors.New("wots-tw: wrong signature length")
	}
	digits := baseW(msg, wp.W, wp.Len1)
	csum := wotsChecksum(digits, wp.W, wp.Len2)
	digits = append(digits, csum...)

	ends := make([][]byte, wp.Ell)
	for i := range wp.Ell {
		a := base.Clone()
		a.SetType(AddrTypeWOTSHash)
		a.SetKeyPair(base.f1)
		a.SetChain(uint32(i))
		ends[i] = wp.chain(p, a, sig[i*wp.N:(i+1)*wp.N],
			int(digits[i]), wp.W-1-int(digits[i]))
	}
	pkADRS := base.Clone()
	pkADRS.SetType(AddrTypeWOTSPK)
	pkADRS.SetKeyPair(base.f1)
	return p.Tl(pkADRS, ends...), nil
}

// --- WOTS+C (§5) ----------------------------------------------------

// wotsCMsgHash is the §5 trial-hash step: produce a digest that the
// signer grinds against the (sum = S, last z digits = 0) predicate. The
// digest is taken as the first Len1·⌈log₂w⌉ bits of a tweakable hash
// over (msg || counter) under an ADRS dedicated to the WOTS+C message
// domain (AddrTypeWOTSCMsg).
func (wp *WOTSParams) wotsCMsgHash(p *Params, base ADRS, msg []byte, counter uint64) []byte {
	a := base.Clone()
	a.SetType(AddrTypeWOTSCMsg)
	a.SetKeyPair(base.f1)
	ctr := ToByteBE(counter, wp.counterBytes())
	// Message-digest length in bytes for `Len1` base-w digits.
	logW := log2Exact(wp.W)
	nBits := wp.Len1 * logW
	nBytes := (nBits + 7) / 8
	// Use T_l as an arbitrary-arity tweakable hash; truncate to nBytes.
	// F() outputs N bytes only, which may be < nBytes. When N·8 < nBits we
	// widen by chaining an internal counter into the tweak. At (n=16,
	// w=16, len1=32) we need 16 bytes = exactly N. For (w=256) we need
	// m=16 bytes too. For broader params, extend via stripe-PRF below.
	if nBytes <= wp.N {
		d := p.Tl(a, msg, ctr)
		return d[:nBytes]
	}
	out := make([]byte, 0, nBytes)
	for stripe := uint32(0); len(out) < nBytes; stripe++ {
		sa := a.Clone()
		sa.SetHash(stripe)
		out = append(out, p.Tl(sa, msg, ctr)...)
	}
	return out[:nBytes]
}

// wotsCDigits grinds the WOTS+C counter: increments `counter` starting
// at 0 until the digest's first Len1 base-w digits sum to S and the
// last Z digits are all zero. Returns (digits, counter). Iterates up
// to 2^RBits times; returns an error if the counter space is exhausted.
func (wp *WOTSParams) wotsCDigits(p *Params, base ADRS, msg []byte) ([]uint8, uint64, error) {
	limit := uint64(1) << uint(wp.RBits)
	if wp.RBits == 64 {
		limit = ^uint64(0)
	}
	for counter := uint64(0); counter < limit; counter++ {
		d := wp.wotsCMsgHash(p, base, msg, counter)
		digits := baseW(d, wp.W, wp.Len1)
		var sum int
		for _, a := range digits {
			sum += int(a)
		}
		if sum != wp.S {
			continue
		}
		ok := true
		for i := wp.Len1 - wp.Z; i < wp.Len1; i++ {
			if digits[i] != 0 {
				ok = false
				break
			}
		}
		if ok {
			return digits, counter, nil
		}
	}
	return nil, 0, errors.New("wotsplusc: counter space exhausted without finding S/z witness")
}

// verifyDigits recomputes digits at the verifier side for a given
// counter and checks the WOTS+C predicate.
func (wp *WOTSParams) verifyDigits(p *Params, base ADRS, msg []byte, counter uint64) ([]uint8, error) {
	d := wp.wotsCMsgHash(p, base, msg, counter)
	digits := baseW(d, wp.W, wp.Len1)
	var sum int
	for _, a := range digits {
		sum += int(a)
	}
	if sum != wp.S {
		return nil, errors.New("wotsplusc: digit sum mismatch")
	}
	for i := wp.Len1 - wp.Z; i < wp.Len1; i++ {
		if digits[i] != 0 {
			return nil, errors.New("wotsplusc: non-zero tail digit")
		}
	}
	return digits, nil
}

// WOTSPlusCSign signs msg under WOTS+C. Signature layout:
//
//	[Ell · N bytes chain elements] [counterBytes() bytes counter BE]
func (wp *WOTSParams) WOTSPlusCSign(p *Params, skSeed, msg []byte, base ADRS) ([]byte, error) {
	if wp.RBits == 0 {
		return nil, errors.New("wotsplusc: params are WOTS-TW; use WOTSSign")
	}
	if len(msg) != wp.M {
		return nil, errors.New("wotsplusc: wrong message length")
	}
	digits, counter, err := wp.wotsCDigits(p, base, msg)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, wp.Ell*wp.N+wp.counterBytes())
	// Sign only the first Ell = Len1 - Z digits; the last Z are zero
	// by construction and need no signature material.
	for i := range wp.Ell {
		sk := wp.secretFor(p, skSeed, base, i)
		a := base.Clone()
		a.SetType(AddrTypeWOTSHash)
		a.SetKeyPair(base.f1)
		a.SetChain(uint32(i))
		out := wp.chain(p, a, sk, 0, int(digits[i]))
		copy(sig[i*wp.N:], out)
	}
	// Counter is stored big-endian in the minimum number of bytes.
	ctrBytes := wp.counterBytes()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	copy(sig[wp.Ell*wp.N:], buf[8-ctrBytes:])
	return sig, nil
}

// WOTSPlusCPKFromSig recovers a candidate pk from a WOTS+C signature.
// The verifier first reads the counter, re-grinds the digest, then
// completes each chain from its revealed start.
func (wp *WOTSParams) WOTSPlusCPKFromSig(p *Params, msg, sig []byte, base ADRS) ([]byte, error) {
	if wp.RBits == 0 {
		return nil, errors.New("wotsplusc: params are WOTS-TW; use WOTSPKFromSig")
	}
	if len(msg) != wp.M {
		return nil, errors.New("wotsplusc: wrong message length")
	}
	ctrBytes := wp.counterBytes()
	if len(sig) != wp.Ell*wp.N+ctrBytes {
		return nil, errors.New("wotsplusc: wrong signature length")
	}
	buf := make([]byte, 8)
	copy(buf[8-ctrBytes:], sig[wp.Ell*wp.N:])
	counter := binary.BigEndian.Uint64(buf)
	digits, err := wp.verifyDigits(p, base, msg, counter)
	if err != nil {
		return nil, err
	}
	ends := make([][]byte, wp.Ell+wp.Z)
	for i := range wp.Ell {
		a := base.Clone()
		a.SetType(AddrTypeWOTSHash)
		a.SetKeyPair(base.f1)
		a.SetChain(uint32(i))
		ends[i] = wp.chain(p, a, sig[i*wp.N:(i+1)*wp.N],
			int(digits[i]), wp.W-1-int(digits[i]))
	}
	// The Z trailing zero-digit chains are reconstructed directly by
	// the verifier: their sk is PRF-derived from SK.seed, and their
	// chain end is c^{0, w-1}(sk). But at verify time SK.seed is not
	// available — instead the paper's construction includes these
	// chain ends implicitly by requiring them to be part of the public
	// key digest. For WOTS+C used as an XMSS leaf, the leaf pk already
	// binds all ℓ+z chains; the verifier therefore only needs the ℓ
	// message-covering chains to recompute the leaf and compares with
	// the published leaf. We return pk over exactly those ℓ ends — the
	// caller (XMSS / SPHINCS+) must use the *same* Ell on both sides.
	//
	// Note: this diverges cleanly from WOTS-TW (which returns pk over
	// all ℓ+csum chains). Callers must not mix the two.
	pkADRS := base.Clone()
	pkADRS.SetType(AddrTypeWOTSPK)
	pkADRS.SetKeyPair(base.f1)
	return p.Tl(pkADRS, ends[:wp.Ell]...), nil
}

// log2Exact returns log2(w) when w is a power of two in [2, 256]; panics
// otherwise. WOTS base-w routines require exact power-of-two w.
func log2Exact(w int) int {
	if w < 2 || w > 256 || bits.OnesCount(uint(w)) != 1 {
		panic("hashsig: w must be a power of two in [2, 256]")
	}
	return bits.TrailingZeros(uint(w))
}
