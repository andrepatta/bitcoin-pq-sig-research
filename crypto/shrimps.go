// Package crypto's SHRIMPS wrapper: two SPHINCS+ (W+C P+FP) instances
// running under a single combined public key. Per Kudinov & Nick,
// "Hash-based Signature Schemes for Bitcoin" (IACR eprint 2025/2203) +
// delvingbitcoin.org/t/2355, parameterized per docs/parameters/.
//
// Key structure:
//
//	         SHRIMPS_pk (32 B, on-chain)
//	       = PK.seed (16 B) || combined_root (16 B)
//	         combined_root = H(pk_compact || pk_fallback)
//	    __________________|___________________
//	   /                                      \
//	 pk_compact (16 B root)          pk_fallback (16 B root)
//	 SPHINCS+ (W+C P+FP)             SPHINCS+ (W+C P+FP)
//	 q_s = 2^10 = 1024               q_s = 2^40
//
// PK.seed is shared across both SPHINCS+ instances (one per-wallet
// public parameter feeding every tweakable hash), matching delving
// 2355's note that a single 16-B seed is sufficient for both.
//
// On-wire signature layout (two variants, tag-selected):
//
//   Compact (tag 0x00):
//     [1 B tag 0x00]
//     [8 B device_counter BE]            ← bookkeeping for rotation triggers
//     [SPHINCS+ compact signature bytes]
//     [16 B pk_compact_active]           ← needed: Hmsg binds PK.root
//     [16 B pk_fallback_sibling]
//
//   Fallback (tag 0x01):
//     [1 B tag 0x01]
//     [8 B fallback_counter BE]
//     [SPHINCS+ fallback signature bytes]
//     [16 B pk_fallback_active]
//     [16 B pk_compact_sibling]
//
// State-file layout (41 bytes, atomic write-then-rename):
//
//	[8 B device_counter BE]          ← compact-instance sig count
//	[8 B fallback_counter BE]        ← fallback-instance sig count
//	[1 B status]                     ← reserved, always 0x00 for now
//	[8 B reserved]                   ← 8 zeroed bytes (fills to 41 for parity
//	                                   with the SHRINCS state file)
//	[16 B combined_root_cached]      ← detect seed mismatch on reload
//
// Parameter choices (paper-canonical per docs/parameters/):
//   - compact SPHINCS+: (H=12, D=1, K=8, ALog2=17, w=16) at q_s=2^10.
//   - fallback SPHINCS+: (H=40, D=5, K=11, ALog2=14, w=256) at q_s=2^40
//     — K=11 uses the unbalanced PORS+FP tree path.
//
// Small-demo geometries (shrimpsDemo*SPHINCS) are available for tests
// only; keygen at paper params takes a few seconds.

package crypto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"qbitcoin/crypto/hashsig"
)

// Sig tag constants.
const (
	shrimpsTagCompact  byte = 0x00
	shrimpsTagFallback byte = 0x01
)

const shrimpsN = 16

// ShrimpsPubKeySize matches SHRINCS: 16 B PK.seed + 16 B combined_root.
const shrimpsPubKeySize = 2 * shrimpsN

const shrimpsStateFileLen = 8 + 8 + 1 + 8 + shrimpsN // 41

// ShrimpsKey is the multi-device SHRIMPS wrapper over two SPHINCS+
// instances. State is purely accounting (both sub-instances are
// stateless in the crypto sense); counters drive wallet-layer rotation
// triggers and paper-faithful per-device / per-signature bookkeeping.
type ShrimpsKey struct {
	Seed          [32]byte
	PublicKey     [32]byte // PK.seed(16) || combined_root(16)
	DeviceCounter uint64   // compact SPHINCS+ sigs issued
	FallbackCtr   uint64   // fallback SPHINCS+ sigs issued
	NDev          uint32   // compact budget numerator
	NDsig         uint32   // compact budget per device

	// io persists state between signs. Nil = no persistence (in-memory
	// key only). See crypto.StateIO in state_file.go.
	io StateIO

	// Cached roots — also persisted to detect seed mismatch.
	compactRoot  []byte // 16 B
	fallbackRoot []byte // 16 B

	// Derived crypto material (not serialized).
	hp            *hashsig.Params
	compactSP     hashsig.SPHINCSParams
	fallbackSP    hashsig.SPHINCSParams
	skCompact     []byte
	skFallback    []byte
	skPRFCompact  []byte
	skPRFFallback []byte

	mu sync.Mutex
}

// ShrimpsSig carries the wire bytes plus the (parsed) counter value
// that was consumed. UsesFallback indicates which SPHINCS+ instance
// produced the signature. The full wire form is in SphincsIG.
type ShrimpsSig struct {
	UsesFallback  bool
	DeviceCounter uint64 // compact counter if !UsesFallback; fallback counter otherwise
	SphincsIG     []byte // full wire bytes (tag + counter + sphincs body + active pk + sibling pk)

	// SiblingPK / SignerPK are kept for backward-compat with existing
	// consumers that may still read them directly. Populated by
	// DeserializeShrimpsSig on parse; ignored by the new Verify which
	// reads exclusively from SphincsIG.
	SignerPK  []byte
	SiblingPK []byte
}

// --- Parameterization -----------------------------------------------------

// shrimpsPaperCompactSPHINCS returns the paper-canonical SPHINCS+
// (W+C P+FP) compact-instance parameters for q_s = 2^10 per
// docs/parameters/, validated against sage costs.sage:
// (H=12, D=1, K=8, ALog2=17, w=16, S=240, MMax=105).
func shrimpsPaperCompactSPHINCS() hashsig.SPHINCSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 16, 16, 0, 240, 32)
	if err != nil {
		panic(fmt.Sprintf("shrimps paper compact: bad WOTS+C params: %v", err))
	}
	return hashsig.SPHINCSParams{
		N:     16,
		H:     12,
		D:     1,
		WOTS:  wp,
		PORS:  hashsig.PORSParams{N: 16, K: 8, ALog2: 17, RBits: 32, MMax: 105},
		RBits: 32,
	}
}

// shrimpsPaperFallbackSPHINCS returns the paper-canonical SPHINCS+
// (W+C P+FP) fallback-instance parameters for q_s = 2^40 per
// docs/parameters/ (the bold row in the paper's Table 1),
// validated against sage costs.sage: (H=40, D=5, K=11, ALog2=14,
// w=256, S=2040, MMax=118). K=11 requires the unbalanced PORS+FP tree path.
func shrimpsPaperFallbackSPHINCS() hashsig.SPHINCSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 16, 256, 0, 2040, 32)
	if err != nil {
		panic(fmt.Sprintf("shrimps paper fallback: bad WOTS+C params: %v", err))
	}
	return hashsig.SPHINCSParams{
		N:     16,
		H:     40,
		D:     5,
		WOTS:  wp,
		PORS:  hashsig.PORSParams{N: 16, K: 11, ALog2: 14, RBits: 32, MMax: 118},
		RBits: 32,
	}
}

// shrimpsDemoCompactSPHINCS / shrimpsDemoFallbackSPHINCS return small
// parameter sets used exclusively by test helpers — keygen in a few ms,
// sufficient to exercise every code path without the multi-second cost
// of paper params.
func shrimpsDemoCompactSPHINCS() hashsig.SPHINCSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 16, 16, 0, 240, 20)
	if err != nil {
		panic(fmt.Sprintf("shrimps demo compact: bad WOTS+C params: %v", err))
	}
	return hashsig.SPHINCSParams{
		N:     16,
		H:     4,
		D:     1,
		WOTS:  wp,
		PORS:  hashsig.PORSParams{N: 16, K: 2, ALog2: 3, RBits: 16, MMax: 8},
		RBits: 16,
	}
}

func shrimpsDemoFallbackSPHINCS() hashsig.SPHINCSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 16, 16, 0, 240, 20)
	if err != nil {
		panic(fmt.Sprintf("shrimps demo fallback: bad WOTS+C params: %v", err))
	}
	return hashsig.SPHINCSParams{
		N:    16,
		H:    6,
		D:    2,
		WOTS: wp,
		// K=3, ALog2=2 → t=12 (unbalanced) — exercises the mixed-depth PORS+FP path.
		PORS:  hashsig.PORSParams{N: 16, K: 3, ALog2: 2, RBits: 20, MMax: 10},
		RBits: 16,
	}
}

// deriveShrimpsMaterial expands the wallet seed into the four sub-seeds
// + shared PK.seed. Paper-convention SHA-256 truncation via sigHashN
// (defined in shrincs.go, same package).
func deriveShrimpsMaterial(seed [32]byte) (pkSeed, skC, skF, skPRFC, skPRFF []byte) {
	pkSeed = sigHashN(append(seed[:], []byte("qbitcoin-shrimps-pkseed")...), shrimpsN)
	skC = sigHashN(append(seed[:], []byte("qbitcoin-shrimps-compact-seed")...), shrimpsN)
	skF = sigHashN(append(seed[:], []byte("qbitcoin-shrimps-fallback-seed")...), shrimpsN)
	skPRFC = sigHashN(append(seed[:], []byte("qbitcoin-shrimps-compact-prf")...), shrimpsN)
	skPRFF = sigHashN(append(seed[:], []byte("qbitcoin-shrimps-fallback-prf")...), shrimpsN)
	return
}

// --- Key construction -----------------------------------------------------

// NewShrimpsKey derives a SHRIMPS key from a 32-byte seed using paper
// parameters (docs/parameters/). Eager keygen: both SPHINCS+ roots are
// computed at construction, which at paper params takes a few seconds
// dominated by the fallback hypertree (h=40, d=5, w=256). ctx is checked
// between the compact and fallback keygen passes so a shutdown
// mid-construction returns ctx.Err() instead of running the full
// hypertree to completion. Callers that need fast construction for
// tests should use newShrimpsKeyWithParams with smaller SPHINCS+ params
// instead.
func NewShrimpsKey(ctx context.Context, seed [32]byte, io StateIO, nDev, nDsig uint32) (*ShrimpsKey, error) {
	return newShrimpsKeyWithParams(ctx, seed, io, nDev, nDsig,
		shrimpsPaperCompactSPHINCS(), shrimpsPaperFallbackSPHINCS())
}

// NewShrimpsFileIO returns a StateIO that persists SHRIMPS state blobs
// to the given path via the default CRC-wrapped atomic-write format.
// Convenience wrapper — equivalent to `&FileStateIO{Path: path}`.
func NewShrimpsFileIO(path string) StateIO {
	if path == "" {
		return nil
	}
	return &FileStateIO{Path: path}
}

// newShrimpsKeyWithParams is the workhorse constructor. The two
// SPHINCS+ params describe the compact and fallback instances
// respectively. Tests invoke this directly with demo-sized params;
// production goes through NewShrimpsKey.
func newShrimpsKeyWithParams(
	ctx context.Context,
	seed [32]byte, io StateIO, nDev, nDsig uint32,
	compactSP, fallbackSP hashsig.SPHINCSParams,
) (*ShrimpsKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkSeed, skC, skF, skPRFC, skPRFF := deriveShrimpsMaterial(seed)
	hp := &hashsig.Params{N: shrimpsN, PKSeed: pkSeed}

	cRoot, err := compactSP.GenPK(hp, skC)
	if err != nil {
		return nil, fmt.Errorf("shrimps: compact keygen: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fRoot, err := fallbackSP.GenPK(hp, skF)
	if err != nil {
		return nil, fmt.Errorf("shrimps: fallback keygen: %w", err)
	}
	pk := shrimpsBuildPublicKey(pkSeed, cRoot, fRoot)

	k := &ShrimpsKey{
		Seed:          seed,
		PublicKey:     pk,
		NDev:          nDev,
		NDsig:         nDsig,
		io:            io,
		compactRoot:   cRoot,
		fallbackRoot:  fRoot,
		hp:            hp,
		compactSP:     compactSP,
		fallbackSP:    fallbackSP,
		skCompact:     skC,
		skFallback:    skF,
		skPRFCompact:  skPRFC,
		skPRFFallback: skPRFF,
	}
	if io != nil {
		if err := k.loadOrInit(); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// shrimpsCombinedRoot returns H(compactRoot || fallbackRoot), 16 B.
func shrimpsCombinedRoot(cRoot, fRoot []byte) [shrimpsN]byte {
	buf := make([]byte, 0, len(cRoot)+len(fRoot))
	buf = append(buf, cRoot...)
	buf = append(buf, fRoot...)
	h := Hash256(buf)
	var out [shrimpsN]byte
	copy(out[:], h[:shrimpsN])
	return out
}

// shrimpsBuildPublicKey returns the 32-byte on-chain pubkey layout:
// [PK.seed (16) || combined_root (16)].
func shrimpsBuildPublicKey(pkSeed, cRoot, fRoot []byte) [32]byte {
	combined := shrimpsCombinedRoot(cRoot, fRoot)
	var out [32]byte
	copy(out[:shrimpsN], pkSeed)
	copy(out[shrimpsN:], combined[:])
	return out
}

// splitShrimpsPubKey parses a 32-byte commitment into (PK.seed, combined_root).
func splitShrimpsPubKey(pk []byte) (pkSeed, root []byte, ok bool) {
	if len(pk) != shrimpsPubKeySize {
		return nil, nil, false
	}
	return pk[:shrimpsN], pk[shrimpsN:], true
}

// --- State file -----------------------------------------------------------

func (k *ShrimpsKey) loadOrInit() error {
	body, err := k.io.Read()
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return k.persistState()
		}
		return ErrStateCorrupted
	}
	if len(body) != shrimpsStateFileLen {
		return ErrStateCorrupted
	}
	devCtr := binary.BigEndian.Uint64(body[:8])
	fbCtr := binary.BigEndian.Uint64(body[8:16])
	// body[16] = status (reserved); body[17:25] = reserved zeros.
	cachedRoot := body[25:41]
	computed := shrimpsCombinedRoot(k.compactRoot, k.fallbackRoot)
	if !equalBytes(cachedRoot, computed[:]) {
		return ErrStateCorrupted
	}
	k.DeviceCounter = devCtr
	k.FallbackCtr = fbCtr
	return nil
}

func (k *ShrimpsKey) persistState() error {
	if k.io == nil {
		return nil
	}
	buf := make([]byte, shrimpsStateFileLen)
	binary.BigEndian.PutUint64(buf[:8], k.DeviceCounter)
	binary.BigEndian.PutUint64(buf[8:16], k.FallbackCtr)
	// buf[16] status, buf[17:25] reserved — all zero.
	combined := shrimpsCombinedRoot(k.compactRoot, k.fallbackRoot)
	copy(buf[25:41], combined[:])
	return k.io.Write(buf)
}

// --- Slot accounting ------------------------------------------------------

// MaxCounter returns the combined compact + fallback budget used for
// SlotHealth normalization. Compact budget = NDev·NDsig; fallback adds
// one per device (NDev).
func (k *ShrimpsKey) MaxCounter() uint64 {
	return uint64(k.NDev)*uint64(k.NDsig) + uint64(k.NDev)
}

// SlotHealth returns usage proportion in [0, 1].
func (k *ShrimpsKey) SlotHealth() float64 {
	max := k.MaxCounter()
	if max == 0 {
		return 1.0
	}
	used := k.DeviceCounter + k.FallbackCtr
	return float64(used) / float64(max)
}

// --- Signing --------------------------------------------------------------

// Sign produces a ShrimpsSig. Compact path is preferred; once its
// budget (NDev·NDsig) is spent the signer silently switches to the
// fallback path. Both are cryptographically stateless (SPHINCS+), so
// counters are pure accounting — they drive wallet rotation triggers
// but do not gate crypto validity. ctx is checked once after the
// mutex is acquired; the inner SPHINCS+ sign is bounded and
// uncancellable past that point.
//
// Persistence: we increment the counter in memory, persist it, and
// only then call the SPHINCS+ sign. Crash between persist and return =
// one wasted "slot" accounting unit; no security impact.
func (k *ShrimpsKey) Sign(ctx context.Context, msg []byte) (*ShrimpsSig, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.io != nil {
		if err := k.reloadCounters(); err != nil {
			return nil, err
		}
	}

	if k.DeviceCounter < uint64(k.NDev)*uint64(k.NDsig) {
		return k.signCompact(msg)
	}
	if k.FallbackCtr < uint64(k.NDev) {
		return k.signFallback(msg)
	}
	return nil, ErrCounterExhausted
}

func (k *ShrimpsKey) reloadCounters() error {
	body, err := k.io.Read()
	if err != nil {
		return ErrStateCorrupted
	}
	if len(body) != shrimpsStateFileLen {
		return ErrStateCorrupted
	}
	k.DeviceCounter = binary.BigEndian.Uint64(body[:8])
	k.FallbackCtr = binary.BigEndian.Uint64(body[8:16])
	return nil
}

func (k *ShrimpsKey) signCompact(msg []byte) (*ShrimpsSig, error) {
	used := k.DeviceCounter
	k.DeviceCounter = used + 1
	if err := k.persistState(); err != nil {
		k.DeviceCounter = used
		return nil, fmt.Errorf("shrimps persist: %w", err)
	}
	spsig, err := k.compactSP.Sign(k.hp, k.skCompact, k.skPRFCompact, nil, msg, k.compactRoot)
	if err != nil {
		return nil, fmt.Errorf("shrimps compact sign: %w", err)
	}
	return k.assembleSig(shrimpsTagCompact, used, spsig, k.compactRoot, k.fallbackRoot), nil
}

func (k *ShrimpsKey) signFallback(msg []byte) (*ShrimpsSig, error) {
	used := k.FallbackCtr
	k.FallbackCtr = used + 1
	if err := k.persistState(); err != nil {
		k.FallbackCtr = used
		return nil, fmt.Errorf("shrimps persist: %w", err)
	}
	spsig, err := k.fallbackSP.Sign(k.hp, k.skFallback, k.skPRFFallback, nil, msg, k.fallbackRoot)
	if err != nil {
		return nil, fmt.Errorf("shrimps fallback sign: %w", err)
	}
	return k.assembleSig(shrimpsTagFallback, used, spsig, k.fallbackRoot, k.compactRoot), nil
}

// assembleSig lays out the on-wire body: tag || counter || sphincs_sig
// || active_root || sibling_root.
func (k *ShrimpsKey) assembleSig(tag byte, counter uint64, spsig, active, sibling []byte) *ShrimpsSig {
	body := make([]byte, 0, 1+8+len(spsig)+2*shrimpsN)
	body = append(body, tag)
	var cb [8]byte
	binary.BigEndian.PutUint64(cb[:], counter)
	body = append(body, cb[:]...)
	body = append(body, spsig...)
	body = append(body, active...)
	body = append(body, sibling...)
	return &ShrimpsSig{
		UsesFallback:  tag == shrimpsTagFallback,
		DeviceCounter: counter,
		SphincsIG:     body,
		SignerPK:      append([]byte{}, active...),
		SiblingPK:     append([]byte{}, sibling...),
	}
}

// --- Verification ---------------------------------------------------------

// VerifyShrimps verifies a ShrimpsSig against the 32-byte on-chain
// commitment using paper SPHINCS+ parameters (docs/parameters/). This
// is the consensus-layer entry point — parameters are fixed so that all
// nodes reach the same verdict.
func VerifyShrimps(commitment [32]byte, msg []byte, sig *ShrimpsSig) bool {
	return verifyShrimpsWithParams(commitment, msg, sig,
		shrimpsPaperCompactSPHINCS(), shrimpsPaperFallbackSPHINCS())
}

// verifyShrimpsWithParams is the workhorse verifier. Tests use demo
// params; production goes through VerifyShrimps.
func verifyShrimpsWithParams(
	commitment [32]byte, msg []byte, sig *ShrimpsSig,
	compactSP, fallbackSP hashsig.SPHINCSParams,
) bool {
	if sig == nil || len(sig.SphincsIG) < 1+8+2*shrimpsN {
		return false
	}
	pkSeed, root, ok := splitShrimpsPubKey(commitment[:])
	if !ok {
		return false
	}
	hp := &hashsig.Params{N: shrimpsN, PKSeed: pkSeed}
	body := sig.SphincsIG
	tag := body[0]
	// Counter at body[1:9] — pure accounting, not bound into the sig.
	rest := body[9:]
	if len(rest) < 2*shrimpsN {
		return false
	}
	sibling := rest[len(rest)-shrimpsN:]
	active := rest[len(rest)-2*shrimpsN : len(rest)-shrimpsN]
	spsig := rest[:len(rest)-2*shrimpsN]

	var cand [shrimpsN]byte
	switch tag {
	case shrimpsTagCompact:
		cand = shrimpsCombinedRoot(active, sibling)
	case shrimpsTagFallback:
		cand = shrimpsCombinedRoot(sibling, active)
	default:
		return false
	}
	if !equalBytes(root, cand[:]) {
		return false
	}

	switch tag {
	case shrimpsTagCompact:
		return compactSP.Verify(hp, msg, spsig, active)
	case shrimpsTagFallback:
		return fallbackSP.Verify(hp, msg, spsig, active)
	}
	return false
}

// --- Wire serialization helpers (back-compat with callers) ----------------

// SerializeShrimpsSig keeps the legacy length-prefixed framing so that
// consumers (txn/script.go, wallet) continue to parse unchanged.
//
//	[1-byte uses_fallback][8-byte counter]
//	[4-byte sig_len][sig=SphincsIG]
//	[4-byte signerpk_len][signerpk]
//	[4-byte siblingpk_len][siblingpk]
func SerializeShrimpsSig(s *ShrimpsSig) []byte {
	buf := make([]byte, 0, 1+8+4+len(s.SphincsIG)+4+len(s.SignerPK)+4+len(s.SiblingPK))
	if s.UsesFallback {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], s.DeviceCounter)
	buf = append(buf, tmp[:]...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(s.SphincsIG)))
	buf = append(buf, l[:]...)
	buf = append(buf, s.SphincsIG...)
	binary.BigEndian.PutUint32(l[:], uint32(len(s.SignerPK)))
	buf = append(buf, l[:]...)
	buf = append(buf, s.SignerPK...)
	binary.BigEndian.PutUint32(l[:], uint32(len(s.SiblingPK)))
	buf = append(buf, l[:]...)
	buf = append(buf, s.SiblingPK...)
	return buf
}

// DeserializeShrimpsSig parses SerializeShrimpsSig output.
func DeserializeShrimpsSig(b []byte) (*ShrimpsSig, error) {
	if len(b) < 1+8+4 {
		return nil, errors.New("shrimps sig: too short")
	}
	s := &ShrimpsSig{UsesFallback: b[0] == 1}
	off := 1
	s.DeviceCounter = binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	read := func() ([]byte, error) {
		if off+4 > len(b) {
			return nil, errors.New("shrimps sig: truncated len")
		}
		n := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if off+int(n) > len(b) {
			return nil, errors.New("shrimps sig: truncated payload")
		}
		v := make([]byte, n)
		copy(v, b[off:off+int(n)])
		off += int(n)
		return v, nil
	}
	var err error
	if s.SphincsIG, err = read(); err != nil {
		return nil, err
	}
	if s.SignerPK, err = read(); err != nil {
		return nil, err
	}
	if s.SiblingPK, err = read(); err != nil {
		return nil, err
	}
	return s, nil
}
