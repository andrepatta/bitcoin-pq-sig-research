// Package crypto's SHRINCS wrapper: stateful unbalanced-XMSS primary
// path + stateless SPHINCS+ (W+C P+FP) fallback. Per Kudinov & Nick,
// "Hash-based Signature Schemes for Bitcoin" (IACR eprint 2025/2203)
// §B.3 + delvingbitcoin.org/t/2158, parameterized per docs/parameters/.
//
// Key structure:
//
//	         SHRINCS_pk (16 B, on-chain)
//	       = H(pk_stateful || pk_stateless)
//	    _________|__________
//	   /                    \
//	 pk_stateful (16 B)   pk_stateless (16 B)
//	 unbalanced-XMSS      SPHINCS+ (W+C P+FP)
//	 WOTS+C leaves        q_s = 2^40-ish fallback
//
// On-wire signature layout (two variants, length-dispatched per paper
// §B.3 `min(stateful, sl) + 16` rule — the signer MUST fall back to
// stateless whenever the stateful sig would not be strictly smaller, so
// the verifier can safely tell them apart by body length alone):
//
//   Stateful:
//     [UXMSS signature bytes]       ← WOTS+C sig + auth path (size is q-dependent)
//     [16 B pk_stateless sibling]
//
//     Body size = 292 + AuthPathLen(q)·16 + 16. Verifier derives q from
//     (bodyLen - 292 - 16) / 16 − 1; ADRS Tree-index 0 at layer 0 is
//     fixed (no per-key tree_height needed on the wire because paper's
//     fallback rule bounds q well below any practical NumLeaves).
//
//   Stateless:
//     [SPHINCS+ signature bytes]
//     [16 B pk_stateless active]    ← needed because SPHINCS+ Hmsg binds PK.root
//     [16 B pk_stateful sibling]
//
//     Body size = sp.SigSize() + 32 — the dispatch threshold.
//
// The stateless path carries pk_stateless explicitly (as an "active" pk)
// AND pk_stateful as sibling — unlike the paper's 2-field layout.
// Reason: SPHINCS+'s H_msg binds PK.root into every signature (FIPS-205
// style), so the verifier cannot derive pk_stateless from sig alone —
// it must receive it. The extra 16 bytes at fallback is negligible vs.
// the ~4 KB SPHINCS+ signature body. The pk binding is still sound:
// verifier recomputes H(sibling_stateful || active_stateless) and
// rejects if it doesn't match the combined SHRINCS pubKey.
//
// State-file layout:
//
//	[8 B q BE]                 ← next leaf index to use
//	[1 B status]               ← 0x00 intact, 0x01 LOST (seed-restored)
//	[16 B stateful_root]       ← cached UXMSS root for fast load
//	[16 B stateless_root]      ← cached SPHINCS+ root for fast load
//
// Parameter choices:
//   - WOTS+C uses m=9, z=0, S=135, rBits=32 per paper §B.3 — ℓ=18
//     chains = len1 = m·8/log₂w. Signature is 18·16 + 4 counter = 292 B
//     (matches blockstream.com/quantum's 324 B figure once the UXMSS
//     auth path, randomness, and stateless-sibling are added). S=135
//     is the centered target where ν is maximal (log₂(1/p_ν) ≈ 5.6),
//     so counter grinding converges in ~50 tries on average.
//   - UXMSS tree height is fixed consensus-wide via ShrincsTreeHeight.
//   - SPHINCS+ fallback: paper-canonical (H=40, D=5, K=11, ALog2=14,
//     w=256) per docs/parameters/; small-demo geometry is available
//     via shrincsDemoFallbackSPHINCS for tests only.

package crypto

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"qbitcoin/crypto/hashsig"
)

var (
	ErrCounterExhausted = errors.New("shrincs: all signing slots exhausted")
	ErrStateCorrupted   = errors.New("shrincs: state file missing or corrupted")
)

// Sub-root / pk-seed size at NIST L1 (n = 16).
const shrincsN = 16

// shrincsStatelessCounter is the sentinel stored in ShrincsSig.Counter
// for signatures emitted via the fallback path. Chosen as MaxUint64
// because it's >= any achievable UXMSS leaf index.
const shrincsStatelessCounter uint64 = ^uint64(0)

// ShrincsTreeHeight is the consensus-fixed UXMSS tree height. Matches
// the useful slot window under the paper's min-rule: with the canonical
// stateless fallback ~4068 B, stateful sigs cease to be strictly smaller
// at q ≈ 234, so NumLeaves = 256 is the smallest power-of-two that
// doesn't leave unreachable slots. Fixing this consensus-wide is what
// lets the verifier reconstruct UXMSS ADRS without a wire field.
const ShrincsTreeHeight uint8 = 8

// ShrincsNumLeaves = 1 << ShrincsTreeHeight.
const ShrincsNumLeaves = 1 << ShrincsTreeHeight

// PublicKey layout: [16-byte PKSeed][16-byte combined-root commitment].
// PKSeed is the public-parameter P feeding every tweakable hash call
// in SPHINCS+/XMSS/WOTS. The verifier MUST use the signer's PKSeed to
// reproduce the same hash evaluations; attaching it to the pubkey is
// the standard FIPS-205 / SPHINCS+ convention.
const shrincsPubKeySize = 2 * shrincsN

// State-file status byte. Only `OK` is emitted today; `LOST` (=0x01) is
// reserved for a future seed-restoration flow (promoteRecoveryKey in
// wallet/rotate.go) where a key rebuilt purely from the mnemonic marks
// its state as LOST to signal "counter should not be trusted beyond
// what's on-disk".
const shrincsStatusOK byte = 0x00

const shrincsStateFileLen = 8 + 1 + shrincsN + shrincsN // 41

// ShrincsKey is a stateful single-device PQ signing key combining an
// unbalanced-XMSS primary and a SPHINCS+ stateless fallback.
type ShrincsKey struct {
	// Exposed (kept for backwards compatibility with callers).
	Seed       [32]byte
	PublicKey  []byte // 16 bytes; H(stateful_root || stateless_root)
	Counter    uint64 // UXMSS next-to-use leaf index
	TreeHeight uint8  // NumLeaves = 1 << TreeHeight

	// io persists state between signs. Nil = no persistence (in-memory
	// key only). Production callers wire either FileStateIO or the
	// wallet package's encrypted store adapter.
	io StateIO

	// Cached roots (also persisted).
	statefulRoot  []byte
	statelessRoot []byte

	// Derived crypto material (not serialized; re-derived from Seed).
	hp        *hashsig.Params
	uxmss     hashsig.UXMSSParams
	sphincs   hashsig.SPHINCSParams
	skSeedStf []byte
	skSeedStl []byte
	skPRFStl  []byte

	mu sync.Mutex
}

// ShrincsSig carries the wire form plus the UXMSS counter when the
// stateful path was used. Counter carries the UXMSS leaf index for
// stateful sigs and shrincsStatelessCounter (MaxUint64) for stateless
// sigs — it lives in the outer SerializeShrincsSig frame, not in
// SphincsIG, so it's the Sig-struct-level discriminator.
type ShrincsSig struct {
	Counter   uint64
	SphincsIG []byte // wire bytes of the SHRINCS signature body (no tag)
}

// IsStateful reports whether this signature was produced via the
// stateful UXMSS path. Uses the outer-frame Counter sentinel (stateless
// sigs carry shrincsStatelessCounter); avoids dispatching on SphincsIG
// length alone because that requires the fallback SPHINCS+ params.
func (s *ShrincsSig) IsStateful() bool {
	return s != nil && s.Counter != shrincsStatelessCounter
}

// --- Parameterization -----------------------------------------------------

// shrincsPaperFallbackSPHINCS returns the paper-canonical SPHINCS+
// (W+C P+FP) parameters for the stateless fallback per docs/parameters/
// — the q_s=2^40 bold row in the paper's Table 1:
// (H=40, D=5, K=11, ALog2=14, w=256, S=2040, MMax=118). Identical to
// shrimpsPaperFallbackSPHINCS by design; the two wrappers share the
// fallback geometry but derive independent keys (domain-separated seeds).
func shrincsPaperFallbackSPHINCS() hashsig.SPHINCSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 16, 256, 0, 2040, 32)
	if err != nil {
		panic(fmt.Sprintf("shrincs paper fallback: bad WOTS+C params: %v", err))
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

// shrincsDemoFallbackSPHINCS returns small-geometry fallback SPHINCS+
// params for tests. Keygen/sign in milliseconds.
func shrincsDemoFallbackSPHINCS() hashsig.SPHINCSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 16, 16, 0, 240, 24)
	if err != nil {
		panic(fmt.Sprintf("shrincs demo fallback: bad WOTS+C params: %v", err))
	}
	return hashsig.SPHINCSParams{
		N:    16,
		H:    8,
		D:    2,
		WOTS: wp,
		// K=3, ALog2=2 → t=12 (unbalanced) — exercises mixed-depth PORS+FP.
		PORS:  hashsig.PORSParams{N: 16, K: 3, ALog2: 2, RBits: 20, MMax: 10},
		RBits: 16,
	}
}

// shrincsWOTSPlusC returns the WOTS+C parameter set for UXMSS leaves.
func shrincsWOTSPlusC() hashsig.WOTSParams {
	wp, err := hashsig.NewWOTSPlusCParams(16, 9, 16, 0, 135, 32)
	if err != nil {
		panic(fmt.Sprintf("shrincs: bad WOTS+C params: %v", err))
	}
	return wp
}

// sigHashN hashes input with SHA-256 and truncates to n bytes. Used for
// signature-internal seed derivation and sighash→digest shrinking. The
// paper's tweakable-hash convention is SHA-256 (§2); truncation is fine
// since inputs are domain-separated.
func sigHashN(input []byte, n int) []byte {
	h := sha256.Sum256(input)
	out := make([]byte, n)
	copy(out, h[:])
	return out
}

// deriveMaterial expands Seed into the seeds feeding UXMSS, SPHINCS+,
// and the SPHINCS+ PRFmsg. Paper-convention SHA-256 truncation.
func deriveMaterial(seed [32]byte) (pkSeed, skStf, skStl, skPRFStl []byte) {
	pkSeed = sigHashN(append(seed[:], []byte("qbitcoin-shrincs-pkseed")...), shrincsN)
	skStf = sigHashN(append(seed[:], []byte("qbitcoin-shrincs-stateful-seed")...), shrincsN)
	skStl = sigHashN(append(seed[:], []byte("qbitcoin-shrincs-stateless-seed")...), shrincsN)
	skPRFStl = sigHashN(append(seed[:], []byte("qbitcoin-shrincs-stateless-prf")...), shrincsN)
	return
}

// --- Key construction -----------------------------------------------------

// NewShrincsKey derives a SHRINCS key from a 32-byte seed using paper
// SPHINCS+ parameters for the stateless fallback. UXMSS tree height is
// fixed consensus-wide (see ShrincsTreeHeight). Eager keygen: fallback
// hypertree (h=40, d=5, w=256) dominates — expect a few seconds at
// paper params. ctx is checked between the stateful and stateless
// keygen passes so a shutdown mid-construction returns ctx.Err()
// instead of running the full hypertree to completion. Test code that
// wants fast fallback keygen should use newShrincsKeyWithParams.
//
// io persists state between signs (counter + cached roots). Pass nil to
// run without persistence (in-memory only). Most callers should use
// NewShrincsFileIO(path) for filesystem persistence; the wallet package
// wires an encrypted-at-rest adapter.
func NewShrincsKey(ctx context.Context, seed [32]byte, io StateIO) (*ShrincsKey, error) {
	return newShrincsKeyWithParams(ctx, seed, io, shrincsPaperFallbackSPHINCS())
}

// NewShrincsFileIO returns a StateIO that persists SHRINCS state blobs
// to the given path via the default CRC-wrapped atomic-write format.
// Convenience wrapper — equivalent to `&FileStateIO{Path: path}`.
func NewShrincsFileIO(path string) StateIO {
	if path == "" {
		return nil
	}
	return &FileStateIO{Path: path}
}

// newShrincsKeyWithParams is the workhorse constructor. `sp` describes
// the SPHINCS+ fallback geometry; tests pass demo params for speed.
func newShrincsKeyWithParams(ctx context.Context, seed [32]byte, io StateIO, sp hashsig.SPHINCSParams) (*ShrincsKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pkSeed, skStf, skStl, skPRFStl := deriveMaterial(seed)
	hp := &hashsig.Params{N: shrincsN, PKSeed: pkSeed}
	uxmss := hashsig.UXMSSParams{
		NumLeaves: ShrincsNumLeaves,
		WOTS:      shrincsWOTSPlusC(),
	}

	// Build sub-roots (eager; stateful is cheap at small heights, fallback
	// at demo params is also cheap. Production may want lazy stateless).
	var base hashsig.ADRS
	base.SetLayer(0)
	base.SetTree(0)
	stfRoot, err := uxmss.GenPK(hp, skStf, base)
	if err != nil {
		return nil, fmt.Errorf("shrincs: stateful keygen: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stlRoot, err := sp.GenPK(hp, skStl)
	if err != nil {
		return nil, fmt.Errorf("shrincs: stateless keygen: %w", err)
	}
	pub := buildPublicKey(pkSeed, stfRoot, stlRoot)

	k := &ShrincsKey{
		Seed:          seed,
		PublicKey:     pub,
		TreeHeight:    ShrincsTreeHeight,
		io:            io,
		statefulRoot:  stfRoot,
		statelessRoot: stlRoot,
		hp:            hp,
		uxmss:         uxmss,
		sphincs:       sp,
		skSeedStf:     skStf,
		skSeedStl:     skStl,
		skPRFStl:      skPRFStl,
	}

	if io != nil {
		if err := k.loadOrInit(); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// combinedRoot returns H(stateful_root || stateless_root) — the second
// half of the public key. Named "combinedRoot" to disambiguate from
// the full public key returned by buildPublicKey.
func combinedRoot(stfRoot, stlRoot []byte) []byte {
	buf := make([]byte, 0, len(stfRoot)+len(stlRoot))
	buf = append(buf, stfRoot...)
	buf = append(buf, stlRoot...)
	h := Hash256(buf)
	return h[:shrincsN]
}

// buildPublicKey returns [PKSeed (16 B) || combinedRoot (16 B)] — the
// 32-byte SHRINCS pubkey that goes into P2MR leaves.
func buildPublicKey(pkSeed, stfRoot, stlRoot []byte) []byte {
	out := make([]byte, shrincsPubKeySize)
	copy(out[:shrincsN], pkSeed)
	copy(out[shrincsN:], combinedRoot(stfRoot, stlRoot))
	return out
}

// splitPublicKey returns (pkSeed, combinedRoot) parsed from a 32-byte
// SHRINCS pubkey. Returns false if the pubkey is the wrong length.
func splitPublicKey(pk []byte) (pkSeed, root []byte, ok bool) {
	if len(pk) != shrincsPubKeySize {
		return nil, nil, false
	}
	return pk[:shrincsN], pk[shrincsN:], true
}

// --- State file -----------------------------------------------------------

func (k *ShrincsKey) loadOrInit() error {
	body, err := k.io.Read()
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			// Fresh key: persist counter=0 with the cached roots.
			return k.persistState(0, shrincsStatusOK)
		}
		return ErrStateCorrupted
	}
	if len(body) != shrincsStateFileLen {
		return ErrStateCorrupted
	}
	k.Counter = binary.BigEndian.Uint64(body[:8])
	// Reject mismatched cached roots — signals a seed mismatch or a
	// corrupted file. (Status byte is informational for now; LOST state
	// could later trigger stateless-only mode.)
	statedStf := body[9 : 9+shrincsN]
	statedStl := body[9+shrincsN : 9+2*shrincsN]
	if !equalBytes(statedStf, k.statefulRoot) || !equalBytes(statedStl, k.statelessRoot) {
		return ErrStateCorrupted
	}
	return nil
}

func (k *ShrincsKey) persistState(counter uint64, status byte) error {
	if k.io == nil {
		return nil
	}
	buf := make([]byte, shrincsStateFileLen)
	binary.BigEndian.PutUint64(buf[:8], counter)
	buf[8] = status
	copy(buf[9:9+shrincsN], k.statefulRoot)
	copy(buf[9+shrincsN:9+2*shrincsN], k.statelessRoot)
	return k.io.Write(buf)
}

// --- Slot accounting ------------------------------------------------------

// NumSlots returns the total number of UXMSS leaves = 1 << TreeHeight.
func (k *ShrincsKey) NumSlots() uint64 { return uint64(1) << k.TreeHeight }

// MaxCounter returns the last usable UXMSS leaf index.
func (k *ShrincsKey) MaxCounter() uint64 {
	n := k.NumSlots()
	if n == 0 {
		return 0
	}
	return n - 1
}

// SlotHealth returns (Counter / NumSlots) — 0 for a fresh key, 1 when
// exhausted. Wallet layer uses this to trigger silent auto-rotation.
func (k *ShrincsKey) SlotHealth() float64 {
	n := k.NumSlots()
	if n == 0 {
		return 1.0
	}
	return float64(k.Counter) / float64(n)
}

// --- Signing --------------------------------------------------------------

// Sign produces a ShrincsSig for msg. The stateful path is tried first;
// if slots are exhausted the signer silently falls back to the
// stateless SPHINCS+ path. ctx is checked once after the mutex is
// acquired and again before persist; the stateful UXMSS / stateless
// SPHINCS+ inner sign is bounded and uncancellable past that point.
// Persistence order (stateful path):
//
//  1. reload state from disk   (catches concurrent writers / crashes)
//  2. bump counter on disk     (persist-before-sign)
//  3. compute signature        (safe: if we crash here, the slot is
//     already "used" on disk and will not be
//     reused — the worst case is one wasted
//     slot, never a reused slot)
func (k *ShrincsKey) Sign(ctx context.Context, msg []byte) (*ShrincsSig, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.io != nil {
		if err := k.reloadCounter(); err != nil {
			return nil, err
		}
	}

	// Paper §B.3 rule: emit stateful only when its body will be strictly
	// smaller than the stateless body. Otherwise fall back to stateless
	// even if UXMSS slots remain — this keeps wire sizes range-disjoint
	// so the verifier can dispatch on length alone (no tag byte).
	if k.Counter < k.NumSlots() && k.statefulBodyLen(k.Counter) < k.statelessBodyLen() {
		return k.signStateful(msg)
	}
	return k.signStateless(msg)
}

// statefulBodyLen returns the SphincsIG size of a stateful sig at leaf q.
// = WOTS+C sig (292) + UXMSS auth path (AuthPathLen(q)·N) + sibling (N).
func (k *ShrincsKey) statefulBodyLen(q uint64) int {
	return k.uxmss.SigSize(int(q)) + shrincsN
}

// statelessBodyLen returns the SphincsIG size of a fallback sig.
// = SPHINCS+ sig size + active pk (N) + sibling pk (N).
func (k *ShrincsKey) statelessBodyLen() int {
	return k.sphincs.SigSize() + 2*shrincsN
}

func (k *ShrincsKey) reloadCounter() error {
	body, err := k.io.Read()
	if err != nil {
		return ErrStateCorrupted
	}
	if len(body) != shrincsStateFileLen {
		return ErrStateCorrupted
	}
	k.Counter = binary.BigEndian.Uint64(body[:8])
	return nil
}

// signStateful signs msg at UXMSS leaf q = k.Counter, persisting q+1
// BEFORE computing the signature.
func (k *ShrincsKey) signStateful(msg []byte) (*ShrincsSig, error) {
	q := k.Counter
	// Persist the next-counter first. Any crash between here and the
	// signature result wastes one slot but never reuses.
	if err := k.persistState(q+1, shrincsStatusOK); err != nil {
		return nil, fmt.Errorf("shrincs persist: %w", err)
	}
	k.Counter = q + 1

	// UXMSS WOTS+C signs an M-byte payload (9 B at the paper params);
	// hash caller's msg down to match. SHA-256 truncation (TCR at the
	// needed width) since `msg` is already a domain-separated sighash
	// digest.
	digest := sigHashN(msg, k.uxmss.WOTS.M)
	var base hashsig.ADRS
	base.SetLayer(0)
	base.SetTree(0)
	uxsig, err := k.uxmss.Sign(k.hp, k.skSeedStf, digest, int(q), base)
	if err != nil {
		return nil, fmt.Errorf("shrincs uxmss sign: %w", err)
	}

	// Wire: uxmss_sig || pk_stateless_sibling. No tag / tree_height / q
	// on the wire — verifier dispatches by length and derives q from
	// the UXMSS auth-path size (paper §B.3 framing).
	out := make([]byte, 0, len(uxsig)+shrincsN)
	out = append(out, uxsig...)
	out = append(out, k.statelessRoot...)

	return &ShrincsSig{Counter: q, SphincsIG: out}, nil
}

// signStateless signs msg via the fallback SPHINCS+ instance. No
// counter is consumed — SPHINCS+ is stateless. Counter is set to
// shrincsStatelessCounter (MaxUint64) so IsStateful() and the outer
// frame can distinguish the path without a tag byte.
func (k *ShrincsKey) signStateless(msg []byte) (*ShrincsSig, error) {
	// opt left empty; PRFmsg counter grinding happens inside sphincs.Sign.
	spsig, err := k.sphincs.Sign(k.hp, k.skSeedStl, k.skPRFStl, nil, msg, k.statelessRoot)
	if err != nil {
		return nil, ErrCounterExhausted
	}
	out := make([]byte, 0, len(spsig)+2*shrincsN)
	out = append(out, spsig...)
	out = append(out, k.statelessRoot...)
	out = append(out, k.statefulRoot...)

	return &ShrincsSig{Counter: shrincsStatelessCounter, SphincsIG: out}, nil
}

// --- Verification ---------------------------------------------------------

// VerifyShrincs verifies a ShrincsSig over msg under the 32-byte
// pubKey = (PKSeed || H(pk_stateful || pk_stateless)). Uses paper
// SPHINCS+ parameters — this is the consensus-layer entry point so the
// fallback geometry is fixed across all nodes.
func VerifyShrincs(pubKey []byte, msg []byte, sig *ShrincsSig) bool {
	return verifyShrincsWithParams(pubKey, msg, sig, shrincsPaperFallbackSPHINCS())
}

// verifyShrincsWithParams is the workhorse verifier; `sp` describes the
// fallback SPHINCS+ geometry. Tests pass demo params matching their
// demo-keygen; production goes through VerifyShrincs.
//
// Dispatch rule: the signer enforces paper §B.3's `min(stateful, sl)`
// so stateful sigs are always strictly smaller than the fixed stateless
// body size. len(body) therefore uniquely identifies the path.
func verifyShrincsWithParams(pubKey []byte, msg []byte, sig *ShrincsSig, sp hashsig.SPHINCSParams) bool {
	if sig == nil {
		return false
	}
	pkSeed, root, ok := splitPublicKey(pubKey)
	if !ok {
		return false
	}
	hp := &hashsig.Params{N: shrincsN, PKSeed: pkSeed}
	body := sig.SphincsIG
	statelessLen := sp.SigSize() + 2*shrincsN
	switch {
	case len(body) == statelessLen:
		return verifyStateless(hp, root, msg, body, sp)
	case len(body) < statelessLen:
		return verifyStateful(hp, root, msg, body)
	default:
		// Oversized body: the paper's min-rule forbids stateful sigs
		// this large, and stateless is a fixed size — reject.
		return false
	}
}

// verifyStateful parses (uxmss_sig || pk_stateless_sibling), derives q
// from the UXMSS auth-path length, and recomputes the candidate combined
// root to compare against `root`.
func verifyStateful(hp *hashsig.Params, root []byte, msg, body []byte) bool {
	wp := shrincsWOTSPlusC()
	wotsLen := wp.SigSize() // 292 B at paper params
	// Minimum stateful body: WOTS+C sig + 1 auth node (q=0) + sibling.
	if len(body) < wotsLen+2*shrincsN {
		return false
	}
	uxsig := body[:len(body)-shrincsN]
	sibling := body[len(body)-shrincsN:]

	// Derive q from |auth path|. Auth path length (bytes) = |uxsig| − |WOTS+C|.
	authBytes := len(uxsig) - wotsLen
	if authBytes <= 0 || authBytes%shrincsN != 0 {
		return false
	}
	authLen := authBytes / shrincsN
	// Our UXMSS layout has AuthPathLen(q) = q+1 for q < NumLeaves-2, and
	// = NumLeaves-1 at the two top leaves. The paper's min-rule caps q
	// well below NumLeaves-2, so `authLen = q + 1` holds unambiguously.
	q := authLen - 1

	// NumLeaves is fixed consensus-wide — spine-hash ADRS depend on it,
	// so the verifier MUST use the same value as the signer.
	uxmss := hashsig.UXMSSParams{
		NumLeaves: ShrincsNumLeaves,
		WOTS:      wp,
	}
	if q >= uxmss.NumLeaves-2 {
		// Paper's min-rule should have prevented this; reject defensively.
		return false
	}
	if len(uxsig) != uxmss.SigSize(q) {
		return false
	}
	digest := sigHashN(msg, uxmss.WOTS.M)
	var base hashsig.ADRS
	base.SetLayer(0)
	base.SetTree(0)
	cand, err := uxmss.PKFromSig(hp, digest, q, uxsig, base)
	if err != nil {
		return false
	}
	return equalBytes(root, combinedRoot(cand, sibling))
}

// verifyStateless parses (sphincs_sig || pk_stateless_active ||
// pk_stateful_sibling) and verifies the SPHINCS+ body under the active
// pk, then confirms the combined root binding. Length is guaranteed by
// the dispatcher to equal sp.SigSize() + 2·N.
func verifyStateless(hp *hashsig.Params, root []byte, msg, body []byte, sp hashsig.SPHINCSParams) bool {
	if len(body) != sp.SigSize()+2*shrincsN {
		return false
	}
	sibling := body[len(body)-shrincsN:]
	active := body[len(body)-2*shrincsN : len(body)-shrincsN]
	spsig := body[:len(body)-2*shrincsN]

	if !equalBytes(root, combinedRoot(sibling, active)) {
		return false
	}
	return sp.Verify(hp, msg, spsig, active)
}

// --- Wire serialization helpers (back-compat with callers) ----------------

// SerializeShrincsSig: counter_be || sig_len_be || sig_bytes. Legacy
// framing preserved for existing call sites (txn/script.go, wallet).
func SerializeShrincsSig(s *ShrincsSig) []byte {
	buf := make([]byte, 12+len(s.SphincsIG))
	binary.BigEndian.PutUint64(buf[:8], s.Counter)
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(s.SphincsIG)))
	copy(buf[12:], s.SphincsIG)
	return buf
}

// DeserializeShrincsSig parses SerializeShrincsSig output.
func DeserializeShrincsSig(b []byte) (*ShrincsSig, error) {
	if len(b) < 12 {
		return nil, errors.New("shrincs sig: too short")
	}
	counter := binary.BigEndian.Uint64(b[:8])
	n := binary.BigEndian.Uint32(b[8:12])
	if uint32(len(b)-12) < n {
		return nil, errors.New("shrincs sig: truncated")
	}
	sig := make([]byte, n)
	copy(sig, b[12:12+n])
	return &ShrincsSig{Counter: counter, SphincsIG: sig}, nil
}

// --- small helpers --------------------------------------------------------

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
