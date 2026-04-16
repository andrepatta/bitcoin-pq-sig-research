package mempool

import (
	"errors"
	"fmt"
	"math"
	"sync"
)

// BlockPolicyEstimator is a Bitcoin Core CBlockPolicyEstimator port,
// rewritten in Go. Same algorithm shape; same three-horizon design;
// same EstimateMedianVal bucket walk; sat/byte units instead of
// sat/kvB (no segwit, no vbytes).
//
// The estimator observes:
//   - tx mempool entries (ProcessTransaction)
//   - block confirmations (ProcessBlock)
//   - mempool removals that aren't from a block (RemoveTx)
//   - reorg disconnects (ProcessDisconnect)
//
// And answers EstimateFee(target, mode) → recommended sat/byte feerate.
//
// Faithfulness vs. simplification:
//   - Three TxConfirmStats horizons, mode-aware query: faithful.
//   - Bucket geometry, decay constants, sufficient-txs thresholds:
//     copied from Core.
//   - Persistence: a hand-rolled binary format mirroring
//     fee_estimates.dat's structure (no Bitcoin compat).
//   - Reorgs: faithful behavior — forget tracked txs from
//     disconnected blocks, don't try to "undo" decayed averages
//     (Core doesn't either; one block of skew is in the noise).

// Bucket geometry. Mirrors Bitcoin's MIN/MAX_BUCKET_FEERATE / FEE_SPACING
// with units relabeled from sat/kvB to sat/B (factor 1000 absorbed).
const (
	minBucketFeerate = 0.001 // sat/B floor (= 1 sat/kvB in Core; lets sub-1-sat/B txs bucket)
	maxBucketFeerate = 1e4   // sat/B ceiling
	feeSpacing       = 1.05
	infFeerate       = math.MaxFloat64
)

// Three horizons. Same numbers as Core's policy/fees.h.
const (
	shortBlockPeriods = 12
	shortScale        = 1
	shortDecay        = 0.962

	medBlockPeriods = 24
	medScale        = 2
	medDecay        = 0.9952

	longBlockPeriods = 42
	longScale        = 24
	longDecay        = 0.99931
)

// Query thresholds. Per Core's policy/fees.h.
const (
	sufficientFeeTxs = 1.0  // min decayed txCt before a bucket-range can answer
	successPctEcon   = 0.60 // ECONOMICAL: 60% in-target (Core's HALF_SUCCESS_PCT)
	successPctNormal = 0.85 // normal: 85% (SUCCESS_PCT)
	successPctConsv  = 0.95 // CONSERVATIVE: 95% (DOUBLE_SUCCESS_PCT)
)

// EstimateMode picks the responsiveness/safety trade-off.
type EstimateMode int

const (
	// ModeUnset: pick economical for short targets, conservative else.
	ModeUnset EstimateMode = iota
	// ModeEconomical: short horizon, accepts more variance.
	ModeEconomical
	// ModeConservative: max across all eligible horizons.
	ModeConservative
)

func (m EstimateMode) String() string {
	switch m {
	case ModeEconomical:
		return "economical"
	case ModeConservative:
		return "conservative"
	default:
		return "unset"
	}
}

// ParseEstimateMode is the inverse of String for CLI/RPC parsing.
func ParseEstimateMode(s string) (EstimateMode, error) {
	switch s {
	case "", "unset":
		return ModeUnset, nil
	case "economical":
		return ModeEconomical, nil
	case "conservative":
		return ModeConservative, nil
	default:
		return ModeUnset, fmt.Errorf("estimator: unknown mode %q", s)
	}
}

// FeeEstimate is the result of one query.
type FeeEstimate struct {
	// SatPerByte is the recommended feerate. Zero = no estimate
	// available (caller should fall back to MinRelayFeeRate).
	SatPerByte float64
	// Blocks is the target the estimate refers to (echoed for caller
	// convenience).
	Blocks uint32
	// Mode is the actual mode used (UNSET resolves to ECONOMICAL or
	// CONSERVATIVE based on target).
	Mode EstimateMode
}

// memPoolTrack is the per-tx record kept while in mempool.
type memPoolTrack struct {
	height uint32 // chain height when first observed
	bucket int    // bucket index in our shared bucket grid
}

// BlockPolicyEstimator is the public type. Thread-safe; one estimator
// per node.
type BlockPolicyEstimator struct {
	mu sync.Mutex

	feeStats   *txConfirmStats // long horizon
	medStats   *txConfirmStats
	shortStats *txConfirmStats

	bestSeenHeight uint32
	firstObserved  uint32 // for warm-up reporting

	// trackedTxs: only contains txs we've seen via ProcessTransaction
	// (and that haven't been confirmed/removed). Confirmation events
	// for txs not in this map are silently ignored — without arrival
	// time we can't compute blocks-to-confirm.
	trackedTxs map[[32]byte]memPoolTrack

	// Shared bucket grid across all three horizons.
	buckets   []float64
	bucketMap []float64 // sorted thresholds for binary search
}

// NewBlockPolicyEstimator constructs a fresh estimator with empty stats.
func NewBlockPolicyEstimator() *BlockPolicyEstimator {
	buckets := buildBuckets()
	bucketMap := append([]float64(nil), buckets...) // identical, kept for clarity
	return &BlockPolicyEstimator{
		feeStats:   newTxConfirmStats(buckets, longBlockPeriods, longDecay, longScale),
		medStats:   newTxConfirmStats(buckets, medBlockPeriods, medDecay, medScale),
		shortStats: newTxConfirmStats(buckets, shortBlockPeriods, shortDecay, shortScale),
		trackedTxs: map[[32]byte]memPoolTrack{},
		buckets:    buckets,
		bucketMap:  bucketMap,
	}
}

// buildBuckets returns geometric upper-bound feerates from min..max,
// then an INF cap for anything paying above max.
func buildBuckets() []float64 {
	var out []float64
	for r := minBucketFeerate; r < maxBucketFeerate; r *= feeSpacing {
		out = append(out, r)
	}
	out = append(out, maxBucketFeerate, infFeerate)
	return out
}

// findBucket maps a feerate to its bucket index (the lowest bucket with
// upper bound >= feerate). Linear scan — bucket count is ~190, fine.
func (e *BlockPolicyEstimator) findBucket(feerate float64) int {
	for i, b := range e.buckets {
		if feerate <= b {
			return i
		}
	}
	return len(e.buckets) - 1
}

// SetBestHeight advances bestSeenHeight to h, handling the three sync
// cases a node encounters:
//
//  1. Fresh-start (bestSeenHeight == 0): just set both anchors.
//     Confirmations processed from here on.
//  2. Post-load resume (bestSeenHeight > 0 and h == bestSeenHeight):
//     no-op; but caller typically also ran clearLive via Load so live
//     counters are already reset.
//  3. Post-load sync gap (bestSeenHeight > 0 and h > bestSeenHeight+1):
//     many blocks were processed while we were offline. Apply a
//     cumulative decay so the historical averages age correctly, and
//     clear any orphaned live counters (they reference txs that are
//     no longer tracked since trackedTxs was reset on Load).
//
// Heights moving backward are ignored — reorgs call ProcessDisconnect
// for that.
func (e *BlockPolicyEstimator) SetBestHeight(h uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if h <= e.bestSeenHeight {
		return
	}
	gap := int(h - e.bestSeenHeight)
	// Gap of >1 on a non-fresh estimator means we're resuming across
	// a sync gap. Catch-up decay keeps the averages consistent with
	// the (decayed) block-time axis they represent.
	if e.bestSeenHeight > 0 && gap > 1 {
		// Apply (gap-1) extra decays — the single-block decay for
		// incoming ProcessBlock calls will handle the remaining step,
		// or if there are no more blocks until queries start, we've
		// advanced at least approximately.
		for i := 0; i < gap-1; i++ {
			e.shortStats.updateMovingAverages()
			e.medStats.updateMovingAverages()
			e.feeStats.updateMovingAverages()
		}
		e.shortStats.clearLive()
		e.medStats.clearLive()
		e.feeStats.clearLive()
	}
	e.bestSeenHeight = h
	if e.firstObserved == 0 {
		e.firstObserved = h
	}
}

// ProcessTransaction records that a tx with the given fee+size entered
// the mempool at validHeight. Caller passes the *current chain tip*
// height as validHeight. Coinbase / zero-fee txs are silently ignored
// (no signal to add).
func (e *BlockPolicyEstimator) ProcessTransaction(txid [32]byte, fee uint64, size int, validHeight uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if size <= 0 || fee == 0 {
		return
	}
	if _, dup := e.trackedTxs[txid]; dup {
		return
	}
	// Don't track txs from before our first observed block — we don't
	// know how long they've been waiting.
	if e.bestSeenHeight == 0 || validHeight < e.firstObserved {
		return
	}

	feerate := float64(fee) / float64(size)
	bucket := e.findBucket(feerate)

	e.trackedTxs[txid] = memPoolTrack{height: validHeight, bucket: bucket}
	e.shortStats.newTx(validHeight, bucket)
	e.medStats.newTx(validHeight, bucket)
	e.feeStats.newTx(validHeight, bucket)
}

// RemoveTx is called when a tx leaves the mempool *not* because of a
// block confirmation (RBF eviction, age, capacity, manual). Following
// Core's removeTx(inBlock=false): forgets tracking and, if the tx had
// been waiting >= scale blocks, marks it as a failure for the
// corresponding targets in each stats horizon.
func (e *BlockPolicyEstimator) RemoveTx(txid [32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.removeTxLocked(txid, false)
}

func (e *BlockPolicyEstimator) removeTxLocked(txid [32]byte, inBlock bool) (memPoolTrack, bool) {
	t, ok := e.trackedTxs[txid]
	if !ok {
		return t, false
	}
	delete(e.trackedTxs, txid)
	e.shortStats.removeTx(t.height, e.bestSeenHeight, t.bucket, inBlock)
	e.medStats.removeTx(t.height, e.bestSeenHeight, t.bucket, inBlock)
	e.feeStats.removeTx(t.height, e.bestSeenHeight, t.bucket, inBlock)
	return t, true
}

// ProcessBlock is called when a new block at `height` connects.
// `confirmedTxids` is the list of NON-COINBASE txids in the block.
// Untracked txids (not seen via ProcessTransaction) are silently
// ignored — without arrival time we can't measure blocks-to-confirm.
func (e *BlockPolicyEstimator) ProcessBlock(height uint32, confirmedTxids [][32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Out-of-order or duplicate block — don't double-process.
	// (Reorgs should call ProcessDisconnect first.)
	if height <= e.bestSeenHeight && e.bestSeenHeight != 0 {
		return
	}
	e.bestSeenHeight = height
	if e.firstObserved == 0 {
		e.firstObserved = height
	}

	// 1. Decay all averages by one block.
	e.shortStats.updateMovingAverages()
	e.medStats.updateMovingAverages()
	e.feeStats.updateMovingAverages()

	// 2. Slide the unconfirmed window: clear the new "current" slot
	//    (its previous contents — txs that have aged through the full
	//    window without confirming — migrate to oldUnconfTxs).
	e.shortStats.clearCurrent(height)
	e.medStats.clearCurrent(height)
	e.feeStats.clearCurrent(height)

	// 3. Process each confirmation. removeTxLocked handles the
	//    unconfTxs/oldUnconfTxs decrements; we then call
	//    recordConfirmedTx on each horizon.
	for _, id := range confirmedTxids {
		t, ok := e.removeTxLocked(id, true)
		if !ok {
			continue
		}
		blocksToConf := int(height) - int(t.height)
		if blocksToConf < 1 {
			// Tx was in mempool at the same height it confirmed in;
			// treat as the tightest bucket (1 block to confirm).
			blocksToConf = 1
		}
		e.shortStats.recordConfirmedTx(blocksToConf, t.bucket)
		e.medStats.recordConfirmedTx(blocksToConf, t.bucket)
		e.feeStats.recordConfirmedTx(blocksToConf, t.bucket)
	}
}

// ProcessDisconnect handles a reorg disconnect for a single block.
// Following Core: forget tracking for any txs in the disconnected
// block (they'll be re-tracked if they re-enter mempool); roll back
// bestSeenHeight; do NOT attempt to "undo" decayed averages — that
// would require a second moving-state and create temporal
// inconsistency. The cost is one block's worth of skew per disconnect,
// which is negligible against the decay window.
func (e *BlockPolicyEstimator) ProcessDisconnect(height uint32, txids [][32]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if height > e.bestSeenHeight {
		return
	}
	for _, id := range txids {
		// Just drop tracking. They'll be re-added by Mempool if the
		// chain layer puts them back into the pool, and ProcessBlock
		// will see them under the new chain.
		delete(e.trackedTxs, id)
	}
	if height == e.bestSeenHeight && height > 0 {
		e.bestSeenHeight = height - 1
	}
}

// EstimateFee returns the recommended feerate for the target.
// Conservative mode walks all eligible horizons and returns the max;
// economical uses only the short horizon.
func (e *BlockPolicyEstimator) EstimateFee(target uint32, mode EstimateMode) FeeEstimate {
	e.mu.Lock()
	defer e.mu.Unlock()

	resolved := mode
	if mode == ModeUnset {
		// Core's heuristic: small targets → conservative (don't underpay
		// if user wants fast confirm); long targets → economical (let
		// the long horizon's statistics smooth it out).
		if target <= shortBlockPeriods {
			resolved = ModeConservative
		} else {
			resolved = ModeEconomical
		}
	}

	switch resolved {
	case ModeEconomical:
		// Short horizon, lower threshold (matches Core's
		// estimateRawFee path used inside EstimateSmartFee
		// "economical").
		fr := e.shortStats.estimateMedianVal(int(target), sufficientFeeTxs, successPctEcon, e.bestSeenHeight)
		return FeeEstimate{SatPerByte: fr, Blocks: target, Mode: ModeEconomical}
	case ModeConservative:
		// Walk all horizons that can cover the target; return the
		// max successful estimate (safer).
		var best float64
		if int(target) <= e.shortStats.totalBlocks() {
			if v := e.shortStats.estimateMedianVal(int(target), sufficientFeeTxs, successPctConsv, e.bestSeenHeight); v > best {
				best = v
			}
		}
		if int(target) <= e.medStats.totalBlocks() {
			if v := e.medStats.estimateMedianVal(int(target), sufficientFeeTxs, successPctNormal, e.bestSeenHeight); v > best {
				best = v
			}
		}
		if int(target) <= e.feeStats.totalBlocks() {
			if v := e.feeStats.estimateMedianVal(int(target), sufficientFeeTxs, successPctNormal, e.bestSeenHeight); v > best {
				best = v
			}
		}
		return FeeEstimate{SatPerByte: best, Blocks: target, Mode: ModeConservative}
	}
	return FeeEstimate{Blocks: target, Mode: resolved}
}

// Stats returns observability counters (no lock — read-only from the
// caller's view; small race in counter values is acceptable).
func (e *BlockPolicyEstimator) Stats() (tracked int, bestHeight uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.trackedTxs), e.bestSeenHeight
}

// ---------------------------------------------------------------------
// txConfirmStats — one per horizon
// ---------------------------------------------------------------------

// txConfirmStats holds per-bucket exponentially-decayed counts of
// (txs observed, confirmed, failed) plus a sliding-window count of
// currently-pending unconfirmed txs by age.
type txConfirmStats struct {
	buckets []float64

	maxPeriods int     // first-dim length of conf/failAvg
	scale      int     // blocks per period
	decay      float64 // per-block multiplier on all averages

	// confAvg[i][b]: decayed count of txs in bucket b that confirmed
	// within (i+1)*scale blocks. Cumulative — confAvg[i] >= confAvg[i-1].
	confAvg [][]float64
	// failAvg[i][b]: decayed count of txs in bucket b that took
	// LONGER than (i+1)*scale blocks to confirm (or were evicted
	// after that long).
	failAvg [][]float64
	// txCtAvg[b]: total observation count (confirmed + aged-out).
	txCtAvg []float64

	// unconfTxs[blockHeight % len][bucket]: live unconfirmed counts.
	// Indexed by entryHeight % windowLen so a fixed ring works without
	// per-block array shifts.
	unconfTxs    [][]int
	oldUnconfTxs []int // txs that aged past the tracking window
}

func newTxConfirmStats(buckets []float64, maxPeriods int, decay float64, scale int) *txConfirmStats {
	nb := len(buckets)
	// Window length in actual blocks = maxPeriods * scale. unconfTxs
	// is indexed by entryHeight%window, so it has windowLen rows.
	windowLen := maxPeriods * scale
	conf := make([][]float64, maxPeriods)
	fail := make([][]float64, maxPeriods)
	for i := range conf {
		conf[i] = make([]float64, nb)
		fail[i] = make([]float64, nb)
	}
	un := make([][]int, windowLen)
	for i := range un {
		un[i] = make([]int, nb)
	}
	return &txConfirmStats{
		buckets:      buckets,
		maxPeriods:   maxPeriods,
		scale:        scale,
		decay:        decay,
		confAvg:      conf,
		failAvg:      fail,
		txCtAvg:      make([]float64, nb),
		unconfTxs:    un,
		oldUnconfTxs: make([]int, nb),
	}
}

// totalBlocks returns the maximum blocks-to-confirm this horizon
// tracks (used to decide whether a target is in-range).
func (s *txConfirmStats) totalBlocks() int { return s.maxPeriods * s.scale }

// updateMovingAverages decays all stored averages by `decay`. Called
// once per new block (before recording confirmations).
func (s *txConfirmStats) updateMovingAverages() {
	for i := range s.confAvg {
		for b := range s.confAvg[i] {
			s.confAvg[i][b] *= s.decay
		}
	}
	for i := range s.failAvg {
		for b := range s.failAvg[i] {
			s.failAvg[i][b] *= s.decay
		}
	}
	for b := range s.txCtAvg {
		s.txCtAvg[b] *= s.decay
	}
}

// clearLive zeroes all live-tracking counters (unconfTxs,
// oldUnconfTxs). Called on Load and on sync-gap catch-up so stale
// counters from before a reload/gap don't pollute query "extra fails".
func (s *txConfirmStats) clearLive() {
	for i := range s.unconfTxs {
		for b := range s.unconfTxs[i] {
			s.unconfTxs[i][b] = 0
		}
	}
	for b := range s.oldUnconfTxs {
		s.oldUnconfTxs[b] = 0
	}
}

// clearCurrent slides the unconfirmed-window: anything currently in
// the slot for the new `height % windowLen` is migrated to
// oldUnconfTxs (it's been waiting `windowLen` blocks already), then
// the slot is zeroed for new arrivals.
func (s *txConfirmStats) clearCurrent(height uint32) {
	if len(s.unconfTxs) == 0 {
		return
	}
	idx := int(height) % len(s.unconfTxs)
	for b := range s.unconfTxs[idx] {
		s.oldUnconfTxs[b] += s.unconfTxs[idx][b]
		s.unconfTxs[idx][b] = 0
	}
}

// newTx records an arriving unconfirmed tx in the ring slot for its
// arrival height.
func (s *txConfirmStats) newTx(height uint32, bucket int) {
	if len(s.unconfTxs) == 0 || bucket < 0 || bucket >= len(s.buckets) {
		return
	}
	idx := int(height) % len(s.unconfTxs)
	s.unconfTxs[idx][bucket]++
}

// removeTx decrements the appropriate live counter for a tx leaving
// the mempool. If inBlock is false AND the tx waited >= scale blocks,
// it's recorded as a failure for the corresponding targets (Core's
// removeTx behavior — txs evicted/aged out without confirming count
// against the buckets they would have been in).
func (s *txConfirmStats) removeTx(entryHeight, bestSeenHeight uint32, bucket int, inBlock bool) {
	if bucket < 0 || bucket >= len(s.buckets) {
		return
	}
	blocksAgo := int(bestSeenHeight) - int(entryHeight)
	if blocksAgo < 0 {
		blocksAgo = 0
	}
	if blocksAgo >= len(s.unconfTxs) {
		if s.oldUnconfTxs[bucket] > 0 {
			s.oldUnconfTxs[bucket]--
		}
	} else {
		idx := int(entryHeight) % len(s.unconfTxs)
		if s.unconfTxs[idx][bucket] > 0 {
			s.unconfTxs[idx][bucket]--
		}
	}
	if !inBlock && blocksAgo >= s.scale && s.scale > 0 {
		periodsAgo := blocksAgo / s.scale
		for i := 0; i < periodsAgo && i < s.maxPeriods; i++ {
			s.failAvg[i][bucket]++
		}
	}
}

// recordConfirmedTx records a successful confirmation of a tx that
// took blocksToConf blocks. Updates confAvg and txCtAvg for the
// appropriate bucket.
func (s *txConfirmStats) recordConfirmedTx(blocksToConf int, bucket int) {
	if blocksToConf < 1 || bucket < 0 || bucket >= len(s.buckets) {
		return
	}
	periodsToConf := (blocksToConf + s.scale - 1) / s.scale
	for i := periodsToConf - 1; i < s.maxPeriods; i++ {
		s.confAvg[i][bucket]++
	}
	s.txCtAvg[bucket]++
}

// estimateMedianVal is the bucket walk that answers a single query.
// Walks bucket indices from highest to lowest, accumulating until the
// running success rate dips below `successBreakPoint`. Returns the
// median of the lowest "passing" run of buckets.
//
// Faithful to Core's TxConfirmStats::EstimateMedianVal(). Returns 0
// when no answer is available (caller falls back to MinRelayFeeRate).
func (s *txConfirmStats) estimateMedianVal(confTarget int, sufficientTxVal, successBreakPoint float64, bestSeenHeight uint32) float64 {
	if confTarget < 1 {
		confTarget = 1
	}
	if confTarget > s.totalBlocks() {
		return 0
	}
	periodTarget := (confTarget + s.scale - 1) / s.scale
	if periodTarget < 1 || periodTarget > s.maxPeriods {
		return 0
	}

	// Skip the +Inf sentinel bucket — it's a catch-all for findBucket
	// (anything above maxBucketFeerate) and isn't a meaningful answer.
	// Walk from the highest *finite* bucket downward.
	maxBucket := len(s.buckets) - 2
	if maxBucket < 0 {
		return 0
	}
	curNearBucket := maxBucket
	bestNearBucket := maxBucket
	bestFarBucket := maxBucket
	foundAnswer := false

	var nConf, totalNum, failNum, extraNum float64
	curFarBucket := maxBucket

	// "Extra fails" = currently-pending txs that have already been
	// waiting >= confTarget blocks (so they're failing in real-time).
	// Indexed via the unconfTxs ring: the slot whose entryHeight is
	// `confTarget` blocks ago.
	extraSlot := -1
	if confTarget < len(s.unconfTxs) {
		extraSlot = (int(bestSeenHeight) - confTarget) % len(s.unconfTxs)
		if extraSlot < 0 {
			extraSlot += len(s.unconfTxs)
		}
	}

	for b := maxBucket; b >= 0; b-- {
		curFarBucket = b
		nConf += s.confAvg[periodTarget-1][b]
		totalNum += s.txCtAvg[b]
		failNum += s.failAvg[periodTarget-1][b]
		extraNum += float64(s.oldUnconfTxs[b])
		if extraSlot >= 0 {
			extraNum += float64(s.unconfTxs[extraSlot][b])
		}

		if totalNum >= sufficientTxVal {
			denom := nConf + failNum + extraNum
			if denom <= 0 {
				continue
			}
			curPct := nConf / denom
			if curPct < successBreakPoint {
				// Failure: fee too low at this accumulated range.
				// Stop — the answer (if any) is buckets above us.
				break
			}
			// Passing range — record and reset accumulators to look
			// for an even lower passing range further down.
			foundAnswer = true
			bestNearBucket = curNearBucket
			bestFarBucket = curFarBucket
			curNearBucket = b - 1
			nConf, totalNum, failNum, extraNum = 0, 0, 0, 0
		}
	}

	if !foundAnswer {
		return 0
	}
	// tx-weighted median across [bestFarBucket..bestNearBucket].
	// Walking straight arithmetic means between endpoints gives bad
	// answers when the range spans many empty buckets (e.g. a single
	// well-populated bucket next to a sparse high-fee tail).
	if bestFarBucket > bestNearBucket {
		bestFarBucket, bestNearBucket = bestNearBucket, bestFarBucket
	}
	if bestFarBucket < 0 {
		bestFarBucket = 0
	}
	if bestNearBucket >= len(s.buckets) {
		bestNearBucket = len(s.buckets) - 1
	}
	var rangeTotal float64
	for j := bestFarBucket; j <= bestNearBucket; j++ {
		rangeTotal += s.txCtAvg[j]
	}
	if rangeTotal <= 0 {
		// No mass in the range (all counts are from confAvg/failAvg
		// outside the target period). Fall back to the low end as a
		// safe lower-bound answer.
		v := s.buckets[bestFarBucket]
		if math.IsInf(v, 0) {
			return s.buckets[len(s.buckets)-2]
		}
		return v
	}
	medianTarget := rangeTotal / 2
	var running float64
	median := s.buckets[bestFarBucket]
	for j := bestFarBucket; j <= bestNearBucket; j++ {
		running += s.txCtAvg[j]
		if running >= medianTarget {
			median = s.buckets[j]
			break
		}
	}
	if math.IsInf(median, 0) {
		return s.buckets[len(s.buckets)-2]
	}
	return median
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

// ErrEstimateUnavailable indicates the estimator couldn't produce a
// recommendation for the given target. Callers fall back to
// MinRelayFeeRate.
var ErrEstimateUnavailable = errors.New("estimator: insufficient data for target")
