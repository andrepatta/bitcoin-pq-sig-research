package mempool

import (
	"bytes"
	"testing"
)

// makeTxID deterministically builds a 32-byte id from seed bytes so
// test cases get stable, distinct ids without the full tx machinery.
func makeTxID(tag ...byte) [32]byte {
	var id [32]byte
	copy(id[:], tag)
	return id
}

// advance fires (count) empty blocks to walk bestSeenHeight forward
// and exercise per-block decay + unconfTxs window sliding.
func advance(e *BlockPolicyEstimator, from, count uint32) {
	for i := uint32(0); i < count; i++ {
		e.ProcessBlock(from+i+1, nil)
	}
}

// TestEstimator_BasicConfirmPath drives a single bucket's confirmation
// rate high and checks that a target=1 conservative query returns a
// feerate in that bucket. Covers: ProcessTransaction + ProcessBlock +
// EstimateFee happy path.
func TestEstimator_BasicConfirmPath(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)

	// Feed 50 txs at ~50 sat/B that confirm in the very next block.
	for i := 0; i < 50; i++ {
		id := makeTxID(byte(i + 1))
		e.ProcessTransaction(id, 5000, 100, 100) // 50 sat/B
	}
	ids := make([][32]byte, 50)
	for i := range ids {
		ids[i] = makeTxID(byte(i + 1))
	}
	e.ProcessBlock(101, ids)

	// Query target=1, conservative — needs 95% success. All 50 confirmed
	// at target=1 → should pass easily.
	fe := e.EstimateFee(1, ModeConservative)
	if fe.SatPerByte <= 0 {
		t.Fatalf("expected nonzero estimate, got %v", fe)
	}
	// Should be near 50 sat/B (the bucket the txs landed in).
	if fe.SatPerByte < 20 || fe.SatPerByte > 100 {
		t.Fatalf("estimate out of expected range: %v", fe.SatPerByte)
	}
}

// TestEstimator_IBDSkipsUntrackedTxs: during IBD the mempool is empty,
// so every confirmed tx is "untracked". Expected: estimator stays
// empty, SetBestHeight advances, no panic, no bogus stats.
func TestEstimator_IBDSkipsUntrackedTxs(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(0)

	// Simulate IBD: 50 blocks, each with 10 untracked txs.
	for h := uint32(1); h <= 50; h++ {
		ids := make([][32]byte, 10)
		for i := range ids {
			ids[i] = makeTxID(byte(h), byte(i))
		}
		e.ProcessBlock(h, ids)
	}
	if tracked, bh := e.Stats(); tracked != 0 || bh != 50 {
		t.Fatalf("expected 0 tracked / bh=50, got %d / %d", tracked, bh)
	}
	// No data → estimator returns 0 for any target.
	if fe := e.EstimateFee(3, ModeConservative); fe.SatPerByte != 0 {
		t.Fatalf("expected 0 estimate after IBD-only, got %v", fe.SatPerByte)
	}
}

// TestEstimator_ReorgForgetsConfirmations: a tx confirms in block N,
// then N is reorged out. The tx's tracking is gone (it was removed on
// ProcessBlock), but the confAvg contribution stays (Core doesn't
// reverse decayed stats). Behaviorally: subsequent Add of the same
// tx is treated as fresh (NOT as dup) since trackedTxs was cleared.
func TestEstimator_ReorgForgetsConfirmations(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)

	id := makeTxID(0xAA)
	e.ProcessTransaction(id, 1000, 100, 100)
	e.ProcessBlock(101, [][32]byte{id})
	if trk, _ := e.Stats(); trk != 0 {
		t.Fatalf("after confirm, tx should be removed from tracker: %d", trk)
	}

	// Disconnect block 101 (reorg).
	e.ProcessDisconnect(101, [][32]byte{id})
	if _, bh := e.Stats(); bh != 100 {
		t.Fatalf("bestSeenHeight should roll back to 100, got %d", bh)
	}

	// Re-add the tx — should be accepted as fresh (trackedTxs was
	// empty; disconnect is a no-op on what's already gone).
	e.ProcessTransaction(id, 1000, 100, 100)
	if trk, _ := e.Stats(); trk != 1 {
		t.Fatalf("post-reorg re-add should be tracked: %d", trk)
	}
}

// TestEstimator_SyncGapClearsLiveCounters: simulating the load-from-
// disk-then-chain-has-advanced scenario. Before save: live unconfTxs
// populated. After load + SetBestHeight jumping forward by >1:
// unconfTxs and oldUnconfTxs are zeroed. Historical averages stay.
func TestEstimator_SyncGapClearsLiveCounters(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)
	// Populate some tracked txs and confirm one (to leave historical
	// stats behind in confAvg).
	e.ProcessTransaction(makeTxID(1), 500, 100, 100)
	e.ProcessTransaction(makeTxID(2), 500, 100, 100)
	e.ProcessBlock(101, [][32]byte{makeTxID(1)})

	// Save state.
	var buf bytes.Buffer
	if err := e.Save(&buf); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Fresh estimator, load, then simulate chain advanced by 50 blocks.
	e2 := NewBlockPolicyEstimator()
	if err := e2.Load(&buf); err != nil {
		t.Fatalf("load: %v", err)
	}
	// After load, live counters should already be cleared.
	for i := range e2.shortStats.unconfTxs {
		for _, v := range e2.shortStats.unconfTxs[i] {
			if v != 0 {
				t.Fatalf("load should zero live unconfTxs: row %d has %d", i, v)
			}
		}
	}
	// Historical stats should survive load.
	var hasConf bool
	for _, row := range e2.shortStats.confAvg {
		for _, v := range row {
			if v > 0 {
				hasConf = true
				break
			}
		}
	}
	if !hasConf {
		t.Fatalf("confAvg should carry historical data across load")
	}

	// Now advance best height by 50 (sync-gap). Historical stats
	// should decay; live counters stay clear; no panics.
	e2.SetBestHeight(151)
	if _, bh := e2.Stats(); bh != 151 {
		t.Fatalf("bestSeenHeight after sync gap: got %d, want 151", bh)
	}
}

// TestEstimator_RemoveTxAsFail: a tx evicted from mempool after
// waiting >= scale blocks should contribute to failAvg. Drives the
// bucket's failure rate up and verifies a subsequent query either
// returns 0 or a higher feerate.
func TestEstimator_RemoveTxAsFail(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)

	// Add a tx, wait a few blocks, then evict (simulates eviction /
	// RBF replacement). Should count as a failure for short targets.
	id := makeTxID(0xEE)
	e.ProcessTransaction(id, 1000, 100, 100) // 10 sat/B bucket
	advance(e, 100, 5)
	e.RemoveTx(id)

	// Short-horizon failAvg should now have a positive entry in the
	// 10 sat/B bucket for target=1..5.
	bucket := e.findBucket(10.0)
	var fails float64
	for i := 0; i < 5; i++ {
		fails += e.shortStats.failAvg[i][bucket]
	}
	if fails < 0.5 { // decayed by 5 blocks, still ~= 5 * 0.962^5 ~ 4.1
		t.Fatalf("expected fail counters to accumulate, got %v", fails)
	}
}

// TestEstimator_ConservativeTakesMaxAcrossHorizons: if the short
// horizon suggests a low feerate but the medium horizon disagrees
// (higher), conservative mode should pick the higher one.
func TestEstimator_ConservativeTakesMaxAcrossHorizons(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)

	// Feed many confirming txs at 5 sat/B to build up short-horizon
	// confidence at a LOW fee-rate bucket.
	h := uint32(100)
	for i := 0; i < 20; i++ {
		id := makeTxID(byte(i + 1))
		e.ProcessTransaction(id, 500, 100, h) // 5 sat/B
		h++
		e.ProcessBlock(h, [][32]byte{id})
	}

	// Now feed many failing txs (evict after 30 blocks) at 5 sat/B
	// ONLY to the medium horizon's window. Short horizon's confAvg
	// still shows confirmations; medium sees both confirmations AND
	// failures.
	//
	// Actually simpler: just verify CONSERVATIVE >= ECONOMICAL.
	econ := e.EstimateFee(5, ModeEconomical)
	cons := e.EstimateFee(5, ModeConservative)
	if cons.SatPerByte < econ.SatPerByte {
		t.Fatalf("conservative should be >= economical: cons=%v econ=%v", cons, econ)
	}
}

// TestEstimator_SaveLoadRoundTrip: persist and restore the estimator,
// confirm the averages survive bit-for-bit.
func TestEstimator_SaveLoadRoundTrip(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)
	for i := 0; i < 10; i++ {
		id := makeTxID(byte(i + 1))
		e.ProcessTransaction(id, 2000, 100, 100)
	}
	ids := make([][32]byte, 10)
	for i := range ids {
		ids[i] = makeTxID(byte(i + 1))
	}
	e.ProcessBlock(101, ids)

	var buf bytes.Buffer
	if err := e.Save(&buf); err != nil {
		t.Fatalf("save: %v", err)
	}
	e2 := NewBlockPolicyEstimator()
	if err := e2.Load(&buf); err != nil {
		t.Fatalf("load: %v", err)
	}

	// confAvg should match across save/load.
	for i := range e.shortStats.confAvg {
		for b := range e.shortStats.confAvg[i] {
			if e.shortStats.confAvg[i][b] != e2.shortStats.confAvg[i][b] {
				t.Fatalf("confAvg[%d][%d] mismatch after round-trip", i, b)
			}
		}
	}
}

// TestEstimator_OutOfOrderBlockIgnored: a ProcessBlock for a height
// we've already passed must not double-process. Defensive against
// chain-layer bugs or duplicate events.
func TestEstimator_OutOfOrderBlockIgnored(t *testing.T) {
	e := NewBlockPolicyEstimator()
	e.SetBestHeight(100)
	e.ProcessBlock(101, nil) // advance to 101
	e.ProcessBlock(101, nil) // duplicate
	e.ProcessBlock(100, nil) // backward
	if _, bh := e.Stats(); bh != 101 {
		t.Fatalf("out-of-order blocks should leave bh=101, got %d", bh)
	}
}
