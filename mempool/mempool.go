package mempool

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"qbitcoin/txn"
)

// Orphan-tx pool bounds. Same shape as the block-orphan pool: cap on
// entries plus a TTL to drop transactions whose missing parent never
// arrives.
const (
	MaxOrphanTxs = 200
	OrphanTxTTL  = 20 * time.Minute
)

// Mempool is an in-memory tx pool.
type Mempool struct {
	mu   sync.RWMutex
	txns map[[32]byte]entry
	// spent maps every UTXO an in-pool tx consumes to that tx's id, so
	// Add can reject a second tx that double-spends an input held by an
	// already-accepted mempool entry. Without this index two conflicting
	// txs can both pass per-tx validation (each is valid against the
	// chain UTXO set), then GetTemplate picks both and the resulting
	// block fails "double spend within block" at validation time.
	spent map[txn.UTXOKey][32]byte

	// estimator (optional) is the BlockPolicyEstimator wired in at
	// startup. nil = no estimation. We notify it on Add (newly-tracked
	// tx) and on RBF eviction (RemoveTx). Block-confirmation events
	// flow via NotifyBlockConnected — the chain layer drives those.
	estimator *BlockPolicyEstimator

	// Orphan pool: txs whose inputs reference UTXOs we don't yet know
	// about (typical pattern: child tx arrived before its parent on the
	// gossip network). Each orphan is indexed both by its txid and by
	// each missing parent txid for fast reconnect after a parent lands.
	orphanMu     sync.Mutex
	orphans      map[[32]byte]orphanTx
	orphansBySrc map[[32]byte][][32]byte // missingParentTxID -> list of orphan txids
}

// SetEstimator wires a BlockPolicyEstimator into the mempool. Call once
// at startup before any Add/Remove. Pass nil to disable.
func (m *Mempool) SetEstimator(e *BlockPolicyEstimator) {
	m.mu.Lock()
	m.estimator = e
	m.mu.Unlock()
}

// Estimator returns the configured estimator (may be nil).
func (m *Mempool) Estimator() *BlockPolicyEstimator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.estimator
}

type orphanTx struct {
	tx       txn.Transaction
	received time.Time
	missing  [][32]byte // parent txids this orphan depends on
}

type entry struct {
	tx   txn.Transaction
	fee  uint64
	size int
}

// New returns a new empty mempool.
func New() *Mempool {
	return &Mempool{
		txns:         map[[32]byte]entry{},
		spent:        map[txn.UTXOKey][32]byte{},
		orphans:      map[[32]byte]orphanTx{},
		orphansBySrc: map[[32]byte][][32]byte{},
	}
}

// Add validates and inserts a transaction. nextHeight + nextTime supply
// the IsFinal context (the chain expects this tx to land in a block at
// or after that height/time).
func (m *Mempool) Add(tx txn.Transaction, u txn.UTXOSet, nextHeight uint32, nextTime uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := tx.TxID()
	if _, ok := m.txns[id]; ok {
		return nil
	}
	if tx.IsCoinbase() {
		return errors.New("mempool: coinbase not allowed")
	}
	if !tx.IsFinal(nextHeight, nextTime) {
		return errors.New("mempool: non-final tx (locktime not yet reached)")
	}
	if cost := txn.SigOpCost(tx); cost > txn.MaxStandardTxSigOpsCost {
		return fmt.Errorf("mempool: tx sigop cost %d exceeds per-tx cap %d", cost, txn.MaxStandardTxSigOpsCost)
	}
	// Collect conflicting in-pool txs (any input clash). Empty = no
	// conflict; non-empty triggers BIP-125-style RBF evaluation later
	// once we know the new tx's fee and size.
	var conflictIDs [][32]byte
	conflictSeen := map[[32]byte]bool{}
	for _, in := range tx.Inputs {
		key := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
		if other, present := m.spent[key]; present && !conflictSeen[other] {
			conflictSeen[other] = true
			conflictIDs = append(conflictIDs, other)
		}
	}
	if len(conflictIDs) > MaxRBFConflicts {
		return fmt.Errorf("mempool: replacement would evict %d txs (cap %d)", len(conflictIDs), MaxRBFConflicts)
	}
	var inSum, outSum uint64
	var missingParents [][32]byte
	for _, in := range tx.Inputs {
		prev, err := u.Get(txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex})
		if err != nil {
			return err
		}
		if prev == nil {
			missingParents = append(missingParents, in.PrevTxID)
			continue
		}
		// Overflow guard before accumulating into uint64 sum.
		if prev.Value > txn.MaxMoney || inSum+prev.Value < inSum {
			return errors.New("mempool: input value overflows MaxMoney")
		}
		inSum += prev.Value
	}
	if len(missingParents) > 0 {
		// Buffer as orphan tx instead of rejecting — the parent may land
		// in a later block or via gossip.
		m.bufferOrphan(tx, missingParents)
		return errors.New("mempool: missing input (buffered as orphan)")
	}
	for _, o := range tx.Outputs {
		if o.Value > txn.MaxMoney || outSum+o.Value < outSum {
			return errors.New("mempool: output value overflows MaxMoney")
		}
		outSum += o.Value
	}
	if outSum > txn.MaxMoney {
		return errors.New("mempool: output sum exceeds MaxMoney")
	}
	if inSum < outSum {
		return errors.New("mempool: outputs exceed inputs")
	}
	size := len(tx.Serialize())
	fee := inSum - outSum

	// Min-relay gate (Bitcoin's -minrelaytxfee analog).
	if !meetsFeeRate(fee, size, MinRelayFeeRate) {
		return fmt.Errorf("mempool: fee %d below min-relay rate %d sat/B for size %d", fee, MinRelayFeeRate, size)
	}

	// BIP-125 RBF rules (subset, no descendant tracking — we don't yet
	// support in-mempool tx chains): a replacement must
	//   (rule 6) pay strictly higher fee-rate than every tx it evicts, AND
	//   (rule 4) pay at least incremental_rate * size more in absolute fee
	//            than the sum of evicted fees (so relay bandwidth is paid
	//            for end-to-end).
	if len(conflictIDs) > 0 {
		var conflictFeeSum uint64
		for _, cid := range conflictIDs {
			c, ok := m.txns[cid]
			if !ok {
				continue
			}
			if !feeRateGreater(fee, size, c.fee, c.size) {
				return fmt.Errorf("mempool: replacement fee-rate not strictly higher than conflict %x", cid)
			}
			conflictFeeSum += c.fee
		}
		minBump := IncrementalRelayFeeRate * uint64(size)
		if fee < conflictFeeSum+minBump {
			return fmt.Errorf("mempool: replacement fee %d < conflict-sum %d + bump %d", fee, conflictFeeSum, minBump)
		}
		// Accepted: evict conflicts in place. Inlined Remove logic so we
		// stay under m.mu and don't re-lock. Notify the estimator that
		// each conflict was evicted (inBlock=false).
		for _, cid := range conflictIDs {
			c, ok := m.txns[cid]
			if !ok {
				continue
			}
			for _, in := range c.tx.Inputs {
				key := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
				if owner, present := m.spent[key]; present && owner == cid {
					delete(m.spent, key)
				}
			}
			delete(m.txns, cid)
			if m.estimator != nil {
				m.estimator.RemoveTx(cid)
			}
		}
	}

	m.txns[id] = entry{tx: tx, fee: fee, size: size}
	for _, in := range tx.Inputs {
		m.spent[txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}] = id
	}
	// nextHeight is the height of the *next* block; the tx is observed
	// at the current tip = nextHeight - 1. The estimator measures
	// blocks-to-confirm as confirmedHeight - validHeight, so passing
	// the current tip yields the correct delta when this tx confirms
	// in any future block.
	if m.estimator != nil {
		validHeight := nextHeight
		if validHeight > 0 {
			validHeight--
		}
		m.estimator.ProcessTransaction(id, fee, size, validHeight)
	}
	// This tx may itself be a parent that orphans were waiting on.
	// Trigger orphan reconnection without holding m.mu (Add re-acquires).
	go m.ProcessOrphansForParent(id, u, nextHeight, nextTime)
	return nil
}

// Remove deletes the given txids from the pool, clearing their input
// reservations from the spent index, AND notifies the estimator that
// each tx was evicted (inBlock=false). For block-confirmation
// eviction, use RemoveForBlock — semantically distinct so the
// estimator can record confirmations vs. failures correctly.
func (m *Mempool) Remove(ids [][32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if !m.removeLocked(id) {
			continue
		}
		if m.estimator != nil {
			m.estimator.RemoveTx(id)
		}
	}
}

// RemoveForBlock removes confirmed txs and notifies the estimator that
// the given height connected with these txids. The estimator uses this
// to record blocks-to-confirm samples in confAvg/txCtAvg. Coinbase
// txids should be filtered out by the caller.
func (m *Mempool) RemoveForBlock(height uint32, ids [][32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		m.removeLocked(id)
	}
	if m.estimator != nil {
		// estimator.ProcessBlock owns its own lock; safe to call while
		// holding m.mu since the two locks are never acquired in the
		// reverse order anywhere.
		m.estimator.ProcessBlock(height, ids)
	}
}

// removeLocked is the inner per-id eviction. Returns true if the tx
// existed and was removed. Caller holds m.mu.
func (m *Mempool) removeLocked(id [32]byte) bool {
	e, ok := m.txns[id]
	if !ok {
		return false
	}
	for _, in := range e.tx.Inputs {
		key := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
		if owner, present := m.spent[key]; present && owner == id {
			delete(m.spent, key)
		}
	}
	delete(m.txns, id)
	return true
}

// Size reports the number of txns in the pool.
func (m *Mempool) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txns)
}

// Get returns a tx by id, or nil.
func (m *Mempool) Get(id [32]byte) *txn.Transaction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.txns[id]
	if !ok {
		return nil
	}
	cp := e.tx
	return &cp
}

// GetTemplate returns an ordered tx template under the given byte and
// sigop budgets, sorted by fee/byte desc. A tx is skipped (not aborted
// on) when it would blow either budget, so smaller / cheaper txs behind
// it still get their shot — matching Bitcoin Core's block-assembler.
//
// Thin wrapper over GetTemplateEntries for callers that only want the
// transactions (mining template assembly needs fee+size per tx for
// BIP-22 getblocktemplate output — those callers use GetTemplateEntries
// directly).
func (m *Mempool) GetTemplate(maxBytes, maxSigOps int) []txn.Transaction {
	entries := m.GetTemplateEntries(maxBytes, maxSigOps)
	out := make([]txn.Transaction, len(entries))
	for i, e := range entries {
		out[i] = e.Tx
	}
	return out
}

// GetTemplateEntries is GetTemplate with per-tx fee and size attached,
// for BIP-22 getblocktemplate which needs to report each transaction's
// fee and sigop cost to the external miner.
func (m *Mempool) GetTemplateEntries(maxBytes, maxSigOps int) []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	type rec struct {
		e     entry
		score float64
	}
	var arr []rec
	for _, e := range m.txns {
		sc := 0.0
		if e.size > 0 {
			sc = float64(e.fee) / float64(e.size)
		}
		arr = append(arr, rec{e, sc})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].score > arr[j].score })
	var out []Entry
	used := 0
	sigOps := 0
	for _, r := range arr {
		if used+r.e.size > maxBytes {
			continue
		}
		cost := txn.SigOpCost(r.e.tx)
		if sigOps+cost > maxSigOps {
			continue
		}
		out = append(out, Entry{Tx: r.e.tx, Fee: r.e.fee, Size: r.e.size})
		used += r.e.size
		sigOps += cost
	}
	return out
}

// All returns every tx currently in the pool.
func (m *Mempool) All() []txn.Transaction {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]txn.Transaction, 0, len(m.txns))
	for _, e := range m.txns {
		out = append(out, e.tx)
	}
	return out
}

// Entry is a mempool tx with its cached fee and size.
type Entry struct {
	Tx   txn.Transaction
	Fee  uint64
	Size int
}

// Entries returns every pool tx along with its fee and byte size, for
// RPC surfaces that want to show rich mempool state.
func (m *Mempool) Entries() []Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Entry, 0, len(m.txns))
	for _, e := range m.txns {
		out = append(out, Entry{Tx: e.tx, Fee: e.fee, Size: e.size})
	}
	return out
}

// --- orphan tx pool ---

// bufferOrphan stores tx for later reprocessing once one of its missing
// parents shows up. Caller-side semantics: the parent Add() call returns
// an error (so the gossip layer can log "rejected"), but the tx is
// retained.
func (m *Mempool) bufferOrphan(tx txn.Transaction, missing [][32]byte) {
	id := tx.TxID()
	m.orphanMu.Lock()
	defer m.orphanMu.Unlock()
	if _, ok := m.orphans[id]; ok {
		return
	}
	m.gcOrphansLocked()
	if len(m.orphans) >= MaxOrphanTxs {
		m.evictOldestOrphanLocked()
	}
	m.orphans[id] = orphanTx{tx: tx, received: time.Now(), missing: missing}
	for _, parent := range missing {
		m.orphansBySrc[parent] = append(m.orphansBySrc[parent], id)
	}
}

func (m *Mempool) gcOrphansLocked() {
	cutoff := time.Now().Add(-OrphanTxTTL)
	for id, o := range m.orphans {
		if o.received.Before(cutoff) {
			m.removeOrphanLocked(id, o.missing)
		}
	}
}

func (m *Mempool) evictOldestOrphanLocked() {
	var oldestID [32]byte
	var oldestT time.Time
	var oldestMissing [][32]byte
	first := true
	for id, o := range m.orphans {
		if first || o.received.Before(oldestT) {
			oldestID = id
			oldestT = o.received
			oldestMissing = o.missing
			first = false
		}
	}
	if !first {
		m.removeOrphanLocked(oldestID, oldestMissing)
	}
}

func (m *Mempool) removeOrphanLocked(id [32]byte, missing [][32]byte) {
	delete(m.orphans, id)
	for _, parent := range missing {
		siblings := m.orphansBySrc[parent]
		for i, h := range siblings {
			if h == id {
				siblings = append(siblings[:i], siblings[i+1:]...)
				break
			}
		}
		if len(siblings) == 0 {
			delete(m.orphansBySrc, parent)
		} else {
			m.orphansBySrc[parent] = siblings
		}
	}
}

// ProcessOrphansForParent retries every orphan that referenced
// `parentTxID` as a missing input. Each retry goes through the normal
// Add path (so it re-runs all consensus checks against the now-updated
// UTXO view). Successful adds are removed from the orphan pool; misses
// are left in place for next time.
func (m *Mempool) ProcessOrphansForParent(parentTxID [32]byte, u txn.UTXOSet, nextHeight uint32, nextTime uint64) {
	m.orphanMu.Lock()
	candidates := make([][32]byte, len(m.orphansBySrc[parentTxID]))
	copy(candidates, m.orphansBySrc[parentTxID])
	m.orphanMu.Unlock()

	for _, id := range candidates {
		m.orphanMu.Lock()
		o, ok := m.orphans[id]
		if ok {
			m.removeOrphanLocked(id, o.missing)
		}
		m.orphanMu.Unlock()
		if !ok {
			continue
		}
		// Add may rebuffer this tx if other parents are still missing —
		// that's the normal flow.
		_ = m.Add(o.tx, u, nextHeight, nextTime)
	}
}

// OrphanTxCount returns the current orphan-tx pool size.
func (m *Mempool) OrphanTxCount() int {
	m.orphanMu.Lock()
	defer m.orphanMu.Unlock()
	return len(m.orphans)
}
