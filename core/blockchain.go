package core

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/logging"
	"qbitcoin/storage"
	"qbitcoin/txn"
)

var log = logging.Module("chain")

// Blockchain tracks the best chain state and applies blocks.
type Blockchain struct {
	db                *storage.DB
	mu                sync.RWMutex
	tipHash           [32]byte
	tipHeight         uint32
	totalWork         *big.Int
	headersHts        map[[32]byte]uint32 // in-memory height index for blocks on the main chain
	knownWork         map[[32]byte]*big.Int
	knownHdrs         map[[32]byte]BlockHeader // all known headers (main + side)
	newBlockSub       []chan struct{}
	connectCbs        []func(Block, uint32)
	pendingConnect    []connectEvent // queued for flushConnected after lock release
	disconnectCbs     []func(Block, uint32)
	pendingDisconnect []connectEvent // same queue type, fired by flushDisconnected

	// Orphan block pool: blocks whose parent is not yet known. PoW is
	// validated before buffering, so each entry is at minimum proof-of-
	// work-cost expensive to produce (no DoS amplification). On parent
	// arrival, processOrphans drains matching children iteratively.
	orphanMu        sync.Mutex
	orphans         map[[32]byte]orphanEntry
	orphansByParent map[[32]byte][][32]byte
}

type orphanEntry struct {
	block    Block
	received time.Time
}

// connectEvent pairs a Block with the height it occupied. Used for the
// connect/disconnect callback queues so each callback sees the right
// height even when many fire in a burst (reorg).
type connectEvent struct {
	block  Block
	height uint32
}

// MaxOrphanBlocks bounds the orphan pool. When full, the oldest entry
// is evicted to make room for the new one.
const MaxOrphanBlocks = 100

// OrphanTTL is the time after which a buffered orphan is GC'd if its
// parent never arrives.
const OrphanTTL = 10 * time.Minute

// NewBlockchain opens or initializes the chain with the genesis block.
func NewBlockchain(db *storage.DB) (*Blockchain, error) {
	bc := &Blockchain{
		db:              db,
		totalWork:       big.NewInt(0),
		headersHts:      map[[32]byte]uint32{},
		knownWork:       map[[32]byte]*big.Int{},
		knownHdrs:       map[[32]byte]BlockHeader{},
		orphans:         map[[32]byte]orphanEntry{},
		orphansByParent: map[[32]byte][][32]byte{},
	}
	// Attempt to load tip from meta.
	th, err := db.Get([]byte(storage.BucketMeta), []byte("best_hash"))
	if err != nil {
		return nil, err
	}
	if len(th) == 32 {
		copy(bc.tipHash[:], th)
		hb, err := db.Get([]byte(storage.BucketMeta), []byte("best_height"))
		if err != nil {
			return nil, err
		}
		if len(hb) == 4 {
			bc.tipHeight = binary.BigEndian.Uint32(hb)
		}
		wb, err := db.Get([]byte(storage.BucketMeta), []byte("total_work"))
		if err != nil {
			return nil, err
		}
		if len(wb) > 0 {
			bc.totalWork = new(big.Int).SetBytes(wb)
		}
		// Rebuild in-memory indices by walking headers.
		if err := bc.rebuildHeightIndex(); err != nil {
			return nil, err
		}
		return bc, nil
	}
	// No tip: write genesis.
	g := Genesis()
	gWork := WorkFromBits(g.Header.Bits)
	if err := bc.persistBlock(g, 0, gWork); err != nil {
		return nil, err
	}
	bc.tipHash = g.Header.Hash()
	bc.tipHeight = 0
	bc.totalWork = new(big.Int).Set(gWork)
	bc.headersHts[bc.tipHash] = 0
	bc.knownWork[bc.tipHash] = new(big.Int).Set(gWork)
	bc.knownHdrs[bc.tipHash] = g.Header
	if err := bc.persistMeta(); err != nil {
		return nil, err
	}
	// Apply coinbase UTXOs (genesis output) and record empty undo.
	undo := undoRecord{}
	for i, out := range g.Txns[0].Outputs {
		k := txn.UTXOKey{TxID: g.Txns[0].TxID(), Index: uint32(i)}
		if err := bc.putUTXO(k, out, true, 0); err != nil {
			return nil, err
		}
		undo.Created = append(undo.Created, k)
	}
	if err := bc.putUndo(bc.tipHash, undo); err != nil {
		return nil, err
	}
	return bc, nil
}

func (bc *Blockchain) rebuildHeightIndex() error {
	// Walk back from tip to genesis via PrevHash to build a contiguous height map.
	cur := bc.tipHash
	h := bc.tipHeight
	for {
		hdrBytes, err := bc.db.Get([]byte(storage.BucketHeaders), cur[:])
		if err != nil {
			return err
		}
		if hdrBytes == nil {
			return errors.New("chain: header missing during reindex")
		}
		hdr, err := DeserializeHeader(hdrBytes)
		if err != nil {
			return err
		}
		bc.headersHts[cur] = h
		bc.knownHdrs[cur] = hdr
		// Load cumulative work for this block.
		wb, err := bc.db.Get([]byte(storage.BucketWork), cur[:])
		if err == nil && len(wb) > 0 {
			bc.knownWork[cur] = new(big.Int).SetBytes(wb)
		}
		if h == 0 {
			return nil
		}
		cur = hdr.PrevHash
		h--
	}
}

// Tip returns the current tip hash and height.
func (bc *Blockchain) Tip() ([32]byte, uint32) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tipHash, bc.tipHeight
}

// Height returns the current height.
func (bc *Blockchain) Height() uint32 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tipHeight
}

// BestHash returns the current tip hash.
func (bc *Blockchain) BestHash() [32]byte {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tipHash
}

// BlockHashAtHeight returns the main-chain block hash at the given height
// by walking back from the tip. Returns false if height is above the tip.
func (bc *Blockchain) BlockHashAtHeight(height uint32) ([32]byte, bool) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if height > bc.tipHeight {
		return [32]byte{}, false
	}
	cur := bc.tipHash
	for h := bc.tipHeight; h > height; h-- {
		hdr, err := bc.header(cur)
		if err != nil {
			return [32]byte{}, false
		}
		cur = hdr.PrevHash
	}
	return cur, true
}

// HeightOf returns the main-chain height of the given block hash. The
// second return is false if the hash isn't on the main chain.
func (bc *Blockchain) HeightOf(h [32]byte) (uint32, bool) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	height, ok := bc.headersHts[h]
	return height, ok
}

// CumulativeWork returns the chainwork at the given block hash (sum of
// per-block work from genesis to h, inclusive). Returns nil if the hash
// is unknown. The returned big.Int is a copy — safe to mutate.
func (bc *Blockchain) CumulativeWork(h [32]byte) *big.Int {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if w, ok := bc.knownWork[h]; ok {
		return new(big.Int).Set(w)
	}
	wb, err := bc.db.Get([]byte(storage.BucketWork), h[:])
	if err != nil || len(wb) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(wb)
}

// MedianTimeOfBlock returns the median-of-11 timestamp ending at (and
// including) the given block hash — this matches Bitcoin's `mediantime`
// field in getblock output. Returns 0 if the hash is unknown.
func (bc *Blockchain) MedianTimeOfBlock(h [32]byte) uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.medianTimestamp(h, 11)
}

// NextMainChainHash returns the hash of the main-chain block that
// succeeds h (h+1). Second return is false if h is the tip or not on
// the main chain.
func (bc *Blockchain) NextMainChainHash(h [32]byte) ([32]byte, bool) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	height, ok := bc.headersHts[h]
	if !ok || height >= bc.tipHeight {
		return [32]byte{}, false
	}
	// Walk back from the tip to height+1.
	cur := bc.tipHash
	for ht := bc.tipHeight; ht > height+1; ht-- {
		hdr, err := bc.header(cur)
		if err != nil {
			return [32]byte{}, false
		}
		cur = hdr.PrevHash
	}
	return cur, true
}

// CurrentBits computes the bits that a next-block header should use.
// On non-retarget boundaries this inherits the tip's bits. On boundaries
// (nextHeight % RetargetInterval == 0) it retargets using the Bitcoin DAA:
// newTarget = oldTarget * clamp(actualTimespan) / TargetTimespanSec.
func (bc *Blockchain) CurrentBits() uint32 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	tipHdr, err := bc.header(bc.tipHash)
	if err != nil {
		return GenesisBits
	}
	nextHeight := uint64(bc.tipHeight) + 1
	if nextHeight%RetargetInterval != 0 {
		return tipHdr.Bits
	}
	// Walk back RetargetInterval-1 steps from tip to find the first block
	// of the window just closed (Bitcoin's off-by-one: 2015 intervals).
	cur := tipHdr
	for i := uint64(0); i < RetargetInterval-1; i++ {
		prev, err := bc.header(cur.PrevHash)
		if err != nil {
			return tipHdr.Bits
		}
		cur = prev
	}
	return ComputeNextWorkRequired(nextHeight, tipHdr.Bits, tipHdr.Timestamp, cur.Timestamp)
}

// MinNextTimestamp returns the smallest timestamp a block built on the current
// tip is allowed to carry under the median-of-11 rule.
func (bc *Blockchain) MinNextTimestamp() uint64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.medianTimestamp(bc.tipHash, 11) + 1
}

// NextBlockContext returns the (height, time) pair that mempool +
// validation use to evaluate IsFinal locktime gates: the height the
// next mined block will carry, and the median-time-past anchor.
func (bc *Blockchain) NextBlockContext() (uint32, uint64) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.tipHeight + 1, bc.medianTimestamp(bc.tipHash, 11)
}

// WaitForNewBlock returns a channel that closes when a new block is accepted.
func (bc *Blockchain) WaitForNewBlock() <-chan struct{} {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	ch := make(chan struct{})
	bc.newBlockSub = append(bc.newBlockSub, ch)
	return ch
}

// OnBlockConnected registers a callback fired for each block appended
// to the main chain (passing the block and its height). During a reorg
// the callback fires once per block applied forward from the common
// ancestor.
func (bc *Blockchain) OnBlockConnected(cb func(Block, uint32)) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.connectCbs = append(bc.connectCbs, cb)
}

// OnBlockDisconnected registers a callback fired for each block
// disconnected from the main chain during a reorg (passing the block
// and the height it occupied just before disconnect). Fires before the
// new branch's blocks are connected, in order from old tip down toward
// the common ancestor.
func (bc *Blockchain) OnBlockDisconnected(cb func(Block, uint32)) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.disconnectCbs = append(bc.disconnectCbs, cb)
}

func (bc *Blockchain) signalNewBlock() {
	for _, ch := range bc.newBlockSub {
		close(ch)
	}
	bc.newBlockSub = nil
}

// fireConnected queues a block for callback dispatch. Callbacks must be
// run WITHOUT bc.mu held — many of them (mempool eviction with orphan
// reprocessing, wallet pending clear, etc.) call back into the chain
// for state queries and would deadlock against the writer that produced
// the block. Callers run the actual dispatch via flushConnected after
// unlocking.
func (bc *Blockchain) fireConnected(b Block, height uint32) {
	bc.pendingConnect = append(bc.pendingConnect, connectEvent{block: b, height: height})
}

// fireDisconnected queues a block-disconnect event for callback
// dispatch. Same deadlock-avoidance contract as fireConnected.
func (bc *Blockchain) fireDisconnected(b Block, height uint32) {
	bc.pendingDisconnect = append(bc.pendingDisconnect, connectEvent{block: b, height: height})
}

// flushConnected drains the pending-connect queue and runs each
// callback (with the block's height). Caller MUST NOT hold bc.mu.
func (bc *Blockchain) flushConnected() {
	bc.mu.Lock()
	pending := bc.pendingConnect
	bc.pendingConnect = nil
	cbs := append([]func(Block, uint32){}, bc.connectCbs...)
	bc.mu.Unlock()
	for _, ev := range pending {
		for _, cb := range cbs {
			func(fn func(Block, uint32), bb Block, h uint32) {
				defer func() { _ = recover() }()
				fn(bb, h)
			}(cb, ev.block, ev.height)
		}
	}
}

// flushDisconnected drains the pending-disconnect queue. Called before
// flushConnected during reorg dispatch so subscribers see the reorg
// order correctly.
func (bc *Blockchain) flushDisconnected() {
	bc.mu.Lock()
	pending := bc.pendingDisconnect
	bc.pendingDisconnect = nil
	cbs := append([]func(Block, uint32){}, bc.disconnectCbs...)
	bc.mu.Unlock()
	for _, ev := range pending {
		for _, cb := range cbs {
			func(fn func(Block, uint32), bb Block, h uint32) {
				defer func() { _ = recover() }()
				fn(bb, h)
			}(cb, ev.block, ev.height)
		}
	}
}

// header reads a BlockHeader from storage.
func (bc *Blockchain) header(h [32]byte) (BlockHeader, error) {
	b, err := bc.db.Get([]byte(storage.BucketHeaders), h[:])
	if err != nil {
		return BlockHeader{}, err
	}
	if b == nil {
		return BlockHeader{}, errors.New("header not found")
	}
	return DeserializeHeader(b)
}

// HasBlock reports whether the chain knows this block hash (main chain or side).
func (bc *Blockchain) HasBlock(h [32]byte) bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if _, ok := bc.headersHts[h]; ok {
		return true
	}
	_, ok := bc.knownHdrs[h]
	return ok
}

// GetBlock retrieves a full block by hash. ctx is checked once before
// the underlying Pebble lookup; the lookup itself is sync and cannot be
// interrupted, but a cancelled ctx short-circuits at the boundary.
func (bc *Blockchain) GetBlock(ctx context.Context, h [32]byte) (*Block, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := bc.db.Get([]byte(storage.BucketBlocks), h[:])
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("block not found")
	}
	return DeserializeBlock(b)
}

// GetHeader returns a header by hash.
func (bc *Blockchain) GetHeader(ctx context.Context, h [32]byte) (BlockHeader, error) {
	if err := ctx.Err(); err != nil {
		return BlockHeader{}, err
	}
	return bc.header(h)
}

// persistBlock writes the full block + header + cumulative-work record atomically.
func (bc *Blockchain) persistBlock(b Block, height uint32, cumulativeWork *big.Int) error {
	hashID := b.Header.Hash()
	batch := bc.db.NewBatch()
	defer batch.Close()

	if err := batch.Put([]byte(storage.BucketBlocks), hashID[:], b.Serialize()); err != nil {
		return err
	}
	if err := batch.Put([]byte(storage.BucketHeaders), hashID[:], b.Header.Serialize()); err != nil {
		return err
	}
	hk := append([]byte("height_"), hashID[:]...)
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], height)
	if err := batch.Put([]byte(storage.BucketMeta), hk, hb[:]); err != nil {
		return err
	}
	if err := batch.Put([]byte(storage.BucketWork), hashID[:], cumulativeWork.Bytes()); err != nil {
		return err
	}
	return batch.Commit()
}

func (bc *Blockchain) persistMeta() error {
	batch := bc.db.NewBatch()
	defer batch.Close()
	if err := batch.Put([]byte(storage.BucketMeta), []byte("best_hash"), bc.tipHash[:]); err != nil {
		return err
	}
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], bc.tipHeight)
	if err := batch.Put([]byte(storage.BucketMeta), []byte("best_height"), hb[:]); err != nil {
		return err
	}
	if err := batch.Put([]byte(storage.BucketMeta), []byte("total_work"), bc.totalWork.Bytes()); err != nil {
		return err
	}
	return batch.Commit()
}

// CoinbaseMaturity is the number of confirmations required before a
// coinbase output can be spent. A coinbase mined at height H becomes
// spendable starting at height H + CoinbaseMaturity (the spending
// transaction must appear in a block of height >= H + 100).
const CoinbaseMaturity = 100

// putUTXO writes a UTXO entry, stamping its containing-tx coinbase flag
// and birth height for later maturity checks.
func (bc *Blockchain) putUTXO(k txn.UTXOKey, o txn.TxOutput, coinbase bool, height uint32) error {
	return bc.db.Put([]byte(storage.BucketUTXOs), k.Bytes(), txn.SerializeOutput(o, coinbase, height))
}

// delUTXO removes a UTXO.
func (bc *Blockchain) delUTXO(k txn.UTXOKey) error {
	return bc.db.Delete([]byte(storage.BucketUTXOs), k.Bytes())
}

// getUTXO returns a UTXO and its stamped coinbase/height metadata, or
// (nil, false, 0, nil) if the key does not exist.
func (bc *Blockchain) getUTXO(k txn.UTXOKey) (*txn.TxOutput, bool, uint32, error) {
	v, err := bc.db.Get([]byte(storage.BucketUTXOs), k.Bytes())
	if err != nil {
		return nil, false, 0, err
	}
	if v == nil {
		return nil, false, 0, nil
	}
	o, coinbase, height, err := txn.DeserializeOutput(v)
	if err != nil {
		return nil, false, 0, err
	}
	return &o, coinbase, height, nil
}

// ChainUTXO returns a UTXOSet view that reads from the chain's bbolt.
func (bc *Blockchain) ChainUTXO() txn.UTXOSet { return &chainUTXO{bc: bc} }

type chainUTXO struct{ bc *Blockchain }

// isImmatureCoinbase reports whether a coinbase UTXO born at `birth`
// cannot yet be spent at the current tip height. Non-coinbase entries
// are always considered mature.
func (bc *Blockchain) isImmatureCoinbase(coinbase bool, birth uint32) bool {
	if !coinbase {
		return false
	}
	tip := bc.tipHeight
	if tip < birth {
		return true // shouldn't happen, but guard
	}
	return tip-birth < CoinbaseMaturity
}

func (c *chainUTXO) Get(k txn.UTXOKey) (*txn.TxOutput, error) {
	o, _, _, err := c.bc.getUTXO(k)
	return o, err
}

func (c *chainUTXO) Put(k txn.UTXOKey, o txn.TxOutput) error {
	// Callers via the UTXOSet interface (mempool / wallet) treat all
	// outputs as non-coinbase; consensus writes go through bc.putUTXO
	// directly with the correct stamp.
	return c.bc.putUTXO(k, o, false, 0)
}
func (c *chainUTXO) Delete(k txn.UTXOKey) error { return c.bc.delUTXO(k) }
func (c *chainUTXO) Has(k txn.UTXOKey) (bool, error) {
	o, _, _, err := c.bc.getUTXO(k)
	return o != nil, err
}

// Balance / AllForAddress filter immature coinbase outputs so wallet UI
// and coin selection never propose to spend coins that consensus would
// reject.
func (c *chainUTXO) Balance(a address.P2MRAddress) (uint64, error) {
	var total uint64
	c.bc.mu.RLock()
	defer c.bc.mu.RUnlock()
	err := c.bc.db.ForEach([]byte(storage.BucketUTXOs), func(k, v []byte) error {
		o, coinbase, birth, err := txn.DeserializeOutput(v)
		if err != nil {
			return err
		}
		if c.bc.isImmatureCoinbase(coinbase, birth) {
			return nil
		}
		if o.Address.MerkleRoot == a.MerkleRoot {
			total += o.Value
		}
		return nil
	})
	return total, err
}

func (c *chainUTXO) AllForAddress(a address.P2MRAddress) ([]txn.UTXOKey, []txn.TxOutput, error) {
	var keys []txn.UTXOKey
	var outs []txn.TxOutput
	c.bc.mu.RLock()
	defer c.bc.mu.RUnlock()
	err := c.bc.db.ForEach([]byte(storage.BucketUTXOs), func(k, v []byte) error {
		o, coinbase, birth, err := txn.DeserializeOutput(v)
		if err != nil {
			return err
		}
		if c.bc.isImmatureCoinbase(coinbase, birth) {
			return nil
		}
		if o.Address.MerkleRoot == a.MerkleRoot {
			kk, err := txn.ParseUTXOKey(k)
			if err != nil {
				return err
			}
			keys = append(keys, kk)
			outs = append(outs, o)
		}
		return nil
	})
	return keys, outs, err
}

// --- undo records ---
//
// For each block applied to the main chain we persist an undoRecord in the
// "undo" bucket keyed by the block hash. On reorg rollback we use this to
// restore the UTXO set to the pre-block state.

type spentEntry struct {
	Key      txn.UTXOKey
	Out      txn.TxOutput
	Coinbase bool
	Height   uint32
}

type undoRecord struct {
	Spent   []spentEntry  // UTXOs destroyed by this block (to be restored on rollback)
	Created []txn.UTXOKey // UTXOs created by this block (to be removed on rollback)
}

func serializeUndo(u undoRecord) []byte {
	var buf []byte
	var tmp [8]byte
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(u.Spent)))
	buf = append(buf, tmp[:4]...)
	for _, s := range u.Spent {
		buf = append(buf, s.Key.Bytes()...)
		buf = append(buf, txn.SerializeOutput(s.Out, s.Coinbase, s.Height)...)
	}
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(u.Created)))
	buf = append(buf, tmp[:4]...)
	for _, k := range u.Created {
		buf = append(buf, k.Bytes()...)
	}
	return buf
}

// maxUndoEntries caps spent/created counts in a persisted undo record.
// A legitimate block tops out around MaxBlockSize / smallest-utxo-entry
// (~50k entries). 1_000_000 is generous headroom; the cap exists so a
// corrupted DB record can't force a billion-entry slice allocation on
// restart.
const maxUndoEntries = 1_000_000

func deserializeUndo(b []byte) (undoRecord, error) {
	var u undoRecord
	if len(b) < 4 {
		return u, errors.New("undo: truncated")
	}
	off := 0
	sn := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if sn > maxUndoEntries {
		return u, errors.New("undo: spent count exceeds cap")
	}
	u.Spent = make([]spentEntry, 0, sn)
	for i := uint32(0); i < sn; i++ {
		if off+36+txn.UTXOEntrySize > len(b) {
			return u, errors.New("undo: spent truncated")
		}
		k, err := txn.ParseUTXOKey(b[off : off+36])
		if err != nil {
			return u, err
		}
		off += 36
		o, coinbase, height, err := txn.DeserializeOutput(b[off : off+txn.UTXOEntrySize])
		if err != nil {
			return u, err
		}
		off += txn.UTXOEntrySize
		u.Spent = append(u.Spent, spentEntry{Key: k, Out: o, Coinbase: coinbase, Height: height})
	}
	if off+4 > len(b) {
		return u, errors.New("undo: created count truncated")
	}
	cn := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if cn > maxUndoEntries {
		return u, errors.New("undo: created count exceeds cap")
	}
	u.Created = make([]txn.UTXOKey, 0, cn)
	for i := uint32(0); i < cn; i++ {
		if off+36 > len(b) {
			return u, errors.New("undo: created truncated")
		}
		k, err := txn.ParseUTXOKey(b[off : off+36])
		if err != nil {
			return u, err
		}
		off += 36
		u.Created = append(u.Created, k)
	}
	return u, nil
}

func (bc *Blockchain) putUndo(hash [32]byte, u undoRecord) error {
	return bc.db.Put([]byte(storage.BucketUndo), hash[:], serializeUndo(u))
}

func (bc *Blockchain) getUndo(hash [32]byte) (undoRecord, error) {
	v, err := bc.db.Get([]byte(storage.BucketUndo), hash[:])
	if err != nil {
		return undoRecord{}, err
	}
	if v == nil {
		return undoRecord{}, errors.New("undo: not found")
	}
	return deserializeUndo(v)
}

// --- atomic UTXO overlay (used by extension + reorg paths) ---
//
// utxoOverlay buffers UTXO / undo / meta mutations in memory so a whole
// reorg (or a single block application) commits atomically via one
// storage.Batch. Reads fall through to the chain DB when a key isn't
// staged. The overlay is NOT thread-safe — it lives inside one
// reorgTo / addBlockOnce call under bc.mu.
//
// Invariant: a UTXOKey is either in `puts` or `dels` (or neither), never
// both. put() and del() enforce this by clearing the opposite entry.
type utxoOverlay struct {
	bc     *Blockchain
	puts   map[txn.UTXOKey]utxoStagedEntry
	dels   map[txn.UTXOKey]struct{}
	undos  map[[32]byte][]byte // block hash -> serialized undoRecord
	metaKV map[string][]byte   // meta-bucket key -> value
}

type utxoStagedEntry struct {
	out      txn.TxOutput
	coinbase bool
	height   uint32
}

func (bc *Blockchain) newOverlay() *utxoOverlay {
	return &utxoOverlay{
		bc:     bc,
		puts:   map[txn.UTXOKey]utxoStagedEntry{},
		dels:   map[txn.UTXOKey]struct{}{},
		undos:  map[[32]byte][]byte{},
		metaKV: map[string][]byte{},
	}
}

// get returns the logical UTXO at key through the overlay.
// (nil, false, 0, nil) means "absent" — either staged-deleted or genuinely
// not in the base DB.
func (o *utxoOverlay) get(k txn.UTXOKey) (*txn.TxOutput, bool, uint32, error) {
	if _, deleted := o.dels[k]; deleted {
		return nil, false, 0, nil
	}
	if e, ok := o.puts[k]; ok {
		out := e.out
		return &out, e.coinbase, e.height, nil
	}
	return o.bc.getUTXO(k)
}

// put stages a UTXO write; cancels any pending delete for the same key.
func (o *utxoOverlay) put(k txn.UTXOKey, out txn.TxOutput, coinbase bool, height uint32) {
	delete(o.dels, k)
	o.puts[k] = utxoStagedEntry{out: out, coinbase: coinbase, height: height}
}

// del stages a UTXO delete; cancels any pending put for the same key.
func (o *utxoOverlay) del(k txn.UTXOKey) {
	delete(o.puts, k)
	o.dels[k] = struct{}{}
}

// putUndo stages an undo-record write for a block.
func (o *utxoOverlay) putUndo(blockHash [32]byte, u undoRecord) {
	o.undos[blockHash] = serializeUndo(u)
}

// putMeta stages a meta-bucket kv write.
func (o *utxoOverlay) putMeta(key string, value []byte) {
	o.metaKV[key] = value
}

// commit flushes every staged op to disk as one atomic pebble batch.
// After a successful commit the overlay MUST NOT be reused.
func (o *utxoOverlay) commit() error {
	batch := o.bc.db.NewBatch()
	defer batch.Close()
	for k := range o.dels {
		if err := batch.Delete([]byte(storage.BucketUTXOs), k.Bytes()); err != nil {
			return err
		}
	}
	for k, e := range o.puts {
		if err := batch.Put([]byte(storage.BucketUTXOs), k.Bytes(),
			txn.SerializeOutput(e.out, e.coinbase, e.height)); err != nil {
			return err
		}
	}
	for h, body := range o.undos {
		hh := h
		if err := batch.Put([]byte(storage.BucketUndo), hh[:], body); err != nil {
			return err
		}
	}
	for key, value := range o.metaKV {
		if err := batch.Put([]byte(storage.BucketMeta), []byte(key), value); err != nil {
			return err
		}
	}
	return batch.Commit()
}

// reorgCommitHook is a test-only failure-injection seam. If set, it is
// called right before overlay.commit() on both the extension and reorg
// paths; a non-nil return aborts the operation with the same semantics
// as a disk-commit failure (no mutation, chain stays at old tip). Real
// consensus code never touches this.
var reorgCommitHook func() error

// testBypassPoW is a test-only switch that disables CheckProof in
// addBlockOnce. Real consensus code never touches this.
var testBypassPoW bool

// testSkipTxValidation is a test-only switch that makes validateAndApply
// skip merkle-inclusion + script Execute checks. Tests that exercise
// reorg atomicity and mempool interactions use this to avoid the
// full SHRINCS/SHRIMPS keygen + signing cost; tx VALUE / UTXO /
// coinbase / double-spend accounting still runs. Real consensus code
// never touches this.
var testSkipTxValidation bool

// testSkipHeaderTimeChecks disables the median-of-11 lower bound and
// the +2h future-cap on block timestamps. Tests that construct
// handcrafted chains flip this so timestamps can be set arbitrarily
// without worrying about wall-clock drift against the pinned
// GenesisTimestamp. Real consensus code never touches this.
var testSkipHeaderTimeChecks bool

// testSkipCoinbaseMaturity disables the CoinbaseMaturity=100 check.
// Reorg + mempool-reinjection tests build short handcrafted chains
// that spend the previous block's coinbase immediately; extending
// them 100 blocks just to satisfy maturity is prohibitive and
// orthogonal to what those tests assert. Real consensus code never
// touches this.
var testSkipCoinbaseMaturity bool

// --- AddBlock with reorg ---

// AddBlockOutcome reports what happened to a block accepted by AddBlock.
// Callers (notably the p2p layer) use this to log accurately — the
// chain's current tip height is NOT a meaningful descriptor for blocks
// that landed on a side branch or in the orphan pool.
type AddBlockOutcome int

const (
	OutcomeUnknown   AddBlockOutcome = iota
	OutcomeDuplicate                 // already known; no-op
	OutcomeExtended                  // appended to main chain
	OutcomeReorg                     // triggered a reorg, this block is now tip
	OutcomeSideChain                 // stored on a side chain (lower cumulative work)
	OutcomeOrphan                    // parent unknown; buffered for later
)

func (o AddBlockOutcome) String() string {
	switch o {
	case OutcomeDuplicate:
		return "duplicate"
	case OutcomeExtended:
		return "extended"
	case OutcomeReorg:
		return "reorg"
	case OutcomeSideChain:
		return "sidechain"
	case OutcomeOrphan:
		return "orphan"
	}
	return "unknown"
}

// AddBlock validates and appends a block to the chain, handling reorgs
// via total work. Returns the outcome plus the block's own height (its
// position in whatever branch it landed on, NOT the chain tip height).
// Height is 0 for orphans (parent unknown). ctx cancellation short-
// circuits before the heavy validation work; once committed, the
// orphan-drain follow-on uses the same ctx.
func (bc *Blockchain) AddBlock(ctx context.Context, b Block) (AddBlockOutcome, uint32, error) {
	if err := ctx.Err(); err != nil {
		return OutcomeUnknown, 0, err
	}
	outcome, height, err := bc.addBlockOnce(ctx, b)
	// Always flush queued callbacks: even if addBlockOnce returned
	// mid-reorg, anything that was already wired up should fire.
	// Disconnect fires before connect so the reorg sequence is
	// observable in order (old-tip down → ancestor+1 up → new-tip).
	bc.flushDisconnected()
	bc.flushConnected()
	if err != nil {
		return outcome, height, err
	}
	// On any successful append, see whether buffered orphans can now connect.
	bc.processOrphans(ctx, b.Header.Hash())
	bc.flushDisconnected()
	bc.flushConnected()
	return outcome, height, nil
}

func (bc *Blockchain) addBlockOnce(ctx context.Context, b Block) (AddBlockOutcome, uint32, error) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	hashID := b.Header.Hash()
	if h, seen := bc.headersHts[hashID]; seen {
		return OutcomeDuplicate, h, nil
	}
	if _, seen := bc.knownHdrs[hashID]; seen {
		return OutcomeDuplicate, 0, nil
	}

	// 1. PoW valid.
	if !testBypassPoW && !CheckProof(b.Header) {
		return OutcomeUnknown, 0, errors.New("block: bad PoW")
	}
	// 2. Parent must be known (either main chain or side).
	parentHdr, parentKnown := bc.knownHdrs[b.Header.PrevHash]
	if !parentKnown {
		// Try to load from storage (in case rebuildHeightIndex only covered main chain).
		ph, err := bc.header(b.Header.PrevHash)
		if err != nil {
			// Parent unknown anywhere: buffer as orphan rather than reject.
			// PoW is already verified so this costs the sender real work.
			bc.bufferOrphan(b)
			return OutcomeOrphan, 0, nil
		}
		parentHdr = ph
		bc.knownHdrs[b.Header.PrevHash] = parentHdr
	}
	parentWork, ok := bc.knownWork[b.Header.PrevHash]
	if !ok {
		wb, err := bc.db.Get([]byte(storage.BucketWork), b.Header.PrevHash[:])
		if err != nil || len(wb) == 0 {
			return OutcomeUnknown, 0, errors.New("block: prev work missing")
		}
		parentWork = new(big.Int).SetBytes(wb)
		bc.knownWork[b.Header.PrevHash] = parentWork
	}

	// 3. Median-of-11 timestamp rule.
	if !testSkipHeaderTimeChecks {
		med := bc.medianTimestamp(b.Header.PrevHash, 11)
		if b.Header.Timestamp <= med {
			return OutcomeUnknown, 0, errors.New("block: timestamp <= median of last 11")
		}
		if b.Header.Timestamp > uint64(time.Now().Unix())+7200 {
			return OutcomeUnknown, 0, errors.New("block: timestamp too far in future")
		}
	}

	// 4. Merkle root matches — and reject CVE-2012-2459 mutations.
	// Bitcoin's odd-level duplicate-last rule makes any level with
	// equal consecutive siblings ambiguous: a shorter tx list hashes
	// to the same root, so an attacker could serve two distinct tx
	// sets under one header.
	root, mutated := b.ComputeMerkleRootMutated()
	if mutated {
		return OutcomeUnknown, 0, errors.New("block: merkle tree mutated (CVE-2012-2459)")
	}
	if root != b.Header.MerkleRoot {
		return OutcomeUnknown, 0, errors.New("block: bad merkle root")
	}

	// 5. Coinbase present.
	if len(b.Txns) == 0 {
		return OutcomeUnknown, 0, errors.New("block: no txns")
	}
	if !b.Txns[0].IsCoinbase() {
		return OutcomeUnknown, 0, errors.New("block: first tx must be coinbase")
	}
	for i := 1; i < len(b.Txns); i++ {
		if b.Txns[i].IsCoinbase() {
			return OutcomeUnknown, 0, errors.New("block: multiple coinbase")
		}
	}

	// 6. Hard size cap. Reject before we touch the UTXO set.
	if sz := len(b.Serialize()); sz > MaxBlockSize {
		return OutcomeUnknown, 0, fmt.Errorf("block: serialized size %d exceeds MaxBlockSize %d", sz, MaxBlockSize)
	}

	// Compute this block's height and cumulative work.
	parentHeight, onMain := bc.headersHts[b.Header.PrevHash]
	if !onMain {
		// Side-chain parent: try to load persisted height.
		hk := append([]byte("height_"), b.Header.PrevHash[:]...)
		hb, err := bc.db.Get([]byte(storage.BucketMeta), hk)
		if err != nil || len(hb) != 4 {
			return OutcomeUnknown, 0, errors.New("block: parent height missing")
		}
		parentHeight = binary.BigEndian.Uint32(hb)
	}
	height := parentHeight + 1
	addedWork := WorkFromBits(b.Header.Bits)
	cumulative := new(big.Int).Add(parentWork, addedWork)

	// Persist block, header, cumulative work (even if this block won't become tip).
	if err := bc.persistBlock(b, height, cumulative); err != nil {
		return OutcomeUnknown, 0, err
	}
	bc.knownWork[hashID] = cumulative
	bc.knownHdrs[hashID] = b.Header

	// Decide whether this block causes a reorg / extension.
	if b.Header.PrevHash == bc.tipHash {
		// Simple extension. Validate txns against live UTXO, stage the
		// block's mutations + tip/meta updates into one overlay, then
		// commit atomically. On commit failure nothing on disk moves.
		overlay := bc.newOverlay()
		if err := bc.validateAndApply(ctx, overlay, b, height); err != nil {
			log.Warn("ConnectBlock failed",
				"hash", crypto.DisplayHex(hashID), "height", height, "err", err)
			return OutcomeUnknown, height, err
		}
		overlay.putMeta("best_hash", append([]byte(nil), hashID[:]...))
		var hb [4]byte
		binary.BigEndian.PutUint32(hb[:], height)
		overlay.putMeta("best_height", append([]byte(nil), hb[:]...))
		overlay.putMeta("total_work", cumulative.Bytes())
		if reorgCommitHook != nil {
			if err := reorgCommitHook(); err != nil {
				log.Warn("ConnectBlock: commit hook aborted", "err", err)
				return OutcomeUnknown, height, err
			}
		}
		if err := overlay.commit(); err != nil {
			return OutcomeUnknown, height, err
		}
		// Disk is authoritative. In-memory update is now safe.
		bc.tipHash = hashID
		bc.tipHeight = height
		bc.totalWork = new(big.Int).Set(cumulative)
		bc.headersHts[hashID] = height
		// Bitcoin Core's UpdateTip analog: one info-level line per new
		// tip, regardless of source (p2p ingress, submitblock from the
		// external miner, generatetoaddress). This is the authoritative
		// "a new block exists" signal — operators don't have to chase
		// which subsystem owns the announce.
		log.Info("UpdateTip: new best",
			"hash", crypto.DisplayHex(hashID),
			"height", height,
			"txs", len(b.Txns),
			"bits", fmt.Sprintf("%08x", b.Header.Bits))
		bc.signalNewBlock()
		bc.fireConnected(b, height)
		return OutcomeExtended, height, nil
	}

	// Not an extension: does it beat the current tip on cumulative work?
	if cumulative.Cmp(bc.totalWork) <= 0 {
		// Side chain; stored but not connected.
		log.Debug("stored side-chain block",
			"hash", crypto.DisplayHex(hashID),
			"side_height", height,
			"main_height", bc.tipHeight,
			"work_gap", new(big.Int).Sub(bc.totalWork, cumulative).String())
		return OutcomeSideChain, height, nil
	}
	// Reorg required.
	log.Info("REORGANIZE",
		"new_tip", crypto.DisplayHex(hashID),
		"new_height", height,
		"old_tip", crypto.DisplayHex(bc.tipHash),
		"old_height", bc.tipHeight)
	if err := bc.reorgTo(ctx, hashID); err != nil {
		log.Warn("REORGANIZE failed", "err", err)
		return OutcomeUnknown, height, err
	}
	bc.signalNewBlock()
	return OutcomeReorg, height, nil
}

// validateAndApply validates non-coinbase txns against the overlay view
// (chain UTXO + already-staged mutations) and stages this block's UTXO
// ops + undo record into the overlay. Caller must have bc.mu held. Does
// NOT update tip / meta and does NOT commit to disk — that is the
// caller's responsibility via overlay.commit. ctx is checked between
// per-tx validation passes so a cancellation mid-validation aborts
// before the overlay accumulates work that would have to be discarded.
func (bc *Blockchain) validateAndApply(ctx context.Context, overlay *utxoOverlay, b Block, height uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	hashID := b.Header.Hash()
	// Median-of-11 timestamp anchors IsFinal time-locked tx checks.
	medTime := bc.medianTimestamp(b.Header.PrevHash, 11)
	var coinbaseVal uint64
	for _, o := range b.Txns[0].Outputs {
		if o.Value > txn.MaxMoney || coinbaseVal+o.Value < coinbaseVal {
			return errors.New("block: coinbase output overflows MaxMoney")
		}
		coinbaseVal += o.Value
	}
	if coinbaseVal > txn.MaxMoney {
		return errors.New("block: coinbase value exceeds MaxMoney")
	}
	// Sigop-cost pre-pass. Purely a static property of the block's leaf
	// scripts (no UTXO lookup), so bail cheaply before we stage any
	// per-input work when the block is over-budget.
	var blockSigOps int
	for i := 1; i < len(b.Txns); i++ {
		blockSigOps += txn.SigOpCost(b.Txns[i])
	}
	if blockSigOps > MaxBlockSigOpsCost {
		return fmt.Errorf("block: sigop cost %d exceeds cap %d", blockSigOps, MaxBlockSigOpsCost)
	}

	spent := map[[36]byte]bool{}
	var totalFees uint64
	var undo undoRecord
	for i := 1; i < len(b.Txns); i++ {
		tx := b.Txns[i]
		if !tx.IsFinal(height, medTime) {
			return fmt.Errorf("block: non-final tx (locktime %d unmet at height %d, mtp %d)", tx.LockTime, height, medTime)
		}
		var inSum, outSum uint64
		for j, in := range tx.Inputs {
			key := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
			var ka [36]byte
			copy(ka[:], key.Bytes())
			if spent[ka] {
				return errors.New("block: double spend within block")
			}
			spent[ka] = true
			prev, prevCoinbase, prevHeight, err := overlay.get(key)
			if err != nil {
				return err
			}
			if prev == nil {
				return fmt.Errorf("block: missing utxo for input %d", j)
			}
			// Coinbase maturity: a coinbase output born at H may only be
			// spent in a block of height >= H + CoinbaseMaturity.
			if !testSkipCoinbaseMaturity && prevCoinbase && height < prevHeight+CoinbaseMaturity {
				return fmt.Errorf("block: coinbase spent before maturity (born %d, spent at %d)", prevHeight, height)
			}
			if !testSkipTxValidation {
				if !address.VerifyInclusion(prev.Address, in.Spend.LeafScript, in.Spend.LeafIndex, in.Spend.MerkleProof) {
					return errors.New("block: bad merkle proof on input")
				}
				sh := txn.SigHash(tx, j)
				ok, err := txn.Execute(in.Spend.LeafScript, in.Spend.Witness, sh)
				if err != nil || !ok {
					return fmt.Errorf("block: script fail on input %d: %v", j, err)
				}
			}
			if prev.Value > txn.MaxMoney || inSum+prev.Value < inSum {
				return errors.New("block: input value overflows MaxMoney")
			}
			inSum += prev.Value
			undo.Spent = append(undo.Spent, spentEntry{Key: key, Out: *prev, Coinbase: prevCoinbase, Height: prevHeight})
		}
		for _, o := range tx.Outputs {
			if o.Value > txn.MaxMoney || outSum+o.Value < outSum {
				return errors.New("block: output value overflows MaxMoney")
			}
			outSum += o.Value
		}
		if outSum > txn.MaxMoney {
			return errors.New("block: tx outputs exceed MaxMoney")
		}
		if inSum < outSum {
			return errors.New("block: outputs exceed inputs")
		}
		totalFees += inSum - outSum
		if totalFees > txn.MaxMoney {
			return errors.New("block: aggregate fees exceed MaxMoney")
		}
	}
	maxCoinbase := BlockReward(int(height)) + totalFees
	if coinbaseVal > maxCoinbase {
		return errors.New("block: coinbase value too high")
	}

	// Stage: remove spent, add created.
	for i := 1; i < len(b.Txns); i++ {
		tx := b.Txns[i]
		for _, in := range tx.Inputs {
			key := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
			overlay.del(key)
		}
	}
	for _, tx := range b.Txns {
		txid := tx.TxID()
		isCB := tx.IsCoinbase()
		for i, o := range tx.Outputs {
			k := txn.UTXOKey{TxID: txid, Index: uint32(i)}
			overlay.put(k, o, isCB, height)
			undo.Created = append(undo.Created, k)
		}
	}
	overlay.putUndo(hashID, undo)
	return nil
}

// rollbackBlock stages the reverse of a block's UTXO effects into the
// overlay, using the block's persisted undo record. Caller holds lock.
// Does NOT commit — reorgTo batches many rollbacks + applies before
// flushing.
func (bc *Blockchain) rollbackBlock(overlay *utxoOverlay, b Block) error {
	hashID := b.Header.Hash()
	u, err := bc.getUndo(hashID)
	if err != nil {
		return err
	}
	// Remove outputs this block created.
	for _, k := range u.Created {
		overlay.del(k)
	}
	// Restore outputs this block spent.
	for _, s := range u.Spent {
		overlay.put(s.Key, s.Out, s.Coinbase, s.Height)
	}
	return nil
}

// reorgTo switches the main chain to end at newTip atomically. Caller
// holds bc.mu.
//
// Strategy: stage every UTXO / undo / meta mutation for the full
// disconnect + connect pass into one utxoOverlay, validate every
// new-branch block against the accumulating overlay view, and commit
// exactly once at the end. If anything in staging or validation fails,
// the overlay is discarded — no disk mutation, no in-memory mutation,
// no callback events fired. The chain stays at `oldTip`.
func (bc *Blockchain) reorgTo(ctx context.Context, newTip [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	oldTip := bc.tipHash
	oldHeight := bc.tipHeight

	// Build path from newTip back to an ancestor that's on the main chain.
	var newBranch [][32]byte // from newTip back toward ancestor (exclusive)
	cur := newTip
	for {
		if _, onMain := bc.headersHts[cur]; onMain {
			break
		}
		newBranch = append(newBranch, cur)
		hdr, ok := bc.knownHdrs[cur]
		if !ok {
			h, err := bc.header(cur)
			if err != nil {
				return fmt.Errorf("reorg: header missing %x", cur)
			}
			hdr = h
		}
		cur = hdr.PrevHash
	}
	ancestor := cur
	ancestorHeight := bc.headersHts[ancestor]
	disconnectCount := int(oldHeight) - int(ancestorHeight)
	connectCount := len(newBranch)

	log.Info("REORGANIZE: starting",
		"ancestor", crypto.DisplayHex(ancestor),
		"ancestor_height", ancestorHeight,
		"disconnect_blocks", disconnectCount,
		"connect_blocks", connectCount,
		"old_tip", crypto.DisplayHex(oldTip),
		"new_tip", crypto.DisplayHex(newTip))

	overlay := bc.newOverlay()

	// Pending in-memory mutations + event queues. We do NOT mutate
	// bc.headersHts or fire any callbacks until overlay.commit() succeeds.
	type disconnectedBlock struct {
		hash   [32]byte
		block  Block
		height uint32
	}
	type connectedBlock struct {
		hash   [32]byte
		block  Block
		height uint32
	}
	var disconnectedBlocks []disconnectedBlock
	var connectedBlocks []connectedBlock

	// Stage disconnect: walk from old tip back to ancestor (exclusive).
	disconnect := bc.tipHash
	for disconnect != ancestor {
		blk, err := bc.GetBlock(ctx, disconnect)
		if err != nil {
			return err
		}
		disconnectHeight, ok := bc.headersHts[disconnect]
		if !ok {
			return fmt.Errorf("reorg: disconnect height missing for %x", disconnect)
		}
		if err := bc.rollbackBlock(overlay, *blk); err != nil {
			return fmt.Errorf("reorg: stage rollback: %w", err)
		}
		disconnectedBlocks = append(disconnectedBlocks, disconnectedBlock{
			hash: disconnect, block: *blk, height: disconnectHeight,
		})
		hdr, ok := bc.knownHdrs[disconnect]
		if !ok {
			hdr = blk.Header
		}
		disconnect = hdr.PrevHash
	}

	// Stage connect: walk new branch in ancestor+1 .. newTip order. Each
	// validateAndApply sees the overlay view, so later blocks correctly
	// consume UTXOs staged by earlier blocks in the same reorg.
	for i := len(newBranch) - 1; i >= 0; i-- {
		h := newBranch[i]
		blk, err := bc.GetBlock(ctx, h)
		if err != nil {
			return err
		}
		hk := append([]byte("height_"), h[:]...)
		hb, err := bc.db.Get([]byte(storage.BucketMeta), hk)
		if err != nil || len(hb) != 4 {
			return errors.New("reorg: height missing")
		}
		height := binary.BigEndian.Uint32(hb)
		if err := bc.validateAndApply(ctx, overlay, *blk, height); err != nil {
			// Overlay is discarded — disk + in-memory state untouched.
			log.Warn("REORGANIZE: connect failed, chain unchanged",
				"hash", crypto.DisplayHex(h), "height", height, "err", err)
			return fmt.Errorf("reorg: validate new branch: %w", err)
		}
		connectedBlocks = append(connectedBlocks, connectedBlock{
			hash: h, block: *blk, height: height,
		})
	}

	// Stage tip / meta into the same batch so the whole reorg is one
	// atomic disk write.
	newTipHeight, ok := bc.heightForHash(newTip)
	if !ok {
		return errors.New("reorg: new tip height missing")
	}
	newTotalWork, ok := bc.knownWork[newTip]
	if !ok {
		return errors.New("reorg: new tip work missing")
	}
	overlay.putMeta("best_hash", append([]byte(nil), newTip[:]...))
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], newTipHeight)
	overlay.putMeta("best_height", append([]byte(nil), hb[:]...))
	overlay.putMeta("total_work", newTotalWork.Bytes())

	if reorgCommitHook != nil {
		if err := reorgCommitHook(); err != nil {
			log.Warn("REORGANIZE: commit hook aborted, chain unchanged", "err", err)
			return fmt.Errorf("reorg: commit hook: %w", err)
		}
	}
	if err := overlay.commit(); err != nil {
		log.Error("REORGANIZE: commit failed, chain unchanged", "err", err)
		return fmt.Errorf("reorg: commit: %w", err)
	}

	// Commit succeeded: disk is now authoritative. Apply deferred
	// in-memory mutations and queue events.
	for _, d := range disconnectedBlocks {
		delete(bc.headersHts, d.hash)
		log.Debug("REORGANIZE: disconnected", "hash", crypto.DisplayHex(d.hash), "height", d.height, "txs", len(d.block.Txns))
		bc.fireDisconnected(d.block, d.height)
	}
	for _, c := range connectedBlocks {
		bc.headersHts[c.hash] = c.height
		log.Debug("REORGANIZE: connected", "hash", crypto.DisplayHex(c.hash), "height", c.height, "txs", len(c.block.Txns))
		bc.fireConnected(c.block, c.height)
	}
	bc.tipHash = newTip
	bc.tipHeight = newTipHeight
	bc.totalWork = new(big.Int).Set(newTotalWork)

	log.Info("REORGANIZE: complete",
		"new_tip", crypto.DisplayHex(newTip),
		"new_height", newTipHeight,
		"depth", disconnectCount)
	return nil
}

// heightForHash returns the height recorded at persistBlock time for any
// block we've ever seen (main or side branch). Reads `height_<hash>` from
// the meta bucket. Caller holds bc.mu.
func (bc *Blockchain) heightForHash(h [32]byte) (uint32, bool) {
	if ht, ok := bc.headersHts[h]; ok {
		return ht, true
	}
	hk := append([]byte("height_"), h[:]...)
	hb, err := bc.db.Get([]byte(storage.BucketMeta), hk)
	if err != nil || len(hb) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(hb), true
}

// --- orphan block pool ---

// bufferOrphan inserts a PoW-valid block whose parent is unknown into
// the in-memory pool, evicting the oldest entry if at capacity. Caller
// must hold bc.mu (we use a separate orphanMu so processOrphans can run
// without the chain lock).
func (bc *Blockchain) bufferOrphan(b Block) {
	hash := b.Header.Hash()
	bc.orphanMu.Lock()
	defer bc.orphanMu.Unlock()
	if _, ok := bc.orphans[hash]; ok {
		return
	}
	bc.gcOrphansLocked()
	if len(bc.orphans) >= MaxOrphanBlocks {
		bc.evictOldestOrphanLocked()
	}
	bc.orphans[hash] = orphanEntry{block: b, received: time.Now()}
	bc.orphansByParent[b.Header.PrevHash] = append(bc.orphansByParent[b.Header.PrevHash], hash)
	log.Debug("stored orphan block",
		"hash", crypto.DisplayHex(hash),
		"missing_parent", crypto.DisplayHex(b.Header.PrevHash),
		"pool_size", len(bc.orphans))
}

func (bc *Blockchain) gcOrphansLocked() {
	cutoff := time.Now().Add(-OrphanTTL)
	for h, e := range bc.orphans {
		if e.received.Before(cutoff) {
			bc.removeOrphanLocked(h, e.block.Header.PrevHash)
		}
	}
}

func (bc *Blockchain) evictOldestOrphanLocked() {
	var oldestHash [32]byte
	var oldestTime time.Time
	first := true
	var oldestParent [32]byte
	for h, e := range bc.orphans {
		if first || e.received.Before(oldestTime) {
			oldestHash = h
			oldestTime = e.received
			oldestParent = e.block.Header.PrevHash
			first = false
		}
	}
	if !first {
		bc.removeOrphanLocked(oldestHash, oldestParent)
	}
}

func (bc *Blockchain) removeOrphanLocked(hash, parent [32]byte) {
	delete(bc.orphans, hash)
	siblings := bc.orphansByParent[parent]
	for i, h := range siblings {
		if h == hash {
			siblings = append(siblings[:i], siblings[i+1:]...)
			break
		}
	}
	if len(siblings) == 0 {
		delete(bc.orphansByParent, parent)
	} else {
		bc.orphansByParent[parent] = siblings
	}
}

// processOrphans drains every orphan whose parent has just become
// known. Called after each successful AddBlock; iterative (not
// recursive) so a long chain of orphans connects without stack growth
// or re-entrant locks.
func (bc *Blockchain) processOrphans(ctx context.Context, connectedHash [32]byte) {
	queue := [][32]byte{connectedHash}
	reconnected := 0
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return
		}
		parent := queue[0]
		queue = queue[1:]

		bc.orphanMu.Lock()
		hashes := bc.orphansByParent[parent]
		// Pull each pending child out of the pool before attempting
		// reconnection, so a re-entry into AddBlock can't see them as
		// orphans of themselves.
		var children []Block
		for _, h := range hashes {
			if e, ok := bc.orphans[h]; ok {
				children = append(children, e.block)
			}
			bc.removeOrphanLocked(h, parent)
		}
		bc.orphanMu.Unlock()

		for _, child := range children {
			childHash := child.Header.Hash()
			outcome, _, err := bc.addBlockOnce(ctx, child)
			if err != nil {
				log.Debug("orphan reconnect rejected",
					"hash", crypto.DisplayHex(childHash),
					"parent", crypto.DisplayHex(parent),
					"err", err)
				continue
			}
			// Only count + cascade on outcomes that actually advanced the
			// chain. OutcomeOrphan re-buffers the block (parent vanished
			// concurrently); OutcomeDuplicate / OutcomeSideChain don't
			// extend the main tip and have no children worth scanning.
			if outcome != OutcomeExtended && outcome != OutcomeReorg {
				log.Debug("orphan reconnect non-extending",
					"hash", crypto.DisplayHex(childHash),
					"parent", crypto.DisplayHex(parent),
					"outcome", outcome)
				continue
			}
			log.Debug("connected orphan block",
				"hash", crypto.DisplayHex(childHash),
				"parent", crypto.DisplayHex(parent))
			reconnected++
			queue = append(queue, childHash)
		}
	}
	if reconnected > 0 {
		log.Info("drained orphan pool",
			"reconnected", reconnected,
			"trigger", crypto.DisplayHex(connectedHash),
			"remaining", bc.OrphanCount())
	}
}

// MissingOrphanParents returns the parent hashes of currently buffered
// orphans whose parent is not in the chain. The network layer uses this
// to issue a `getblocks` toward the missing root so the gap fills in.
func (bc *Blockchain) MissingOrphanParents() [][32]byte {
	bc.orphanMu.Lock()
	defer bc.orphanMu.Unlock()
	out := make([][32]byte, 0, len(bc.orphansByParent))
	for parent := range bc.orphansByParent {
		if !bc.HasBlock(parent) {
			out = append(out, parent)
		}
	}
	return out
}

// OrphanCount returns the current pool size (mainly for tests + metrics).
func (bc *Blockchain) OrphanCount() int {
	bc.orphanMu.Lock()
	defer bc.orphanMu.Unlock()
	return len(bc.orphans)
}

// medianTimestamp returns the median of up to `count` timestamps walking back from
// (and including) `from`. If fewer than count ancestors exist (short chain), uses
// whatever is available. Returns 0 if the start header can't be loaded.
func (bc *Blockchain) medianTimestamp(from [32]byte, count int) uint64 {
	var ts []uint64
	cur := from
	for i := 0; i < count; i++ {
		hdr, ok := bc.knownHdrs[cur]
		if !ok {
			h, err := bc.header(cur)
			if err != nil {
				break
			}
			hdr = h
		}
		ts = append(ts, hdr.Timestamp)
		if hdr.PrevHash == ([32]byte{}) {
			break
		}
		cur = hdr.PrevHash
	}
	if len(ts) == 0 {
		return 0
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts[len(ts)/2]
}

// FindTx searches the mempool-external chain for a transaction. Returns the tx,
// containing block hash, height, and found=true on success. ctx is
// polled inside the per-block scan so a cancellation aborts a long
// linear search promptly (the chain has no tx index yet — full scan).
func (bc *Blockchain) FindTx(ctx context.Context, txid [32]byte) (txn.Transaction, [32]byte, uint32, bool, error) {
	if err := ctx.Err(); err != nil {
		return txn.Transaction{}, [32]byte{}, 0, false, err
	}
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	var foundTx txn.Transaction
	var foundHash [32]byte
	var foundHeight uint32
	var found bool
	var ctxErr error
	err := bc.db.ForEach([]byte(storage.BucketBlocks), func(k, v []byte) error {
		if found {
			return nil
		}
		if err := ctx.Err(); err != nil {
			ctxErr = err
			return err
		}
		blk, err := DeserializeBlock(v)
		if err != nil {
			return nil // ignore corrupt entries
		}
		for _, tx := range blk.Txns {
			id := tx.TxID()
			if id == txid {
				foundTx = tx
				copy(foundHash[:], k)
				if h, ok := bc.headersHts[foundHash]; ok {
					foundHeight = h
				}
				found = true
				return nil
			}
		}
		return nil
	})
	if ctxErr != nil {
		return foundTx, foundHash, 0, false, ctxErr
	}
	if err != nil {
		return foundTx, foundHash, 0, false, err
	}
	return foundTx, foundHash, foundHeight, found, nil
}

// AddrTxRecord is a single wallet-history entry for an address.
type AddrTxRecord struct {
	TxID      [32]byte
	BlockHash [32]byte
	Height    uint32
	Received  uint64 // sum of outputs paying `addr`
	Sent      uint64 // sum of inputs spending prior outputs that paid `addr`
	Coinbase  bool
}

// ListTxsForAddress scans the chain (main-chain blocks only) and returns
// every tx that either paid `addr` (Received > 0) or spent a prior output
// that paid `addr` (Sent > 0). Records are sorted by ascending height,
// then by position within the block.
//
// Two-pass over main-chain blocks: pass 1 indexes (txid,index) -> value
// for every output that paid `addr`; pass 2 classifies each tx by
// summing its outputs to `addr` (received) and looking up each input's
// prev reference against the index (sent). O(chain) — acceptable for
// the RPC query path; not consensus-critical. ctx is polled between
// blocks so a long scan can be cancelled.
func (bc *Blockchain) ListTxsForAddress(ctx context.Context, addr address.P2MRAddress) ([]AddrTxRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	type blockAt struct {
		hash   [32]byte
		height uint32
	}
	mainChain := make([]blockAt, 0, bc.tipHeight+1)
	for h, height := range bc.headersHts {
		mainChain = append(mainChain, blockAt{hash: h, height: height})
	}
	sort.Slice(mainChain, func(i, j int) bool { return mainChain[i].height < mainChain[j].height })

	// Pass 1: index outputs to addr.
	paidToAddr := map[txn.UTXOKey]uint64{}
	for _, ba := range mainChain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := bc.db.Get([]byte(storage.BucketBlocks), ba.hash[:])
		if err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		blk, err := DeserializeBlock(raw)
		if err != nil {
			continue
		}
		for _, tx := range blk.Txns {
			id := tx.TxID()
			for i, out := range tx.Outputs {
				if out.Address.MerkleRoot == addr.MerkleRoot {
					paidToAddr[txn.UTXOKey{TxID: id, Index: uint32(i)}] = out.Value
				}
			}
		}
	}

	// Pass 2: classify each tx.
	var out []AddrTxRecord
	for _, ba := range mainChain {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		raw, err := bc.db.Get([]byte(storage.BucketBlocks), ba.hash[:])
		if err != nil {
			return nil, err
		}
		if raw == nil {
			continue
		}
		blk, err := DeserializeBlock(raw)
		if err != nil {
			continue
		}
		for _, tx := range blk.Txns {
			id := tx.TxID()
			var recv uint64
			for _, o := range tx.Outputs {
				if o.Address.MerkleRoot == addr.MerkleRoot {
					recv += o.Value
				}
			}
			var sent uint64
			if !tx.IsCoinbase() {
				for _, in := range tx.Inputs {
					if v, ok := paidToAddr[txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}]; ok {
						sent += v
					}
				}
			}
			if recv == 0 && sent == 0 {
				continue
			}
			out = append(out, AddrTxRecord{
				TxID:      id,
				BlockHash: ba.hash,
				Height:    ba.height,
				Received:  recv,
				Sent:      sent,
				Coinbase:  tx.IsCoinbase(),
			})
		}
	}
	return out, nil
}

// Locator returns a list of hashes to use in a getblocks exchange
// (tip, tip-1, tip-2, tip-4, tip-8, ... , genesis).
func (bc *Blockchain) Locator() [][32]byte {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	var out [][32]byte
	cur := bc.tipHash
	step := 1
	h := int(bc.tipHeight)
	for h >= 0 {
		out = append(out, cur)
		if h == 0 {
			break
		}
		dec := step
		if dec > h {
			dec = h
		}
		for i := 0; i < dec; i++ {
			hdr, err := bc.header(cur)
			if err != nil {
				return out
			}
			cur = hdr.PrevHash
		}
		h -= dec
		if len(out) >= 10 {
			step *= 2
		}
	}
	return out
}

// BlocksAfter returns up to n block hashes after the first hash in `locator` found in our chain.
// ctx cancellation short-circuits before the chain walk; nil is returned
// on a cancelled context (callers treat empty as "nothing to send", same
// as locator-not-found).
func (bc *Blockchain) BlocksAfter(ctx context.Context, locator [][32]byte, n int) [][32]byte {
	if err := ctx.Err(); err != nil {
		return nil
	}
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	var fork uint32
	found := false
	for _, h := range locator {
		if ht, ok := bc.headersHts[h]; ok {
			fork = ht
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	// Walk forward from fork+1 to tip.
	// Build height→hash map by walking back from tip.
	byHeight := map[uint32][32]byte{}
	cur := bc.tipHash
	height := bc.tipHeight
	for {
		byHeight[height] = cur
		if height == 0 {
			break
		}
		hdr, err := bc.header(cur)
		if err != nil {
			break
		}
		cur = hdr.PrevHash
		height--
	}
	var out [][32]byte
	for h := fork + 1; h <= bc.tipHeight && len(out) < n; h++ {
		if hh, ok := byHeight[h]; ok {
			out = append(out, hh)
		}
	}
	return out
}

// Helpers for callers to sort/known-hash things if needed.
var _ sort.Interface = (*sortBytes)(nil)

type sortBytes [][32]byte

func (s sortBytes) Len() int           { return len(s) }
func (s sortBytes) Less(i, j int) bool { return string(s[i][:]) < string(s[j][:]) }
func (s sortBytes) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// unused assertion
var _ = crypto.Hash256
