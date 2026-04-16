package mempool

import (
	"encoding/binary"
	"sync"
	"testing"

	"qbitcoin/address"
	"qbitcoin/core"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// These tests exercise the interaction between mempool.Add and a reorg
// that disconnects blocks — specifically, the re-injection callback
// that cmd/qbitcoind/main.go wires up via core.Blockchain.OnBlockDisconnected.
// The callback body is duplicated here (not imported) so the test
// doesn't pull in main's flag parsing. Any semantic drift between the
// two copies should be caught by the assertions.

func reinjectCallback(chain *core.Blockchain, pool *Mempool) func(core.Block, uint32) {
	return func(b core.Block, _ uint32) {
		nh, nt := chain.NextBlockContext()
		u := chain.ChainUTXO()
		for _, tx := range b.Txns {
			if tx.IsCoinbase() {
				continue
			}
			_ = pool.Add(tx, u, nh, nt)
		}
	}
}

// ---- fixtures ----

func reinjectAddr(tag byte) address.P2MRAddress {
	var a address.P2MRAddress
	a.MerkleRoot[0] = tag
	a.MerkleRoot[31] = tag ^ 0xFF
	return a
}

func reinjectCoinbase(height uint32, tag byte, addr address.P2MRAddress) txn.Transaction {
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], height)
	return txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0xFFFFFFFF,
			Spend:     address.P2MRSpend{Witness: [][]byte{hb[:], {tag}}},
		}},
		Outputs: []txn.TxOutput{{
			Value:   core.BlockReward(int(height)),
			Address: addr,
		}},
	}
}

func reinjectSpend(prevTxID [32]byte, prevIdx uint32, value uint64, to address.P2MRAddress) txn.Transaction {
	return txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  prevTxID,
			PrevIndex: prevIdx,
			Spend:     address.P2MRSpend{LeafScript: address.LeafScript{0x01, 0xAB}, Witness: [][]byte{{0xCC}}},
		}},
		Outputs: []txn.TxOutput{{Value: value, Address: to}},
	}
}

func reinjectBuildBlock(prev [32]byte, timestamp uint64, txns []txn.Transaction) core.Block {
	leaves := make([][32]byte, len(txns))
	for i, t := range txns {
		leaves[i] = t.TxID()
	}
	h := core.BlockHeader{
		Version:    1,
		PrevHash:   prev,
		MerkleRoot: crypto.MerkleRoot(leaves),
		Timestamp:  timestamp,
		Bits:       core.GenesisBits,
		Nonce:      0,
	}
	return core.Block{Header: h, Txns: txns}
}

// ---- harness ----

type reorgHarness struct {
	t     *testing.T
	bc    *core.Blockchain
	pool  *Mempool
	mu    sync.Mutex
	fired []core.Block
}

func newReorgHarness(t *testing.T) *reorgHarness {
	t.Helper()
	core.TestEnableReorgBypasses(t)
	bc := core.TestNewChain(t)
	pool := New()
	h := &reorgHarness{t: t, bc: bc, pool: pool}
	base := reinjectCallback(bc, pool)
	bc.OnBlockDisconnected(func(b core.Block, height uint32) {
		h.mu.Lock()
		h.fired = append(h.fired, b)
		h.mu.Unlock()
		base(b, height)
	})
	return h
}

func (h *reorgHarness) genesis() [32]byte {
	g, _ := h.bc.Tip()
	return g
}

// ---- tests ----

// TestReinject_BasicRoundTrip — a non-coinbase tx in a disconnected
// block ends up in the mempool after reorg, provided its input is
// restored by the rollback.
func TestReinject_BasicRoundTrip(t *testing.T) {
	h := newReorgHarness(t)
	addr := reinjectAddr(0x10)
	addrDst := reinjectAddr(0x11)
	genesis := h.genesis()

	// Main: A (cbA → U) -> B (T spends U) -> C (padding so side must
	// reach height 4 to overtake). Branching off A keeps cbA's output
	// available on the side branch.
	cbA := reinjectCoinbase(1, 0xA0, addr)
	blkA := reinjectBuildBlock(genesis, 1000, []txn.Transaction{cbA})
	mustAdd(t, h.bc, blkA, core.OutcomeExtended)

	T := reinjectSpend(cbA.TxID(), 0, 1_000_000_000, addrDst)
	blkB := reinjectBuildBlock(blkA.Header.Hash(), 1001,
		[]txn.Transaction{reinjectCoinbase(2, 0xB0, addr), T})
	mustAdd(t, h.bc, blkB, core.OutcomeExtended)

	blkC := reinjectBuildBlock(blkB.Header.Hash(), 1002,
		[]txn.Transaction{reinjectCoinbase(3, 0xC0, addr)})
	mustAdd(t, h.bc, blkC, core.OutcomeExtended)

	s1 := reinjectBuildBlock(blkA.Header.Hash(), 2000,
		[]txn.Transaction{reinjectCoinbase(2, 0xB1, addr)})
	mustAdd(t, h.bc, s1, core.OutcomeSideChain)
	s2 := reinjectBuildBlock(s1.Header.Hash(), 2001,
		[]txn.Transaction{reinjectCoinbase(3, 0xC1, addr)})
	mustAdd(t, h.bc, s2, core.OutcomeSideChain)
	s3 := reinjectBuildBlock(s2.Header.Hash(), 2002,
		[]txn.Transaction{reinjectCoinbase(4, 0xD1, addr)})
	mustAdd(t, h.bc, s3, core.OutcomeReorg)

	if got := h.pool.Get(T.TxID()); got == nil {
		t.Fatal("expected T back in mempool after reorg")
	}
}

// TestReinject_DroppedWhenDoubleSpentByNewBranch — a disconnected tx is
// silently rejected (not re-injected) when the new branch has already
// consumed its input.
func TestReinject_DroppedWhenDoubleSpentByNewBranch(t *testing.T) {
	h := newReorgHarness(t)
	addr := reinjectAddr(0x20)
	addrAlt := reinjectAddr(0x21)
	genesis := h.genesis()

	cbA := reinjectCoinbase(1, 0xA0, addr)
	blkA := reinjectBuildBlock(genesis, 1000, []txn.Transaction{cbA})
	mustAdd(t, h.bc, blkA, core.OutcomeExtended)

	T := reinjectSpend(cbA.TxID(), 0, 1_000_000_000, addrAlt)
	blkB := reinjectBuildBlock(blkA.Header.Hash(), 1001,
		[]txn.Transaction{reinjectCoinbase(2, 0xB0, addr), T})
	mustAdd(t, h.bc, blkB, core.OutcomeExtended)

	blkC := reinjectBuildBlock(blkB.Header.Hash(), 1002,
		[]txn.Transaction{reinjectCoinbase(3, 0xC0, addr)})
	mustAdd(t, h.bc, blkC, core.OutcomeExtended)

	// Side s1 also consumes cbA's output but pays Talt instead of T.
	// Side must reach height 4 to overtake main's height-3 tip.
	Talt := reinjectSpend(cbA.TxID(), 0, 1_000_000_000, addr)
	s1 := reinjectBuildBlock(blkA.Header.Hash(), 2000,
		[]txn.Transaction{reinjectCoinbase(2, 0xB1, addr), Talt})
	mustAdd(t, h.bc, s1, core.OutcomeSideChain)
	s2 := reinjectBuildBlock(s1.Header.Hash(), 2001,
		[]txn.Transaction{reinjectCoinbase(3, 0xC1, addr)})
	mustAdd(t, h.bc, s2, core.OutcomeSideChain)
	s3 := reinjectBuildBlock(s2.Header.Hash(), 2002,
		[]txn.Transaction{reinjectCoinbase(4, 0xD1, addr)})
	mustAdd(t, h.bc, s3, core.OutcomeReorg)

	if got := h.pool.Get(T.TxID()); got != nil {
		t.Fatal("T should not re-enter mempool (input consumed by new branch)")
	}
	if got := h.pool.Get(Talt.TxID()); got != nil {
		t.Fatal("Talt confirmed on new chain, should not appear in mempool")
	}
}

// TestReinject_SkipsCoinbase — coinbase txs of a disconnected block are
// not passed to pool.Add.
func TestReinject_SkipsCoinbase(t *testing.T) {
	h := newReorgHarness(t)
	addr := reinjectAddr(0x40)
	genesis := h.genesis()

	cbA := reinjectCoinbase(1, 0xA0, addr)
	blkA := reinjectBuildBlock(genesis, 1000, []txn.Transaction{cbA})
	mustAdd(t, h.bc, blkA, core.OutcomeExtended)

	s1 := reinjectBuildBlock(genesis, 2000,
		[]txn.Transaction{reinjectCoinbase(1, 0xA1, addr)})
	mustAdd(t, h.bc, s1, core.OutcomeSideChain)
	s2 := reinjectBuildBlock(s1.Header.Hash(), 2001,
		[]txn.Transaction{reinjectCoinbase(2, 0xB1, addr)})
	mustAdd(t, h.bc, s2, core.OutcomeReorg)

	if got := h.pool.Get(cbA.TxID()); got != nil {
		t.Fatal("coinbase from disconnected block should not enter mempool")
	}
	if h.pool.Size() != 0 {
		t.Fatalf("pool should be empty, size=%d", h.pool.Size())
	}
}

// TestReinject_SurvivesMultiBlockDisconnect — 3-deep reorg where every
// disconnected block has a non-coinbase tx, all inputs independent and
// restored by rollback. All three must re-enter.
func TestReinject_SurvivesMultiBlockDisconnect(t *testing.T) {
	h := newReorgHarness(t)
	addr := reinjectAddr(0x50)
	addrDst := reinjectAddr(0x51)
	genesis := h.genesis()

	// Build up three spendable coinbases at heights 1/2/3.
	cb1 := reinjectCoinbase(1, 0xA0, addr)
	cb2 := reinjectCoinbase(2, 0xA1, addr)
	cb3 := reinjectCoinbase(3, 0xA2, addr)
	blk1 := reinjectBuildBlock(genesis, 1000, []txn.Transaction{cb1})
	mustAdd(t, h.bc, blk1, core.OutcomeExtended)
	blk2 := reinjectBuildBlock(blk1.Header.Hash(), 1001, []txn.Transaction{cb2})
	mustAdd(t, h.bc, blk2, core.OutcomeExtended)
	blk3 := reinjectBuildBlock(blk2.Header.Hash(), 1002, []txn.Transaction{cb3})
	mustAdd(t, h.bc, blk3, core.OutcomeExtended)

	// Heights 4/5/6 each spend one of those three.
	T1 := reinjectSpend(cb1.TxID(), 0, 1_000_000_000, addrDst)
	T2 := reinjectSpend(cb2.TxID(), 0, 1_000_000_000, addrDst)
	T3 := reinjectSpend(cb3.TxID(), 0, 1_000_000_000, addrDst)
	blk4 := reinjectBuildBlock(blk3.Header.Hash(), 1003,
		[]txn.Transaction{reinjectCoinbase(4, 0xB0, addr), T1})
	mustAdd(t, h.bc, blk4, core.OutcomeExtended)
	blk5 := reinjectBuildBlock(blk4.Header.Hash(), 1004,
		[]txn.Transaction{reinjectCoinbase(5, 0xB1, addr), T2})
	mustAdd(t, h.bc, blk5, core.OutcomeExtended)
	blk6 := reinjectBuildBlock(blk5.Header.Hash(), 1005,
		[]txn.Transaction{reinjectCoinbase(6, 0xB2, addr), T3})
	mustAdd(t, h.bc, blk6, core.OutcomeExtended)

	// Side branches off blk3 and is one block longer → overtakes.
	s1 := reinjectBuildBlock(blk3.Header.Hash(), 2000,
		[]txn.Transaction{reinjectCoinbase(4, 0xC0, addr)})
	mustAdd(t, h.bc, s1, core.OutcomeSideChain)
	s2 := reinjectBuildBlock(s1.Header.Hash(), 2001,
		[]txn.Transaction{reinjectCoinbase(5, 0xC1, addr)})
	mustAdd(t, h.bc, s2, core.OutcomeSideChain)
	s3 := reinjectBuildBlock(s2.Header.Hash(), 2002,
		[]txn.Transaction{reinjectCoinbase(6, 0xC2, addr)})
	mustAdd(t, h.bc, s3, core.OutcomeSideChain)
	s4 := reinjectBuildBlock(s3.Header.Hash(), 2003,
		[]txn.Transaction{reinjectCoinbase(7, 0xC3, addr)})
	mustAdd(t, h.bc, s4, core.OutcomeReorg)

	for i, T := range []txn.Transaction{T1, T2, T3} {
		if got := h.pool.Get(T.TxID()); got == nil {
			t.Fatalf("T%d did not re-enter mempool", i+1)
		}
	}
	if h.pool.Size() != 3 {
		t.Fatalf("pool size = %d, want 3", h.pool.Size())
	}
}

// TestReinject_DisconnectCallbackFiresOnlyPostCommit — the harness
// records which blocks its OnBlockDisconnected callback sees. For a
// failing reorg the callback must fire zero times (no mutation landed).
// For a successful reorg, exactly the old-branch blocks fire.
func TestReinject_DisconnectCallbackFiresOnlyPostCommit(t *testing.T) {
	h := newReorgHarness(t)
	addr := reinjectAddr(0x60)
	addrDst := reinjectAddr(0x61)
	genesis := h.genesis()

	cbA := reinjectCoinbase(1, 0xA0, addr)
	blkA := reinjectBuildBlock(genesis, 1000, []txn.Transaction{cbA})
	mustAdd(t, h.bc, blkA, core.OutcomeExtended)
	T := reinjectSpend(cbA.TxID(), 0, 1_000_000_000, addrDst)
	blkB := reinjectBuildBlock(blkA.Header.Hash(), 1001,
		[]txn.Transaction{reinjectCoinbase(2, 0xB0, addr), T})
	mustAdd(t, h.bc, blkB, core.OutcomeExtended)
	blkC := reinjectBuildBlock(blkB.Header.Hash(), 1002,
		[]txn.Transaction{reinjectCoinbase(3, 0xC0, addr)})
	mustAdd(t, h.bc, blkC, core.OutcomeExtended)

	// Side branch off A. Its third block contains a non-existent-input
	// spend; that block is stored as side-chain (no validation at that
	// point), and only when the 4th side block arrives and triggers
	// reorg does the validation fire and abort.
	sideA := reinjectBuildBlock(blkA.Header.Hash(), 2000,
		[]txn.Transaction{reinjectCoinbase(2, 0xB1, addr)})
	mustAdd(t, h.bc, sideA, core.OutcomeSideChain)
	sideB := reinjectBuildBlock(sideA.Header.Hash(), 2001,
		[]txn.Transaction{reinjectCoinbase(3, 0xC1, addr)})
	mustAdd(t, h.bc, sideB, core.OutcomeSideChain)
	badSpend := reinjectSpend([32]byte{0xDE, 0xAD}, 0, 100, addrDst)
	sideCinvalid := reinjectBuildBlock(sideB.Header.Hash(), 2002,
		[]txn.Transaction{reinjectCoinbase(4, 0xD1, addr), badSpend})
	// sideCinvalid is at height 4 and overtakes main's height-3 tip →
	// reorg attempt fires, validation fails, chain stays at main.
	if _, _, err := h.bc.AddBlock(t.Context(), sideCinvalid); err == nil {
		t.Fatal("expected reorg to fail")
	}

	h.mu.Lock()
	firedCount := len(h.fired)
	h.mu.Unlock()
	if firedCount != 0 {
		t.Fatalf("disconnect callback fired %d times for failed reorg; want 0", firedCount)
	}
	// And T must NOT be in the pool (blkB stayed on the main chain).
	if got := h.pool.Get(T.TxID()); got != nil {
		t.Fatal("T should not be in mempool — blkB was never disconnected")
	}
}

// ---- helpers ----

func mustAdd(t *testing.T, bc *core.Blockchain, b core.Block, want core.AddBlockOutcome) {
	t.Helper()
	got, _, err := bc.AddBlock(t.Context(), b)
	if err != nil {
		t.Fatalf("AddBlock(%x): %v", b.Header.Hash(), err)
	}
	if got != want {
		t.Fatalf("AddBlock(%x) outcome = %v, want %v", b.Header.Hash(), got, want)
	}
}
