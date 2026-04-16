package core

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"
	"sync"
	"testing"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/storage"
	"qbitcoin/txn"
)

// These tests exercise the reorgTo atomicity refactor + the OnBlockDisconnected
// event ordering used for mempool re-injection in cmd/qbitcoind/main.go.
// They use the package-level test-bypass flags (testBypassPoW,
// testSkipTxValidation, testSkipHeaderTimeChecks) to avoid the otherwise
// prohibitive cost of mining + signing a deep test chain.

// enableTestBypasses is the in-package shorthand for
// TestEnableReorgBypasses (defined in testhelpers.go, which is exported
// for cross-package test use).
func enableTestBypasses(t *testing.T) {
	t.Helper()
	TestEnableReorgBypasses(t)
}

func newReorgTestChain(t *testing.T) (*Blockchain, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bc, err := NewBlockchain(db)
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	return bc, db
}

// testAddr builds a deterministic 32-byte P2MR address tagged by `tag`.
// Distinct tags produce distinct addresses, so UTXO balance queries can
// tell apart outputs from different test fixtures.
func testAddr(tag byte) address.P2MRAddress {
	var a address.P2MRAddress
	a.MerkleRoot[0] = tag
	a.MerkleRoot[31] = tag ^ 0xFF
	return a
}

// testCoinbase builds a minimal coinbase tx at `height` with a
// distinguishing `tag` in the witness so two coinbases at the same
// height (one per branch) have distinct TxIDs.
func testCoinbase(height uint32, tag byte, addr address.P2MRAddress) txn.Transaction {
	var heightBytes [4]byte
	binary.BigEndian.PutUint32(heightBytes[:], height)
	return txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0xFFFFFFFF,
			Spend:     address.P2MRSpend{Witness: [][]byte{heightBytes[:], {tag}}},
		}},
		Outputs: []txn.TxOutput{{
			Value:   BlockReward(int(height)),
			Address: addr,
		}},
	}
}

// testSpend builds a non-coinbase tx that consumes a single prev UTXO
// and produces one output at `value` paying `toAddr`. The remainder
// (prevValue - value) is left as miner fee. Script/proof/witness are
// bogus but validated only when testSkipTxValidation=false.
func testSpend(prevTxID [32]byte, prevIndex uint32, value uint64, toAddr address.P2MRAddress) txn.Transaction {
	return txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  prevTxID,
			PrevIndex: prevIndex,
			Spend:     address.P2MRSpend{LeafScript: address.LeafScript{0x01, 0xAB}, Witness: [][]byte{{0xCC}}},
		}},
		Outputs: []txn.TxOutput{{
			Value:   value,
			Address: toAddr,
		}},
	}
}

// testBuildBlock constructs a Block whose header cleanly commits to the
// supplied tx list. Nonce is left at 0 (PoW bypassed); timestamp is the
// caller's responsibility (mostly ignored under testSkipHeaderTimeChecks).
func testBuildBlock(prev [32]byte, timestamp uint64, txns []txn.Transaction) Block {
	leaves := make([][32]byte, len(txns))
	for i, t := range txns {
		leaves[i] = t.TxID()
	}
	h := BlockHeader{
		Version:    1,
		PrevHash:   prev,
		MerkleRoot: crypto.MerkleRoot(leaves),
		Timestamp:  timestamp,
		Bits:       GenesisBits,
		Nonce:      0,
	}
	return Block{Header: h, Txns: txns}
}

// --- snapshot helpers ---

// chainSnapshot is a byte-comparable view of all disk + in-memory state
// that a reorg should (and only should) mutate.
type chainSnapshot struct {
	tipHash    [32]byte
	tipHeight  uint32
	totalWork  string // hex of big-endian bytes
	utxos      string // sorted hex blob: key36 || value45, joined with '|'
	undos      string // sorted hex blob: hash32 || body, joined with '|'
	headersHts string // sorted "hex:height;..."
}

func takeSnapshot(t *testing.T, bc *Blockchain) chainSnapshot {
	t.Helper()
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	snap := chainSnapshot{
		tipHash:   bc.tipHash,
		tipHeight: bc.tipHeight,
		totalWork: hexOf(bc.totalWork.Bytes()),
	}
	// UTXOs: collect then sort.
	var utxoRows [][]byte
	err := bc.db.ForEach([]byte(storage.BucketUTXOs), func(k, v []byte) error {
		row := make([]byte, 0, len(k)+len(v))
		row = append(row, k...)
		row = append(row, v...)
		utxoRows = append(utxoRows, row)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot utxos: %v", err)
	}
	sort.Slice(utxoRows, func(i, j int) bool { return bytes.Compare(utxoRows[i], utxoRows[j]) < 0 })
	var ub bytes.Buffer
	for i, r := range utxoRows {
		if i > 0 {
			ub.WriteByte('|')
		}
		ub.WriteString(hexOf(r))
	}
	snap.utxos = ub.String()

	// Undo records.
	var undoRows [][]byte
	err = bc.db.ForEach([]byte(storage.BucketUndo), func(k, v []byte) error {
		row := make([]byte, 0, len(k)+len(v))
		row = append(row, k...)
		row = append(row, v...)
		undoRows = append(undoRows, row)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot undos: %v", err)
	}
	sort.Slice(undoRows, func(i, j int) bool { return bytes.Compare(undoRows[i], undoRows[j]) < 0 })
	var rb bytes.Buffer
	for i, r := range undoRows {
		if i > 0 {
			rb.WriteByte('|')
		}
		rb.WriteString(hexOf(r))
	}
	snap.undos = rb.String()

	// headersHts: capture the main-chain index only, sorted by hash.
	type entry struct {
		h [32]byte
		v uint32
	}
	ent := make([]entry, 0, len(bc.headersHts))
	for h, v := range bc.headersHts {
		ent = append(ent, entry{h: h, v: v})
	}
	sort.Slice(ent, func(i, j int) bool { return bytes.Compare(ent[i].h[:], ent[j].h[:]) < 0 })
	var hb bytes.Buffer
	for i, e := range ent {
		if i > 0 {
			hb.WriteByte(';')
		}
		hb.WriteString(hexOf(e.h[:]))
		hb.WriteByte(':')
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], e.v)
		hb.WriteString(hexOf(n[:]))
	}
	snap.headersHts = hb.String()
	return snap
}

func hexOf(b []byte) string {
	const hx = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i] = hx[c>>4]
		out[2*i+1] = hx[c&0x0F]
	}
	return string(out)
}

func assertSnapshotEq(t *testing.T, label string, a, b chainSnapshot) {
	t.Helper()
	if a.tipHash != b.tipHash {
		t.Errorf("%s: tipHash differs: %x vs %x", label, a.tipHash, b.tipHash)
	}
	if a.tipHeight != b.tipHeight {
		t.Errorf("%s: tipHeight differs: %d vs %d", label, a.tipHeight, b.tipHeight)
	}
	if a.totalWork != b.totalWork {
		t.Errorf("%s: totalWork differs", label)
	}
	if a.utxos != b.utxos {
		t.Errorf("%s: UTXO set differs\n  before:\n    %s\n  after:\n    %s", label, a.utxos, b.utxos)
	}
	if a.undos != b.undos {
		t.Errorf("%s: undo records differ", label)
	}
	if a.headersHts != b.headersHts {
		t.Errorf("%s: headersHts differs: %s vs %s", label, a.headersHts, b.headersHts)
	}
}

// ---- tests ----

// TestReorg_AtomicOnInvalidBlock is the headline atomicity test: a
// validly-PoW'd side branch that internally contains an invalid block
// (referencing a non-existent UTXO) must not leave the chain in a
// partially-reorged state. Snapshot before the reorg attempt must equal
// snapshot after.
func TestReorg_AtomicOnInvalidBlock(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	genesis := bc.tipHash
	addrMain := testAddr(0x11)
	addrSide := testAddr(0x22)

	// Main: genesis -> A -> B  (height 2)
	blkA := testBuildBlock(genesis, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addrMain)})
	mustAddBlock(t, bc, blkA, OutcomeExtended)
	blkB := testBuildBlock(blkA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addrMain)})
	mustAddBlock(t, bc, blkB, OutcomeExtended)

	// Side: genesis -> A' -> B'_invalid -> C'  (height 3, more work than main)
	// B'_invalid's 2nd tx spends a non-existent UTXO → validateAndApply
	// rejects when the reorg tries to connect it.
	sideA := testBuildBlock(genesis, 2000, []txn.Transaction{testCoinbase(1, 0xA1, addrSide)})
	mustAddBlock(t, bc, sideA, OutcomeSideChain)

	badSpend := testSpend([32]byte{0xDE, 0xAD}, 0, 100, addrSide)
	sideBinvalid := testBuildBlock(sideA.Header.Hash(), 2001,
		[]txn.Transaction{testCoinbase(2, 0xB1, addrSide), badSpend})
	mustAddBlock(t, bc, sideBinvalid, OutcomeSideChain)

	sideC := testBuildBlock(sideBinvalid.Header.Hash(), 2002,
		[]txn.Transaction{testCoinbase(3, 0xC1, addrSide)})

	// Snapshot the full state right before the reorg attempt.
	before := takeSnapshot(t, bc)
	if before.tipHash != blkB.Header.Hash() {
		t.Fatalf("pre-reorg tip should be B, got %x", before.tipHash)
	}

	// Adding sideC should trigger a reorg attempt that fails mid-connect.
	outcome, _, err := bc.AddBlock(t.Context(), sideC)
	if err == nil {
		t.Fatalf("AddBlock(sideC) expected reorg failure, got outcome=%v", outcome)
	}

	after := takeSnapshot(t, bc)
	assertSnapshotEq(t, "after failed reorg", before, after)

	// Sanity: the new tip must still be B, not partially-reorged.
	if bc.tipHash != blkB.Header.Hash() {
		t.Fatalf("tip moved on failed reorg: got %x want %x", bc.tipHash, blkB.Header.Hash())
	}
}

// TestReorg_AtomicAcrossRestart confirms that a failed reorg's "no
// mutation" guarantee is durable: closing and reopening the DB yields
// the same pre-reorg state.
func TestReorg_AtomicAcrossRestart(t *testing.T) {
	enableTestBypasses(t)
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := NewBlockchain(db)
	if err != nil {
		t.Fatal(err)
	}
	genesis := bc.tipHash
	addr := testAddr(0x33)

	blkA := testBuildBlock(genesis, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addr)})
	mustAddBlock(t, bc, blkA, OutcomeExtended)
	blkB := testBuildBlock(blkA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addr)})
	mustAddBlock(t, bc, blkB, OutcomeExtended)

	sideA := testBuildBlock(genesis, 2000, []txn.Transaction{testCoinbase(1, 0xA1, addr)})
	mustAddBlock(t, bc, sideA, OutcomeSideChain)
	badSpend := testSpend([32]byte{0xBE, 0xEF}, 0, 100, addr)
	sideBinvalid := testBuildBlock(sideA.Header.Hash(), 2001,
		[]txn.Transaction{testCoinbase(2, 0xB1, addr), badSpend})
	mustAddBlock(t, bc, sideBinvalid, OutcomeSideChain)
	sideC := testBuildBlock(sideBinvalid.Header.Hash(), 2002,
		[]txn.Transaction{testCoinbase(3, 0xC1, addr)})

	before := takeSnapshot(t, bc)
	if _, _, err := bc.AddBlock(t.Context(), sideC); err == nil {
		t.Fatal("expected failing reorg")
	}

	// Close and reopen — the on-disk state must match what we had before.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2, err := storage.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	bc2, err := NewBlockchain(db2)
	if err != nil {
		t.Fatal(err)
	}
	after := takeSnapshot(t, bc2)
	assertSnapshotEq(t, "post-restart vs pre-reorg", before, after)
}

// TestReorg_AtomicWithCommitHookFailure uses reorgCommitHook to simulate
// a disk-commit failure AFTER all staging passes. State must still be
// fully unchanged. Then the hook is cleared and the reorg succeeds.
func TestReorg_AtomicWithCommitHookFailure(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	genesis := bc.tipHash
	addrMain := testAddr(0x44)
	addrSide := testAddr(0x55)

	blkA := testBuildBlock(genesis, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addrMain)})
	mustAddBlock(t, bc, blkA, OutcomeExtended)
	blkB := testBuildBlock(blkA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addrMain)})
	mustAddBlock(t, bc, blkB, OutcomeExtended)

	sideA := testBuildBlock(genesis, 2000, []txn.Transaction{testCoinbase(1, 0xA1, addrSide)})
	mustAddBlock(t, bc, sideA, OutcomeSideChain)
	sideB := testBuildBlock(sideA.Header.Hash(), 2001, []txn.Transaction{testCoinbase(2, 0xB1, addrSide)})
	mustAddBlock(t, bc, sideB, OutcomeSideChain)
	sideC := testBuildBlock(sideB.Header.Hash(), 2002, []txn.Transaction{testCoinbase(3, 0xC1, addrSide)})

	before := takeSnapshot(t, bc)

	reorgCommitHook = func() error { return errInjected }
	_, _, err := bc.AddBlock(t.Context(), sideC)
	reorgCommitHook = nil
	if err == nil {
		t.Fatal("expected commit-hook injected failure")
	}
	after := takeSnapshot(t, bc)
	assertSnapshotEq(t, "after hook-aborted reorg", before, after)

	// Hook cleared — the same sideC block (now cached? No: sideC was
	// persisted but the parent chain is unchanged; we'd need to re-apply
	// the side by advancing work). Extend the side with another block to
	// retry the reorg.
	sideD := testBuildBlock(sideC.Header.Hash(), 2003, []txn.Transaction{testCoinbase(4, 0xD1, addrSide)})
	outcome, _, err := bc.AddBlock(t.Context(), sideD)
	if err != nil {
		t.Fatalf("retry reorg after hook cleared: %v", err)
	}
	if outcome != OutcomeReorg {
		t.Fatalf("expected OutcomeReorg on retry, got %v", outcome)
	}
	if bc.tipHash != sideD.Header.Hash() {
		t.Fatalf("tip did not advance to sideD: got %x want %x", bc.tipHash, sideD.Header.Hash())
	}
}

// errInjected is the sentinel returned by reorgCommitHook in tests.
var errInjected = errReorgInjected{}

type errReorgInjected struct{}

func (errReorgInjected) Error() string { return "injected commit failure" }

// TestReorg_SuccessMatchesDirectApply verifies the positive atomicity
// property: the UTXO set after a successful reorg equals what you'd
// get by applying the winning branch directly on a fresh chain.
func TestReorg_SuccessMatchesDirectApply(t *testing.T) {
	enableTestBypasses(t)

	addr := testAddr(0x66)

	// Chain via reorg: main=[A,B,C], then side=[A',B',C',D'] overtakes.
	bcReorg, _ := newReorgTestChain(t)
	genesisR := bcReorg.tipHash

	mA := testBuildBlock(genesisR, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addr)})
	mustAddBlock(t, bcReorg, mA, OutcomeExtended)
	mB := testBuildBlock(mA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addr)})
	mustAddBlock(t, bcReorg, mB, OutcomeExtended)
	mC := testBuildBlock(mB.Header.Hash(), 1002, []txn.Transaction{testCoinbase(3, 0xC0, addr)})
	mustAddBlock(t, bcReorg, mC, OutcomeExtended)

	sA := testBuildBlock(genesisR, 2000, []txn.Transaction{testCoinbase(1, 0xA1, addr)})
	mustAddBlock(t, bcReorg, sA, OutcomeSideChain)
	sB := testBuildBlock(sA.Header.Hash(), 2001, []txn.Transaction{testCoinbase(2, 0xB1, addr)})
	mustAddBlock(t, bcReorg, sB, OutcomeSideChain)
	sC := testBuildBlock(sB.Header.Hash(), 2002, []txn.Transaction{testCoinbase(3, 0xC1, addr)})
	mustAddBlock(t, bcReorg, sC, OutcomeSideChain)
	sD := testBuildBlock(sC.Header.Hash(), 2003, []txn.Transaction{testCoinbase(4, 0xD1, addr)})
	mustAddBlock(t, bcReorg, sD, OutcomeReorg)

	// Chain via direct apply: only the winning branch, clean start.
	bcDirect, _ := newReorgTestChain(t)
	// Rebuild side blocks bit-for-bit against bcDirect's genesis (same
	// genesis constant, so headers hash identically).
	if bcDirect.tipHash != genesisR {
		t.Fatalf("genesis mismatch across chains")
	}
	mustAddBlock(t, bcDirect, sA, OutcomeExtended)
	mustAddBlock(t, bcDirect, sB, OutcomeExtended)
	mustAddBlock(t, bcDirect, sC, OutcomeExtended)
	mustAddBlock(t, bcDirect, sD, OutcomeExtended)

	// Compare UTXO sets only — block/undo stores legitimately differ
	// (bcReorg also stored the losing main chain as side-chain blocks).
	reorgUTXO := dumpUTXOs(t, bcReorg)
	directUTXO := dumpUTXOs(t, bcDirect)
	if reorgUTXO != directUTXO {
		t.Errorf("UTXO divergence after reorg vs direct apply\n  reorg:  %s\n  direct: %s",
			reorgUTXO, directUTXO)
	}
	if bcReorg.tipHash != bcDirect.tipHash {
		t.Fatalf("tip divergence: reorg=%x direct=%x", bcReorg.tipHash, bcDirect.tipHash)
	}
	if bcReorg.totalWork.Cmp(bcDirect.totalWork) != 0 {
		t.Fatalf("totalWork divergence: reorg=%s direct=%s",
			bcReorg.totalWork.String(), bcDirect.totalWork.String())
	}
	if bcReorg.tipHeight != bcDirect.tipHeight {
		t.Fatalf("tipHeight divergence: reorg=%d direct=%d", bcReorg.tipHeight, bcDirect.tipHeight)
	}
}

// TestReorg_NoEventsFiredOnFailedReorg pins the post-commit-event-order
// invariant: subscribers only ever see events for reorgs that actually
// landed.
func TestReorg_NoEventsFiredOnFailedReorg(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	type event struct {
		kind string
		h    [32]byte
	}
	var mu sync.Mutex
	var events []event
	bc.OnBlockConnected(func(b Block, _ uint32) {
		mu.Lock()
		events = append(events, event{kind: "connect", h: b.Header.Hash()})
		mu.Unlock()
	})
	bc.OnBlockDisconnected(func(b Block, _ uint32) {
		mu.Lock()
		events = append(events, event{kind: "disconnect", h: b.Header.Hash()})
		mu.Unlock()
	})

	genesis := bc.tipHash
	addr := testAddr(0x77)

	mA := testBuildBlock(genesis, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addr)})
	mustAddBlock(t, bc, mA, OutcomeExtended)
	mB := testBuildBlock(mA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addr)})
	mustAddBlock(t, bc, mB, OutcomeExtended)

	// Snapshot event count after the clean extensions.
	mu.Lock()
	extensionEvents := len(events)
	mu.Unlock()

	sA := testBuildBlock(genesis, 2000, []txn.Transaction{testCoinbase(1, 0xA1, addr)})
	mustAddBlock(t, bc, sA, OutcomeSideChain)
	badSpend := testSpend([32]byte{0xCA, 0xFE}, 0, 100, addr)
	sBinvalid := testBuildBlock(sA.Header.Hash(), 2001,
		[]txn.Transaction{testCoinbase(2, 0xB1, addr), badSpend})
	mustAddBlock(t, bc, sBinvalid, OutcomeSideChain)
	sC := testBuildBlock(sBinvalid.Header.Hash(), 2002,
		[]txn.Transaction{testCoinbase(3, 0xC1, addr)})

	if _, _, err := bc.AddBlock(t.Context(), sC); err == nil {
		t.Fatal("expected failing reorg")
	}

	mu.Lock()
	totalEvents := len(events)
	mu.Unlock()
	if totalEvents != extensionEvents {
		t.Fatalf("failed reorg fired %d events (expected 0 beyond the %d extensions)",
			totalEvents-extensionEvents, extensionEvents)
	}
}

// TestReorg_CorrectEventsFiredOnSuccess verifies that a successful
// reorg fires disconnect-events first (old tip down), then
// connect-events (ancestor+1 up), in order.
func TestReorg_CorrectEventsFiredOnSuccess(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	type event struct {
		kind string
		h    [32]byte
	}
	var mu sync.Mutex
	var events []event
	bc.OnBlockConnected(func(b Block, _ uint32) {
		mu.Lock()
		events = append(events, event{kind: "connect", h: b.Header.Hash()})
		mu.Unlock()
	})
	bc.OnBlockDisconnected(func(b Block, _ uint32) {
		mu.Lock()
		events = append(events, event{kind: "disconnect", h: b.Header.Hash()})
		mu.Unlock()
	})

	genesis := bc.tipHash
	addr := testAddr(0x88)

	mA := testBuildBlock(genesis, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addr)})
	mustAddBlock(t, bc, mA, OutcomeExtended)
	mB := testBuildBlock(mA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addr)})
	mustAddBlock(t, bc, mB, OutcomeExtended)

	// Clear events so we only see the reorg-fired ones.
	mu.Lock()
	events = nil
	mu.Unlock()

	sA := testBuildBlock(genesis, 2000, []txn.Transaction{testCoinbase(1, 0xA1, addr)})
	mustAddBlock(t, bc, sA, OutcomeSideChain)
	sB := testBuildBlock(sA.Header.Hash(), 2001, []txn.Transaction{testCoinbase(2, 0xB1, addr)})
	mustAddBlock(t, bc, sB, OutcomeSideChain)
	sC := testBuildBlock(sB.Header.Hash(), 2002, []txn.Transaction{testCoinbase(3, 0xC1, addr)})
	mustAddBlock(t, bc, sC, OutcomeReorg)

	mu.Lock()
	got := append([]event(nil), events...)
	mu.Unlock()

	// Expected sequence: disconnect(mB), disconnect(mA), connect(sA),
	// connect(sB), connect(sC).
	want := []event{
		{"disconnect", mB.Header.Hash()},
		{"disconnect", mA.Header.Hash()},
		{"connect", sA.Header.Hash()},
		{"connect", sB.Header.Hash()},
		{"connect", sC.Header.Hash()},
	}
	if len(got) != len(want) {
		t.Fatalf("event count: got %d want %d (%v)", len(got), len(want), got)
	}
	for i, e := range got {
		if e != want[i] {
			t.Errorf("event[%d]: got {%s %x} want {%s %x}",
				i, e.kind, e.h[:4], want[i].kind, want[i].h[:4])
		}
	}
}

// TestReorg_ExtensionAtomicOnCommitFailure covers the simple-extension
// code path: a commit failure during a non-reorg block apply must also
// leave the chain unchanged.
func TestReorg_ExtensionAtomicOnCommitFailure(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	genesis := bc.tipHash
	addr := testAddr(0x99)

	mA := testBuildBlock(genesis, 1000, []txn.Transaction{testCoinbase(1, 0xA0, addr)})
	mustAddBlock(t, bc, mA, OutcomeExtended)

	before := takeSnapshot(t, bc)

	// Inject a failure right before extension commit.
	reorgCommitHook = func() error { return errInjected }
	mB := testBuildBlock(mA.Header.Hash(), 1001, []txn.Transaction{testCoinbase(2, 0xB0, addr)})
	_, _, err := bc.AddBlock(t.Context(), mB)
	reorgCommitHook = nil
	if err == nil {
		t.Fatal("expected extension to fail under commit hook")
	}

	after := takeSnapshot(t, bc)
	assertSnapshotEq(t, "after aborted extension", before, after)
}

// ---- small helpers ----

func mustAddBlock(t *testing.T, bc *Blockchain, b Block, want AddBlockOutcome) {
	t.Helper()
	got, _, err := bc.AddBlock(t.Context(), b)
	if err != nil {
		t.Fatalf("AddBlock(%x): %v", b.Header.Hash(), err)
	}
	if got != want {
		t.Fatalf("AddBlock(%x) outcome = %v, want %v", b.Header.Hash(), got, want)
	}
}

func dumpUTXOs(t *testing.T, bc *Blockchain) string {
	t.Helper()
	var rows [][]byte
	err := bc.db.ForEach([]byte(storage.BucketUTXOs), func(k, v []byte) error {
		row := make([]byte, 0, len(k)+len(v))
		row = append(row, k...)
		row = append(row, v...)
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatalf("dumpUTXOs: %v", err)
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i], rows[j]) < 0 })
	var buf bytes.Buffer
	for i, r := range rows {
		if i > 0 {
			buf.WriteByte('|')
		}
		buf.WriteString(hexOf(r))
	}
	return buf.String()
}

// Avoid "declared and not used" for math/big if later tests drop it.
var _ = big.NewInt
