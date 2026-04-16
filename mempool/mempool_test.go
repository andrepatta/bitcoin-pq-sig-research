package mempool

import (
	"os"
	"testing"

	"qbitcoin/address"
	"qbitcoin/txn"
)

// Existing tests build minimal-fee fixtures that predate the min-relay
// gate. Disable it for the package-test run; RBF/min-relay logic is
// covered separately in their own tests.
func TestMain(m *testing.M) {
	MinRelayFeeRate = 0
	os.Exit(m.Run())
}

func mkUTXO(t *testing.T, val uint64) (txn.UTXOSet, txn.UTXOKey) {
	t.Helper()
	u := txn.NewMemUTXOSet()
	k := txn.UTXOKey{TxID: [32]byte{0xAA}, Index: 0}
	if err := u.Put(k, txn.TxOutput{Value: val, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xBB}}}); err != nil {
		t.Fatal(err)
	}
	return u, k
}

// TestMempool_RejectsNonFinal proves IsFinal gating runs at mempool entry.
func TestMempool_RejectsNonFinal(t *testing.T) {
	u, k := mkUTXO(t, 1000)
	mp := New()
	tx := txn.Transaction{
		Inputs:  []txn.TxInput{{PrevTxID: k.TxID, PrevIndex: k.Index}},
		Outputs: []txn.TxOutput{{Value: 900, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xCC}}}},
		// LockTime = nextHeight => not yet final (strict <).
		LockTime: 50,
	}
	if err := mp.Add(tx, u, 50, 0); err == nil {
		t.Fatal("expected non-final rejection")
	}
	if err := mp.Add(tx, u, 51, 0); err != nil {
		t.Fatalf("should accept once height passes locktime: %v", err)
	}
}

// TestMempool_RejectsOutputOverMaxMoney proves the per-output cap fires
// before the inSum<outSum check would catch an overflow.
func TestMempool_RejectsOutputOverMaxMoney(t *testing.T) {
	u, k := mkUTXO(t, 1)
	mp := New()
	tx := txn.Transaction{
		Inputs:  []txn.TxInput{{PrevTxID: k.TxID, PrevIndex: k.Index}},
		Outputs: []txn.TxOutput{{Value: txn.MaxMoney + 1, Address: address.P2MRAddress{}}},
	}
	if err := mp.Add(tx, u, 1, 0); err == nil {
		t.Fatal("expected MaxMoney rejection")
	}
}

// TestAdd_IdempotentOnDuplicate pins the no-op-on-re-add contract that
// the reorg re-injection path relies on: after a disconnected-block tx
// lands in the pool, a concurrent relay-triggered Add of the same tx
// must not double-count it or corrupt the `spent` conflict index.
func TestAdd_IdempotentOnDuplicate(t *testing.T) {
	u, k := mkUTXO(t, 1000)
	mp := New()
	tx := txn.Transaction{
		Inputs:  []txn.TxInput{{PrevTxID: k.TxID, PrevIndex: k.Index}},
		Outputs: []txn.TxOutput{{Value: 900, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xCC}}}},
	}
	if err := mp.Add(tx, u, 1, 0); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := mp.Add(tx, u, 1, 0); err != nil {
		t.Fatalf("duplicate Add should be a no-op, got error: %v", err)
	}
	if mp.Size() != 1 {
		t.Fatalf("duplicate Add grew the pool to %d entries; want 1", mp.Size())
	}
	// The conflict-tracking index should still map each input exactly
	// once to this tx's id — not a stale entry from a phantom prior Add.
	id := tx.TxID()
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if len(mp.spent) != 1 {
		t.Fatalf("spent-index size = %d, want 1", len(mp.spent))
	}
	if owner := mp.spent[k]; owner != id {
		t.Fatalf("spent[k] = %x, want %x", owner, id)
	}
}

// TestRemoveForBlock_ClearsConflictIndex guards the symmetric contract
// used by reorg connect-events: once a block confirms a tx,
// RemoveForBlock must drop both the tx entry AND the input reservations
// in `spent`. Otherwise a subsequent reorg disconnect would fail to
// re-admit the tx's input because `spent` still claims it.
func TestRemoveForBlock_ClearsConflictIndex(t *testing.T) {
	u, k := mkUTXO(t, 1000)
	mp := New()
	tx := txn.Transaction{
		Inputs:  []txn.TxInput{{PrevTxID: k.TxID, PrevIndex: k.Index}},
		Outputs: []txn.TxOutput{{Value: 900, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xCC}}}},
	}
	if err := mp.Add(tx, u, 1, 0); err != nil {
		t.Fatalf("Add: %v", err)
	}
	id := tx.TxID()
	mp.RemoveForBlock(1, [][32]byte{id})
	if mp.Size() != 0 {
		t.Fatalf("pool size after RemoveForBlock = %d, want 0", mp.Size())
	}
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	if len(mp.spent) != 0 {
		t.Fatalf("spent-index not cleared after confirmation: %d entries left", len(mp.spent))
	}
}
