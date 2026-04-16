package mempool

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/txn"
)

// TestMempool_OrphanFlow buffers a child whose parent is missing, then
// supplies the parent and confirms the child reconnects.
func TestMempool_OrphanFlow(t *testing.T) {
	u := txn.NewMemUTXOSet()
	parentID := [32]byte{0xAA}
	parentOut := txn.UTXOKey{TxID: parentID, Index: 0}

	// Child references parent — but parent UTXO is not yet in u.
	child := txn.Transaction{
		Inputs:  []txn.TxInput{{PrevTxID: parentID, PrevIndex: 0}},
		Outputs: []txn.TxOutput{{Value: 50, Address: address.P2MRAddress{}}},
	}
	mp := New()
	if err := mp.Add(child, u, 1, 0); err == nil {
		t.Fatal("expected error noting orphan buffering")
	}
	if mp.OrphanTxCount() != 1 {
		t.Fatalf("expected 1 orphan, got %d", mp.OrphanTxCount())
	}
	if mp.Get(child.TxID()) != nil {
		t.Fatal("orphan should not yet be in main pool")
	}

	// Now the parent's output appears in the UTXO set.
	if err := u.Put(parentOut, txn.TxOutput{Value: 100, Address: address.P2MRAddress{}}); err != nil {
		t.Fatal(err)
	}
	mp.ProcessOrphansForParent(parentID, u, 1, 0)
	if mp.Get(child.TxID()) == nil {
		t.Fatal("child should have reconnected")
	}
	if mp.OrphanTxCount() != 0 {
		t.Fatalf("orphan pool should drain, got %d", mp.OrphanTxCount())
	}
}
