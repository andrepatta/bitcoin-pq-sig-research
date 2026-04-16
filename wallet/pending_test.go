package wallet

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/txn"
)

// TestPendingTxs_RoundTrip writes a couple of pending entries, lists
// them, then clears one and confirms the remainder. Uses a plaintext
// Store directly — RecordPending/PendingTxs/ClearPending only need the
// wallet dir; they don't touch the Store's encryption path (pending
// txs are already-broadcast, non-secret).
func TestPendingTxs_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	w := &Wallet{store: store, name: "test"}

	tx1 := &txn.Transaction{Version: 1, Outputs: []txn.TxOutput{{Value: 1, Address: address.P2MRAddress{MerkleRoot: [32]byte{0x01}}}}}
	tx2 := &txn.Transaction{Version: 1, Outputs: []txn.TxOutput{{Value: 2, Address: address.P2MRAddress{MerkleRoot: [32]byte{0x02}}}}}

	if err := w.RecordPending(t.Context(), tx1); err != nil {
		t.Fatal(err)
	}
	if err := w.RecordPending(t.Context(), tx2); err != nil {
		t.Fatal(err)
	}
	got, err := w.PendingTxs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(got))
	}

	w.ClearPending(tx1.TxID())
	got, err = w.PendingTxs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].TxID() != tx2.TxID() {
		t.Fatalf("expected only tx2 to remain, got %+v", got)
	}
}
