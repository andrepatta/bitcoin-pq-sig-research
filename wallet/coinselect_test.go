package wallet

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/txn"
)

func mkUTXO(values ...uint64) ([]txn.UTXOKey, []txn.TxOutput) {
	keys := make([]txn.UTXOKey, len(values))
	outs := make([]txn.TxOutput, len(values))
	for i, v := range values {
		keys[i] = txn.UTXOKey{TxID: [32]byte{byte(i + 1)}, Index: 0}
		outs[i] = txn.TxOutput{Value: v, Address: address.P2MRAddress{}}
	}
	return keys, outs
}

// TestSelectCoins_LargestFirst proves the selector picks the single
// large UTXO over multiple smaller ones, minimizing signature count.
func TestSelectCoins_LargestFirst(t *testing.T) {
	k, o := mkUTXO(50, 30, 200, 10)
	sk, _, sum, ok := SelectCoins(k, o, 100)
	if !ok {
		t.Fatal("expected coverage")
	}
	if len(sk) != 1 || sum != 200 {
		t.Fatalf("expected one 200-value pick, got len=%d sum=%d", len(sk), sum)
	}
}

// TestSelectCoins_MultipleNeeded falls through largest-first until the
// target is met.
func TestSelectCoins_MultipleNeeded(t *testing.T) {
	k, o := mkUTXO(50, 30, 20, 10)
	sk, _, sum, ok := SelectCoins(k, o, 80)
	if !ok {
		t.Fatal("expected coverage")
	}
	// 50 + 30 = 80 — exactly two largest UTXOs.
	if len(sk) != 2 || sum != 80 {
		t.Fatalf("expected 2 inputs summing to 80, got len=%d sum=%d", len(sk), sum)
	}
}

// TestSelectCoins_Insufficient reports false when nothing covers target.
func TestSelectCoins_Insufficient(t *testing.T) {
	k, o := mkUTXO(10, 5, 3)
	if _, _, _, ok := SelectCoins(k, o, 1000); ok {
		t.Fatal("expected insufficient funds")
	}
}
