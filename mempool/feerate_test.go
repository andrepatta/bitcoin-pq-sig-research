package mempool

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/txn"
)

// build1in1out makes a tx spending k for fee = 1000 - outValue.
// Address bytes vary by `tag` so different calls produce different
// txids (otherwise they'd hash identically and dedupe in the pool).
func build1in1out(k txn.UTXOKey, outValue uint64, tag byte) txn.Transaction {
	return txn.Transaction{
		Inputs:  []txn.TxInput{{PrevTxID: k.TxID, PrevIndex: k.Index}},
		Outputs: []txn.TxOutput{{Value: outValue, Address: address.P2MRAddress{MerkleRoot: [32]byte{tag}}}},
	}
}

// TestMempool_MinRelayFeeRate gates the simple "tx fee too low" path.
func TestMempool_MinRelayFeeRate(t *testing.T) {
	saved := MinRelayFeeRate
	MinRelayFeeRate = 1
	defer func() { MinRelayFeeRate = saved }()

	u, k := mkUTXO(t, 1000)
	mp := New()
	// fee=0, size > 0 → must reject.
	if err := mp.Add(build1in1out(k, 1000, 0x10), u, 1, 0); err == nil {
		t.Fatal("expected min-relay rejection at fee=0")
	}
	// fee=500, size ~80 B → 500 sat / 80 B > 1 sat/B → accept.
	if err := mp.Add(build1in1out(k, 500, 0x11), u, 1, 0); err != nil {
		t.Fatalf("expected accept at fee=500: %v", err)
	}
}

// TestMempool_RBF_Replaces proves a higher-fee tx evicts the original.
func TestMempool_RBF_Replaces(t *testing.T) {
	saved := MinRelayFeeRate
	MinRelayFeeRate = 0
	defer func() { MinRelayFeeRate = saved }()

	u, k := mkUTXO(t, 1000)
	mp := New()

	orig := build1in1out(k, 900, 0x20) // fee = 100
	if err := mp.Add(orig, u, 1, 0); err != nil {
		t.Fatalf("orig add: %v", err)
	}
	// Conflict: same input. Fee 200 > 100, fee-rate strictly higher
	// (same size, more fee), bump > IncrementalRelayFeeRate * size.
	repl := build1in1out(k, 700, 0x21) // fee = 300
	if err := mp.Add(repl, u, 1, 0); err != nil {
		t.Fatalf("rbf add: %v", err)
	}
	if mp.Get(orig.TxID()) != nil {
		t.Fatal("expected original to be evicted")
	}
	if mp.Get(repl.TxID()) == nil {
		t.Fatal("expected replacement to be present")
	}
}

// TestMempool_RBF_RejectsLowerFee proves a same-feerate-or-lower
// replacement attempt is rejected (BIP-125 rule 6).
func TestMempool_RBF_RejectsLowerFee(t *testing.T) {
	saved := MinRelayFeeRate
	MinRelayFeeRate = 0
	defer func() { MinRelayFeeRate = saved }()

	u, k := mkUTXO(t, 1000)
	mp := New()

	orig := build1in1out(k, 500, 0x30) // fee = 500
	if err := mp.Add(orig, u, 1, 0); err != nil {
		t.Fatalf("orig add: %v", err)
	}
	repl := build1in1out(k, 700, 0x31) // fee = 300, lower than orig
	if err := mp.Add(repl, u, 1, 0); err == nil {
		t.Fatal("expected RBF rejection on lower fee")
	}
	if mp.Get(orig.TxID()) == nil {
		t.Fatal("original must remain after rejected RBF")
	}
}

// TestMempool_RBF_BumpRequirement proves rule 4: replacement must pay
// > sum(conflicts.fee) + incremental_rate * size.
func TestMempool_RBF_BumpRequirement(t *testing.T) {
	savedMin := MinRelayFeeRate
	savedInc := IncrementalRelayFeeRate
	MinRelayFeeRate = 0
	IncrementalRelayFeeRate = 100 // exaggerated bump requirement
	defer func() {
		MinRelayFeeRate = savedMin
		IncrementalRelayFeeRate = savedInc
	}()

	u, k := mkUTXO(t, 1_000_000)
	mp := New()
	orig := build1in1out(k, 999_900, 0x40) // fee=100
	if err := mp.Add(orig, u, 1, 0); err != nil {
		t.Fatalf("orig add: %v", err)
	}
	// Replacement: higher absolute fee AND higher fee-rate, but the
	// extra over the conflict's fee is < 100 sat/B * size, so rule 4
	// kills it.
	repl := build1in1out(k, 999_899, 0x41) // fee=101
	if err := mp.Add(repl, u, 1, 0); err == nil {
		t.Fatal("expected RBF rejection on insufficient bump")
	}
}
