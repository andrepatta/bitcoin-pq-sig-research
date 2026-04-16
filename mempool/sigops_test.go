package mempool

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// mkSigOpsTx builds a 1-input, 1-output tx where the input's leaf is a
// P2PK template and the witness carries the given scheme tag (drives
// SigOpCost's per-CHECKSIG cost lookup). prevTxID differentiates UTXOs;
// outTag differentiates output addresses so two txs don't share a TxID.
func mkSigOpsTx(prevTxID [32]byte, scheme byte, outTag byte) txn.Transaction {
	leaf := address.NewP2PKLeaf([]byte{1, 2, 3, 4})
	return txn.Transaction{
		Inputs: []txn.TxInput{{
			PrevTxID: prevTxID,
			Spend: address.P2MRSpend{
				LeafScript: leaf,
				Witness:    [][]byte{{scheme}},
			},
		}},
		Outputs: []txn.TxOutput{{
			Value:   900,
			Address: address.P2MRAddress{MerkleRoot: [32]byte{outTag}},
		}},
	}
}

// putUTXO seeds a funding output at the given key.
func putUTXO(t *testing.T, u txn.UTXOSet, k txn.UTXOKey, val uint64) {
	t.Helper()
	if err := u.Put(k, txn.TxOutput{Value: val, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xBB}}}); err != nil {
		t.Fatal(err)
	}
}

// TestGetTemplate_RespectsSigOpsBudget packs the mempool with two txs
// whose combined sigop cost exceeds a tight template budget. The
// higher-fee tx must fit, the second must be skipped.
func TestGetTemplate_RespectsSigOpsBudget(t *testing.T) {
	u := txn.NewMemUTXOSet()
	// Two independent funding UTXOs.
	k1 := txn.UTXOKey{TxID: [32]byte{0xA1}, Index: 0}
	k2 := txn.UTXOKey{TxID: [32]byte{0xA2}, Index: 0}
	putUTXO(t, u, k1, 10_000)
	putUTXO(t, u, k2, 10_000)

	mp := New()
	// tx1: SHRIMPS witness (cost 2 per CHECKSIG), higher fee-rate → preferred.
	// tx2: SHRINCS witness (cost 1 per CHECKSIG), lower fee-rate → skipped
	// when template budget is already spent.
	tx1 := mkSigOpsTx(k1.TxID, crypto.SchemeShrimps, 0xC1)
	tx1.Outputs[0].Value = 1_000 // fee = 9_000
	tx2 := mkSigOpsTx(k2.TxID, crypto.SchemeShrincs, 0xC2)
	tx2.Outputs[0].Value = 9_000 // fee = 1_000

	if err := mp.Add(tx1, u, 1, 0); err != nil {
		t.Fatalf("Add tx1: %v", err)
	}
	if err := mp.Add(tx2, u, 1, 0); err != nil {
		t.Fatalf("Add tx2: %v", err)
	}

	// Budget: 2 sigops — fits tx1 (cost 2), forces tx2 (cost 1) to be
	// skipped because 2+1 > 2.
	out := mp.GetTemplate(1<<20, 2)
	if len(out) != 1 {
		t.Fatalf("template size = %d, want 1 (sigop budget should gate tx2)", len(out))
	}
	if out[0].TxID() != tx1.TxID() {
		t.Fatal("expected higher-fee SHRIMPS tx in template")
	}

	// Budget: 3 sigops — both fit (2 + 1).
	out = mp.GetTemplate(1<<20, 3)
	if len(out) != 2 {
		t.Fatalf("template size = %d, want 2 at raised budget", len(out))
	}

	// Budget: 1 sigop — tx1 (cost 2) skipped, tx2 (cost 1) fits.
	out = mp.GetTemplate(1<<20, 1)
	if len(out) != 1 {
		t.Fatalf("template size = %d, want 1 (only tx2 fits cost=1 budget)", len(out))
	}
	if out[0].TxID() != tx2.TxID() {
		t.Fatal("expected lower-cost SHRINCS tx when SHRIMPS doesn't fit")
	}
}

// TestAdd_RejectsOverPerTxSigOpsCap guards the mempool entry gate: a
// single tx whose sigop cost crosses MaxStandardTxSigOpsCost must be
// rejected before any UTXO or fee math runs.
func TestAdd_RejectsOverPerTxSigOpsCap(t *testing.T) {
	u := txn.NewMemUTXOSet()
	mp := New()

	// Build a tx with enough SHRIMPS-witness inputs to exceed the per-tx
	// cap: (cap / 2) + 1 inputs charges (cap + 2), one over.
	n := txn.MaxStandardTxSigOpsCost/2 + 1
	leaf := address.NewP2PKLeaf([]byte{1, 2, 3, 4})
	ins := make([]txn.TxInput, n)
	for i := range ins {
		var p [32]byte
		p[0] = byte(i)
		p[1] = byte(i >> 8)
		ins[i] = txn.TxInput{
			PrevTxID: p,
			Spend: address.P2MRSpend{
				LeafScript: leaf,
				Witness:    [][]byte{{crypto.SchemeShrimps}},
			},
		}
	}
	tx := txn.Transaction{
		Inputs:  ins,
		Outputs: []txn.TxOutput{{Value: 1, Address: address.P2MRAddress{}}},
	}

	err := mp.Add(tx, u, 1, 0)
	if err == nil {
		t.Fatal("expected per-tx sigop cap rejection")
	}
	if mp.Size() != 0 {
		t.Fatalf("pool size = %d after reject, want 0", mp.Size())
	}
}
