package core

import (
	"strings"
	"testing"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// mkSigOpsTx builds a non-coinbase tx whose N inputs all carry a valid
// P2PK leaf + a witness whose first byte is `scheme` (drives per-
// CHECKSIG cost lookup). PrevTxID is seeded by `tag` so otherwise-
// identical txs produce distinct TxIDs. Spends are blank otherwise —
// we never run through UTXO lookup or script execution
// (testSkipTxValidation is on, and the sigop pre-pass fires first).
func mkSigOpsTx(tag byte, scheme byte, inputs int) txn.Transaction {
	leaf := address.NewP2PKLeaf([]byte{1, 2, 3, 4})
	ins := make([]txn.TxInput, inputs)
	for i := range ins {
		var prev [32]byte
		prev[0] = tag
		prev[1] = byte(i)
		prev[2] = byte(i >> 8)
		ins[i] = txn.TxInput{
			PrevTxID:  prev,
			PrevIndex: uint32(i),
			Spend: address.P2MRSpend{
				LeafScript: leaf,
				Witness:    [][]byte{{scheme}},
			},
		}
	}
	return txn.Transaction{
		Version: 1,
		Inputs:  ins,
		Outputs: []txn.TxOutput{{Value: 1, Address: address.P2MRAddress{MerkleRoot: [32]byte{tag}}}},
	}
}

// TestBlockSigOpsCap_Rejects builds a block whose cumulative sigop
// cost exceeds MaxBlockSigOpsCost by exactly 2 units (one extra
// SHRIMPS input over the 40_000 × ShrimpsVerifyCost line). Consensus
// must reject with the sigop-cap error message before any UTXO work.
func TestBlockSigOpsCap_Rejects(t *testing.T) {
	enableTestBypasses(t)
	bc := TestNewChain(t)

	// 5 non-coinbase txs × 8001 SHRIMPS inputs = 40_005 × 2 = 80_010
	// sigop cost — 10 over the cap.
	const (
		nTxs      = 5
		perTx     = 8001
		totalCost = nTxs * perTx * 2
	)
	if totalCost <= MaxBlockSigOpsCost {
		t.Fatalf("fixture miscomputed: totalCost=%d must exceed cap=%d", totalCost, MaxBlockSigOpsCost)
	}

	cb := testCoinbase(1, 0x01, testAddr(0xA0))
	txs := []txn.Transaction{cb}
	for i := range nTxs {
		txs = append(txs, mkSigOpsTx(byte(0x10+i), crypto.SchemeShrimps, perTx))
	}
	b := testBuildBlock(bc.BestHash(), 1_700_000_001, txs)
	_, _, err := bc.AddBlock(t.Context(), b)
	if err == nil {
		t.Fatal("expected sigop-cap rejection, got nil")
	}
	if !strings.Contains(err.Error(), "sigop cost") {
		t.Fatalf("expected sigop-cap error, got %v", err)
	}
}

// TestBlockSigOpsCap_Boundary pins the `>` boundary in the pre-pass.
// A block sitting exactly at the cap (40_000 × ShrimpsVerifyCost =
// 80_000) must pass the sigop gate — it'll still fail further down on
// the missing-UTXO lookup, but the error surface must not be the
// sigop-cap message. This guards against an off-by-one flipping `>`
// to `>=`.
func TestBlockSigOpsCap_Boundary(t *testing.T) {
	enableTestBypasses(t)
	bc := TestNewChain(t)

	const (
		nTxs      = 5
		perTx     = 8000
		totalCost = nTxs * perTx * 2
	)
	if totalCost != MaxBlockSigOpsCost {
		t.Fatalf("fixture miscomputed: totalCost=%d, want cap=%d", totalCost, MaxBlockSigOpsCost)
	}

	cb := testCoinbase(1, 0x02, testAddr(0xA1))
	txs := []txn.Transaction{cb}
	for i := range nTxs {
		txs = append(txs, mkSigOpsTx(byte(0x20+i), crypto.SchemeShrimps, perTx))
	}
	b := testBuildBlock(bc.BestHash(), 1_700_000_001, txs)
	_, _, err := bc.AddBlock(t.Context(), b)
	if err == nil {
		t.Fatal("expected failure further down the pipeline (UTXO missing)")
	}
	if strings.Contains(err.Error(), "sigop cost") {
		t.Fatalf("at-cap block was wrongly rejected by the sigop gate: %v", err)
	}
}
