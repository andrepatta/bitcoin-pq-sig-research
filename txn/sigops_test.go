package txn

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/crypto"
)

// mkInput builds a TxInput with a valid P2PK leaf script and a witness
// whose first byte is `scheme` (crypto.SchemeShrincs / SchemeShrimps).
// The leaf carries a tiny dummy pubkey — SigOpCost only counts
// OP_CHECKSIG occurrences and peeks at the witness scheme-tag.
func mkInput(scheme byte) TxInput {
	leaf := address.NewP2PKLeaf([]byte{1, 2, 3, 4})
	witness := [][]byte{{scheme}}
	return TxInput{
		Spend: address.P2MRSpend{LeafScript: leaf, Witness: witness},
	}
}

// mkInputLeaf is mkInput but with a caller-supplied raw leaf script,
// used to exercise edge cases like malformed or empty leaves.
func mkInputLeaf(leaf address.LeafScript, scheme byte) TxInput {
	return TxInput{
		Spend: address.P2MRSpend{LeafScript: leaf, Witness: [][]byte{{scheme}}},
	}
}

// TestSigOpCost_Opcodes pins the weight table that both the per-block
// cap (core.MaxBlockSigOpsCost) and the per-tx mempool cap depend on.
// Changing these numbers is a hard fork; this test fails loudly first.
func TestSigOpCost_Opcodes(t *testing.T) {
	cases := []struct {
		name string
		tx   Transaction
		want int
	}{
		{"empty tx", Transaction{}, 0},
		{"one shrincs", Transaction{Inputs: []TxInput{mkInput(crypto.SchemeShrincs)}}, ShrincsVerifyCost},
		{"one shrimps", Transaction{Inputs: []TxInput{mkInput(crypto.SchemeShrimps)}}, ShrimpsVerifyCost},
		{"mixed", Transaction{Inputs: []TxInput{
			mkInput(crypto.SchemeShrincs),
			mkInput(crypto.SchemeShrimps),
			mkInput(crypto.SchemeShrincs),
		}}, 2*ShrincsVerifyCost + ShrimpsVerifyCost},
		{"empty leaf charges 0", Transaction{Inputs: []TxInput{{}}}, 0},
		{"leaf with no CHECKSIG charges 0", Transaction{Inputs: []TxInput{
			mkInputLeaf(address.LeafScript{0x00}, crypto.SchemeShrincs),
		}}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SigOpCost(tc.tx); got != tc.want {
				t.Fatalf("SigOpCost = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestSigOpCost_CoinbaseIsZero pins the invariant that coinbase inputs
// contribute nothing — they are never script-executed, so charging
// them would just waste the block's verification budget.
func TestSigOpCost_CoinbaseIsZero(t *testing.T) {
	cb := Transaction{
		Inputs: []TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0xFFFFFFFF,
			// A coinbase with a CHECKSIG-bearing leaf still costs 0
			// because IsCoinbase short-circuits.
			Spend: address.P2MRSpend{
				LeafScript: address.NewP2PKLeaf([]byte{1, 2, 3, 4}),
				Witness:    [][]byte{{crypto.SchemeShrimps}},
			},
		}},
	}
	if !cb.IsCoinbase() {
		t.Fatal("fixture is not recognized as coinbase")
	}
	if got := SigOpCost(cb); got != 0 {
		t.Fatalf("coinbase SigOpCost = %d, want 0", got)
	}
}

// TestMaxStandardTxSigOpsCost_Ratio pins the 1/5 relationship with the
// block cap. If someone retunes the ratio without considering template
// packing behaviour (a tx at exactly the per-tx cap must still fit in
// a block with room to spare) this guards the regression.
func TestMaxStandardTxSigOpsCost_Ratio(t *testing.T) {
	if MaxStandardTxSigOpsCost*5 != 80_000 {
		t.Fatalf("MaxStandardTxSigOpsCost = %d; expected MaxBlockSigOpsCost (80_000) / 5", MaxStandardTxSigOpsCost)
	}
}

// TestSigOpCost_MissingWitnessDefaultsToMax guards the worst-case
// accounting policy: a leaf with CHECKSIG but no witness (or an
// unrecognized scheme tag) charges ShrimpsVerifyCost so a malformed
// witness can't under-budget the policy check.
func TestSigOpCost_MissingWitnessDefaultsToMax(t *testing.T) {
	tx := Transaction{Inputs: []TxInput{{
		Spend: address.P2MRSpend{
			LeafScript: address.NewP2PKLeaf([]byte{1, 2, 3, 4}),
			Witness:    nil,
		},
	}}}
	if got := SigOpCost(tx); got != ShrimpsVerifyCost {
		t.Fatalf("missing-witness default = %d, want %d (ShrimpsVerifyCost)", got, ShrimpsVerifyCost)
	}
}
