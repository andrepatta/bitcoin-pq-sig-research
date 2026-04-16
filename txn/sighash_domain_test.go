package txn

import (
	"testing"

	"qbitcoin/address"
	"qbitcoin/crypto"
)

// TestSigHash_DomainBound proves the chain-ID domain string is mixed
// into the preimage: a hash computed without the domain (the legacy
// formulation) must NOT equal the new SigHash output.
func TestSigHash_DomainBound(t *testing.T) {
	tx := Transaction{
		Version: 1,
		Inputs: []TxInput{
			{PrevTxID: [32]byte{0xAA}, PrevIndex: 0, Spend: address.P2MRSpend{}},
		},
		Outputs:  []TxOutput{{Value: 100, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xBB}}}},
		LockTime: 0,
	}
	got := SigHash(tx, 0)

	cp := tx
	cp.Inputs = []TxInput{{PrevTxID: tx.Inputs[0].PrevTxID, PrevIndex: tx.Inputs[0].PrevIndex}}
	legacy := crypto.Hash256(cp.Serialize())

	if got == legacy {
		t.Fatal("SigHash must not equal the un-domain-separated hash")
	}
}

// TestSigHash_StableForSameInput is a regression guard: identical txs
// produce identical sighashes (the domain prepend is deterministic).
func TestSigHash_StableForSameInput(t *testing.T) {
	// Both inputs carry distinct non-empty Spend so that zeroing
	// input[0] vs input[1] produces visibly different preimages.
	spend := address.P2MRSpend{LeafScript: address.LeafScript{0xAB}}
	tx := Transaction{
		Version: 1,
		Inputs: []TxInput{
			{PrevTxID: [32]byte{0x11}, PrevIndex: 7, Spend: spend},
			{PrevTxID: [32]byte{0x22}, PrevIndex: 3, Spend: spend},
		},
		Outputs: []TxOutput{{Value: 42, Address: address.P2MRAddress{MerkleRoot: [32]byte{0x33}}}},
	}
	if SigHash(tx, 0) != SigHash(tx, 0) {
		t.Fatal("SigHash should be deterministic")
	}
	if SigHash(tx, 0) == SigHash(tx, 1) {
		t.Fatal("different inputs should yield different sighashes")
	}
}
