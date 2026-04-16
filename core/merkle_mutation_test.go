package core

import (
	"strings"
	"testing"

	"qbitcoin/txn"
)

// TestAddBlockRejectsMutatedMerkle ensures validateAndApply rejects a
// block whose tx list exhibits CVE-2012-2459 duplicate-sibling
// ambiguity. The MerkleRoot is honestly computed against the (mutated)
// tx list, so the test isolates the mutation check from the ordinary
// "bad merkle root" path.
func TestAddBlockRejectsMutatedMerkle(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	tip := bc.tipHash
	cb := testCoinbase(1, 0x01, testAddr(0x10))
	// Arbitrary non-coinbase tx. Content doesn't matter under
	// testSkipTxValidation — only its TxID.
	spend := testSpend([32]byte{0xEE}, 0, 10, testAddr(0x11))
	other := testSpend([32]byte{0xEE}, 1, 10, testAddr(0x12))
	// Attacker's shape: 4 leaves with a duplicate pair at (2,3).
	// Bitcoin Core compares pairs at (0,1),(2,3),... before the
	// odd-length duplicate-last step, so an odd-length honest tree
	// [cb,other,spend] wouldn't trip the check; the 4-leaf variant
	// is the paper-faithful attacker encoding.
	mutated := []txn.Transaction{cb, other, spend, spend}

	b := testBuildBlock(tip, 1, mutated)
	_, _, err := bc.AddBlock(t.Context(), b)
	if err == nil {
		t.Fatalf("expected mutation rejection, got nil")
	}
	if !strings.Contains(err.Error(), "mutated") {
		t.Fatalf("expected mutation error, got: %v", err)
	}
}

// TestAddBlockAcceptsUnmutatedMerkle is the positive control: same
// block shape but with distinct non-coinbase txs passes the mutation
// check (other consensus rules still apply; here we only care that the
// mutation rule itself does not false-positive).
func TestAddBlockAcceptsUnmutatedMerkle(t *testing.T) {
	enableTestBypasses(t)
	bc, _ := newReorgTestChain(t)

	tip := bc.tipHash
	cb := testCoinbase(1, 0x01, testAddr(0x10))
	a := testSpend([32]byte{0xEE}, 0, 10, testAddr(0x11))
	bspend := testSpend([32]byte{0xEE}, 1, 10, testAddr(0x12))
	if a.TxID() == bspend.TxID() {
		t.Fatalf("test setup: expected distinct TxIDs")
	}
	clean := []txn.Transaction{cb, a, bspend}

	blk := testBuildBlock(tip, 1, clean)
	_, _, err := bc.AddBlock(t.Context(), blk)
	if err != nil && strings.Contains(err.Error(), "mutated") {
		t.Fatalf("clean tx list wrongly flagged mutated: %v", err)
	}
}
