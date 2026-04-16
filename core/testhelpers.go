package core

import (
	"sync"
	"testing"

	"qbitcoin/storage"
)

// testFlagMu serializes tests (across packages) that toggle the package-
// level test bypass flags. Benign in production — never locked there.
var testFlagMu sync.Mutex

// This file ships exported helpers used by other packages' tests (e.g.
// mempool's reorg-interaction tests) to build a minimal in-memory
// Blockchain with consensus-validation bypasses flipped on. Every
// function here takes *testing.T, which makes them structurally
// unusable from production code.

// TestEnableReorgBypasses flips the package-level test bypass flags
// (PoW, tx-script verification, header time checks, reorg commit hook)
// and registers a t.Cleanup to reset them. Callers hold the internal
// testFlagMu for the test's lifetime so concurrent tests don't see a
// mid-flip state.
func TestEnableReorgBypasses(t *testing.T) {
	t.Helper()
	testFlagMu.Lock()
	testBypassPoW = true
	testSkipTxValidation = true
	testSkipHeaderTimeChecks = true
	testSkipCoinbaseMaturity = true
	t.Cleanup(func() {
		testBypassPoW = false
		testSkipTxValidation = false
		testSkipHeaderTimeChecks = false
		testSkipCoinbaseMaturity = false
		reorgCommitHook = nil
		testFlagMu.Unlock()
	})
}

// TestNewChain opens a fresh storage.DB under t.TempDir() and returns a
// Blockchain built on it. Must be called after TestEnableReorgBypasses.
// The DB is closed via t.Cleanup.
func TestNewChain(t *testing.T) *Blockchain {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bc, err := NewBlockchain(db)
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	return bc
}
