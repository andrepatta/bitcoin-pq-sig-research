package txn

import "testing"

func TestIsFinal_NoLockTime(t *testing.T) {
	tx := Transaction{}
	if !tx.IsFinal(0, 0) {
		t.Fatal("LockTime=0 should always be final")
	}
}

func TestIsFinal_HeightLock(t *testing.T) {
	tx := Transaction{LockTime: 100}
	if tx.IsFinal(100, 0) {
		t.Fatal("LockTime=100 must not be final at height 100 (strict <)")
	}
	if !tx.IsFinal(101, 0) {
		t.Fatal("LockTime=100 must be final at height 101")
	}
}

func TestIsFinal_TimeLock(t *testing.T) {
	tx := Transaction{LockTime: uint32(LockTimeThreshold + 100)}
	cutoff := LockTimeThreshold + 100
	if tx.IsFinal(0, cutoff) {
		t.Fatal("must not be final exactly at LockTime")
	}
	if !tx.IsFinal(0, cutoff+1) {
		t.Fatal("must be final 1s past LockTime")
	}
}
