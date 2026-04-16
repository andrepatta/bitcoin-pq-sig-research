package p2p

import (
	"testing"
	"time"
)

// TestMarkAsked_DedupsWithinTTL verifies the second caller sees false
// (skip getdata) until either clearAsked or TTL expiry.
func TestMarkAsked_DedupsWithinTTL(t *testing.T) {
	n := &Node{asked: map[[32]byte]time.Time{}}
	h := [32]byte{0xAA}
	if !n.markAsked(h) {
		t.Fatal("first markAsked should return true")
	}
	if n.markAsked(h) {
		t.Fatal("second markAsked within TTL should return false")
	}
	n.clearAsked(h)
	if !n.markAsked(h) {
		t.Fatal("after clear, markAsked should return true again")
	}
}

// TestMarkAsked_TTLExpiry forces an expired entry by fabricating a past
// deadline, then confirms the next call refreshes.
func TestMarkAsked_TTLExpiry(t *testing.T) {
	n := &Node{asked: map[[32]byte]time.Time{}}
	h := [32]byte{0xBB}
	n.asked[h] = time.Now().Add(-time.Second)
	if !n.markAsked(h) {
		t.Fatal("expired entry should be reclaimable")
	}
}
