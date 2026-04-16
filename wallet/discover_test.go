package wallet

import (
	"context"
	"path/filepath"
	"testing"

	"qbitcoin/address"
)

// fakeActivity is an AddressActivity that reports "active" for any
// address in its set. Keyed by P2MRAddress.MerkleRoot (32-byte hash),
// so two Account builds of the same seed at the same index collide
// correctly.
type fakeActivity struct {
	active map[[32]byte]bool
}

func (f fakeActivity) HasActivity(_ context.Context, a address.P2MRAddress) (bool, error) {
	return f.active[a.MerkleRoot], nil
}

// TestDiscoverAccounts_StopsAtGap covers the BIP-44 §Account Discovery
// happy path: two consecutive-used accounts followed by a gap of
// AccountDiscoveryGapLimit inactive ones ⇒ discovery stops and sets
// active to the highest-used index. Slow because every scanned index
// triggers a paper-params SHRINCS+SHRIMPS keygen (~1s).
func TestDiscoverAccounts_StopsAtGap(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	// Shrink the gap so the test scans ~3-4 indices instead of 20+.
	// Local override with t.Cleanup keeps other tests honest.
	prevGap := AccountDiscoveryGapLimit
	AccountDiscoveryGapLimit = 1
	t.Cleanup(func() { AccountDiscoveryGapLimit = prevGap })

	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()

	// Restore via a caller-supplied mnemonic. The mnemonic doesn't
	// actually need prior history on any real chain — we fake the
	// activity check.
	w, _, err := reg.Create(ctx, "restore", nil, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Pre-derive idx 1 so we know the address to mark as "active".
	acct1, err := BuildAccount(ctx, w.masterSeed, 1, w.store)
	if err != nil {
		t.Fatalf("BuildAccount(1): %v", err)
	}
	addr0 := w.Address()
	addr1 := acct1.Address

	fake := fakeActivity{active: map[[32]byte]bool{
		addr0.MerkleRoot: true,
		addr1.MerkleRoot: true,
	}}

	got, err := w.DiscoverAccounts(ctx, fake)
	if err != nil {
		t.Fatalf("DiscoverAccounts: %v", err)
	}
	if got != 1 {
		t.Fatalf("highest_used: got %d want 1", got)
	}
	if w.CurrentAccountIndex() != 1 {
		t.Fatalf("active idx: got %d want 1", w.CurrentAccountIndex())
	}
	if w.Address().MerkleRoot != addr1.MerkleRoot {
		t.Fatal("Address did not advance to the highest-used account")
	}
}

// TestDiscoverAccounts_NoActivity covers the fresh-restore path where
// the mnemonic has no on-chain history: discovery must leave the active
// index at 0 rather than wandering into the gap window.
func TestDiscoverAccounts_NoActivity(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	prevGap := AccountDiscoveryGapLimit
	AccountDiscoveryGapLimit = 1
	t.Cleanup(func() { AccountDiscoveryGapLimit = prevGap })

	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()

	w, _, err := reg.Create(ctx, "empty", nil, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	addrBefore := w.Address()

	got, err := w.DiscoverAccounts(ctx, fakeActivity{active: map[[32]byte]bool{}})
	if err != nil {
		t.Fatalf("DiscoverAccounts: %v", err)
	}
	if got != 0 {
		t.Fatalf("no activity: got %d want 0", got)
	}
	if w.CurrentAccountIndex() != 0 {
		t.Fatalf("active idx: got %d want 0", w.CurrentAccountIndex())
	}
	if w.Address().MerkleRoot != addrBefore.MerkleRoot {
		t.Fatal("Address changed on no-activity discovery")
	}
}

// TestDiscoverAccounts_RejectsNil catches the programmer error of
// forgetting to wire an activity checker.
func TestDiscoverAccounts_RejectsNil(t *testing.T) {
	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()
	w, _, err := reg.Create(ctx, "x", nil, "")
	if err != nil {
		if testing.Short() {
			t.Skip("needs full keygen; skipped under -short")
		}
		t.Fatalf("Create: %v", err)
	}
	if _, err := w.DiscoverAccounts(ctx, nil); err == nil {
		t.Fatal("nil activity should error")
	}
}
