package wallet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests use testparams for crypto speed isn't available in the
// wallet package (it's a crypto-internal helper), so the tests create
// real paper-params SHRINCS/SHRIMPS keys. That keeps them honest but
// slow: each BuildAccount call takes ~1s at paper params. The tests
// cache the keys by reusing the same wallet across subtests where
// possible; where independence is required we accept the cost.
//
// To skip under -short, tests guard with t.Skip.

func TestRegistry_CreateLoadUnloadList(t *testing.T) {
	if testing.Short() {
		t.Skip("registry tests build paper-params SHRINCS/SHRIMPS keys (~1s per account); skipped under -short")
	}
	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)

	// Create "main" (plaintext).
	ctx := context.Background()
	w, mn, err := reg.Create(ctx, "main", nil, "")
	if err != nil {
		t.Fatalf("Create main: %v", err)
	}
	if !ValidateMnemonic(mn) {
		t.Fatalf("auto-generated mnemonic invalid: %q", mn)
	}
	if w.IsEncrypted() {
		t.Fatal("expected plaintext wallet")
	}

	// Default routing: exactly one loaded → defaults to it.
	w2, err := reg.Get("")
	if err != nil {
		t.Fatalf("Get(\"\"): %v", err)
	}
	if w2.Name() != "main" {
		t.Fatalf("Get(\"\") returned %q want main", w2.Name())
	}

	// Create a second wallet "cold" (encrypted).
	pass := []byte("zxcv")
	w3, _, err := reg.Create(ctx, "cold", pass, "")
	if err != nil {
		t.Fatalf("Create cold: %v", err)
	}
	if !w3.IsEncrypted() || w3.IsLocked() {
		t.Fatalf("cold: encrypted=%v locked=%v", w3.IsEncrypted(), w3.IsLocked())
	}

	// Default routing: two loaded → ambiguous.
	if _, err := reg.Get(""); !errors.Is(err, ErrAmbiguousDefault) {
		t.Fatalf("Get(\"\") with 2 wallets: got %v want ErrAmbiguousDefault", err)
	}
	// Named routing still works.
	if _, err := reg.Get("main"); err != nil {
		t.Fatalf("Get(main): %v", err)
	}

	// List sorted by name.
	list := reg.List()
	if len(list) != 2 {
		t.Fatalf("List len: got %d want 2", len(list))
	}
	if list[0].Name != "cold" || list[1].Name != "main" {
		t.Fatalf("List order: %+v", list)
	}

	// Unload "main" — "cold" becomes the default.
	if err := reg.Unload("main"); err != nil {
		t.Fatalf("Unload main: %v", err)
	}
	def := reg.Default()
	if def == nil || def.Name() != "cold" {
		t.Fatalf("Default after unload: %v", def)
	}

	// Unload nonexistent.
	if err := reg.Unload("ghost"); !errors.Is(err, ErrWalletNotLoaded) {
		t.Fatalf("Unload ghost: got %v", err)
	}

	// Re-load main from disk.
	mainLoaded, err := reg.Load(ctx, "main", false)
	if err != nil {
		t.Fatalf("Load main: %v", err)
	}
	if mainLoaded.IsEncrypted() {
		t.Fatal("reloaded main should still be plaintext")
	}
}

func TestRegistry_InvalidNames(t *testing.T) {
	base := t.TempDir()
	reg := NewRegistry(base)
	cases := []string{"", ".", "..", "foo/bar", "foo\\bar", "foo\x00bar", "foo bar", "wallet.meta"}
	for _, bad := range cases {
		if _, _, err := reg.Create(context.Background(), bad, nil, ""); !errors.Is(err, ErrInvalidWalletName) {
			t.Errorf("Create(%q): got %v want ErrInvalidWalletName", bad, err)
		}
	}
}

func TestRegistry_DuplicateCreateRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()
	if _, _, err := reg.Create(ctx, "w1", nil, ""); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, _, err := reg.Create(ctx, "w1", nil, ""); !errors.Is(err, ErrWalletAlreadyLoaded) {
		t.Fatalf("duplicate Create: got %v want ErrWalletAlreadyLoaded", err)
	}
}

func TestWallet_LockUnlockCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()
	pass := []byte("zxcvbnm")
	w, _, err := reg.Create(ctx, "enc", pass, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	addrBefore := w.Address()

	if err := w.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if !w.IsLocked() {
		t.Fatal("expected IsLocked")
	}
	// Address still works post-lock via addr cache.
	addrAfter := w.Address()
	if addrBefore != addrAfter {
		t.Fatal("Address changed across lock cycle")
	}
	// Sign/NewReceiveAddress/SetActiveAccount fail.
	if _, err := w.NewReceiveAddress(ctx); !errors.Is(err, ErrLocked) {
		t.Fatalf("NewReceiveAddress locked: got %v want ErrLocked", err)
	}
	if _, err := w.SetActiveAccount(ctx, 0); !errors.Is(err, ErrLocked) {
		t.Fatalf("SetActiveAccount locked: got %v want ErrLocked", err)
	}

	// Wrong passphrase rejected.
	if err := w.Unlock(ctx, []byte("wrong"), 0); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Unlock wrong pass: got %v want ErrBadPassphrase", err)
	}
	if !w.IsLocked() {
		t.Fatal("should stay locked after bad passphrase")
	}

	// Correct unlock.
	if err := w.Unlock(ctx, pass, 0); err != nil {
		t.Fatalf("Unlock correct: %v", err)
	}
	if w.IsLocked() {
		t.Fatal("should be unlocked after correct passphrase")
	}
}

func TestWallet_AutoLockTimer(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()
	pass := []byte("abc")
	w, _, err := reg.Create(ctx, "autolock", pass, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = w.Lock()

	// Unlock with a short timeout.
	if err := w.Unlock(ctx, pass, 150*time.Millisecond); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if w.IsLocked() {
		t.Fatal("should be unlocked immediately after Unlock")
	}
	time.Sleep(400 * time.Millisecond)
	if !w.IsLocked() {
		t.Fatal("auto-lock timer should have fired by now")
	}
}

func TestRegistry_AutoloadFile(t *testing.T) {
	// This test doesn't actually load wallets; it exercises the file
	// format. Does not need keygen — safe under -short.
	base := filepath.Join(t.TempDir(), "datadir", "wallets")
	reg := NewRegistry(base)

	// Empty → no error, no names.
	names, err := reg.Autoload()
	if err != nil {
		t.Fatalf("Autoload empty: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("empty autoload: got %v", names)
	}

	// Add three, read back sorted.
	for _, n := range []string{"cold", "alpha", "main"} {
		if err := reg.SetAutoload(n, true); err != nil {
			t.Fatalf("SetAutoload %s: %v", n, err)
		}
	}
	names, _ = reg.Autoload()
	if len(names) != 3 || names[0] != "alpha" || names[1] != "cold" || names[2] != "main" {
		t.Fatalf("autoload ordering: got %v", names)
	}

	// Remove middle.
	if err := reg.SetAutoload("cold", false); err != nil {
		t.Fatal(err)
	}
	names, _ = reg.Autoload()
	if len(names) != 2 || strings.Join(names, ",") != "alpha,main" {
		t.Fatalf("after remove: got %v", names)
	}

	// Duplicate add → idempotent.
	if err := reg.SetAutoload("alpha", true); err != nil {
		t.Fatal(err)
	}
	names, _ = reg.Autoload()
	if len(names) != 2 {
		t.Fatalf("duplicate add leaked: %v", names)
	}

	// Invalid names rejected.
	if err := reg.SetAutoload("../etc", true); !errors.Is(err, ErrInvalidWalletName) {
		t.Fatalf("invalid name: got %v", err)
	}

	// Comments and blank lines in the file are ignored on read.
	if err := os.WriteFile(reg.autoloadFile(),
		[]byte("# comment\n\nalpha\n   # indented comment also ignored?\n\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	names, _ = reg.Autoload()
	if len(names) != 1 || names[0] != "alpha" {
		t.Fatalf("comment parsing: got %v", names)
	}
}

func TestWallet_LoadEncryptedComesUpLocked(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	base := filepath.Join(t.TempDir(), "wallets")
	reg := NewRegistry(base)
	ctx := context.Background()
	pass := []byte("p")
	if _, _, err := reg.Create(ctx, "r", pass, ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Unload, then load again.
	if err := reg.Unload("r"); err != nil {
		t.Fatal(err)
	}
	w, err := reg.Load(ctx, "r", false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !w.IsLocked() {
		t.Fatal("encrypted wallet should come up locked after Load")
	}
	// Address/Bech32 still work from addr cache.
	addr, err := w.Bech32()
	if err != nil {
		t.Fatalf("Bech32 on locked: %v", err)
	}
	if addr == "" {
		t.Fatal("empty Bech32 on locked wallet")
	}
}
