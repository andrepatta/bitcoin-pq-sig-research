package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Tiny budgets keep the auto-switch test tractable. Production
// geometry is nDev=1024, nDsig=1; for tests use 2 each so we exhaust
// the compact budget quickly.
const (
	testShrimpsNDev  uint32 = 2
	testShrimpsNDsig uint32 = 2
)

func shrimpsTmpState(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "shrimps.state")
}

func TestShrimpsRoundTripCompact(t *testing.T) {
	k, err := newTestShrimpsKey(testSeed(0x51), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	if err != nil {
		t.Fatal(err)
	}
	if k.PublicKey == ([32]byte{}) {
		t.Fatal("zero-valued PublicKey")
	}
	msg := []byte("shrimps compact msg")
	sig, err := k.Sign(t.Context(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if sig.UsesFallback {
		t.Fatal("expected compact tag on fresh key")
	}
	if !verifyTestShrimps(k.PublicKey, msg, sig) {
		t.Fatal("verify failed for compact signature")
	}
}

func TestShrimpsAutoSwitchToFallback(t *testing.T) {
	k, err := newTestShrimpsKey(testSeed(0x52), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	if err != nil {
		t.Fatal(err)
	}
	budget := uint64(k.NDev) * uint64(k.NDsig)
	for i := uint64(0); i < budget; i++ {
		sig, err := k.Sign(t.Context(), []byte("m"))
		if err != nil {
			t.Fatalf("compact sig #%d: %v", i, err)
		}
		if sig.UsesFallback {
			t.Fatalf("sig #%d: expected compact tag", i)
		}
	}
	sig, err := k.Sign(t.Context(), []byte("fallback"))
	if err != nil {
		t.Fatalf("post-switch sign: %v", err)
	}
	if !sig.UsesFallback {
		t.Fatal("expected fallback tag after compact budget exhausted")
	}
	if !verifyTestShrimps(k.PublicKey, []byte("fallback"), sig) {
		t.Fatal("verify failed for fallback signature")
	}
}

func TestShrimpsHardExhaustionReturnsError(t *testing.T) {
	k, err := newTestShrimpsKey(testSeed(0x53), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	if err != nil {
		t.Fatal(err)
	}
	total := uint64(k.NDev)*uint64(k.NDsig) + uint64(k.NDev)
	for i := uint64(0); i < total; i++ {
		if _, err := k.Sign(t.Context(), []byte("m")); err != nil {
			t.Fatalf("sig #%d: %v", i, err)
		}
	}
	if _, err := k.Sign(t.Context(), []byte("m")); err != ErrCounterExhausted {
		t.Fatalf("expected ErrCounterExhausted, got %v", err)
	}
}

func TestShrimpsCounterPersistsAcrossReload(t *testing.T) {
	path := shrimpsTmpState(t)
	seed := testSeed(0x54)
	k, err := newTestShrimpsKey(seed, path, testShrimpsNDev, testShrimpsNDsig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Sign(t.Context(), []byte("m")); err != nil {
		t.Fatal(err)
	}
	if k.DeviceCounter != 1 {
		t.Fatalf("in-memory counter: got %d want 1", k.DeviceCounter)
	}
	k2, err := newTestShrimpsKey(seed, path, testShrimpsNDev, testShrimpsNDsig)
	if err != nil {
		t.Fatal(err)
	}
	if k2.DeviceCounter != 1 {
		t.Fatalf("reloaded counter: got %d want 1", k2.DeviceCounter)
	}
}

func TestShrimpsPersistBeforeSign(t *testing.T) {
	path := shrimpsTmpState(t)
	k, err := newTestShrimpsKey(testSeed(0x55), path, testShrimpsNDev, testShrimpsNDsig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Sign(t.Context(), []byte("m")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != shrimpsStateFileLen+stateFileCRCLen {
		t.Fatalf("state file size: got %d want %d", len(data), shrimpsStateFileLen+stateFileCRCLen)
	}
	if data[7] != 0x01 {
		t.Fatalf("device counter LSB after one sign: got 0x%X want 0x01", data[7])
	}
}

func TestShrimpsVerifyRejectsWrongMessage(t *testing.T) {
	k, _ := newTestShrimpsKey(testSeed(0x56), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	sig, err := k.Sign(t.Context(), []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if verifyTestShrimps(k.PublicKey, []byte("tampered"), sig) {
		t.Fatal("verify accepted different message")
	}
}

func TestShrimpsVerifyRejectsWrongCommitment(t *testing.T) {
	k1, _ := newTestShrimpsKey(testSeed(0x57), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	k2, _ := newTestShrimpsKey(testSeed(0x58), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	sig, err := k1.Sign(t.Context(), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	if verifyTestShrimps(k2.PublicKey, []byte("m"), sig) {
		t.Fatal("verify accepted sig under unrelated commitment")
	}
}

func TestShrimpsVerifyRejectsTamperedActivePK(t *testing.T) {
	k, _ := newTestShrimpsKey(testSeed(0x59), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	sig, err := k.Sign(t.Context(), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	bad := &ShrimpsSig{
		UsesFallback:  sig.UsesFallback,
		DeviceCounter: sig.DeviceCounter,
		SphincsIG:     bytes.Clone(sig.SphincsIG),
	}
	// Active pk sits at offset len-2*shrimpsN.
	off := len(bad.SphincsIG) - 2*shrimpsN
	bad.SphincsIG[off] ^= 0xff
	if verifyTestShrimps(k.PublicKey, []byte("m"), bad) {
		t.Fatal("verify accepted tampered active pk")
	}
}

func TestShrimpsSigSerializationRoundTrip(t *testing.T) {
	k, _ := newTestShrimpsKey(testSeed(0x5A), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	sig, err := k.Sign(t.Context(), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	wire := SerializeShrimpsSig(sig)
	back, err := DeserializeShrimpsSig(wire)
	if err != nil {
		t.Fatal(err)
	}
	if back.UsesFallback != sig.UsesFallback ||
		back.DeviceCounter != sig.DeviceCounter ||
		!bytes.Equal(back.SphincsIG, sig.SphincsIG) {
		t.Fatal("serialize/deserialize round-trip mismatch")
	}
	if !verifyTestShrimps(k.PublicKey, []byte("m"), back) {
		t.Fatal("verify failed after serialize round-trip")
	}
}

func TestShrimpsStateFileCorruptedRejected(t *testing.T) {
	path := shrimpsTmpState(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newTestShrimpsKey(testSeed(0x5B), path, testShrimpsNDev, testShrimpsNDsig)
	if err != ErrStateCorrupted {
		t.Fatalf("expected ErrStateCorrupted, got %v", err)
	}
}

func TestShrimpsSlotHealth(t *testing.T) {
	k, _ := newTestShrimpsKey(testSeed(0x5C), shrimpsTmpState(t), testShrimpsNDev, testShrimpsNDsig)
	if k.SlotHealth() != 0.0 {
		t.Fatalf("fresh key slot health: got %v want 0.0", k.SlotHealth())
	}
	_, _ = k.Sign(t.Context(), []byte("m"))
	if got := k.SlotHealth(); got <= 0.0 || got > 1.0 {
		t.Fatalf("post-sign slot health out of range: %v", got)
	}
}
