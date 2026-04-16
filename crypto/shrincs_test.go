package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testSeed(b byte) (s [32]byte) {
	for i := range s {
		s[i] = b
	}
	return s
}

func tmpStateFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "shrincs.state")
}

func TestShrincsRoundTripStateful(t *testing.T) {
	k, err := newTestShrincsKey(testSeed(0x42), tmpStateFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.PublicKey) != shrincsPubKeySize {
		t.Fatalf("PublicKey size: got %d want %d", len(k.PublicKey), shrincsPubKeySize)
	}

	msg := []byte("hello shrincs")
	sig, err := k.Sign(t.Context(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.IsStateful() {
		t.Fatal("expected stateful tag on fresh key")
	}
	if !verifyTestShrincs(k.PublicKey, msg, sig) {
		t.Fatal("verify returned false for a fresh stateful signature")
	}
}

func TestShrincsCounterAdvancesAndPersists(t *testing.T) {
	path := tmpStateFile(t)
	seed := testSeed(0x42)
	k, err := newTestShrincsKey(seed, path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := k.Sign(t.Context(), []byte("m")); err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
	}
	if k.Counter != 3 {
		t.Fatalf("in-memory counter: got %d want 3", k.Counter)
	}
	// Reload from disk: counter must survive.
	k2, err := newTestShrincsKey(seed, path)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Counter != 3 {
		t.Fatalf("reloaded counter: got %d want 3", k2.Counter)
	}
}

func TestShrincsPersistBeforeSign(t *testing.T) {
	// The persist-before-sign invariant says the state file must carry
	// counter+1 by the time Sign returns. The weaker test we can do
	// structurally is to read the file AFTER Sign and confirm the new
	// counter is already there — catching an obvious regression where
	// persist happened after sign.
	path := tmpStateFile(t)
	k, err := newTestShrincsKey(testSeed(0x11), path)
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
	if len(data) != shrincsStateFileLen+stateFileCRCLen {
		t.Fatalf("state file size: got %d want %d", len(data), shrincsStateFileLen+stateFileCRCLen)
	}
	// Counter at offset 0, big-endian uint64.
	if data[7] != 0x01 {
		t.Fatalf("state file counter LSB: got 0x%X want 0x01 after one sign", data[7])
	}
}

func TestShrincsAutoFallbackWhenExhausted(t *testing.T) {
	// Paper §B.3's min-rule: Sign auto-falls-back to stateless once the
	// stateful body would be ≥ stateless body. With demo fallback params
	// this triggers well before NumSlots, so we iterate until we see the
	// transition and then assert the fallback sig verifies.
	k, err := newTestShrincsKey(testSeed(0x77), tmpStateFile(t))
	if err != nil {
		t.Fatal(err)
	}
	var fallbackSig *ShrincsSig
	for i := uint64(0); i < k.NumSlots(); i++ {
		sig, err := k.Sign(t.Context(), []byte("m"))
		if err != nil {
			t.Fatalf("sign #%d: %v", i, err)
		}
		if !sig.IsStateful() {
			fallbackSig = sig
			break
		}
	}
	if fallbackSig == nil {
		t.Fatal("never hit fallback within NumSlots iterations")
	}
	if !verifyTestShrincs(k.PublicKey, []byte("m"), fallbackSig) {
		t.Fatal("verify failed for stateless-path signature")
	}
}

func TestShrincsVerifyRejectsWrongMessage(t *testing.T) {
	k, err := newTestShrincsKey(testSeed(0x42), tmpStateFile(t))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := k.Sign(t.Context(), []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	if verifyTestShrincs(k.PublicKey, []byte("tampered"), sig) {
		t.Fatal("verify accepted different message")
	}
}

func TestShrincsVerifyRejectsWrongPubKey(t *testing.T) {
	k1, _ := newTestShrincsKey(testSeed(0x11), tmpStateFile(t))
	k2, _ := newTestShrincsKey(testSeed(0x22), tmpStateFile(t))
	msg := []byte("m")
	sig, err := k1.Sign(t.Context(), msg)
	if err != nil {
		t.Fatal(err)
	}
	if verifyTestShrincs(k2.PublicKey, msg, sig) {
		t.Fatal("verify accepted sig under unrelated pubkey")
	}
}

func TestShrincsVerifyRejectsTamperedSibling(t *testing.T) {
	k, _ := newTestShrincsKey(testSeed(0x33), tmpStateFile(t))
	sig, err := k.Sign(t.Context(), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	bad := &ShrincsSig{Counter: sig.Counter}
	bad.SphincsIG = bytes.Clone(sig.SphincsIG)
	// Flip last byte (inside the trailing pk_stateless sibling).
	bad.SphincsIG[len(bad.SphincsIG)-1] ^= 0xff
	if verifyTestShrincs(k.PublicKey, []byte("m"), bad) {
		t.Fatal("verify accepted tampered sibling pk")
	}
}

func TestShrincsSigSerializationRoundTrip(t *testing.T) {
	k, _ := newTestShrincsKey(testSeed(0x55), tmpStateFile(t))
	sig, err := k.Sign(t.Context(), []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	wire := SerializeShrincsSig(sig)
	back, err := DeserializeShrincsSig(wire)
	if err != nil {
		t.Fatal(err)
	}
	if back.Counter != sig.Counter || !bytes.Equal(back.SphincsIG, sig.SphincsIG) {
		t.Fatal("serialize/deserialize round-trip mismatch")
	}
	if !verifyTestShrincs(k.PublicKey, []byte("m"), back) {
		t.Fatal("verify failed after serialize round-trip")
	}
}

func TestShrincsStateFileCorruptedRejected(t *testing.T) {
	path := tmpStateFile(t)
	// Write garbage of unexpected length.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02}, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := newTestShrincsKey(testSeed(0x42), path)
	if err != ErrStateCorrupted {
		t.Fatalf("expected ErrStateCorrupted, got %v", err)
	}
}

func TestShrincsSlotHealth(t *testing.T) {
	k, _ := newTestShrincsKey(testSeed(0x42), tmpStateFile(t))
	if k.SlotHealth() != 0.0 {
		t.Fatalf("fresh key slot health: got %v want 0.0", k.SlotHealth())
	}
	_, _ = k.Sign(t.Context(), []byte("m"))
	if got := k.SlotHealth(); got <= 0.0 || got > 1.0 {
		t.Fatalf("post-sign slot health out of range: %v", got)
	}
}
