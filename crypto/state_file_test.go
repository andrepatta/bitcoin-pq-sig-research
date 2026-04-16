package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStateFile_RoundTrip exercises the happy path.
func TestStateFile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	body := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := writeStateFile(path, body); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readStateFile(path, len(body))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("body mismatch: got %x want %x", got, body)
	}
}

// TestStateFile_CRCRejectsCorruption flips a byte inside the body and
// expects the read to fail with ErrStateCorrupted.
func TestStateFile_CRCRejectsCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	body := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := writeStateFile(path, body); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[3] ^= 0x01 // flip a body byte
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(path, len(body)); err != ErrStateCorrupted {
		t.Fatalf("expected ErrStateCorrupted, got %v", err)
	}
}

// TestStateFile_RejectsWrongLength rejects a file of unexpected length
// (legacy format / external tampering).
func TestStateFile_RejectsWrongLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(path, 8); err != ErrStateCorrupted {
		t.Fatalf("expected ErrStateCorrupted, got %v", err)
	}
}

// TestStateFile_NoSilentReinitOnCorruption ensures a corrupt counter
// byte triggers ErrStateCorrupted rather than the file-missing reinit
// path that resets counters to 0 (catastrophic for stateful sigs).
func TestStateFile_NoSilentReinitOnCorruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	body := make([]byte, 16)
	body[0] = 0xAA
	if err := writeStateFile(path, body); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt the counter region.
	raw[0] ^= 0xFF
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = readStateFile(path, len(body))
	if err != ErrStateCorrupted {
		t.Fatalf("counter corruption must be detected, got %v", err)
	}
	// And the file must not have been silently reset.
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("read should not have removed the file: %v", statErr)
	}
}
