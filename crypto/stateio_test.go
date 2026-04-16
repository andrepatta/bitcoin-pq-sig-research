package crypto

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
)

// memStateIO is an in-memory StateIO implementation, used to prove the
// interface abstraction works for non-filesystem backends (the wallet
// package later wires an AES-GCM one). Absent state is indicated by
// wrapping os.ErrNotExist.
type memStateIO struct {
	mu   sync.Mutex
	body []byte
	set  bool
}

func (m *memStateIO) Read() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.set {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(m.body), nil
}

func (m *memStateIO) Write(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.body = bytes.Clone(data)
	m.set = true
	return nil
}

// TestShrincsKey_CustomStateIO signs under an in-memory StateIO,
// confirming the refactor isn't filesystem-coupled. Also validates
// that os.ErrNotExist wrapping works for fresh-key init.
func TestShrincsKey_CustomStateIO(t *testing.T) {
	io := &memStateIO{}
	k, err := newShrincsKeyWithParams(context.Background(), testSeed(0xCA), io, shrincsDemoFallbackSPHINCS())
	if err != nil {
		t.Fatalf("newShrincsKeyWithParams: %v", err)
	}
	// State should have been written on first init.
	io.mu.Lock()
	firstBody := bytes.Clone(io.body)
	firstSet := io.set
	io.mu.Unlock()
	if !firstSet {
		t.Fatal("fresh key: StateIO.Write should have been called during loadOrInit")
	}
	if len(firstBody) != shrincsStateFileLen {
		t.Fatalf("state body size: got %d want %d", len(firstBody), shrincsStateFileLen)
	}
	// Sign and verify.
	sig, err := k.Sign(context.Background(), []byte("m"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !verifyShrincsWithParams(k.PublicKey, []byte("m"), sig, shrincsDemoFallbackSPHINCS()) {
		t.Fatal("verify failed for memStateIO-backed sig")
	}
	// Counter in the state body should have advanced.
	io.mu.Lock()
	postBody := bytes.Clone(io.body)
	io.mu.Unlock()
	if bytes.Equal(firstBody, postBody) {
		t.Fatal("counter did not advance in custom StateIO after Sign")
	}
}

// TestShrimpsKey_CustomStateIO exercises the same property for SHRIMPS.
func TestShrimpsKey_CustomStateIO(t *testing.T) {
	io := &memStateIO{}
	k, err := newShrimpsKeyWithParams(context.Background(), testSeed(0xCB), io, 4, 2,
		shrimpsDemoCompactSPHINCS(), shrimpsDemoFallbackSPHINCS())
	if err != nil {
		t.Fatalf("newShrimpsKeyWithParams: %v", err)
	}
	if _, err := k.Sign(context.Background(), []byte("x")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	io.mu.Lock()
	defer io.mu.Unlock()
	if !io.set || len(io.body) != shrimpsStateFileLen {
		t.Fatalf("SHRIMPS state via custom StateIO not persisted correctly: set=%v len=%d", io.set, len(io.body))
	}
}

// TestShrincsKey_NilStateIO confirms nil StateIO means in-memory only —
// signing works but state is not persisted anywhere.
func TestShrincsKey_NilStateIO(t *testing.T) {
	k, err := newShrincsKeyWithParams(context.Background(), testSeed(0xCC), nil, shrincsDemoFallbackSPHINCS())
	if err != nil {
		t.Fatalf("newShrincsKeyWithParams: %v", err)
	}
	if _, err := k.Sign(context.Background(), []byte("m")); err != nil {
		t.Fatalf("Sign with nil StateIO: %v", err)
	}
	// No panic, no crash. Counter still advances in memory.
	if k.Counter == 0 {
		t.Fatal("counter did not advance in-memory")
	}
}

// TestFileStateIO_Corruption covers ErrStateCorrupted surfacing when
// the on-disk CRC fails.
func TestFileStateIO_Corruption(t *testing.T) {
	tmp := t.TempDir() + "/s"
	f := &FileStateIO{Path: tmp}
	if err := f.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Corrupt a byte.
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 0xFF
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(); !errors.Is(err, ErrStateCorrupted) {
		t.Fatalf("Read after tamper: got %v want ErrStateCorrupted", err)
	}
}

// TestFileStateIO_MissingReturnsNotExist covers the fresh-key path.
func TestFileStateIO_MissingReturnsNotExist(t *testing.T) {
	tmp := t.TempDir() + "/missing"
	f := &FileStateIO{Path: tmp}
	_, err := f.Read()
	if err == nil {
		t.Fatal("Read of missing file: got nil err")
	}
	if !os.IsNotExist(err) && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read of missing: got %v want os.ErrNotExist", err)
	}
}
