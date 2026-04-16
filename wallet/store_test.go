package wallet

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateStore_Plaintext(t *testing.T) {
	dir := t.TempDir()
	s, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if s.IsEncrypted() {
		t.Fatal("expected plaintext store")
	}
	if s.IsLocked() {
		t.Fatal("plaintext store must never be locked")
	}
	// wallet.meta must exist on disk.
	if _, err := os.Stat(filepath.Join(dir, MetaFileName)); err != nil {
		t.Fatalf("meta not persisted: %v", err)
	}
	// Round-trip a secret file.
	if err := s.WriteFile("mnemonic", []byte("abandon abandon...")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := s.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "abandon abandon..." {
		t.Fatalf("got %q, want %q", got, "abandon abandon...")
	}
	// File should be plaintext on disk.
	raw, err := os.ReadFile(filepath.Join(dir, "mnemonic"))
	if err != nil {
		t.Fatalf("raw read: %v", err)
	}
	if string(raw) != "abandon abandon..." {
		t.Fatal("plaintext store should not encrypt on disk")
	}
	// Lock / Unlock / ChangePassphrase all reject plaintext stores.
	if err := s.Unlock([]byte("foo")); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("Unlock on plaintext: got %v want ErrNotEncrypted", err)
	}
	if err := s.Lock(); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("Lock on plaintext: got %v want ErrNotEncrypted", err)
	}
	if err := s.ChangePassphrase([]byte("a"), []byte("b")); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("ChangePassphrase on plaintext: got %v want ErrNotEncrypted", err)
	}
}

func TestCreateStore_Encrypted(t *testing.T) {
	dir := t.TempDir()
	s, err := CreateStore(dir, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if !s.IsEncrypted() {
		t.Fatal("expected encrypted store")
	}
	if s.IsLocked() {
		t.Fatal("freshly-created encrypted store should be unlocked")
	}
	// Write a secret and confirm on-disk is ciphertext.
	plain := []byte("correct horse battery staple is not my mnemonic")
	if err := s.WriteFile("mnemonic", plain); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "mnemonic"+encSuffix))
	if err != nil {
		t.Fatalf("reading .enc: %v", err)
	}
	if bytes.Contains(onDisk, plain) {
		t.Fatal("plaintext leaked into on-disk .enc file")
	}
	// No plaintext copy on disk.
	if _, err := os.Stat(filepath.Join(dir, "mnemonic")); !os.IsNotExist(err) {
		t.Fatal("encrypted store should not leave plaintext copy")
	}
	// Round-trip: read back, decrypt matches.
	got, err := s.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypt mismatch: got %q want %q", got, plain)
	}
}

func TestStore_LockUnlockCycle(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("s3cret")
	s, err := CreateStore(dir, pass)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	body := []byte("hello world")
	if err := s.WriteFile("state", body); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := s.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if !s.IsLocked() {
		t.Fatal("expected IsLocked after Lock")
	}
	// Reads and writes fail while locked.
	if _, err := s.ReadFile("state"); !errors.Is(err, ErrLocked) {
		t.Fatalf("ReadFile while locked: got %v want ErrLocked", err)
	}
	if err := s.WriteFile("state2", body); !errors.Is(err, ErrLocked) {
		t.Fatalf("WriteFile while locked: got %v want ErrLocked", err)
	}
	// Wrong passphrase yields ErrBadPassphrase.
	if err := s.Unlock([]byte("wrong")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Unlock wrong pass: got %v want ErrBadPassphrase", err)
	}
	if !s.IsLocked() {
		t.Fatal("should stay locked after bad passphrase")
	}
	// Correct passphrase unlocks.
	if err := s.Unlock(pass); err != nil {
		t.Fatalf("Unlock correct: %v", err)
	}
	got, err := s.ReadFile("state")
	if err != nil {
		t.Fatalf("ReadFile after unlock: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("content mismatch after unlock: got %q want %q", got, body)
	}
}

func TestOpenStore_EncryptedComesUpLocked(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("zxcvbnm")
	s, err := CreateStore(dir, pass)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.WriteFile("mnemonic", []byte("phrase")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if !s2.IsEncrypted() {
		t.Fatal("reopened store should be encrypted")
	}
	if !s2.IsLocked() {
		t.Fatal("reopened encrypted store should be locked until Unlock is called")
	}
	if err := s2.Unlock(pass); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	got, err := s2.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "phrase" {
		t.Fatalf("got %q", got)
	}
}

func TestOpenStore_PlaintextComesUpReady(t *testing.T) {
	dir := t.TempDir()
	s, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.WriteFile("mnemonic", []byte("phrase")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if s2.IsEncrypted() {
		t.Fatal("reopened plaintext store claims encrypted")
	}
	if s2.IsLocked() {
		t.Fatal("plaintext reopened store should not be locked")
	}
	got, err := s2.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "phrase" {
		t.Fatalf("got %q", got)
	}
}

func TestCreateStore_ExistingDirRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := CreateStore(dir, nil); err != nil {
		t.Fatalf("first CreateStore: %v", err)
	}
	if _, err := CreateStore(dir, nil); !errors.Is(err, ErrStoreExists) {
		t.Fatalf("second CreateStore: got %v want ErrStoreExists", err)
	}
}

func TestOpenStore_Missing(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenStore(dir); !errors.Is(err, ErrStoreMissing) {
		t.Fatalf("OpenStore of empty dir: got %v want ErrStoreMissing", err)
	}
}

func TestEncrypt_UpgradePlainToEncrypted(t *testing.T) {
	dir := t.TempDir()
	s, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	// Populate some secret files.
	if err := s.WriteFile("mnemonic", []byte("m1")); err != nil {
		t.Fatalf("write mnemonic: %v", err)
	}
	if err := s.WriteFile("acct_0_shrincs.state", []byte("shrincs-state-bytes")); err != nil {
		t.Fatalf("write shrincs: %v", err)
	}
	// Public artifact — should NOT be encrypted.
	pubPath := filepath.Join(dir, "acct_0.addr")
	if err := os.WriteFile(pubPath, []byte("pub-addr-32bytes----------------"), 0o600); err != nil {
		t.Fatalf("write public: %v", err)
	}

	// Upgrade.
	pass := []byte("hunter2")
	if err := s.Encrypt(pass); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !s.IsEncrypted() {
		t.Fatal("post-Encrypt store should report encrypted")
	}
	if s.IsLocked() {
		t.Fatal("post-Encrypt store should be unlocked")
	}

	// On disk: .enc files exist, plaintexts are gone, public file intact.
	if _, err := os.Stat(filepath.Join(dir, "mnemonic"+encSuffix)); err != nil {
		t.Fatalf("mnemonic.enc missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mnemonic")); !os.IsNotExist(err) {
		t.Fatal("plaintext mnemonic should have been removed")
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("public file vanished: %v", err)
	}
	if string(pub) != "pub-addr-32bytes----------------" {
		t.Fatalf("public file was modified: %q", pub)
	}

	// Roundtrip both secret files through Store.
	got, err := s.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("read mnemonic: %v", err)
	}
	if string(got) != "m1" {
		t.Fatalf("mnemonic content: got %q", got)
	}
	got, err = s.ReadFile("acct_0_shrincs.state")
	if err != nil {
		t.Fatalf("read shrincs: %v", err)
	}
	if string(got) != "shrincs-state-bytes" {
		t.Fatalf("shrincs content: got %q", got)
	}

	// Reopen fresh and unlock — survives across process lifetimes.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if err := s2.Unlock(pass); err != nil {
		t.Fatalf("Unlock after reopen: %v", err)
	}
	got, err = s2.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("read after reopen: %v", err)
	}
	if string(got) != "m1" {
		t.Fatalf("reopened content: got %q", got)
	}
}

func TestEncrypt_RejectIfAlreadyEncrypted(t *testing.T) {
	dir := t.TempDir()
	s, err := CreateStore(dir, []byte("p"))
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.Encrypt([]byte("p2")); !errors.Is(err, ErrAlreadyEncrypted) {
		t.Fatalf("Encrypt on already-encrypted: got %v want ErrAlreadyEncrypted", err)
	}
}

func TestEncrypt_RejectEmptyPassphrase(t *testing.T) {
	dir := t.TempDir()
	s, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.Encrypt(nil); err == nil {
		t.Fatal("Encrypt(nil) should fail")
	}
}

func TestOpenStore_RejectsPartialUpgrade(t *testing.T) {
	dir := t.TempDir()
	// Simulate mid-upgrade: meta says plaintext but a stray .enc file exists.
	s, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.WriteFile("mnemonic", []byte("m")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Drop a stray .enc file.
	if err := os.WriteFile(filepath.Join(dir, "mnemonic"+encSuffix), []byte("junk"), 0o600); err != nil {
		t.Fatalf("writing stray .enc: %v", err)
	}
	// Reopen should reject.
	if _, err := OpenStore(dir); !errors.Is(err, ErrPartialUpgrade) {
		t.Fatalf("OpenStore: got %v want ErrPartialUpgrade", err)
	}
}

func TestOpenStore_CleansOrphanPlaintext(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("p")
	s, err := CreateStore(dir, pass)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.WriteFile("mnemonic", []byte("m")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Simulate a crashed Pass 4: create a plaintext sibling of mnemonic.enc.
	strayPath := filepath.Join(dir, "mnemonic")
	if err := os.WriteFile(strayPath, []byte("old-m"), 0o600); err != nil {
		t.Fatalf("writing stray plaintext: %v", err)
	}
	// OpenStore should clean it up silently.
	if _, err := OpenStore(dir); err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := os.Stat(strayPath); !os.IsNotExist(err) {
		t.Fatal("orphan plaintext should have been removed by OpenStore")
	}
}

func TestChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	oldPass := []byte("old")
	newPass := []byte("new")
	s, err := CreateStore(dir, oldPass)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.WriteFile("mnemonic", []byte("m")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Wrong old passphrase rejected.
	if err := s.ChangePassphrase([]byte("wrong"), newPass); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("ChangePassphrase wrong-old: got %v want ErrBadPassphrase", err)
	}

	// Empty new passphrase rejected.
	if err := s.ChangePassphrase(oldPass, nil); err == nil {
		t.Fatal("ChangePassphrase with empty newPass must fail")
	}

	// Happy path.
	if err := s.ChangePassphrase(oldPass, newPass); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}

	// Old passphrase no longer works after reopen+unlock.
	if err := s.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := s.Unlock(oldPass); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("Unlock with old pass: got %v want ErrBadPassphrase", err)
	}
	if err := s.Unlock(newPass); err != nil {
		t.Fatalf("Unlock with new pass: %v", err)
	}
	got, err := s.ReadFile("mnemonic")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "m" {
		t.Fatalf("content after pass change: %q", got)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	// Binary encoding of Meta is stable.
	orig := Meta{
		Version:    metaFormatVersion,
		Encrypted:  true,
		Salt:       [16]byte{1, 2, 3},
		Iterations: 200_000,
		Nonce:      [12]byte{9, 8, 7},
		EncMEK:     []byte{0xaa, 0xbb, 0xcc, 0xdd},
	}
	raw := encodeMeta(orig)
	got, err := decodeMeta(raw)
	if err != nil {
		t.Fatalf("decodeMeta: %v", err)
	}
	if got.Version != orig.Version || got.Encrypted != orig.Encrypted ||
		got.Salt != orig.Salt || got.Iterations != orig.Iterations ||
		got.Nonce != orig.Nonce || !bytes.Equal(got.EncMEK, orig.EncMEK) {
		t.Fatalf("meta roundtrip mismatch:\n  orig=%+v\n  got=%+v", orig, got)
	}
}

func TestOpenStore_UnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	// Hand-craft a meta with a future version.
	m := Meta{Version: 99, Encrypted: false}
	if err := atomicWrite(filepath.Join(dir, MetaFileName), encodeMeta(m)); err != nil {
		t.Fatalf("atomicWrite: %v", err)
	}
	if _, err := OpenStore(dir); !errors.Is(err, ErrUnsupportedMetaVersion) {
		t.Fatalf("OpenStore future version: got %v want ErrUnsupportedMetaVersion", err)
	}
}

func TestEncryptedFile_TamperDetected(t *testing.T) {
	dir := t.TempDir()
	pass := []byte("p")
	s, err := CreateStore(dir, pass)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}
	if err := s.WriteFile("state", []byte("body")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Corrupt a ciphertext byte.
	encPath := filepath.Join(dir, "state"+encSuffix)
	raw, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("read enc: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(encPath, raw, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := s.ReadFile("state"); err == nil {
		t.Fatal("tampered read should fail integrity check")
	}
}

func TestAtomicWrite_OverwritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := atomicWrite(path, []byte("first")); err != nil {
		t.Fatalf("atomicWrite 1: %v", err)
	}
	if err := atomicWrite(path, []byte("second")); err != nil {
		t.Fatalf("atomicWrite 2: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("got %q", got)
	}
	// No leftover .tmp.
	if _, err := os.Stat(path + atomicTempSuffix); !os.IsNotExist(err) {
		t.Fatal(".tmp leftover after atomicWrite")
	}
}

func TestKDF_Determinism(t *testing.T) {
	pass := []byte("same")
	salt := []byte("1234567890123456")
	k1, err := deriveKEK(pass, salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := deriveKEK(pass, salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("KDF not deterministic")
	}
	// Different passphrase produces different key.
	k3, err := deriveKEK([]byte("different"), salt, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k3) {
		t.Fatal("KDF collision on different passphrase")
	}
	// Different salt produces different key.
	k4, err := deriveKEK(pass, []byte("different-salt-!"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k4) {
		t.Fatal("KDF collision on different salt")
	}
}

func TestPublicArtifactDetection(t *testing.T) {
	cases := []struct {
		name string
		pub  bool
	}{
		{"acct_0.addr", true},
		{"acct_123.addr", true},
		{"acct_0_shrincs.state", false},
		{"mnemonic", false},
		{"wallet.meta", false},
		{"acct_0.addr.enc", false}, // enc-suffixed, not a public artifact
	}
	for _, c := range cases {
		if got := isPublicArtifact(c.name); got != c.pub {
			t.Errorf("isPublicArtifact(%q) = %v, want %v", c.name, got, c.pub)
		}
	}
}
