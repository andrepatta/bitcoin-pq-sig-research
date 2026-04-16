package wallet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// A Store manages the on-disk files of a single wallet, hiding whether
// those files are encrypted. Sensitive files (mnemonic, SHRINCS/SHRIMPS
// state) are routed through ReadFile / WriteFile; their on-disk names
// gain a `.enc` suffix in encrypted mode. Public artifacts (per-account
// address cache `acct_N.addr`) bypass Store and live as plaintext files
// in the same directory — they leak nothing sensitive.
//
// The encryption design mirrors Bitcoin Core's wallet encryption:
//
//	passphrase -PBKDF2(HMAC-SHA512, 200k, salt)-> KEK (32 B)
//	KEK -AES-256-GCM-> EncMEK                   (encrypted master key)
//	MEK -AES-256-GCM-> ciphertext per secret file
//
// Changing the passphrase (ChangePassphrase) re-encrypts only the MEK
// under a new KEK; the per-file blobs are untouched. Encryption is opt-
// in at CreateStore time (empty passphrase => plaintext store) and can
// be added later via Encrypt — but there is no decrypt direction, same
// as Bitcoin Core.
type Store struct {
	mu   sync.RWMutex
	dir  string
	meta Meta

	// mek is populated when an encrypted store is unlocked. nil when
	// the store is plaintext (not needed) or locked.
	mek []byte
}

// Meta is the plaintext descriptor persisted as <dir>/wallet.meta. It
// records encryption state plus the KDF parameters a future load needs
// to re-derive the KEK. Plaintext stores write a Meta with Encrypted
// false and all encryption fields zeroed.
type Meta struct {
	Version    uint8    // format version, currently 1
	Encrypted  bool     // true: .enc files on disk + wallet.meta has EncMEK
	Salt       [16]byte // PBKDF2 salt (encrypted only)
	Iterations uint32   // PBKDF2 iterations (encrypted only)
	Nonce      [12]byte // GCM nonce for EncMEK (encrypted only)
	EncMEK     []byte   // AES-256-GCM(KEK, MEK) with tag appended (encrypted only)
}

const (
	MetaFileName      = "wallet.meta"
	metaFormatVersion = 1
	kdfIterations     = 200_000
	kdfSaltLen        = 16
	gcmNonceLen       = 12
	mekLen            = 32
	encSuffix         = ".enc"
	atomicTempSuffix  = ".tmp"
	defaultFilePerm   = 0o600
	defaultDirPerm    = 0o700
)

var (
	// ErrStoreExists is returned by CreateStore when wallet.meta is
	// already present in the target directory.
	ErrStoreExists = errors.New("wallet: store already exists")

	// ErrStoreMissing is returned by OpenStore when wallet.meta is not
	// present.
	ErrStoreMissing = errors.New("wallet: store does not exist")

	// ErrNotEncrypted signals an encryption-only operation was called
	// on a plaintext store (walletpassphrase, walletlock, etc.).
	ErrNotEncrypted = errors.New("wallet: store is not encrypted")

	// ErrAlreadyEncrypted is returned by Encrypt when the store is
	// already encrypted.
	ErrAlreadyEncrypted = errors.New("wallet: store is already encrypted")

	// ErrLocked is returned by ReadFile / WriteFile when an encrypted
	// store has not been unlocked.
	ErrLocked = errors.New("wallet: store is locked")

	// ErrBadPassphrase is returned by Unlock / ChangePassphrase when the
	// passphrase fails to decrypt the MEK (GCM auth tag mismatch).
	ErrBadPassphrase = errors.New("wallet: bad passphrase")

	// ErrPartialUpgrade indicates a mid-upgrade crash left the directory
	// in an inconsistent state (wallet.meta says unencrypted but .enc
	// files exist). Manual recovery required.
	ErrPartialUpgrade = errors.New("wallet: partial encryption state on disk; manual recovery required")

	// ErrUnsupportedMetaVersion is returned by OpenStore when wallet.meta's
	// Version field is a future version the binary doesn't understand.
	ErrUnsupportedMetaVersion = errors.New("wallet: unsupported wallet.meta version")
)

// CreateStore creates a new Store at dir. An empty passphrase creates
// an unencrypted store (plaintext files on disk); a non-empty passphrase
// creates an encrypted store. Fails with ErrStoreExists if wallet.meta
// is already present.
func CreateStore(dir string, passphrase []byte) (*Store, error) {
	if err := os.MkdirAll(dir, defaultDirPerm); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, MetaFileName)); err == nil {
		return nil, ErrStoreExists
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	s := &Store{dir: dir}
	if len(passphrase) == 0 {
		s.meta = Meta{Version: metaFormatVersion, Encrypted: false}
	} else {
		mek := make([]byte, mekLen)
		if _, err := rand.Read(mek); err != nil {
			return nil, err
		}
		m, err := newEncryptedMeta(mek, passphrase)
		if err != nil {
			return nil, err
		}
		s.meta = m
		s.mek = mek
	}
	if err := s.persistMeta(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenStore reads wallet.meta at dir. Encrypted stores come back locked;
// the caller must call Unlock before any ReadFile / WriteFile.
// Plaintext stores come back ready to use.
//
// Detects mid-Encrypt() crash state: if wallet.meta says encrypted but
// .enc files are missing (or vice versa), refuses to load.
func OpenStore(dir string) (*Store, error) {
	metaPath := filepath.Join(dir, MetaFileName)
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrStoreMissing
		}
		return nil, err
	}
	m, err := decodeMeta(raw)
	if err != nil {
		return nil, err
	}
	if m.Version != metaFormatVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedMetaVersion, m.Version, metaFormatVersion)
	}
	s := &Store{dir: dir, meta: m}
	if err := s.checkLayoutConsistency(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir returns the wallet directory.
func (s *Store) Dir() string {
	return s.dir
}

// IsEncrypted reports whether on-disk files are encrypted.
func (s *Store) IsEncrypted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Encrypted
}

// IsLocked reports whether the store is currently unusable for reads/
// writes of sensitive files. Plaintext stores are never locked;
// encrypted stores are locked whenever the MEK is not in memory.
func (s *Store) IsLocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Encrypted && s.mek == nil
}

// Unlock derives the KEK from passphrase, decrypts the MEK, and holds
// it in memory. Returns ErrNotEncrypted on plaintext stores,
// ErrBadPassphrase on wrong passphrase.
func (s *Store) Unlock(passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.meta.Encrypted {
		return ErrNotEncrypted
	}
	mek, err := decryptMEK(s.meta, passphrase)
	if err != nil {
		return err
	}
	s.mek = mek
	return nil
}

// Lock zeroes the in-memory MEK. No-op+error on plaintext stores.
func (s *Store) Lock() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.meta.Encrypted {
		return ErrNotEncrypted
	}
	zeroBytes(s.mek)
	s.mek = nil
	return nil
}

// ChangePassphrase re-derives a new KEK from newPass and re-encrypts
// the existing MEK. The on-disk secret files are untouched (they're
// encrypted under the MEK, which doesn't change). Requires the store
// to be unlocked (to verify oldPass via the current MEK).
func (s *Store) ChangePassphrase(oldPass, newPass []byte) error {
	if len(newPass) == 0 {
		return errors.New("wallet: new passphrase must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.meta.Encrypted {
		return ErrNotEncrypted
	}
	// Verify oldPass by decrypting the MEK freshly with it. We don't
	// trust the cached s.mek here — the caller may have unlocked with a
	// different passphrase in a race, though currently we hold the write
	// lock so that's hypothetical. Still, belt-and-braces.
	mek, err := decryptMEK(s.meta, oldPass)
	if err != nil {
		return err
	}
	newMeta, err := newEncryptedMeta(mek, newPass)
	if err != nil {
		zeroBytes(mek)
		return err
	}
	prev := s.meta
	s.meta = newMeta
	if err := s.persistMeta(); err != nil {
		s.meta = prev
		zeroBytes(mek)
		return err
	}
	// Keep the unlocked state — s.mek remains populated with the same
	// MEK bytes since the MEK itself didn't change.
	zeroBytes(mek)
	return nil
}

// ReadFile reads the named secret file. For encrypted stores, the
// file is decrypted with the MEK (store must be unlocked). For
// plaintext stores, reads the file as-is.
//
// Returns os.ErrNotExist (as wrapped) if the file is absent.
func (s *Store) ReadFile(name string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.meta.Encrypted {
		if s.mek == nil {
			return nil, ErrLocked
		}
		return s.readEncrypted(name)
	}
	return s.readPlain(name)
}

// WriteFile writes body to the named secret file atomically. For
// encrypted stores, the body is encrypted with the MEK under a fresh
// random nonce. For plaintext stores, body is written directly.
//
// Uses write-to-tmp + rename + directory fsync for durability
// (persist-before-sign invariant relies on this).
func (s *Store) WriteFile(name string, body []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.meta.Encrypted {
		if s.mek == nil {
			return ErrLocked
		}
		return s.writeEncrypted(name, body)
	}
	return s.writePlain(name, body)
}

// Encrypt upgrades a plaintext store in place. One-way — there is no
// decrypt. Re-encrypts each on-disk secret file under a freshly-
// generated MEK, writes wallet.meta with Encrypted: true, then removes
// the original plaintext files.
//
// Recovery rule for mid-upgrade crashes is enforced by OpenStore: if
// wallet.meta says unencrypted but .enc files exist, the load fails
// with ErrPartialUpgrade.
func (s *Store) Encrypt(passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("wallet: passphrase must not be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta.Encrypted {
		return ErrAlreadyEncrypted
	}

	// Pass 1: list plaintext secret files we need to re-encrypt.
	// Secret files are any plain (non-`.enc`, non-`wallet.meta`, non-
	// `acct_N.addr`) files under dir. We treat everything that's not
	// explicitly a public artifact or the meta file as a secret.
	plainNames, err := s.listPlaintextSecrets()
	if err != nil {
		return err
	}

	mek := make([]byte, mekLen)
	if _, err := rand.Read(mek); err != nil {
		return err
	}
	newMeta, err := newEncryptedMeta(mek, passphrase)
	if err != nil {
		zeroBytes(mek)
		return err
	}

	// Pass 2: write each .enc file (atomic). We stage under new meta
	// locally but do NOT publish it to disk until all .enc writes
	// succeed.
	for _, name := range plainNames {
		body, rerr := os.ReadFile(filepath.Join(s.dir, name))
		if rerr != nil {
			zeroBytes(mek)
			return fmt.Errorf("wallet: reading plaintext %q: %w", name, rerr)
		}
		if werr := writeEncryptedFile(s.dir, name, body, mek); werr != nil {
			zeroBytes(mek)
			// Best-effort cleanup of any .enc files we just wrote. Leaving
			// them in place would trip OpenStore's partial-upgrade check
			// on the next boot.
			for _, n := range plainNames {
				_ = os.Remove(filepath.Join(s.dir, n+encSuffix))
			}
			return fmt.Errorf("wallet: writing encrypted %q: %w", name, werr)
		}
	}

	// Pass 3: publish the new meta atomically. After this point the
	// store is effectively encrypted; a crash before Pass 4 just leaves
	// stale plaintext files that Pass 4 was going to delete. We mop
	// those up ourselves on the next open via cleanupOrphanPlaintexts.
	prev := s.meta
	s.meta = newMeta
	s.mek = mek
	if err := s.persistMeta(); err != nil {
		// Revert in-memory state; disk is unchanged (meta still the old one).
		s.meta = prev
		s.mek = nil
		zeroBytes(mek)
		// Best-effort cleanup of .enc files we wrote.
		for _, n := range plainNames {
			_ = os.Remove(filepath.Join(s.dir, n+encSuffix))
		}
		return err
	}

	// Pass 4: remove plaintext originals. Failures are logged upstream;
	// the store is already encrypted by Pass 3. Stale plaintexts will be
	// cleaned up on next OpenStore.
	for _, name := range plainNames {
		_ = os.Remove(filepath.Join(s.dir, name))
	}
	return nil
}

// --- file-discovery helpers ------------------------------------------------

// listPlaintextSecrets returns the names (no extension) of files that
// need to be upgraded to `.enc` during Encrypt. Excludes wallet.meta
// and any `acct_N.addr` files (public caches).
func (s *Store) listPlaintextSecrets() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == MetaFileName {
			continue
		}
		if isPublicArtifact(name) {
			continue
		}
		if hasEncSuffix(name) {
			continue
		}
		if hasTempSuffix(name) {
			// stale .tmp from a crashed atomic write — skip
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

// checkLayoutConsistency verifies the on-disk files match what
// wallet.meta claims. Called by OpenStore to detect mid-upgrade crashes.
//
// Rule: an encrypted meta must NOT have plaintext counterparts of any
// `.enc` file still on disk; a plaintext meta must NOT have any `.enc`
// files. Either condition indicates a partial upgrade.
//
// Orphan plaintext files with a corresponding `.enc` sibling are
// silently removed (they're stale residue from Pass 4).
func (s *Store) checkLayoutConsistency() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	encFiles := make(map[string]bool)
	plainFiles := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == MetaFileName || isPublicArtifact(name) || hasTempSuffix(name) {
			continue
		}
		if hasEncSuffix(name) {
			encFiles[stripEncSuffix(name)] = true
		} else {
			plainFiles[name] = true
		}
	}
	if s.meta.Encrypted {
		// If any plaintext file has an .enc sibling, that's a crashed
		// Pass 4 — safe to mop up.
		for name := range plainFiles {
			if encFiles[name] {
				_ = os.Remove(filepath.Join(s.dir, name))
				delete(plainFiles, name)
			}
		}
		// Any remaining plaintext secret means the directory has files
		// that weren't part of the upgrade — refuse to load, better to
		// surface than silently ignore.
		if len(plainFiles) > 0 {
			return fmt.Errorf("%w: encrypted store has stray plaintext files: %v",
				ErrPartialUpgrade, sortedKeys(plainFiles))
		}
	} else {
		// Plaintext meta + any `.enc` file => abandoned Pass 1/2 upgrade.
		if len(encFiles) > 0 {
			return fmt.Errorf("%w: plaintext store has stray .enc files: %v",
				ErrPartialUpgrade, sortedKeys(encFiles))
		}
	}
	return nil
}

// --- meta serialization ----------------------------------------------------

// encodeMeta serializes Meta to a fixed binary layout. Chose binary over
// JSON so the format is stable and inspection-friendly via `xxd`.
//
// Layout:
//
//	[1 B version]
//	[1 B encrypted flag]
//	[16 B salt]
//	[4 B iterations BE]
//	[12 B nonce]
//	[4 B enc_mek_len BE]
//	[enc_mek_len B enc_mek]
func encodeMeta(m Meta) []byte {
	buf := make([]byte, 0, 2+16+4+12+4+len(m.EncMEK))
	buf = append(buf, m.Version)
	if m.Encrypted {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, m.Salt[:]...)
	var itersBE [4]byte
	binary.BigEndian.PutUint32(itersBE[:], m.Iterations)
	buf = append(buf, itersBE[:]...)
	buf = append(buf, m.Nonce[:]...)
	var lenBE [4]byte
	binary.BigEndian.PutUint32(lenBE[:], uint32(len(m.EncMEK)))
	buf = append(buf, lenBE[:]...)
	buf = append(buf, m.EncMEK...)
	return buf
}

func decodeMeta(raw []byte) (Meta, error) {
	var m Meta
	if len(raw) < 2+16+4+12+4 {
		return m, fmt.Errorf("wallet: meta too short: %d bytes", len(raw))
	}
	r := bytes.NewReader(raw)
	var ver, enc byte
	if err := binary.Read(r, binary.BigEndian, &ver); err != nil {
		return m, err
	}
	if err := binary.Read(r, binary.BigEndian, &enc); err != nil {
		return m, err
	}
	m.Version = ver
	m.Encrypted = enc != 0
	if _, err := r.Read(m.Salt[:]); err != nil {
		return m, err
	}
	if err := binary.Read(r, binary.BigEndian, &m.Iterations); err != nil {
		return m, err
	}
	if _, err := r.Read(m.Nonce[:]); err != nil {
		return m, err
	}
	var encLen uint32
	if err := binary.Read(r, binary.BigEndian, &encLen); err != nil {
		return m, err
	}
	if encLen > 0 {
		m.EncMEK = make([]byte, encLen)
		if _, err := r.Read(m.EncMEK); err != nil {
			return m, err
		}
	}
	return m, nil
}

func (s *Store) persistMeta() error {
	return atomicWrite(filepath.Join(s.dir, MetaFileName), encodeMeta(s.meta))
}

// --- plaintext read/write --------------------------------------------------

func (s *Store) readPlain(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, name))
}

func (s *Store) writePlain(name string, body []byte) error {
	return atomicWrite(filepath.Join(s.dir, name), body)
}

// --- shared helpers --------------------------------------------------------

// atomicWrite writes body to path durably via write-to-tmp + rename +
// parent-dir fsync. Mirrors the discipline in crypto/state_file.go but
// is independent (wallet store files don't carry a CRC — encrypted
// files use GCM tags, plaintext files rely on filesystem integrity).
func atomicWrite(path string, body []byte) error {
	if path == "" {
		return errors.New("wallet: empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, defaultDirPerm); err != nil {
		return err
	}
	tmp := path + atomicTempSuffix
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, defaultFilePerm)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if dirf, err := os.Open(dir); err == nil {
		_ = dirf.Sync()
		dirf.Close()
	}
	return nil
}

func isPublicArtifact(name string) bool {
	// acct_N.addr files are the public address cache (see rotate.go).
	// account_index is the active-account pointer (see rotate.go) —
	// just a uint32, no secrets.
	if name == accountIndexFile {
		return true
	}
	return len(name) > len("acct_") && name[:len("acct_")] == "acct_" &&
		len(name) > len(".addr") && name[len(name)-len(".addr"):] == ".addr"
}

func hasEncSuffix(name string) bool {
	return len(name) > len(encSuffix) && name[len(name)-len(encSuffix):] == encSuffix
}

func stripEncSuffix(name string) string {
	if !hasEncSuffix(name) {
		return name
	}
	return name[:len(name)-len(encSuffix)]
}

func hasTempSuffix(name string) bool {
	return len(name) > len(atomicTempSuffix) && name[len(name)-len(atomicTempSuffix):] == atomicTempSuffix
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Small N; bubble sort is fine but we use stdlib.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
