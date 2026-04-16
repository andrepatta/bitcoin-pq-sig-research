package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// deriveKEK derives the key-encryption-key from a passphrase + salt via
// PBKDF2-HMAC-SHA512. 200k iterations is a ~second on modern hardware,
// sufficient to blunt offline brute force while keeping unlock latency
// acceptable. Reuses stdlib's crypto/pbkdf2 (Go 1.24+).
func deriveKEK(passphrase []byte, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha512.New, string(passphrase), salt, iterations, mekLen)
}

// newEncryptedMeta generates a fresh salt + nonce, derives KEK from
// passphrase, and seals the MEK under it. Returns a Meta populated for
// on-disk persistence. mek is not zeroed by this function; the caller
// owns its lifetime.
func newEncryptedMeta(mek, passphrase []byte) (Meta, error) {
	if len(mek) != mekLen {
		return Meta{}, fmt.Errorf("wallet: MEK must be %d bytes, got %d", mekLen, len(mek))
	}
	var salt [kdfSaltLen]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return Meta{}, err
	}
	kek, err := deriveKEK(passphrase, salt[:], kdfIterations)
	if err != nil {
		return Meta{}, err
	}
	defer zeroBytes(kek)

	var nonce [gcmNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Meta{}, err
	}
	encMEK, err := gcmSeal(kek, nonce[:], mek, nil)
	if err != nil {
		return Meta{}, err
	}
	return Meta{
		Version:    metaFormatVersion,
		Encrypted:  true,
		Salt:       salt,
		Iterations: kdfIterations,
		Nonce:      nonce,
		EncMEK:     encMEK,
	}, nil
}

// decryptMEK derives the KEK from passphrase + meta.Salt and uses it to
// unseal meta.EncMEK. Caller owns the returned MEK and must zero it
// when done.
func decryptMEK(m Meta, passphrase []byte) ([]byte, error) {
	if !m.Encrypted {
		return nil, ErrNotEncrypted
	}
	kek, err := deriveKEK(passphrase, m.Salt[:], int(m.Iterations))
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)
	mek, err := gcmOpen(kek, m.Nonce[:], m.EncMEK, nil)
	if err != nil {
		// GCM auth-tag mismatch most likely means wrong passphrase.
		return nil, ErrBadPassphrase
	}
	if len(mek) != mekLen {
		return nil, errors.New("wallet: decrypted MEK has wrong length")
	}
	return mek, nil
}

// gcmSeal encrypts plaintext under key using AES-256-GCM. Returns the
// ciphertext+tag (no nonce prefix — the nonce is carried separately in
// the Meta record).
func gcmSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("wallet: wrong nonce size: got %d, want %d", len(nonce), aead.NonceSize())
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// gcmOpen decrypts a GCM ciphertext+tag produced by gcmSeal.
func gcmOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("wallet: wrong nonce size: got %d, want %d", len(nonce), aead.NonceSize())
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// --- per-file encryption ---------------------------------------------------

// writeEncryptedFile encrypts body under mek with a fresh random nonce
// and writes it atomically to <dir>/<name>.enc.
//
// On-disk layout per file: [12 B nonce || ciphertext || 16 B GCM tag].
// Fresh nonce per write — AES-GCM's catastrophic nonce-reuse failure
// mode means we MUST regenerate on every write, including rewrites of
// the same file (SHRINCS/SHRIMPS state files are rewritten on every sign).
func writeEncryptedFile(dir, name string, body, mek []byte) error {
	var nonce [gcmNonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	ct, err := gcmSeal(mek, nonce[:], body, nil)
	if err != nil {
		return err
	}
	out := make([]byte, 0, gcmNonceLen+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return atomicWrite(filepath.Join(dir, name+encSuffix), out)
}

// readEncryptedFile reads and decrypts <dir>/<name>.enc under mek.
// Returns os.ErrNotExist if the .enc file is absent.
func readEncryptedFile(dir, name string, mek []byte) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name+encSuffix))
	if err != nil {
		return nil, err
	}
	if len(raw) < gcmNonceLen+16 { // nonce + GCM tag
		return nil, errors.New("wallet: encrypted file too short")
	}
	nonce := raw[:gcmNonceLen]
	ct := raw[gcmNonceLen:]
	return gcmOpen(mek, nonce, ct, nil)
}

// Store-method shims: these live here because they touch the MEK-bearing
// code path. The plaintext counterparts are in store.go::readPlain /
// writePlain.

func (s *Store) readEncrypted(name string) ([]byte, error) {
	return readEncryptedFile(s.dir, name, s.mek)
}

func (s *Store) writeEncrypted(name string, body []byte) error {
	return writeEncryptedFile(s.dir, name, body, s.mek)
}
