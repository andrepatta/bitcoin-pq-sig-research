package wallet

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/tyler-smith/go-bip39"
)

// BIP-32 / BIP-44 key derivation, hardened-only subset.
//
// Non-hardened derivation is deliberately omitted: Bitcoin's non-hardened
// formula `child_priv = parse256(I[:32]) + k_par mod n` requires
// secp256k1 point addition, which hash-based SHRINCS/SHRIMPS keys don't
// support. Hardened derivation is pure HMAC-SHA512 and works exactly
// like Bitcoin. The consequence — no xpub / watch-only wallets — is
// accepted and documented.
//
// We use I[:32] directly as the child 32-byte seed (skipping Bitcoin's
// mod n reduction, which is meaningless when the seed isn't a secp256k1
// scalar).
//
// Coin type: we use 1' (SLIP-44 "testnet") because the SLIP-44 registry
// has no allocation for post-quantum Bitcoin experiments, and 1' signals
// clearly that this is not mainnet Bitcoin.

// HardenedOffset is the BIP-32 hardened index offset (2^31).
const HardenedOffset uint32 = 0x80000000

// CoinType is the BIP-44 coin_type for this chain (SLIP-44 "testnet").
const CoinType uint32 = 1

// Leaf indices for the per-account key pair.
const (
	ShrincsChild uint32 = 0
	ShrimpsChild uint32 = 1
)

// ExtKey is a BIP-32 extended key: 32-byte key material + 32-byte chain code.
type ExtKey struct {
	Key   [32]byte
	Chain [32]byte
}

// GenerateMnemonic returns a 24-word BIP-39 mnemonic (256-bit entropy).
func GenerateMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// MnemonicToSeed derives a 64-byte master seed via standard BIP-39
// (PBKDF2-HMAC-SHA512).
func MnemonicToSeed(mnemonic, passphrase string) ([64]byte, error) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	var out [64]byte
	copy(out[:], seed)
	return out, nil
}

// ValidateMnemonic reports whether the mnemonic is BIP-39 valid.
func ValidateMnemonic(m string) bool { return bip39.IsMnemonicValid(m) }

// MasterKey derives the BIP-32 master extended key from a 64-byte seed:
// I = HMAC-SHA512("Bitcoin seed", seed); I[:32] = key, I[32:] = chain.
func MasterKey(seed [64]byte) ExtKey {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed[:])
	I := mac.Sum(nil)
	var ext ExtKey
	copy(ext.Key[:], I[:32])
	copy(ext.Chain[:], I[32:])
	return ext
}

// DeriveHardened returns the hardened child at index i.
// I = HMAC-SHA512(parent.Chain, 0x00 || parent.Key || ser32(i | 2^31)).
func DeriveHardened(parent ExtKey, i uint32) ExtKey {
	mac := hmac.New(sha512.New, parent.Chain[:])
	mac.Write([]byte{0x00})
	mac.Write(parent.Key[:])
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], i|HardenedOffset)
	mac.Write(ib[:])
	I := mac.Sum(nil)
	var child ExtKey
	copy(child.Key[:], I[:32])
	copy(child.Chain[:], I[32:])
	return child
}

// DerivePath walks a sequence of hardened indices from master.
func DerivePath(master ExtKey, path []uint32) ExtKey {
	cur := master
	for _, i := range path {
		cur = DeriveHardened(cur, i)
	}
	return cur
}

// DeriveAccountKeys returns the SHRINCS and SHRIMPS 32-byte seeds for
// account N, derived along m/44'/1'/N'/0' and m/44'/1'/N'/1'.
func DeriveAccountKeys(masterSeed [64]byte, accountIndex uint32) (shrincsSeed, shrimpsSeed [32]byte, err error) {
	if accountIndex >= HardenedOffset {
		return shrincsSeed, shrimpsSeed, errors.New("wallet: account index exceeds hardened range")
	}
	m := MasterKey(masterSeed)
	account := DerivePath(m, []uint32{44, CoinType, accountIndex})
	shrincsSeed = DeriveHardened(account, ShrincsChild).Key
	shrimpsSeed = DeriveHardened(account, ShrimpsChild).Key
	return shrincsSeed, shrimpsSeed, nil
}
