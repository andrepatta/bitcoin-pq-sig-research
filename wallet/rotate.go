package wallet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"qbitcoin/address"
	"qbitcoin/crypto"
)

// accountAddrFile is the per-account public-address cache. Contents =
// the raw 32-byte P2MR Merkle root. Purely a performance cache so
// ListAccounts can avoid full SHRINCS/SHRIMPS keygen (which builds a
// 2^16-leaf UXMSS tree + SPHINCS+ roots — seconds per account). The
// address is public information already published on-chain whenever
// the account receives funds, so caching it leaks nothing — kept in
// plaintext even when the wallet is encrypted.
func accountAddrFile(dataDir string, idx uint32) string {
	return filepath.Join(dataDir, fmt.Sprintf("acct_%d.addr", idx))
}

// writeAddrCache persists the 32-byte address for account idx. Best-effort:
// a write failure does not fail the calling keygen, it only means the next
// ListAccounts will rebuild via full keygen instead of a cache hit.
func writeAddrCache(dataDir string, idx uint32, addr address.P2MRAddress) {
	_ = os.WriteFile(accountAddrFile(dataDir, idx), addr.MerkleRoot[:], 0o600)
}

// readAddrCache loads a cached address for account idx. Returns ok=false
// when the cache is missing or malformed; callers fall back to full
// keygen on a miss.
func readAddrCache(dataDir string, idx uint32) (address.P2MRAddress, bool) {
	b, err := os.ReadFile(accountAddrFile(dataDir, idx))
	if err != nil || len(b) != 32 {
		return address.P2MRAddress{}, false
	}
	var a address.P2MRAddress
	copy(a.MerkleRoot[:], b)
	return a, true
}

// Account bundles the keys for a single account index derived from the
// master mnemonic via BIP-32 hardened derivation (m/44'/1'/N'/{0',1'}).
// Each account is an independent 2-leaf P2MR address — fresh receive
// addresses come from incrementing the account index (paper §14
// "key-pool" approach).
type Account struct {
	Index      uint32
	ShrincsKey *crypto.ShrincsKey
	ShrimpsKey *crypto.ShrimpsKey
	Address    address.P2MRAddress
	Leaves     []address.LeafScript
}

// BuildAccount derives all keys for accountIndex and composes the
// 2-leaf address. State files for SHRINCS/SHRIMPS are routed through
// the wallet's Store so encrypted wallets automatically gain at-rest
// protection for their signing state. `acct_<N>.addr` stays plaintext
// in the wallet dir — see accountAddrFile's comment for why.
//
// ctx propagates through the SHRINCS + SHRIMPS keygen passes so a
// shutdown mid-keygen returns ctx.Err(). Requires the store to be
// unlocked (callers must check w.IsLocked first).
func BuildAccount(ctx context.Context, masterSeed [64]byte, accountIndex uint32, store *Store) (*Account, error) {
	if store == nil {
		return nil, errors.New("wallet: BuildAccount requires a non-nil Store")
	}
	if store.IsLocked() {
		return nil, ErrLocked
	}
	shrincsSeed, shrimpsSeed, err := DeriveAccountKeys(masterSeed, accountIndex)
	if err != nil {
		return nil, err
	}

	shrincsName := fmt.Sprintf("acct_%d_shrincs.state", accountIndex)
	shrimpsName := fmt.Sprintf("acct_%d_shrimps.state", accountIndex)

	shK, err := crypto.NewShrincsKey(ctx, shrincsSeed, newStoreStateIO(store, shrincsName))
	if err != nil {
		return nil, err
	}
	smK, err := crypto.NewShrimpsKey(ctx, shrimpsSeed, newStoreStateIO(store, shrimpsName), 1024, 1)
	if err != nil {
		return nil, err
	}

	addr, leaves := address.BuildTwoLeafAddress(shK.PublicKey, smK.PublicKey[:])
	writeAddrCache(store.Dir(), accountIndex, addr)
	return &Account{
		Index:      accountIndex,
		ShrincsKey: shK,
		ShrimpsKey: smK,
		Address:    addr,
		Leaves:     leaves,
	}, nil
}

// SlotHealth returns the worst health among the account's keys. This
// is a purely informational UX hint — there is no on-chain rotation
// protocol triggered by it. Callers may surface this to users so they
// can manually move funds to a fresh account (higher-indexed address)
// before SHRINCS drains far enough that signatures switch to the
// expensive SPHINCS+ stateless fallback.
func (a *Account) SlotHealth() float64 {
	sh := a.ShrincsKey.SlotHealth()
	if s2 := a.ShrimpsKey.SlotHealth(); s2 > sh {
		sh = s2
	}
	return sh
}

// --- account_index file --------------------------------------------------

// Plain-text 4-byte big-endian file persisting which account is
// currently active. Not sensitive (just a number) — kept unencrypted
// so locked encrypted wallets can still answer Address() / Bech32()
// queries by reading the plaintext acct_<idx>.addr cache.

const accountIndexFile = "account_index"

func readAccountIndex(dir string) (uint32, error) {
	b, err := os.ReadFile(filepath.Join(dir, accountIndexFile))
	if err != nil {
		return 0, err
	}
	if len(b) != 4 {
		return 0, fmt.Errorf("wallet: account_index file wrong length: %d", len(b))
	}
	return binary.BigEndian.Uint32(b), nil
}

func writeAccountIndex(dir string, idx uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], idx)
	return atomicWrite(filepath.Join(dir, accountIndexFile), b[:])
}
