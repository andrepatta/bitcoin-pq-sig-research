package wallet

import (
	"qbitcoin/crypto"
)

// storeStateIO adapts a wallet Store to crypto.StateIO. The key blob is
// stored under `name` in the Store, which transparently encrypts it at
// rest when the wallet is encrypted. Used by wallet.BuildAccount to
// route SHRINCS/SHRIMPS state through the wallet's encrypted backend.
//
// Adds a CRC32-trailer around the body (same wire shape as
// crypto.FileStateIO), so encrypted wallets retain the same defense
// against silent single-bit flips that FileStateIO provides — AES-GCM
// catches ciphertext tampering, but the CRC guards the plaintext body
// against bugs in the write path or in-memory corruption between
// encrypt and sign.
type storeStateIO struct {
	store *Store
	name  string
}

func newStoreStateIO(store *Store, name string) crypto.StateIO {
	return &storeStateIO{store: store, name: name}
}

func (s *storeStateIO) Read() ([]byte, error) {
	// For encrypted stores, ReadFile auto-decrypts under the MEK and
	// returns the original body (which still has a CRC trailer). We
	// strip the CRC to match FileStateIO's contract (caller receives
	// body only). Re-verifying the CRC here catches bit flips in
	// memory between decrypt and parse — AES-GCM has already caught
	// ciphertext-level tampering at the store boundary.
	//
	// Store.ReadFile returns *os.PathError wrapping os.ErrNotExist on
	// missing files for both backends, so errors.Is(err, os.ErrNotExist)
	// works for callers without explicit rewrapping here.
	data, err := s.store.ReadFile(s.name)
	if err != nil {
		return nil, err
	}
	return crypto.StripAndVerifyCRC(data)
}

func (s *storeStateIO) Write(body []byte) error {
	wrapped := crypto.AppendCRC(body)
	return s.store.WriteFile(s.name, wrapped)
}
