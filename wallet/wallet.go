package wallet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/logging"
	"qbitcoin/txn"
)

var log = logging.Module("wallet")

// Wallet is a named, independently-lockable wallet managing one active
// account (2-leaf P2MR = SHRINCS primary + SHRIMPS multi-device). Per
// the Bitcoin Core model: each loaded wallet is a distinct object held
// by the node's Registry; multi-wallet routing uses the name field.
//
// Lifecycle:
//   - CreateWallet writes wallet.meta + mnemonic (+ state files lazily).
//   - LoadWallet opens an existing wallet. Encrypted wallets come up
//     locked — Address/Bech32/ListAccounts still work (served from the
//     plaintext acct_N.addr caches), but Sign/Send and any method that
//     touches the mnemonic returns ErrLocked until Unlock is called.
//   - Plaintext wallets are always unlocked; Lock/Unlock/Encrypt/
//     ChangePassphrase return ErrNotEncrypted.
//
// There is no on-chain rotation protocol: users who want fresh receive
// addresses just increment the account index (paper §14 key-pool).
type Wallet struct {
	mu         sync.Mutex
	name       string   // display name, used for multi-wallet routing
	masterSeed [64]byte // zeroed when locked (encrypted wallet), populated otherwise
	store      *Store
	activeIdx  uint32   // always known — from account_index file
	current    *Account // non-nil when unlocked; nil when locked
	keypoolSig chan struct{}
	autoLock   *time.Timer // auto-lock timer (encrypted + Unlock-with-timeout only)
}

// KeypoolSize is how many future accounts the wallet pre-derives (just
// the 32-byte P2MR address — mirrors Bitcoin Core's keypool) so
// ListAccounts / new-address handout stays instant. Paper §14 calls
// this the "key-pool" approach.
const KeypoolSize = 10

// ErrWalletClosed is returned once Close has been called on a wallet
// but methods are still invoked. Belt-and-braces against a racy
// Registry.Unload.
var ErrWalletClosed = errors.New("wallet: closed")

// CreateWallet materializes a new wallet directory. An empty
// passphrase creates an unencrypted wallet (files on disk as plaintext);
// a non-empty passphrase creates an encrypted wallet. `providedMnemonic`
// may be empty — a fresh 24-word BIP-39 mnemonic is generated.
//
// Returns the wallet and the (possibly freshly-generated) mnemonic for
// one-time display; the caller is responsible for surfacing the
// mnemonic to the user before dropping it.
func CreateWallet(ctx context.Context, name, dir string, passphrase []byte, providedMnemonic string) (*Wallet, string, error) {
	if name == "" {
		return nil, "", errors.New("wallet: name must not be empty")
	}
	store, err := CreateStore(dir, passphrase)
	if err != nil {
		return nil, "", err
	}
	mnemonic := providedMnemonic
	if mnemonic == "" {
		mnemonic, err = GenerateMnemonic()
		if err != nil {
			return nil, "", err
		}
	}
	if !ValidateMnemonic(mnemonic) {
		return nil, "", errors.New("wallet: invalid mnemonic")
	}
	if err := store.WriteFile("mnemonic", []byte(mnemonic)); err != nil {
		return nil, "", err
	}
	seed, err := MnemonicToSeed(mnemonic, "")
	if err != nil {
		return nil, "", err
	}
	if err := writeAccountIndex(store.Dir(), 0); err != nil {
		return nil, "", err
	}
	w := &Wallet{
		name:       name,
		masterSeed: seed,
		store:      store,
		activeIdx:  0,
		keypoolSig: make(chan struct{}, 1),
	}
	acct, err := BuildAccount(ctx, seed, 0, store)
	if err != nil {
		return nil, "", err
	}
	w.current = acct
	go w.keypoolFiller()
	w.signalKeypool()
	return w, mnemonic, nil
}

// LoadWallet opens an existing wallet directory. Encrypted wallets come
// up locked — call Unlock before signing. Plaintext wallets come up
// with the active account materialized.
func LoadWallet(ctx context.Context, name, dir string) (*Wallet, error) {
	if name == "" {
		return nil, errors.New("wallet: name must not be empty")
	}
	store, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	idx, err := readAccountIndex(store.Dir())
	if err != nil {
		return nil, fmt.Errorf("wallet: read account_index: %w", err)
	}
	w := &Wallet{
		name:       name,
		store:      store,
		activeIdx:  idx,
		keypoolSig: make(chan struct{}, 1),
	}
	if !store.IsEncrypted() {
		if err := w.rebuildCurrent(ctx); err != nil {
			return nil, err
		}
	}
	go w.keypoolFiller()
	w.signalKeypool()
	return w, nil
}

// Name returns the wallet's routing name.
func (w *Wallet) Name() string { return w.name }

// DataDir returns the wallet's on-disk directory.
func (w *Wallet) DataDir() string { return w.store.Dir() }

// IsEncrypted mirrors the underlying Store.
func (w *Wallet) IsEncrypted() bool { return w.store.IsEncrypted() }

// IsLocked mirrors the underlying Store.
func (w *Wallet) IsLocked() bool { return w.store.IsLocked() }

// Unlock decrypts the MEK, reloads the mnemonic, derives the master
// seed, and builds the current account. If timeout > 0, an auto-lock
// timer fires after that duration. Passing timeout == 0 keeps the
// wallet unlocked until explicit Lock().
func (w *Wallet) Unlock(ctx context.Context, passphrase []byte, timeout time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.store.IsEncrypted() {
		return ErrNotEncrypted
	}
	if !w.store.IsLocked() {
		// Already unlocked — just refresh the auto-lock timer if one is
		// requested. No passphrase check.
		w.resetAutoLockLocked(timeout)
		return nil
	}
	if err := w.store.Unlock(passphrase); err != nil {
		return err
	}
	if err := w.rebuildCurrentLocked(ctx); err != nil {
		// Roll back store unlock so we don't leak the MEK.
		_ = w.store.Lock()
		return err
	}
	w.resetAutoLockLocked(timeout)
	return nil
}

// Lock zeroes the master seed and the MEK. Signing operations will
// return ErrLocked until the next Unlock.
func (w *Wallet) Lock() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.store.IsEncrypted() {
		return ErrNotEncrypted
	}
	w.cancelAutoLockLocked()
	// Zero the in-memory master seed before flipping the store state.
	for i := range w.masterSeed {
		w.masterSeed[i] = 0
	}
	w.current = nil
	return w.store.Lock()
}

// Encrypt upgrades a plaintext wallet in place (one-way). After
// success the wallet is encrypted AND unlocked; the caller is expected
// to hold the passphrase and will need it again on the next LoadWallet.
func (w *Wallet) Encrypt(passphrase []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.store.IsEncrypted() {
		return ErrAlreadyEncrypted
	}
	return w.store.Encrypt(passphrase)
}

// ChangePassphrase re-encrypts the MEK under a new KEK derived from
// newPass. oldPass is required even when already unlocked — belt-and-
// braces against a caller with a stale unlocked handle.
func (w *Wallet) ChangePassphrase(oldPass, newPass []byte) error {
	return w.store.ChangePassphrase(oldPass, newPass)
}

// Address returns the current account's 32-byte P2MR address. Works
// even when locked — falls back to the plaintext acct_<idx>.addr cache.
func (w *Wallet) Address() address.P2MRAddress {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current != nil {
		return w.current.Address
	}
	if addr, ok := readAddrCache(w.store.Dir(), w.activeIdx); ok {
		return addr
	}
	// No cache and no keys — locked encrypted wallet whose addr cache
	// got deleted. Return zero; callers should not hit this in normal
	// operation since CreateWallet/LoadWallet always writes the cache.
	return address.P2MRAddress{}
}

// Bech32 returns the bech32-encoded current address.
func (w *Wallet) Bech32() (string, error) {
	return address.EncodeBech32(w.Address())
}

// CurrentAccountIndex returns the active account index.
func (w *Wallet) CurrentAccountIndex() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.activeIdx
}

// NewReceiveAddress derives the next account, makes it current, and
// persists the new index. Paper §14 "key-pool" UX. Requires the wallet
// to be unlocked.
func (w *Wallet) NewReceiveAddress(ctx context.Context) (address.P2MRAddress, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.requireUnlockedLocked(); err != nil {
		return address.P2MRAddress{}, err
	}
	next, err := BuildAccount(ctx, w.masterSeed, w.activeIdx+1, w.store)
	if err != nil {
		return address.P2MRAddress{}, err
	}
	w.current = next
	w.activeIdx = next.Index
	if err := writeAccountIndex(w.store.Dir(), next.Index); err != nil {
		return address.P2MRAddress{}, err
	}
	log.Info("wallet: advanced to new receive address", "wallet", w.name, "index", next.Index)
	w.signalKeypool()
	return next.Address, nil
}

// AccountInfo summarizes a derivable account.
type AccountInfo struct {
	Index   uint32
	Address address.P2MRAddress
	Active  bool
}

var (
	acctStateRe = regexp.MustCompile(`^acct_(\d+)_shrincs\.state(?:\.enc)?$`)
	acctAddrRe  = regexp.MustCompile(`^acct_(\d+)\.addr$`)
)

// ListAccounts returns every account index that has on-disk state
// under the wallet dir, plus the currently active index. Addresses are
// re-derived from the master seed if the cache is missing, which means
// a locked encrypted wallet can ONLY list accounts whose addr caches
// are on disk — the common case after any successful SetActiveAccount.
func (w *Wallet) ListAccounts(ctx context.Context) ([]AccountInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w.mu.Lock()
	activeIdx := w.activeIdx
	seed := w.masterSeed
	locked := w.store.IsLocked()
	dir := w.store.Dir()
	w.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	seen := map[uint32]struct{}{activeIdx: {}}
	for _, e := range entries {
		name := e.Name()
		for _, re := range []*regexp.Regexp{acctStateRe, acctAddrRe} {
			if m := re.FindStringSubmatch(name); m != nil {
				if n, err := strconv.ParseUint(m[1], 10, 32); err == nil {
					seen[uint32(n)] = struct{}{}
				}
				break
			}
		}
	}
	idxs := make([]uint32, 0, len(seen))
	for i := range seen {
		idxs = append(idxs, i)
	}
	sort.Slice(idxs, func(i, j int) bool { return idxs[i] < idxs[j] })

	out := make([]AccountInfo, 0, len(idxs))
	for _, idx := range idxs {
		addr, ok := readAddrCache(dir, idx)
		if !ok {
			// Cache miss: need full keygen via the master seed.
			if locked {
				// Can't rebuild a locked wallet's account keys — just
				// skip this index. Should be rare; would happen if a
				// user manually deleted the .addr cache while locked.
				log.Warn("wallet: skipping account with missing addr cache while locked", "wallet", w.name, "index", idx)
				continue
			}
			acct, err := BuildAccount(ctx, seed, idx, w.store)
			if err != nil {
				return nil, fmt.Errorf("wallet: rebuild account %d: %w", idx, err)
			}
			addr = acct.Address
		}
		out = append(out, AccountInfo{
			Index:   idx,
			Address: addr,
			Active:  idx == activeIdx,
		})
	}
	return out, nil
}

// SetActiveAccount switches to an arbitrary index, deriving new keys if
// needed. Requires the wallet to be unlocked.
func (w *Wallet) SetActiveAccount(ctx context.Context, idx uint32) (address.P2MRAddress, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.requireUnlockedLocked(); err != nil {
		return address.P2MRAddress{}, err
	}
	acct, err := BuildAccount(ctx, w.masterSeed, idx, w.store)
	if err != nil {
		return address.P2MRAddress{}, err
	}
	w.current = acct
	w.activeIdx = idx
	if err := writeAccountIndex(w.store.Dir(), idx); err != nil {
		return address.P2MRAddress{}, err
	}
	log.Info("wallet: switched active account", "wallet", w.name, "index", idx)
	w.signalKeypool()
	return acct.Address, nil
}

// Balance sums outputs for the current address.
func (w *Wallet) Balance(u txn.UTXOSet) (uint64, error) {
	return u.Balance(w.Address())
}

// SlotHealth returns the current account's worst-leaf health in [0, 1].
// Informational only; a locked wallet returns 0.
func (w *Wallet) SlotHealth() float64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.current == nil {
		return 0
	}
	return w.current.SlotHealth()
}

// SelectCoins greedily picks UTXOs to cover `target` using a
// largest-first strategy.
func SelectCoins(keys []txn.UTXOKey, outs []txn.TxOutput, target uint64) ([]txn.UTXOKey, []txn.TxOutput, uint64, bool) {
	idx := make([]int, len(outs))
	for i := range outs {
		idx[i] = i
	}
	sort.Slice(idx, func(i, j int) bool { return outs[idx[i]].Value > outs[idx[j]].Value })
	var sk []txn.UTXOKey
	var so []txn.TxOutput
	var sum uint64
	for _, i := range idx {
		sk = append(sk, keys[i])
		so = append(so, outs[i])
		sum += outs[i].Value
		if sum >= target {
			return sk, so, sum, true
		}
	}
	return sk, so, sum, false
}

// BuildTx selects UTXOs from the current address and constructs an
// unsigned tx. Works while locked — addresses alone are enough to
// reason about outputs; signing is what requires keys.
func (w *Wallet) BuildTx(ctx context.Context, u txn.UTXOSet, to address.P2MRAddress, amount, fee uint64) (*txn.Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if amount > txn.MaxMoney || fee > txn.MaxMoney || amount+fee < amount {
		return nil, errors.New("wallet: amount+fee overflows MaxMoney")
	}
	target := amount + fee
	keys, outs, err := u.AllForAddress(w.Address())
	if err != nil {
		return nil, err
	}
	selected, _, sum, ok := SelectCoins(keys, outs, target)
	if !ok {
		return nil, fmt.Errorf("wallet: insufficient funds (have %d, need %d)", sum, target)
	}
	tx := &txn.Transaction{Version: 1}
	for _, k := range selected {
		tx.Inputs = append(tx.Inputs, txn.TxInput{PrevTxID: k.TxID, PrevIndex: k.Index})
	}
	tx.Outputs = append(tx.Outputs, txn.TxOutput{Value: amount, Address: to})
	if change := sum - target; change > 0 {
		tx.Outputs = append(tx.Outputs, txn.TxOutput{Value: change, Address: w.Address()})
	}
	return tx, nil
}

// Sign signs each input with leaf 0 (SHRINCS primary). Requires the
// wallet to be unlocked.
func (w *Wallet) Sign(ctx context.Context, tx *txn.Transaction) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.requireUnlockedLocked(); err != nil {
		return err
	}
	for i := range tx.Inputs {
		if err := ctx.Err(); err != nil {
			return err
		}
		sighash := txn.SigHash(*tx, i)
		sig, err := w.current.ShrincsKey.Sign(ctx, sighash[:])
		if err != nil {
			return fmt.Errorf("wallet: shrincs sign input %d: %w", i, err)
		}
		// Scheme-tag prefix: OP_CHECKSIG dispatches on this first byte.
		tagged := append([]byte{crypto.SchemeShrincs}, crypto.SerializeShrincsSig(sig)...)
		if err := w.attachSpendLocked(tx, i, 0, tagged); err != nil {
			return err
		}
	}
	return nil
}

// Send builds and signs a fully-witnessed tx.
func (w *Wallet) Send(ctx context.Context, u txn.UTXOSet, to address.P2MRAddress, amount, fee uint64) (*txn.Transaction, error) {
	tx, err := w.BuildTx(ctx, u, to, amount, fee)
	if err != nil {
		return nil, err
	}
	if err := w.Sign(ctx, tx); err != nil {
		return nil, err
	}
	return tx, nil
}

// EstimateTxSize returns a conservative byte-count prediction.
func EstimateTxSize(numInputs, numOutputs int) int {
	const (
		baseOverhead  = 16
		inputOverhead = 900
		outputSize    = 40
	)
	return baseOverhead + numInputs*inputOverhead + numOutputs*outputSize
}

// SendAtFeerate is Send with an explicit sat/byte feerate. Adaptive:
// signs once at an estimated fee, then rebuilds-and-resigns once if
// the real post-sign size exceeds the estimate.
func (w *Wallet) SendAtFeerate(ctx context.Context, u txn.UTXOSet, to address.P2MRAddress, amount uint64, feerate float64) (*txn.Transaction, error) {
	if feerate < 0 {
		return nil, errors.New("wallet: negative feerate")
	}
	numOutputs := 2
	feeFor := func(size int) (uint64, error) {
		fee := uint64(feerate*float64(size) + 0.999)
		if fee > txn.MaxMoney {
			return 0, errors.New("wallet: feerate*size overflows MaxMoney")
		}
		return fee, nil
	}

	initialFee, err := feeFor(EstimateTxSize(1, numOutputs))
	if err != nil {
		return nil, err
	}
	trial, err := w.BuildTx(ctx, u, to, amount, initialFee)
	if err != nil {
		return nil, err
	}
	if n := len(trial.Inputs); n > 1 {
		if refined, rerr := feeFor(EstimateTxSize(n, numOutputs)); rerr == nil && refined > initialFee {
			trial, err = w.BuildTx(ctx, u, to, amount, refined)
			if err != nil {
				return nil, err
			}
			initialFee = refined
		}
	}
	if err := w.Sign(ctx, trial); err != nil {
		return nil, err
	}
	actualSize := len(trial.Serialize())
	neededFee, err := feeFor(actualSize)
	if err != nil {
		return nil, err
	}
	if initialFee >= neededFee {
		return trial, nil
	}
	log.Warn("wallet: size estimate underpaid, rebuilding at corrected fee",
		"initial_fee", initialFee, "needed_fee", neededFee, "actual_size", actualSize)
	tx2, err := w.BuildTx(ctx, u, to, amount, neededFee)
	if err != nil {
		return nil, err
	}
	if err := w.Sign(ctx, tx2); err != nil {
		return nil, err
	}
	actual2 := len(tx2.Serialize())
	if needed2, _ := feeFor(actual2); neededFee < needed2 {
		log.Warn("wallet: rebuilt tx still slightly underpays; sending anyway",
			"fee", neededFee, "needed", needed2, "size", actual2)
	}
	return tx2, nil
}

// SignWithShrimps signs each input via leaf 1 (SHRIMPS multi-device).
func (w *Wallet) SignWithShrimps(ctx context.Context, tx *txn.Transaction) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.requireUnlockedLocked(); err != nil {
		return err
	}
	for i := range tx.Inputs {
		if err := ctx.Err(); err != nil {
			return err
		}
		sighash := txn.SigHash(*tx, i)
		sig, err := w.current.ShrimpsKey.Sign(ctx, sighash[:])
		if err != nil {
			return fmt.Errorf("wallet: shrimps sign input %d: %w", i, err)
		}
		tagged := append([]byte{crypto.SchemeShrimps}, crypto.SerializeShrimpsSig(sig)...)
		if err := w.attachSpendLocked(tx, i, 1, tagged); err != nil {
			return err
		}
	}
	return nil
}

// attachSpendLocked fills in the input's P2MRSpend for a given leaf.
// Caller must hold w.mu.
func (w *Wallet) attachSpendLocked(tx *txn.Transaction, idx int, leafIdx uint32, sigBytes []byte) error {
	leaves := w.current.Leaves
	if int(leafIdx) >= len(leaves) {
		return errors.New("wallet: leaf index out of range")
	}
	leafHashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = address.LeafHash(l)
	}
	proof := crypto.MerkleProof(leafHashes, int(leafIdx))
	tx.Inputs[idx].Spend = address.P2MRSpend{
		LeafScript:  leaves[leafIdx],
		LeafIndex:   leafIdx,
		MerkleProof: proof,
		Witness:     [][]byte{sigBytes},
	}
	return nil
}

// --- pending-tx persistence (plain files under <walletdir>/pending/) -----
//
// A "pending" tx is one we've built, signed, and broadcast locally but
// haven't yet seen confirmed. Persisted so the node can rebroadcast on
// startup/periodic ticker. These files contain already-broadcast
// transactions — not secret, so plaintext on disk is fine even for
// encrypted wallets.

const pendingDirName = "pending"

func pendingPath(dir string, txid [32]byte) string {
	return filepath.Join(dir, pendingDirName, fmt.Sprintf("%x.tx", txid))
}

// RecordPending stores a signed tx as a wallet-pending entry.
func (w *Wallet) RecordPending(ctx context.Context, tx *txn.Transaction) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id := tx.TxID()
	dir := filepath.Join(w.store.Dir(), pendingDirName)
	if err := os.MkdirAll(dir, defaultDirPerm); err != nil {
		return err
	}
	return atomicWrite(pendingPath(w.store.Dir(), id), tx.Serialize())
}

// ClearPending drops a confirmed tx from the pending set.
func (w *Wallet) ClearPending(txid [32]byte) {
	_ = os.Remove(pendingPath(w.store.Dir(), txid))
}

// PendingTxs returns every wallet-pending tx still on disk. Decoding
// errors drop the offending entry from the result rather than failing
// the whole call — corruption of one entry shouldn't blind us to all.
func (w *Wallet) PendingTxs(ctx context.Context) ([]txn.Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir := filepath.Join(w.store.Dir(), pendingDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []txn.Transaction
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			continue
		}
		tx, _, derr := txn.DeserializeTx(data)
		if derr != nil {
			continue
		}
		out = append(out, *tx)
	}
	return out, nil
}

// --- helpers -------------------------------------------------------------

// requireUnlockedLocked returns ErrLocked if an encrypted wallet is
// locked. Plaintext wallets always pass. Caller must hold w.mu.
func (w *Wallet) requireUnlockedLocked() error {
	if w.store.IsLocked() {
		return ErrLocked
	}
	if w.current == nil {
		return ErrLocked
	}
	return nil
}

func (w *Wallet) rebuildCurrent(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.rebuildCurrentLocked(ctx)
}

func (w *Wallet) rebuildCurrentLocked(ctx context.Context) error {
	mn, err := w.store.ReadFile("mnemonic")
	if err != nil {
		return fmt.Errorf("wallet: read mnemonic: %w", err)
	}
	seed, err := MnemonicToSeed(string(mn), "")
	if err != nil {
		return fmt.Errorf("wallet: derive seed: %w", err)
	}
	w.masterSeed = seed
	acct, err := BuildAccount(ctx, seed, w.activeIdx, w.store)
	if err != nil {
		return err
	}
	w.current = acct
	return nil
}

func (w *Wallet) resetAutoLockLocked(timeout time.Duration) {
	w.cancelAutoLockLocked()
	if timeout > 0 {
		w.autoLock = time.AfterFunc(timeout, func() {
			_ = w.Lock()
			log.Info("wallet: auto-lock timer fired", "wallet", w.name)
		})
	}
}

func (w *Wallet) cancelAutoLockLocked() {
	if w.autoLock != nil {
		w.autoLock.Stop()
		w.autoLock = nil
	}
}

// signalKeypool nudges the background filler. Non-blocking.
func (w *Wallet) signalKeypool() {
	select {
	case w.keypoolSig <- struct{}{}:
	default:
	}
}

// keypoolFiller pre-derives P2MR addresses for upcoming account indices
// so ListAccounts / newaddress stays instant. Background-only, logged
// on failure, never blocks a signing path.
func (w *Wallet) keypoolFiller() {
	for range w.keypoolSig {
		w.mu.Lock()
		locked := w.store.IsLocked()
		base := w.activeIdx
		seed := w.masterSeed
		store := w.store
		w.mu.Unlock()
		if locked {
			continue
		}
		for i := uint32(1); i <= KeypoolSize; i++ {
			idx := base + i
			if _, ok := readAddrCache(store.Dir(), idx); ok {
				continue
			}
			if _, err := BuildAccount(context.Background(), seed, idx, store); err != nil {
				log.Warn("wallet: keypool precompute failed", "wallet", w.name, "index", idx, "err", err)
				continue
			}
			log.Debug("wallet: keypool precomputed", "wallet", w.name, "index", idx)
		}
	}
}
