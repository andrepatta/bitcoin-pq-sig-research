# `wallet/` — multi-wallet, encryption, BIP-32 hardened KDF

Wallet design is **Bitcoin Core-style multi-wallet**: zero wallets is the clean default, multiple wallets coexist under `<datadir>/wallets/<name>/`, every per-wallet RPC call is routed via `?wallet=<name>` (or defaults to the single loaded wallet). Encryption is opt-in per-wallet, AES-256-GCM at rest under a PBKDF2-HMAC-SHA512-derived KEK.

---

## 1. Files

| File | Owns |
|---|---|
| `wallet.go` | The named, per-wallet object: lifecycle, address, balance, BuildTx / Sign / Send, account management, `ErrLocked` guard. |
| `registry.go` | Multi-wallet manager: Create / Load / Unload / Get / List / Default, with `?wallet=<name>` routing and a persisted `wallets.autoload` list. |
| `store.go` | Per-wallet on-disk Store: common ReadFile / WriteFile API that routes through plaintext files or AES-256-GCM ciphertext depending on encryption state. `wallet.meta` descriptor records encryption + KDF params. |
| `encrypt.go` | PBKDF2-HMAC-SHA512 KDF (200k iterations, 16 B salt) + AES-256-GCM seal/open + `Encrypt()` one-way upgrade with mid-crash recovery (handled by `Store.checkLayoutConsistency`). |
| `state_io.go` | `storeStateIO` — adapter bridging `Store` to `crypto.StateIO`, so SHRINCS / SHRIMPS state files inherit the wallet's encryption mode transparently. CRC wrap is still applied under the GCM layer. |
| `mnemonic.go` | BIP-39 seed + BIP-32 HMAC-SHA512 hardened derivation. |
| `rotate.go` | `Account` bundle (SHRINCS + SHRIMPS) + `BuildAccount` per account index. `account_index` (plaintext 4-byte file) tracks which account is currently active. `acct_<N>.addr` (plaintext 32-byte cache) lets a locked wallet answer `Address()` without keygen. No on-chain rotation — filename retained because it owns the active-account state machine. |

---

## 2. BIP-32 / BIP-44 derivation

```
BIP-39 mnemonic (24 words)
        ↓  PBKDF2-HMAC-SHA512 (standard BIP-39, 2048 iters)
64 B master seed
        ↓  BIP-32 HMAC-SHA512:  m
        ↓  m / 44'                       (purpose, hardened)
        ↓  m / 44' / 1'                  (coin type = SLIP-44 testnet, hardened)
        ↓  m / 44' / 1' / N'             (account N, hardened)
       ↙                          ↘
  m / .. / N' / 0'             m / .. / N' / 1'
  SHRINCS seed (32 B)          SHRIMPS seed (32 B)
        ↓                                    ↓
  ShrincsKey N                          ShrimpsKey N
```

**Every level is hardened.** Non-hardened derivation needs `child_priv = parse256(I[:32]) + k_par mod n` — secp256k1 point addition, which hash-based keys don't support. Therefore: **no xpub, no watch-only wallets**. See [`docs/invariants.md`](../invariants.md) §9.

```go
type ExtKey struct { Key, ChainCode [32]byte }

func MasterKey(seed []byte) ExtKey                            // m
func DeriveHardened(parent ExtKey, idx uint32) ExtKey         // m / idx'
func DeriveAccountKeys(master ExtKey, account uint32) (shrincsSeed, shrimpsSeed [32]byte)
```

The 24-word mnemonic recovers all accounts forever. `account_0`, `account_1`, … are all derivable on demand. Paper §14 calls this the "key-pool" approach: precompute many pubkeys, hand them out as fresh receive addresses.

### Mnemonic-restore account discovery (BIP-44 §Account Discovery)

When the user calls `POST /wallet/create` with a **caller-supplied** mnemonic (i.e. restoring an existing seed rather than auto-generating a fresh one), the handler runs BIP-44 §Account Discovery before returning. For each index `0, 1, 2, …` the wallet derives the 2-leaf P2MR address and asks whether it has any on-chain history; the scan stops after `AccountDiscoveryGapLimit` (default `20`, matches BIP-44) consecutive unused indices. The active index is then set to the highest-used account found, so the restored wallet reports the balance actually present on chain instead of starting blank at account 0.

```go
package wallet

var AccountDiscoveryGapLimit = 20                            // BIP-44 default; var, not const, so tests can shrink it

type AddressActivity interface {
    HasActivity(ctx context.Context, addr address.P2MRAddress) (bool, error)
}

func (w *Wallet) DiscoverAccounts(ctx context.Context, activity AddressActivity) (uint32, error)
```

- **Only runs for user-supplied mnemonics.** Auto-generated mnemonics cannot have prior history — discovery is skipped to avoid a pointless 20× keygen on wallet creation.
- **Adapter lives in `cmd/qbitcoind/wallet_rpc.go`.** `chainAddressActivity` wraps `core.Blockchain.ListTxsForAddress`; any recorded receive or spend counts as activity. The `wallet/` package stays free of `core/` imports.
- **Cost.** One SHRINCS+SHRIMPS keygen per scanned index (~1 s at paper params). A fresh empty mnemonic scans exactly `AccountDiscoveryGapLimit` indices; a restore with `K` used accounts scans `K + AccountDiscoveryGapLimit`. State files and `acct_<N>.addr` caches are written along the way — the scan doubles as keypool pre-derivation.
- **Response.** `POST /wallet/create` includes `"discovered_account_index": N` when discovery ran, so the caller can surface "restored; active at account N" to the user.

---

## 3. Multi-wallet registry

`Registry` is the top-level manager. One process can hold zero, one, or many wallets in memory.

```go
type WalletInfo struct {
    Name       string
    Encrypted  bool
    Locked     bool
    Address    string         // bech32
}

type Registry struct { /* unexported */ }

func NewRegistry(dataDir string) (*Registry, error)
func (r *Registry) Create(ctx context.Context, name, passphrase, mnemonic string, autoload bool) (*Wallet, error)
func (r *Registry) Load(ctx context.Context, name, passphrase string, autoload bool) (*Wallet, error)
func (r *Registry) Unload(name string) error
func (r *Registry) Get(name string) (*Wallet, error)
func (r *Registry) Default() (*Wallet, error)            // ErrAmbiguousDefault if 2+ loaded
func (r *Registry) List() []WalletInfo
```

### `?wallet=<name>` routing

Per-wallet RPCs accept `?wallet=<name>`:

| Loaded count | `?wallet=` provided? | Behavior |
|---|---|---|
| 0 | — | `404 no wallet loaded` |
| 1 | absent | Default routing — single loaded wallet |
| 1 | `?wallet=foo` | Must match the single loaded wallet, else `404` |
| 2+ | absent | `412 ambiguous default` |
| 2+ | `?wallet=foo` | Routes to `foo`, else `404` |

Encrypted + locked wallets return `423 wallet is locked` from handlers that need signing; read-only handlers (`/wallet/status`) still answer from plaintext caches.

### `wallets.autoload`

`<datadir>/wallets.autoload` is a newline-separated list of wallet names re-loaded on node boot. Encrypted ones come up locked; `POST /wallet/passphrase` unlocks for a timed window.

---

## 4. Encryption (AES-256-GCM at rest)

Opt-in, Bitcoin Core-style: `createwallet` with empty passphrase = plaintext (with explicit `y/N` confirmation); non-empty passphrase = encrypted.

### KDF

```
KEK := PBKDF2-HMAC-SHA512(passphrase, salt, iters=200_000, dklen=32)
```

Salt is 16 random bytes generated at wallet-creation time, stored in `wallet.meta`.

### Sealing

```
nonce := random 12 B (per write — never reused)
ciphertext_with_tag := AES-256-GCM.Seal(KEK, nonce, plaintext, aad)
file_bytes := nonce || ciphertext_with_tag
```

Each write generates a fresh nonce. AES-GCM-SIV would buy nonce-misuse resistance but isn't needed because `Store.WriteFile` controls the nonce generation entirely.

### Encrypting an existing plaintext wallet

`encryptwallet <name>` (→ `POST /wallet/encrypt`) is **one-way** — matches Bitcoin Core's no-`decryptwallet` policy. Implementation in `Wallet.Encrypt(ctx, passphrase)`:

1. Generate fresh `salt`, derive `KEK`.
2. For every plaintext file under the wallet dir: read → seal under (KEK, fresh nonce) → write to `<file>.enc.tmp`.
3. Persist new `wallet.meta` (encryption: GCM, KDF: PBKDF2-HMAC-SHA512, iters: 200000, salt: …) to `wallet.meta.tmp`.
4. Rename all `.tmp` files in dependency order (data files first, meta last).
5. Delete the original plaintext files.

A crash mid-step is recovered by `Store.checkLayoutConsistency` at next load: the presence of any `.tmp` file or a `.enc` file alongside a plaintext one triggers cleanup.

### `wallet.meta` descriptor

```json
{
    "version": 1,
    "encryption": "gcm",       // or "none"
    "kdf": "pbkdf2-sha512",
    "kdf_iters": 200000,
    "kdf_salt": "<base64 16B>"
}
```

---

## 5. State-file integration (persist-before-sign)

`storeStateIO` (in `state_io.go`) implements `crypto.StateIO` against the wallet's `Store`. SHRINCS / SHRIMPS treat it identically to `FileStateIO` — they don't know about encryption.

Layering (innermost first):

```
plaintext body
  ↓  AppendCRC                 (CRC32-IEEE trailer — defends against in-memory bit flips)
crc-wrapped plaintext
  ↓  AES-256-GCM.Seal          (only if wallet is encrypted)
sealed bytes
  ↓  atomic write+rename+fsync  (FileStateIO write protocol)
on-disk state file
```

The CRC is **inside** the GCM ciphertext. Reasons:

1. GCM defends against ciphertext-side tamper (any flipped bit in the ciphertext makes Open fail with auth-tag error).
2. The CRC defends against a bit flip *between decrypt-in-memory and the next signing call* — GCM can't catch that because by then the data is plaintext in RAM.

Together they cover every realistic corruption path that doesn't require active malice + KEK access.

See [`docs/operations/persist-before-sign.md`](../operations/persist-before-sign.md) for the full lifecycle.

---

## 6. Wallet lifecycle

```go
type Wallet struct { /* unexported */ }

// Lifecycle
func CreateWallet(ctx context.Context, store *Store, mnemonic, passphrase string) (*Wallet, string, error)
func LoadWallet(ctx context.Context, store *Store) (*Wallet, error)         // returns locked if encrypted
func (w *Wallet) Unlock(passphrase string, timeout time.Duration) error
func (w *Wallet) Lock() error                                               // zeroes MEK in memory
func (w *Wallet) Encrypt(ctx context.Context, passphrase string) error      // one-way upgrade
func (w *Wallet) ChangePassphrase(old, new string) error
func (w *Wallet) IsLocked() bool

// Address
func (w *Wallet) Address() (string, error)                                  // returns "" if locked
func (w *Wallet) NewReceiveAddress(ctx context.Context) (string, error)
func (w *Wallet) SetActiveAccount(ctx context.Context, idx uint32) error
func (w *Wallet) ListAccounts(ctx context.Context) ([]AccountInfo, error)

// Money
func (w *Wallet) Balance(utxos txn.UTXOSet) (uint64, error)
func (w *Wallet) BuildTx(ctx context.Context, utxos txn.UTXOSet, to address.P2MRAddress, amount, fee uint64) (*txn.Transaction, error)
func (w *Wallet) Sign(ctx context.Context, tx *txn.Transaction) error
func (w *Wallet) SignWithShrimps(ctx context.Context, tx *txn.Transaction) error
func (w *Wallet) Send(ctx context.Context, utxos txn.UTXOSet, to address.P2MRAddress, amount, fee uint64) (*txn.Transaction, error)
func (w *Wallet) SendAtFeerate(ctx context.Context, utxos txn.UTXOSet, to address.P2MRAddress, amount, feerate uint64) (*txn.Transaction, error)
func (w *Wallet) RecordPending(ctx context.Context, tx *txn.Transaction) error
func (w *Wallet) PendingTxs(ctx context.Context) ([]txn.Transaction, error)
```

`ErrLocked` is the guard. `Sign` / `BuildTx` / `Send` / `SendAtFeerate` / `Encrypt` / `ChangePassphrase` all return `ErrLocked` on an encrypted-locked wallet. Read-only methods (`Address`, `Balance`, `ListAccounts`) succeed by reading the plaintext address cache (`acct_<N>.addr`).

---

## 7. Signing flow

```
Wallet.Sign(ctx, tx) → for each input i:
    sigHash := txn.SigHash(*tx, i)
    sig, _ := account.ShrincsKey.Sign(ctx, sigHash[:])     // SHRINCS auto-falls-back internally
    tagged := append([]byte{crypto.SchemeShrincs}, crypto.SerializeShrincsSig(sig)...)
    attachSpend(tx, i, leaf=0, witness=[tagged])
```

`SHRINCS.Sign()` always succeeds — see [`shrincs.md`](shrincs.md). It emits a stateful UXMSS sig while that sig would be strictly smaller than the fallback SPHINCS+ sig; the moment the min-rule flips it auto-falls-back to stateless (W+C P+FP). Sig size jumps from ~324 B → ~4 KB at the transition point.

The wallet exposes `SlotHealth()` so UIs can surface a hint ("your primary key is N% consumed — consider a fresh receive address") to avoid the jump for users who care.

`Wallet.SignWithShrimps(ctx, tx)` is the alternate entry point for multi-device scenarios where the SHRINCS key is not on this device — uses leaf 1 with `crypto.SchemeShrimps = 0x01` tag.

---

## 8. Wallet directory layout

```
<datadir>/
  wallets.autoload                          # newline-separated wallet names
  wallets/
    <name>/
      wallet.meta                           # JSON descriptor (encryption mode + KDF params)
      mnemonic.encrypted | mnemonic.plain   # the BIP-39 mnemonic (encrypted iff wallet is)
      account_index                         # 4-byte plaintext: which account is active
      accounts/
        acct_0/
          shrincs.state                     # encrypted iff wallet is
          shrimps.state                     # encrypted iff wallet is
          shrincs.addr                      # plaintext 32-byte address cache
        acct_1/
          ...
      pending.txs                           # outbound txs awaiting confirmation
```

Plaintext caches (`account_index`, `*.addr`) live alongside the encrypted state files so a locked wallet can still answer `Address()` and `Balance()` without the KEK.

---

## 9. Errors

```go
var (
    ErrLocked              = errors.New("wallet: locked")
    ErrNotEncrypted        = errors.New("wallet: not encrypted")
    ErrAlreadyEncrypted    = errors.New("wallet: already encrypted")
    ErrBadPassphrase       = errors.New("wallet: bad passphrase")
    ErrWalletNotLoaded     = errors.New("wallet: not loaded")
    ErrAmbiguousDefault    = errors.New("wallet: ambiguous default")
)
```

These map to specific HTTP status codes — see `wallet_rpc.go::walletErrToStatus` and [`rpc.md`](rpc.md) §status-codes.

---

## 10. Tests

| Test file | Coverage |
|---|---|
| `wallet/store_test.go` | Plaintext + encrypted Store round-trip; encrypt-upgrade; passphrase change; mid-crash recovery. |
| `wallet/registry_test.go` | Create / Load / Unload / List, autoload persistence, duplicate-create rejection, ambiguous-default. |
| `wallet/coinselect_test.go` | Coin selection algorithm (greedy, fee-aware). |
| `wallet/pending_test.go` | RecordPending lifecycle, mempool-presence rebroadcast guard. |
| `wallet/paper_roundtrip_test.go` | End-to-end paper-params signing of both leaves of a 2-leaf P2MR address. |
