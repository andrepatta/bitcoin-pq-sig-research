package wallet

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Registry is the node-owned manager of loaded wallets. Mirrors
// Bitcoin Core's wallet directory model:
//
//   - `createwallet <name>` creates a new wallet under <baseDir>/<name>.
//   - `loadwallet <name>`   loads an existing wallet, locked for
//     encrypted stores.
//   - `unloadwallet <name>` removes it from the in-memory map; on-disk
//     files stay (user calls rm -rf to destroy).
//
// Wallets listed in <baseDir>/../wallets.autoload are re-loaded on
// startup (LoadAutoload). Default routing: a single loaded wallet IS
// the default; with multiple, the CLI must specify -rpcwallet=<name>
// or callers use Registry.Default().
type Registry struct {
	mu          sync.RWMutex
	baseDir     string             // <datadir>/wallets
	wallets     map[string]*Wallet // name → wallet (possibly locked)
	defaultName string             // empty when zero or >1 wallets are loaded
	autoloadSet map[string]bool    // snapshot of autoload file contents
}

// WalletInfo summarizes a loaded wallet for /wallets RPC responses.
type WalletInfo struct {
	Name      string
	Encrypted bool
	Locked    bool
	Address   string
}

// Error sentinels for multi-wallet routing.
var (
	ErrWalletNotLoaded     = errors.New("wallet: no wallet loaded")
	ErrWalletAlreadyLoaded = errors.New("wallet: already loaded")
	ErrAmbiguousDefault    = errors.New("wallet: multiple wallets loaded, specify wallet name")
	ErrInvalidWalletName   = errors.New("wallet: invalid wallet name")
)

// NewRegistry constructs a Registry rooted at <datadir>/wallets. The
// directory is created on first use.
func NewRegistry(baseDir string) *Registry {
	return &Registry{
		baseDir:     baseDir,
		wallets:     make(map[string]*Wallet),
		autoloadSet: make(map[string]bool),
	}
}

// BaseDir returns the root directory wallets live under.
func (r *Registry) BaseDir() string { return r.baseDir }

// validateName rejects names that would be awkward or dangerous as
// directory components. Only alphanumeric, `_`, and `-` are permitted;
// empty, `.`, `..`, and path separators are rejected. Matches Bitcoin
// Core's wallet-name validator.
func validateName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("%w: %q", ErrInvalidWalletName, name)
	}
	if strings.ContainsAny(name, "/\\\x00") {
		return fmt.Errorf("%w: contains path separator or NUL: %q", ErrInvalidWalletName, name)
	}
	for _, c := range name {
		isAlnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '_' && c != '-' {
			return fmt.Errorf("%w: %q contains disallowed character %q", ErrInvalidWalletName, name, c)
		}
	}
	return nil
}

func (r *Registry) walletDir(name string) string {
	return filepath.Join(r.baseDir, name)
}

// Create materializes a new wallet and loads it. Returns the mnemonic
// for one-time display.
//
// passphrase may be empty (unencrypted wallet). providedMnemonic may be
// empty to auto-generate.
func (r *Registry) Create(ctx context.Context, name string, passphrase []byte, providedMnemonic string) (*Wallet, string, error) {
	if err := validateName(name); err != nil {
		return nil, "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.wallets[name]; dup {
		return nil, "", fmt.Errorf("%w: %s", ErrWalletAlreadyLoaded, name)
	}
	if err := os.MkdirAll(r.baseDir, defaultDirPerm); err != nil {
		return nil, "", err
	}
	w, mn, err := CreateWallet(ctx, name, r.walletDir(name), passphrase, providedMnemonic)
	if err != nil {
		return nil, "", err
	}
	r.wallets[name] = w
	r.refreshDefaultLocked()
	return w, mn, nil
}

// Load opens an existing wallet from disk (encrypted comes up locked).
// autoload=true adds the wallet to the persistent wallets.autoload list.
func (r *Registry) Load(ctx context.Context, name string, autoload bool) (*Wallet, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.wallets[name]; dup {
		return nil, fmt.Errorf("%w: %s", ErrWalletAlreadyLoaded, name)
	}
	w, err := LoadWallet(ctx, name, r.walletDir(name))
	if err != nil {
		return nil, err
	}
	r.wallets[name] = w
	r.refreshDefaultLocked()
	if autoload {
		if err := r.setAutoloadLocked(name, true); err != nil {
			log.Warn("wallet: failed to update autoload", "wallet", name, "err", err)
		}
	}
	return w, nil
}

// Unload removes the wallet from the registry. On-disk files are not
// deleted.
func (r *Registry) Unload(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.wallets[name]
	if !ok {
		return ErrWalletNotLoaded
	}
	if w.IsEncrypted() {
		// Best-effort lock so MEK memory is zeroed on unload.
		_ = w.Lock()
	}
	delete(r.wallets, name)
	r.refreshDefaultLocked()
	return nil
}

// Get returns the wallet named `name`. An empty name returns the
// default (the single loaded wallet, else ErrAmbiguousDefault).
func (r *Registry) Get(name string) (*Wallet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if name == "" {
		if r.defaultName == "" {
			if len(r.wallets) == 0 {
				return nil, ErrWalletNotLoaded
			}
			return nil, ErrAmbiguousDefault
		}
		return r.wallets[r.defaultName], nil
	}
	w, ok := r.wallets[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrWalletNotLoaded, name)
	}
	return w, nil
}

// Default returns the default wallet, or nil if zero or >1 are loaded.
// Non-error variant used by the miner's coinbase-fallback path.
func (r *Registry) Default() *Wallet {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defaultName == "" {
		return nil
	}
	return r.wallets[r.defaultName]
}

// List returns info on all loaded wallets, sorted by name.
func (r *Registry) List() []WalletInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]WalletInfo, 0, len(r.wallets))
	for name, w := range r.wallets {
		addr, _ := w.Bech32()
		out = append(out, WalletInfo{
			Name:      name,
			Encrypted: w.IsEncrypted(),
			Locked:    w.IsLocked(),
			Address:   addr,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// refreshDefaultLocked picks a default wallet: exactly one loaded ⇒
// that one; otherwise (zero or many) no default. Matches Bitcoin Core's
// behavior where `-rpcwallet=<name>` is required once multiple wallets
// are loaded — no silent "stick with the first wallet" path that could
// accidentally route commands to a surprising destination. Caller must
// hold r.mu.
func (r *Registry) refreshDefaultLocked() {
	switch len(r.wallets) {
	case 1:
		for name := range r.wallets {
			r.defaultName = name
			return
		}
	default:
		r.defaultName = ""
	}
}

// --- autoload list management ---------------------------------------------

// autoloadFile returns <baseDir>/../wallets.autoload. The file lives in
// the node datadir (one level up from wallets/), which matches how
// Bitcoin Core manages settings files.
func (r *Registry) autoloadFile() string {
	return filepath.Join(filepath.Dir(r.baseDir), "wallets.autoload")
}

// Autoload returns the persisted set of wallet names to auto-load on
// startup. Missing file → empty list (not an error).
func (r *Registry) Autoload() ([]string, error) {
	raw, err := os.ReadFile(r.autoloadFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" || strings.HasPrefix(name, "#") {
			continue
		}
		if validateName(name) != nil {
			log.Warn("wallet: skipping invalid name in wallets.autoload", "name", name)
			continue
		}
		names = append(names, name)
	}
	return names, scanner.Err()
}

// SetAutoload adds or removes a wallet from the persistent autoload
// list. enable=true adds; enable=false removes. Idempotent.
func (r *Registry) SetAutoload(name string, enable bool) error {
	if err := validateName(name); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.setAutoloadLocked(name, enable)
}

func (r *Registry) setAutoloadLocked(name string, enable bool) error {
	current, err := r.Autoload()
	if err != nil {
		return err
	}
	present := false
	for _, n := range current {
		if n == name {
			present = true
			break
		}
	}
	var next []string
	switch {
	case enable && !present:
		next = append(current, name)
	case !enable && present:
		next = make([]string, 0, len(current))
		for _, n := range current {
			if n != name {
				next = append(next, n)
			}
		}
	default:
		return nil
	}
	sort.Strings(next)
	var buf bytes.Buffer
	for _, n := range next {
		buf.WriteString(n)
		buf.WriteByte('\n')
	}
	return atomicWrite(r.autoloadFile(), buf.Bytes())
}

// LoadAutoload loads every wallet listed in wallets.autoload, returning
// any errors encountered without aborting on the first failure. Encrypted
// wallets come up locked — the caller must walletpassphrase them before
// signing resumes.
func (r *Registry) LoadAutoload(ctx context.Context) []error {
	names, err := r.Autoload()
	if err != nil {
		return []error{fmt.Errorf("wallet: read autoload: %w", err)}
	}
	var errs []error
	for _, name := range names {
		if _, err := r.Load(ctx, name, false); err != nil {
			errs = append(errs, fmt.Errorf("wallet %q: %w", name, err))
			continue
		}
		log.Info("wallet: auto-loaded", "wallet", name)
	}
	return errs
}

// Close locks all encrypted wallets and clears the registry. Called on
// node shutdown. Safe to call multiple times.
func (r *Registry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, w := range r.wallets {
		if w.IsEncrypted() && !w.IsLocked() {
			_ = w.Lock()
		}
	}
	r.wallets = make(map[string]*Wallet)
	r.defaultName = ""
}
