package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"qbitcoin/address"
	"qbitcoin/core"
	"qbitcoin/wallet"
)

// chainAddressActivity adapts *core.Blockchain to wallet.AddressActivity
// so BIP-44 account discovery during /wallet/create can ask whether a
// candidate address has ever had on-chain activity. Any recorded
// receive or spend counts as activity; a zero-length result means the
// gap-counter ticks up.
type chainAddressActivity struct {
	chain *core.Blockchain
}

func (c chainAddressActivity) HasActivity(ctx context.Context, addr address.P2MRAddress) (bool, error) {
	if c.chain == nil {
		return false, nil
	}
	recs, err := c.chain.ListTxsForAddress(ctx, addr)
	if err != nil {
		return false, err
	}
	return len(recs) > 0, nil
}

// registerWalletAdminHandlers wires the multi-wallet admin endpoints.
// They operate on the Registry only.
//
// Endpoints:
//
//	POST /wallet/create            {name, passphrase, mnemonic?}
//	POST /wallet/load              {name, passphrase?, autoload?}
//	POST /wallet/unload            {name}
//	GET  /wallets                  → [{name, encrypted, locked, address}]
//	POST /wallet/encrypt           {name, passphrase}
//	POST /wallet/passphrase        {name, passphrase, timeout_seconds}
//	POST /wallet/lock              {name}
//	POST /wallet/passphrasechange  {name, old, new}
//
// Empty `passphrase` at create-time is explicitly allowed — that's the
// Bitcoin Core "unencrypted wallet" path.
//
// `activity` is used during /wallet/create to scan a user-supplied
// mnemonic's account space and advance the active index past any
// previously-used accounts (BIP-44 §Account Discovery). Pass nil to
// skip discovery — /wallet/create still accepts a mnemonic, it just
// starts at account 0. Auto-generated mnemonics never trigger
// discovery since they have no prior history.
func registerWalletAdminHandlers(mux *http.ServeMux, reg *wallet.Registry, activity wallet.AddressActivity) {
	mux.HandleFunc("/wallets", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(rw, "GET required", http.StatusMethodNotAllowed)
			return
		}
		out := make([]map[string]any, 0)
		for _, info := range reg.List() {
			out = append(out, map[string]any{
				"name":      info.Name,
				"encrypted": info.Encrypted,
				"locked":    info.Locked,
				"address":   info.Address,
			})
		}
		writeJSON(rw, out)
	})

	mux.HandleFunc("/wallet/create", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name       string `json:"name"`
			Passphrase string `json:"passphrase"`
			Mnemonic   string `json:"mnemonic"`
			Autoload   bool   `json:"autoload"` // persist in wallets.autoload
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w, mn, err := reg.Create(r.Context(), req.Name, []byte(req.Passphrase), req.Mnemonic)
		if err != nil {
			status := walletErrToStatus(err)
			http.Error(rw, err.Error(), status)
			return
		}
		if req.Autoload {
			if err := reg.SetAutoload(req.Name, true); err != nil {
				// Non-fatal — wallet is already created and loaded.
				// Log the autoload failure but don't fail the whole
				// call, or the caller has no easy way to clean up.
				http.Error(rw, "created but autoload persist failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		// BIP-44 §Account Discovery: only meaningful when the user
		// supplied an existing mnemonic — an auto-generated one can't
		// have prior on-chain history. Discovery advances the active
		// index to the highest-used account so the restored wallet
		// reports the balance that's actually on-chain.
		discovered := uint32(0)
		ranDiscovery := false
		if req.Mnemonic != "" && activity != nil {
			idx, derr := w.DiscoverAccounts(r.Context(), activity)
			if derr != nil {
				http.Error(rw, "wallet created but account discovery failed: "+derr.Error(), http.StatusInternalServerError)
				return
			}
			discovered = idx
			ranDiscovery = true
		}
		b32, _ := w.Bech32()
		resp := map[string]any{
			"name":      w.Name(),
			"encrypted": w.IsEncrypted(),
			"locked":    w.IsLocked(),
			"address":   b32,
			"path":      w.DataDir(),
			// Returned ONCE at creation time. Caller must surface it to
			// the user — there is no other way to recover it later.
			"mnemonic": mn,
		}
		if ranDiscovery {
			resp["discoveredaccountindex"] = discovered
		}
		writeJSON(rw, resp)
	})

	mux.HandleFunc("/wallet/load", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name       string `json:"name"`
			Passphrase string `json:"passphrase"`
			Autoload   bool   `json:"autoload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w, err := reg.Load(r.Context(), req.Name, req.Autoload)
		if err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		// If a passphrase was supplied AND the wallet is encrypted,
		// also unlock it in the same call. No timeout — matches
		// Bitcoin Core's `loadwallet` which doesn't auto-lock.
		if len(req.Passphrase) > 0 && w.IsEncrypted() {
			if uerr := w.Unlock(r.Context(), []byte(req.Passphrase), 0); uerr != nil {
				http.Error(rw, uerr.Error(), walletErrToStatus(uerr))
				return
			}
		}
		b32, _ := w.Bech32()
		writeJSON(rw, map[string]any{
			"name":      w.Name(),
			"encrypted": w.IsEncrypted(),
			"locked":    w.IsLocked(),
			"address":   b32,
		})
	})

	mux.HandleFunc("/wallet/unload", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		if err := reg.Unload(req.Name); err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		writeJSON(rw, map[string]any{"unloaded": true, "name": req.Name})
	})

	mux.HandleFunc("/wallet/encrypt", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name       string `json:"name"`
			Passphrase string `json:"passphrase"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w, err := reg.Get(req.Name)
		if err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		if err := w.Encrypt([]byte(req.Passphrase)); err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		writeJSON(rw, map[string]any{"encrypted": true})
	})

	mux.HandleFunc("/wallet/passphrase", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name           string `json:"name"`
			Passphrase     string `json:"passphrase"`
			TimeoutSeconds int64  `json:"timeout_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w, err := reg.Get(req.Name)
		if err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		timeout := time.Duration(req.TimeoutSeconds) * time.Second
		if err := w.Unlock(r.Context(), []byte(req.Passphrase), timeout); err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		writeJSON(rw, map[string]any{"locked": w.IsLocked(), "timeout_seconds": req.TimeoutSeconds})
	})

	mux.HandleFunc("/wallet/lock", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w, err := reg.Get(req.Name)
		if err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		if err := w.Lock(); err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		writeJSON(rw, map[string]any{"locked": true})
	})

	mux.HandleFunc("/wallet/passphrasechange", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name string `json:"name"`
			Old  string `json:"old"`
			New  string `json:"new"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		w, err := reg.Get(req.Name)
		if err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		if err := w.ChangePassphrase([]byte(req.Old), []byte(req.New)); err != nil {
			http.Error(rw, err.Error(), walletErrToStatus(err))
			return
		}
		writeJSON(rw, map[string]any{"ok": true})
	})
}

// walletErrToStatus maps wallet-package sentinel errors onto HTTP
// status codes. Unknown errors → 500. Errors that CLIs want to
// pretty-print distinctly (locked, not-encrypted, bad-passphrase) get
// their own 4xx code so the client can render a clean one-liner
// without string-matching the error text.
//
// Status choices intentionally mirror Bitcoin Core's RPC-error spirit:
//   - 404 Not Found        : named wallet isn't loaded (or doesn't exist)
//   - 409 Conflict         : create/load would collide with existing state
//   - 423 Locked           : wallet is encrypted and not unlocked
//   - 401 Unauthorized     : bad passphrase (distinguishes from 400 to
//     make brute-force attempts visible in logs)
//   - 400 Bad Request      : malformed input, empty names, etc.
//   - 412 Precondition Fail: ambiguous default wallet; specify -rpcwallet
func walletErrToStatus(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, wallet.ErrWalletNotLoaded):
		return http.StatusNotFound
	case errors.Is(err, wallet.ErrWalletAlreadyLoaded),
		errors.Is(err, wallet.ErrStoreExists),
		errors.Is(err, wallet.ErrAlreadyEncrypted),
		errors.Is(err, wallet.ErrPartialUpgrade):
		return http.StatusConflict
	case errors.Is(err, wallet.ErrLocked):
		return http.StatusLocked
	case errors.Is(err, wallet.ErrBadPassphrase):
		return http.StatusUnauthorized
	case errors.Is(err, wallet.ErrInvalidWalletName),
		errors.Is(err, wallet.ErrNotEncrypted):
		return http.StatusBadRequest
	case errors.Is(err, wallet.ErrAmbiguousDefault):
		return http.StatusPreconditionFailed
	case errors.Is(err, wallet.ErrStoreMissing):
		return http.StatusNotFound
	}
	// Catch-all for unexpected errors (keygen failures, I/O errors).
	return http.StatusInternalServerError
}

// bech32ForAddr is a small helper shared with runRPC so the admin
// handlers can log addresses without duplicating the encode-or-hex
// fallback. Kept here to avoid extending runRPC's import surface.
var _ = address.P2MRAddress{} // silences unused-import when imports change

// resolveWallet picks the wallet to act on for a legacy /wallet/*
// request. Routing priority:
//
//  1. `?wallet=<name>` query parameter — explicit routing via
//     `qbitcoin-cli -rpcwallet=<name>`. Looks up in the Registry.
//     Returns 404 if the name isn't loaded, 423 if locked.
//
//  2. Empty name + exactly one wallet loaded → use that wallet as the
//     default (mirrors `bitcoin-cli` behavior when a single wallet is
//     loaded — no explicit routing required).
//
//  3. Empty name + zero wallets → 404 "no wallet loaded".
//
//  4. Empty name + 2+ wallets → 412 (ambiguous). Caller must pass
//     -rpcwallet.
func resolveWallet(r *http.Request, reg *wallet.Registry) (*wallet.Wallet, int, error) {
	name := r.URL.Query().Get("wallet")
	if name != "" {
		w, err := reg.Get(name)
		if err != nil {
			return nil, walletErrToStatus(err), err
		}
		return w, 0, nil
	}
	if def := reg.Default(); def != nil {
		return def, 0, nil
	}
	if len(reg.List()) > 1 {
		return nil, http.StatusPreconditionFailed, wallet.ErrAmbiguousDefault
	}
	return nil, http.StatusNotFound, wallet.ErrWalletNotLoaded
}
