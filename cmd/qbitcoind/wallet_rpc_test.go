package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"qbitcoin/wallet"
)

// newTestServer wires up a fresh Registry rooted under a temp dir and
// returns an httptest server with the multi-wallet admin handlers
// registered. Other endpoints (legacy /wallet/*, /block/*, etc.) are
// intentionally NOT registered so the test exercises only what this
// refactor adds.
func newTestServer(t *testing.T) (*httptest.Server, *wallet.Registry) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "wallets")
	reg := wallet.NewRegistry(base)
	mux := http.NewServeMux()
	registerWalletAdminHandlers(mux, reg, nil)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		reg.Close()
	})
	return srv, reg
}

// do is a tiny JSON-RPC helper: POST body as JSON, parse response as
// JSON; returns status + decoded body. No assertions here — the test
// decides what to check per call.
func do(t *testing.T, method, url string, body any) (int, map[string]any) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return resp.StatusCode, map[string]any{"_error_body": string(raw)}
	}
	var out map[string]any
	if len(raw) == 0 {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode response: %v (raw=%q)", err, raw)
	}
	return resp.StatusCode, out
}

func doArr(t *testing.T, method, url string) (int, []map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return resp.StatusCode, nil
	}
	var out []map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestWalletAdmin_CreateListUnloadLoad_Plaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	srv, _ := newTestServer(t)

	// Create plaintext wallet.
	status, body := do(t, "POST", srv.URL+"/wallet/create", map[string]any{
		"name":       "main",
		"passphrase": "",
	})
	if status != 200 {
		t.Fatalf("create: status %d body %v", status, body)
	}
	if body["encrypted"].(bool) {
		t.Fatal("expected plaintext")
	}
	if body["locked"].(bool) {
		t.Fatal("plaintext wallet should not be locked")
	}
	if body["mnemonic"].(string) == "" {
		t.Fatal("mnemonic should be returned")
	}
	addr := body["address"].(string)
	if addr == "" {
		t.Fatal("missing address")
	}

	// List.
	status, arr := doArr(t, "GET", srv.URL+"/wallets")
	if status != 200 {
		t.Fatalf("list: status %d", status)
	}
	if len(arr) != 1 || arr[0]["name"].(string) != "main" {
		t.Fatalf("list: %v", arr)
	}

	// Unload.
	status, _ = do(t, "POST", srv.URL+"/wallet/unload", map[string]any{"name": "main"})
	if status != 200 {
		t.Fatalf("unload: %d", status)
	}
	status, arr = doArr(t, "GET", srv.URL+"/wallets")
	if status != 200 || len(arr) != 0 {
		t.Fatalf("post-unload list: %d %v", status, arr)
	}

	// Load.
	status, body = do(t, "POST", srv.URL+"/wallet/load", map[string]any{"name": "main"})
	if status != 200 {
		t.Fatalf("load: %d %v", status, body)
	}
	if body["address"].(string) != addr {
		t.Fatalf("load returned different address: %q vs %q", body["address"], addr)
	}
}

func TestWalletAdmin_EncryptedCreate_And_UnlockLockCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	srv, _ := newTestServer(t)

	// Create encrypted.
	status, body := do(t, "POST", srv.URL+"/wallet/create", map[string]any{
		"name":       "enc",
		"passphrase": "hunter2",
	})
	if status != 200 {
		t.Fatalf("create enc: %d %v", status, body)
	}
	if !body["encrypted"].(bool) {
		t.Fatal("expected encrypted")
	}
	if body["locked"].(bool) {
		t.Fatal("freshly-created encrypted should be unlocked")
	}

	// Lock.
	status, body = do(t, "POST", srv.URL+"/wallet/lock", map[string]any{"name": "enc"})
	if status != 200 || !body["locked"].(bool) {
		t.Fatalf("lock: %d %v", status, body)
	}

	// Wrong passphrase → 401.
	status, _ = do(t, "POST", srv.URL+"/wallet/passphrase", map[string]any{
		"name":            "enc",
		"passphrase":      "wrong",
		"timeout_seconds": 60,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong pass: got %d want 401", status)
	}

	// Correct passphrase unlocks.
	status, body = do(t, "POST", srv.URL+"/wallet/passphrase", map[string]any{
		"name":            "enc",
		"passphrase":      "hunter2",
		"timeout_seconds": 60,
	})
	if status != 200 {
		t.Fatalf("unlock: %d %v", status, body)
	}
	if body["locked"].(bool) {
		t.Fatal("wallet should be unlocked")
	}
}

func TestWalletAdmin_EncryptUpgradePath(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	srv, _ := newTestServer(t)

	// Plaintext wallet.
	if status, _ := do(t, "POST", srv.URL+"/wallet/create", map[string]any{
		"name": "w",
	}); status != 200 {
		t.Fatalf("create plaintext: %d", status)
	}

	// Upgrade to encrypted.
	status, body := do(t, "POST", srv.URL+"/wallet/encrypt", map[string]any{
		"name":       "w",
		"passphrase": "p",
	})
	if status != 200 {
		t.Fatalf("encrypt: %d %v", status, body)
	}

	// /wallets reflects encryption.
	_, arr := doArr(t, "GET", srv.URL+"/wallets")
	if !arr[0]["encrypted"].(bool) {
		t.Fatal("listed wallet still reports encrypted=false after encryptwallet")
	}

	// Cannot double-encrypt.
	status, _ = do(t, "POST", srv.URL+"/wallet/encrypt", map[string]any{
		"name":       "w",
		"passphrase": "p2",
	})
	if status != http.StatusConflict {
		t.Fatalf("double encrypt: got %d want 409", status)
	}
}

func TestWalletAdmin_PassphraseChange(t *testing.T) {
	if testing.Short() {
		t.Skip("needs full keygen; skipped under -short")
	}
	srv, _ := newTestServer(t)

	if status, _ := do(t, "POST", srv.URL+"/wallet/create", map[string]any{
		"name":       "pw",
		"passphrase": "old",
	}); status != 200 {
		t.Fatal("create")
	}

	// Wrong old → 401.
	status, _ := do(t, "POST", srv.URL+"/wallet/passphrasechange", map[string]any{
		"name": "pw", "old": "wrong", "new": "new",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong old: %d want 401", status)
	}

	// Correct rotation.
	status, _ = do(t, "POST", srv.URL+"/wallet/passphrasechange", map[string]any{
		"name": "pw", "old": "old", "new": "new",
	})
	if status != 200 {
		t.Fatalf("rotate: %d", status)
	}

	// Lock, then old passphrase no longer unlocks.
	do(t, "POST", srv.URL+"/wallet/lock", map[string]any{"name": "pw"})
	status, _ = do(t, "POST", srv.URL+"/wallet/passphrase", map[string]any{
		"name": "pw", "passphrase": "old", "timeout_seconds": 10,
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("old pass after rotation: %d want 401", status)
	}
	status, _ = do(t, "POST", srv.URL+"/wallet/passphrase", map[string]any{
		"name": "pw", "passphrase": "new", "timeout_seconds": 10,
	})
	if status != 200 {
		t.Fatalf("new pass: %d", status)
	}
}

func TestWalletAdmin_InvalidNameRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	status, _ := do(t, "POST", srv.URL+"/wallet/create", map[string]any{
		"name": "../etc/passwd",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("bad name: %d want 400", status)
	}
}

func TestWalletAdmin_NotFoundOnUnknown(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/wallet/lock", "/wallet/passphrase", "/wallet/encrypt", "/wallet/unload", "/wallet/passphrasechange"} {
		status, _ := do(t, "POST", srv.URL+path, map[string]any{"name": "ghost"})
		if status != http.StatusNotFound {
			t.Errorf("%s: got %d want 404", path, status)
		}
	}
}
