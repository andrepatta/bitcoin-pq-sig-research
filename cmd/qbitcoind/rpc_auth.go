package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// CookieFilename is the on-disk name for the auto-generated RPC
// credential, under the node's datadir. Matches Bitcoin Core's
// `.cookie` convention so familiar tooling works without surprises.
const CookieFilename = ".cookie"

// cookieUser is the reserved username written into .cookie. Any caller
// that can read the file is authorized, so the username is fixed —
// secret material is entirely in the random password half.
const cookieUser = "__cookie__"

// writeCookie generates a fresh random password and writes
// "__cookie__:<hex>" to <datadir>/.cookie with mode 0600. The file is
// rewritten on every startup: a prior stale cookie becomes unusable,
// which is the behavior operators expect from Bitcoin Core.
//
// The returned cleanup function removes the file; the caller should
// defer it so a clean shutdown doesn't leave stale credentials behind.
// If the process crashes, the next startup simply overwrites it.
func writeCookie(datadir string) (user, pass string, cleanup func(), err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", nil, fmt.Errorf("read random for cookie: %w", err)
	}
	pass = hex.EncodeToString(buf)
	user = cookieUser
	path := filepath.Join(datadir, CookieFilename)
	// os.WriteFile truncates on existing files but keeps their mode,
	// so explicitly chmod in case an older file had looser perms.
	if err = os.WriteFile(path, []byte(user+":"+pass), 0o600); err != nil {
		return "", "", nil, fmt.Errorf("write cookie %s: %w", path, err)
	}
	if err = os.Chmod(path, 0o600); err != nil {
		return "", "", nil, fmt.Errorf("chmod cookie %s: %w", path, err)
	}
	cleanup = func() { _ = os.Remove(path) }
	return user, pass, cleanup, nil
}

// basicAuthMiddleware rejects every request whose HTTP Basic
// credentials don't match. Constant-time compare on both halves
// prevents timing oracles from leaking the expected password to a
// network attacker probing the endpoint.
//
// WWW-Authenticate is set on the 401 response so a standards-
// conforming HTTP client (including the CLI's error mapping) can
// tell an RPC-auth failure apart from a domain-level "bad passphrase"
// 401 emitted by /wallet/passphrase and friends.
func basicAuthMiddleware(user, pass string, next http.Handler) http.Handler {
	expectedUser := []byte(user)
	expectedPass := []byte(pass)
	const realm = `Basic realm="qbitcoin"`
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok {
			rw.Header().Set("WWW-Authenticate", realm)
			http.Error(rw, "RPC authorization required", http.StatusUnauthorized)
			return
		}
		userOK := subtle.ConstantTimeCompare([]byte(u), expectedUser) == 1
		passOK := subtle.ConstantTimeCompare([]byte(p), expectedPass) == 1
		if !userOK || !passOK {
			rw.Header().Set("WWW-Authenticate", realm)
			http.Error(rw, "bad RPC credentials", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(rw, r)
	})
}
