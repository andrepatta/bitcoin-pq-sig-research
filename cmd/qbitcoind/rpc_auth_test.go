package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBasicAuthMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte("ok"))
	})
	h := basicAuthMiddleware("u", "p", inner)
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []struct {
		name        string
		user, pass  string
		setAuth     bool
		wantStatus  int
		wantAuthHdr bool
	}{
		{name: "no creds", setAuth: false, wantStatus: 401, wantAuthHdr: true},
		{name: "wrong user", user: "x", pass: "p", setAuth: true, wantStatus: 401, wantAuthHdr: true},
		{name: "wrong pass", user: "u", pass: "x", setAuth: true, wantStatus: 401, wantAuthHdr: true},
		{name: "ok", user: "u", pass: "p", setAuth: true, wantStatus: 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", srv.URL, nil)
			if tc.setAuth {
				req.SetBasicAuth(tc.user, tc.pass)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.wantStatus)
			}
			if tc.wantAuthHdr && resp.Header.Get("WWW-Authenticate") == "" {
				t.Errorf("missing WWW-Authenticate header on 401")
			}
		})
	}
}

func TestWriteCookie(t *testing.T) {
	dir := t.TempDir()
	user, pass, cleanup, err := writeCookie(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if user != cookieUser {
		t.Errorf("user = %q, want %q", user, cookieUser)
	}
	if len(pass) != 64 { // 32 random bytes, hex-encoded
		t.Errorf("pass length = %d, want 64", len(pass))
	}
	path := filepath.Join(dir, CookieFilename)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Cookie must be mode 0600 — this is the sole gate between the
	// RPC and anyone else on the host, so a 0644 cookie is a security
	// regression worth catching in CI.
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("cookie perms = %o, want 0600", mode)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(body))
	want := user + ":" + pass
	if got != want {
		t.Errorf("cookie contents = %q, want %q", got, want)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("cleanup did not remove cookie: err=%v", err)
	}
}

func TestResolveRPCAuth(t *testing.T) {
	t.Run("static flags win", func(t *testing.T) {
		u, p, cleanup, err := resolveRPCAuth("alice", "secret", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if cleanup != nil {
			t.Errorf("static auth should return no cleanup (would delete nothing); got non-nil")
		}
		if u != "alice" || p != "secret" {
			t.Errorf("got (%q,%q), want (alice,secret)", u, p)
		}
	})
	t.Run("cookie fallback", func(t *testing.T) {
		dir := t.TempDir()
		u, p, cleanup, err := resolveRPCAuth("", "", dir)
		if err != nil {
			t.Fatal(err)
		}
		if cleanup == nil {
			t.Fatal("cookie path must return a cleanup func")
		}
		defer cleanup()
		if u != cookieUser || len(p) != 64 {
			t.Errorf("cookie creds malformed: (%q,%q)", u, p)
		}
		if _, err := os.Stat(filepath.Join(dir, CookieFilename)); err != nil {
			t.Errorf("cookie file missing: %v", err)
		}
	})
	t.Run("half-set flag pair is an error", func(t *testing.T) {
		if _, _, _, err := resolveRPCAuth("alice", "", t.TempDir()); err == nil {
			t.Error("user-only should error")
		}
		if _, _, _, err := resolveRPCAuth("", "secret", t.TempDir()); err == nil {
			t.Error("pass-only should error")
		}
	})
}
