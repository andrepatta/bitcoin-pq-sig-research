// qbitcoin-cli is a thin HTTP client for the qbitcoin node RPC, patterned after
// bitcoin-cli. All state lives in the node; this binary just issues
// requests to its /... endpoints.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"
)

func usage() {
	fmt.Fprint(os.Stderr, `Usage: qbitcoin-cli [flags] <command> [args]

Global flags:
  -rpc <url>                  node RPC base URL (default http://127.0.0.1:8334)
  -rpcwallet <name>           route per-wallet commands to this wallet
  -rpcuser <user>             RPC Basic auth user (overrides cookie)
  -rpcpassword <pass>         RPC Basic auth password (overrides cookie)
  -rpccookiefile <path>       RPC cookie file (default <datadir>/.cookie)
  -datadir <path>             node data directory (default ~/.qbitcoin)

Wallet admin (multi-wallet, Bitcoin-Core-style):
  createwallet <name> [--import-mnemonic]
                                     create a wallet (prompts for passphrase;
                                     empty passphrase -> unencrypted wallet,
                                     with confirmation). With --import-mnemonic,
                                     prompts for an existing BIP-39 mnemonic
                                     instead of generating a fresh one.
  encryptwallet <name>               add encryption to an unencrypted wallet
                                     (prompts for passphrase twice)
  loadwallet <name> [--autoload]     load a wallet into the node
  unloadwallet <name>                unload a wallet from the node
  listwallets                        list loaded wallets
  walletpassphrase <name> <seconds>  unlock an encrypted wallet for <seconds>
                                     (0 = until explicit walletlock)
  walletlock <name>                  zero the MEK in memory; lock the wallet
  walletpassphrasechange <name>      rotate the passphrase (prompts for old + new)

Per-wallet (use -rpcwallet=<name> to route, or single-loaded default):
  getbalance                         current wallet balance (BTC)
  getwalletinfo                      full wallet state (balance, encryption, etc.)
  getaddress                         current wallet bech32 address (qbitcoin extension)
  getnewaddress                      advance to next account index, print new address
  setaccount <index>                 switch active wallet account (qbitcoin)
  listaccounts                       list known accounts (qbitcoin)
  sendtoaddress <addr> <amount> [fee]
                                     build, sign, broadcast a tx; amount is in BTC.
                                     Omit fee to auto-estimate at target=6 blocks.
  send <addr> <amount> [fee]         alias for sendtoaddress
  gettransaction <txid>              wallet-view transaction (category, amount, details)
  listtransactions [addr]            tx history for an address (defaults to current wallet)

Chain / node state:
  getblockchaininfo                  rolled-up chain state
  getbestblockhash                   tip block hash
  getblockcount                      current tip height
  getblock <hash|latest> [verbosity] 0=hex, 1=JSON w/ txids, 2=JSON w/ tx objects
  getblockhash <height>              main-chain block hash at the given height
  getrawtransaction <txid> [verbose] chain-view tx; verbose=false returns raw hex
  sendrawtransaction <hex>           broadcast a pre-signed raw transaction
  decoderawtransaction <hex>         decode raw hex to JSON
  getrawmempool [verbose]            mempool txids (or verbose per-tx object)
  getmempoolinfo                     mempool size, bytes, min feerate
  estimatesmartfee <target> [mode]   fee estimator (BTC/kvB); mode=unset|economical|conservative
  validateaddress <addr>             address validation + decode

Network / node:
  getnetworkinfo                     version, connections, relay fee
  getpeerinfo                        connected peers with per-peer stats
  getconnectioncount                 connected peer count
  uptime                             seconds since node RPC started
  help                               list available commands

Mining:
  getmininginfo                      chain tip state (height, difficulty, mempool)
  generatetoaddress <n> <addr>       regtest helper: mine n blocks paying coinbase to addr
  getblocktemplate                   BIP-22 template; external miners pull + submit
  submitblock <hexdata>              BIP-22 submitblock; returns null on accept

Node lifecycle:
  start [qbitcoind args...]          launch qbitcoind detached with --daemon;
                                     extra args are passed through verbatim
                                     (e.g. start --datadir /tmp/qb --rpc 18334)
  stop                               ask the running node to shut down gracefully

Passphrase input: by default read from stdin with no echo (interactive TTY).
Non-TTY stdin is read line by line — useful for scripts:
    echo "secret" | qbitcoin-cli walletpassphrase main 300
`)
}

func main() {
	rpc := flag.String("rpc", "http://127.0.0.1:8334", "node RPC base URL")
	rpcWallet := flag.String("rpcwallet", "", "wallet name to route per-wallet commands to")
	rpcUser := flag.String("rpcuser", "", "RPC auth user (overrides cookie file; pair with -rpcpassword)")
	rpcPassword := flag.String("rpcpassword", "", "RPC auth password (overrides cookie file; pair with -rpcuser)")
	rpcCookieFile := flag.String("rpccookiefile", "", "path to RPC cookie file (default: <datadir>/.cookie)")
	datadir := flag.String("datadir", defaultDataDir(), "node data directory (used to locate the RPC cookie)")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]
	c := &client{base: *rpc, walletName: *rpcWallet}
	if err := c.resolveAuth(*rpcUser, *rpcPassword, *rpcCookieFile, *datadir); err != nil {
		die("%v", err)
	}
	var err error
	switch cmd {
	// --- wallet admin (multi-wallet) ---
	case "createwallet":
		err = c.createWallet(rest)
	case "encryptwallet":
		err = c.encryptWallet(rest)
	case "loadwallet":
		err = c.loadWallet(rest)
	case "unloadwallet":
		err = c.unloadWallet(rest)
	case "listwallets":
		err = c.printGET("/wallets")
	case "walletpassphrase":
		err = c.walletPassphrase(rest)
	case "walletlock":
		err = c.walletLock(rest)
	case "walletpassphrasechange":
		err = c.walletPassphraseChange(rest)
	// --- per-wallet (respect -rpcwallet) ---
	case "getbalance":
		err = c.printGET(c.walletPath("/wallet/balance"))
	case "getwalletinfo":
		err = c.printGET(c.walletPath("/wallet/info"))
	case "getaddress":
		err = c.getAddress()
	case "getnewaddress", "newaddress":
		err = c.printPOST(c.walletPath("/wallet/newaddress"), nil)
	case "listaccounts":
		err = c.printGET(c.walletPath("/wallet/accounts"))
	case "setaccount":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		idx, e := strconv.ParseUint(rest[0], 10, 32)
		if e != nil {
			die("index: %v", e)
		}
		body, _ := json.Marshal(map[string]any{"index": idx})
		err = c.printPOST(c.walletPath("/wallet/setaccount"), body)
	case "send", "sendtoaddress":
		if len(rest) < 2 {
			usage()
			os.Exit(2)
		}
		to := rest[0]
		amt, e := parseBTCAmount(rest[1])
		if e != nil {
			die("amount: %v", e)
		}
		payload := map[string]any{"to": to, "amount": amt}
		if len(rest) >= 3 {
			fee, e := parseBTCAmount(rest[2])
			if e != nil {
				die("fee: %v", e)
			}
			payload["fee"] = fee
		}
		body, _ := json.Marshal(payload)
		err = c.printPOST(c.walletPath("/wallet/send"), body)
	case "gettransaction":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		// Wallet-view (bitcoin-cli gettransaction) — categorizes the tx
		// against the current wallet's address set.
		err = c.printGET(c.walletPath("/wallet/gettransaction/" + rest[0]))
	case "listtransactions":
		var addr string
		if len(rest) >= 1 {
			addr = rest[0]
		} else {
			addr, err = c.currentAddress()
			if err != nil {
				die("%v", err)
			}
		}
		err = c.printGET("/address/transactions/" + addr)
	// --- chain / node state (wallet-agnostic) ---
	case "estimatesmartfee":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		target := rest[0]
		mode := ""
		if len(rest) >= 2 {
			mode = rest[1]
		}
		path := "/fee/estimate?target=" + target
		if mode != "" {
			path += "&mode=" + mode
		}
		err = c.printGET(path)
	case "getrawtransaction":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		path := "/tx/" + rest[0]
		if len(rest) >= 2 {
			path += "?verbose=" + rest[1]
		}
		err = c.printGET(path)
	case "sendrawtransaction":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		err = c.printPOST("/tx/broadcast", []byte(rest[0]))
	case "decoderawtransaction":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		err = c.printPOST("/tx/decode", []byte(rest[0]))
	case "getblockcount":
		err = c.getBlockCount()
	case "getbestblockhash":
		err = c.printGET("/block/best")
	case "getblockchaininfo":
		err = c.printGET("/chain/info")
	case "getblock":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		path := "/block/" + rest[0]
		if len(rest) >= 2 && rest[0] != "latest" && rest[0] != "best" {
			if _, e := strconv.Atoi(rest[1]); e != nil {
				die("verbosity: %v", e)
			}
			path += "?verbosity=" + rest[1]
		}
		err = c.printGET(path)
	case "getblockhash":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		err = c.printGET("/blockhash/" + rest[0])
	case "getpeerinfo", "getpeers":
		err = c.printGET("/peers")
	case "getnetworkinfo":
		err = c.printGET("/network/info")
	case "getconnectioncount":
		err = c.printGET("/node/connectioncount")
	case "uptime":
		err = c.printGET("/node/uptime")
	case "getrawmempool":
		path := "/mempool"
		if len(rest) >= 1 {
			path += "?verbose=" + rest[0]
		}
		err = c.printGET(path)
	case "getmempoolinfo":
		err = c.printGET("/mempool/info")
	case "validateaddress":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		err = c.printGET("/address/validate/" + rest[0])
	case "help":
		err = c.printGET("/help")
	case "generatetoaddress":
		if len(rest) < 2 {
			usage()
			os.Exit(2)
		}
		n, e := strconv.Atoi(rest[0])
		if e != nil {
			die("nblocks: %v", e)
		}
		payload := map[string]any{"nblocks": n, "address": rest[1]}
		body, _ := json.Marshal(payload)
		err = c.printPOST("/mining/generatetoaddress", body)
	case "getmininginfo":
		err = c.printGET("/mining/info")
	case "getblocktemplate":
		// BIP-22 template pull. No params — mempool-backed template is
		// produced fresh per call. Miners loop-poll this endpoint.
		err = c.printGET("/mining/getblocktemplate")
	case "submitblock":
		if len(rest) < 1 {
			usage()
			os.Exit(2)
		}
		body, _ := json.Marshal(map[string]any{"hexdata": rest[0]})
		err = c.printPOST("/mining/submitblock", body)
	case "start":
		err = startDaemon(rest)
	case "stop":
		err = c.printPOST("/node/stop", nil)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		die("%v", err)
	}
}

type client struct {
	base       string
	walletName string
	user, pass string // HTTP Basic auth; empty = send no Authorization header
}

// resolveAuth picks credentials in the same precedence order as
// qbitcoind: explicit -rpcuser/-rpcpassword pair > cookie file at
// -rpccookiefile > default <datadir>/.cookie. A missing cookie is not
// fatal — the request goes out unauthenticated and the server will
// reply 401, giving the user a clean error. Mixing one of the CLI
// flag pair without the other is always an error so a half-set config
// doesn't silently fall through to the cookie.
func (c *client) resolveAuth(user, pass, cookieFile, datadir string) error {
	cliUserSet := user != ""
	cliPassSet := pass != ""
	if cliUserSet != cliPassSet {
		return fmt.Errorf("-rpcuser and -rpcpassword must be set together")
	}
	if cliUserSet {
		c.user = user
		c.pass = pass
		return nil
	}
	path := cookieFile
	if path == "" {
		path = filepath.Join(datadir, ".cookie")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		// Cookie absent / unreadable — surface nothing here; the
		// server's 401 with WWW-Authenticate will trigger the richer
		// CLI hint in formatHTTPError.
		return nil
	}
	line := strings.TrimSpace(string(b))
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return fmt.Errorf("cookie file %s is malformed", path)
	}
	c.user = line[:idx]
	c.pass = line[idx+1:]
	return nil
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".qbitcoin"
	}
	return filepath.Join(home, ".qbitcoin")
}

// walletPath appends ?wallet=<name> to path when -rpcwallet is set.
// Used for endpoints that route per-wallet (send, newaddress, etc.).
func (c *client) walletPath(path string) string {
	if c.walletName == "" {
		return path
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "wallet=" + url.QueryEscape(c.walletName)
}

func (c *client) do(method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, formatHTTPError(resp.StatusCode, resp.Header, b)
	}
	return b, nil
}

// formatHTTPError maps common HTTP statuses to user-facing hints so
// CLI output doesn't force the user to decode obscure codes. Mirrors
// the semantics wired in wallet_rpc.go::walletErrToStatus.
//
// 401 has two distinct sources: an RPC-layer auth failure (server sets
// WWW-Authenticate) and a wallet-layer bad-passphrase rejection. The
// header disambiguates them so users get a hint aimed at the actual
// problem.
func formatHTTPError(status int, header http.Header, body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	switch status {
	case http.StatusLocked: // 423
		return fmt.Errorf("wallet is locked — run `walletpassphrase <name> <seconds>` first (%s)", trimmed)
	case http.StatusUnauthorized: // 401
		if header.Get("WWW-Authenticate") != "" {
			return fmt.Errorf("RPC auth failed — check -rpcuser/-rpcpassword or the cookie file in -datadir (%s)", trimmed)
		}
		return fmt.Errorf("bad passphrase (%s)", trimmed)
	case http.StatusNotFound: // 404
		return fmt.Errorf("not found — is the wallet loaded? (%s)", trimmed)
	case http.StatusConflict: // 409
		return fmt.Errorf("conflict (%s)", trimmed)
	case http.StatusPreconditionFailed: // 412
		return fmt.Errorf("multiple wallets loaded — specify -rpcwallet=<name> (%s)", trimmed)
	}
	return fmt.Errorf("HTTP %d: %s", status, trimmed)
}

func (c *client) printGET(path string) error {
	b, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	return printPretty(b)
}

func (c *client) printPOST(path string, body []byte) error {
	b, err := c.do("POST", path, body)
	if err != nil {
		return err
	}
	return printPretty(b)
}

func (c *client) currentAddress() (string, error) {
	b, err := c.do("GET", c.walletPath("/wallet/status"), nil)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	s, ok := m["address"].(string)
	if !ok {
		return "", fmt.Errorf("address missing from /wallet/status")
	}
	return s, nil
}

func (c *client) getAddress() error {
	s, err := c.currentAddress()
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func (c *client) getBlockCount() error {
	b, err := c.do("GET", "/chain/info", nil)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	fmt.Printf("%v\n", m["blocks"])
	return nil
}

// --- multi-wallet commands -------------------------------------------------

func (c *client) createWallet(rest []string) error {
	if len(rest) < 1 {
		return fmt.Errorf("usage: createwallet <name> [--no-encrypt] [--autoload] [--import-mnemonic]")
	}
	name := rest[0]
	noEncrypt := false
	autoload := false
	importMnemonic := false
	for _, a := range rest[1:] {
		switch a {
		case "--no-encrypt":
			noEncrypt = true
		case "--autoload":
			autoload = true
		case "--import-mnemonic":
			importMnemonic = true
		}
	}

	var mnemonic string
	if importMnemonic {
		m, err := promptMnemonic("Enter BIP-39 mnemonic: ")
		if err != nil {
			return err
		}
		mnemonic = m
	}

	var pass []byte
	if noEncrypt {
		// Scripted path: skip prompt + confirmation, create plaintext.
		// Used by docker entrypoint and other automation.
	} else {
		var err error
		pass, err = promptConfirmedPassphrase("Enter passphrase (empty for no encryption): ")
		if err != nil {
			return err
		}
		if len(pass) == 0 {
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "WARNING: No passphrase entered. This wallet will be UNENCRYPTED —")
			fmt.Fprintln(os.Stderr, "anyone with filesystem access to the datadir can spend its funds.")
			fmt.Fprintln(os.Stderr, "You can add encryption later with: encryptwallet "+name)
			if !confirmYN("Continue? [y/N] ") {
				return fmt.Errorf("aborted")
			}
		}
	}
	body, _ := json.Marshal(map[string]any{
		"name":       name,
		"passphrase": string(pass),
		"mnemonic":   mnemonic,
		"autoload":   autoload,
	})
	raw, err := c.do("POST", "/wallet/create", body)
	if err != nil {
		return err
	}
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}
	fmt.Println("============================================================")
	fmt.Printf("Wallet %q created.\n", name)
	fmt.Println()
	if importMnemonic {
		fmt.Println("Imported from the provided mnemonic.")
	} else {
		// Print the mnemonic prominently; this is the only time we get it.
		fmt.Println("MNEMONIC (back this up NOW — it will NOT be shown again):")
		fmt.Println()
		if mn, ok := resp["mnemonic"].(string); ok {
			fmt.Println("    " + mn)
		}
	}
	fmt.Println()
	fmt.Printf("Address:   %v\n", resp["address"])
	fmt.Printf("Path:      %v\n", resp["path"])
	fmt.Printf("Encrypted: %v\n", resp["encrypted"])
	fmt.Println("============================================================")
	return nil
}

func (c *client) encryptWallet(rest []string) error {
	if len(rest) < 1 {
		return fmt.Errorf("usage: encryptwallet <name>")
	}
	name := rest[0]
	pass, err := promptConfirmedPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}
	if len(pass) == 0 {
		return fmt.Errorf("passphrase must not be empty")
	}
	body, _ := json.Marshal(map[string]any{"name": name, "passphrase": string(pass)})
	_, err = c.do("POST", "/wallet/encrypt", body)
	if err != nil {
		return err
	}
	fmt.Printf("Wallet %q is now encrypted.\n", name)
	return nil
}

func (c *client) loadWallet(rest []string) error {
	if len(rest) < 1 {
		return fmt.Errorf("usage: loadwallet <name> [--autoload]")
	}
	name := rest[0]
	autoload := false
	for _, a := range rest[1:] {
		if a == "--autoload" {
			autoload = true
		}
	}
	body, _ := json.Marshal(map[string]any{"name": name, "autoload": autoload})
	return c.printPOST("/wallet/load", body)
}

func (c *client) unloadWallet(rest []string) error {
	if len(rest) < 1 {
		return fmt.Errorf("usage: unloadwallet <name>")
	}
	body, _ := json.Marshal(map[string]any{"name": rest[0]})
	return c.printPOST("/wallet/unload", body)
}

func (c *client) walletPassphrase(rest []string) error {
	if len(rest) < 2 {
		return fmt.Errorf("usage: walletpassphrase <name> <seconds>")
	}
	name := rest[0]
	secs, err := strconv.ParseInt(rest[1], 10, 64)
	if err != nil {
		return fmt.Errorf("seconds: %w", err)
	}
	pass, err := promptPassphrase("Enter passphrase: ")
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"name":            name,
		"passphrase":      string(pass),
		"timeout_seconds": secs,
	})
	return c.printPOST("/wallet/passphrase", body)
}

func (c *client) walletLock(rest []string) error {
	if len(rest) < 1 {
		return fmt.Errorf("usage: walletlock <name>")
	}
	body, _ := json.Marshal(map[string]any{"name": rest[0]})
	return c.printPOST("/wallet/lock", body)
}

func (c *client) walletPassphraseChange(rest []string) error {
	if len(rest) < 1 {
		return fmt.Errorf("usage: walletpassphrasechange <name>")
	}
	name := rest[0]
	oldPass, err := promptPassphrase("Enter current passphrase: ")
	if err != nil {
		return err
	}
	newPass, err := promptConfirmedPassphrase("Enter new passphrase: ")
	if err != nil {
		return err
	}
	if len(newPass) == 0 {
		return fmt.Errorf("new passphrase must not be empty")
	}
	body, _ := json.Marshal(map[string]any{
		"name": name,
		"old":  string(oldPass),
		"new":  string(newPass),
	})
	return c.printPOST("/wallet/passphrasechange", body)
}

// --- passphrase prompt helpers ---------------------------------------------

// stdinReader is a process-wide bufio.Reader over os.Stdin. A fresh
// bufio.Reader would discard any bytes the last prompt buffered ahead
// from the underlying file — subsequent reads would then block on empty
// stdin even though the user's input is already there. Sharing one
// reader across all prompt callsites keeps scripted `printf "a\nb\n" |
// qbitcoin-cli ...` invocations working.
var stdinReader = bufio.NewReader(os.Stdin)

// readLineFromStdin reads a single newline-terminated line from the
// shared stdinReader. Returns the line without the trailing \r?\n.
func readLineFromStdin() (string, error) {
	line, err := stdinReader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptPassphrase reads a passphrase from stdin, echoing nothing when
// stdin is a terminal. Non-TTY stdin (piped scripts) falls back to the
// shared bufio reader. A final newline is always printed to stderr so
// subsequent output lines up after the no-echo prompt.
func promptPassphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	line, err := readLineFromStdin()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return []byte(line), nil
}

// promptMnemonic reads a BIP-39 mnemonic from stdin with no echo on a
// TTY, then normalizes to lowercase single-spaced words. Empty input
// is rejected; the server does the authoritative BIP-39 validation.
func promptMnemonic(prompt string) (string, error) {
	raw, err := promptPassphrase(prompt)
	if err != nil {
		return "", err
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(string(raw))), " ")
	if normalized == "" {
		return "", fmt.Errorf("mnemonic must not be empty")
	}
	return normalized, nil
}

// promptConfirmedPassphrase reads a passphrase, then asks for
// confirmation; returns an error if they differ. Empty is allowed
// (the CreateWallet path uses that to opt out of encryption, but
// enforces extra confirmation via confirmYN).
func promptConfirmedPassphrase(prompt string) ([]byte, error) {
	p1, err := promptPassphrase(prompt)
	if err != nil {
		return nil, err
	}
	p2, err := promptPassphrase("Confirm passphrase: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p1, p2) {
		return nil, fmt.Errorf("passphrases do not match")
	}
	return p1, nil
}

// confirmYN reads a single line and returns true iff it starts with
// 'y' or 'Y'. Anything else (including empty, EOF, or non-TTY with no
// input) is a "no".
func confirmYN(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, err := readLineFromStdin()
	if err != nil {
		return false
	}
	line = strings.TrimSpace(line)
	return len(line) > 0 && (line[0] == 'y' || line[0] == 'Y')
}

// --- output helpers --------------------------------------------------------

// printPretty formats a server JSON response for the terminal. Matches
// bitcoin-cli's convention: bare JSON strings (e.g. from getnewaddress,
// getbestblockhash) and bare numbers (e.g. from getbalance, uptime) are
// printed unquoted on a single line. Objects/arrays are indented JSON.
func printPretty(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 {
		first := trimmed[0]
		if first == '"' {
			var s string
			if err := json.Unmarshal(trimmed, &s); err == nil {
				fmt.Println(s)
				return nil
			}
		}
		if first == '-' || first == '.' || (first >= '0' && first <= '9') {
			fmt.Println(string(trimmed))
			return nil
		}
		if string(trimmed) == "true" || string(trimmed) == "false" || string(trimmed) == "null" {
			fmt.Println(string(trimmed))
			return nil
		}
	}
	// UseNumber preserves the original JSON number literal (e.g. keeps
	// "50.00000000" as-is instead of renormalizing through float64 to
	// "50"). Matches bitcoin-cli's output, where BTC amounts always
	// retain their 8-decimal form.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		os.Stdout.Write(b)
		return nil
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	// Match bitcoin-cli: no HTML-safety escaping in human-readable output.
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// parseBTCAmount accepts either a whole-number satoshi string (legacy)
// or a decimal BTC string (e.g. "0.5", "1.23456789") and returns the
// amount in satoshis. A value containing a '.' is interpreted as BTC;
// an integer input is treated as BTC (to match bitcoin-cli's
// sendtoaddress convention). Matches the server's BTC convention
// everywhere but accepts raw satoshi via "<n>sat" suffix.
func parseBTCAmount(s string) (uint64, error) {
	if strings.HasSuffix(s, "sat") {
		return strconv.ParseUint(strings.TrimSuffix(s, "sat"), 10, 64)
	}
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		whole, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return whole * 100_000_000, nil
	}
	whole, err := strconv.ParseUint(s[:dot], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("whole part: %w", err)
	}
	frac := s[dot+1:]
	if len(frac) > 8 {
		return 0, fmt.Errorf("more than 8 fractional digits")
	}
	// Right-pad to 8 digits so "0.5" → "50000000".
	for len(frac) < 8 {
		frac += "0"
	}
	fracN, err := strconv.ParseUint(frac, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("frac part: %w", err)
	}
	return whole*100_000_000 + fracN, nil
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "qbitcoin-cli: "+format+"\n", args...)
	os.Exit(1)
}

// startDaemon runs `qbitcoind --daemon <args>` and waits for the parent
// process to detach (qbitcoind's `--daemon` path prints the child pid
// and exits immediately, so this returns as soon as the daemonize
// handoff completes).
//
// qbitcoind is located by checking alongside the qbitcoin-cli binary
// first (works when both ship together under build/bin/ or /usr/bin/)
// and then falling back to $PATH. The CLI's own -rpc URL flag is NOT
// translated into qbitcoind's -rpc port — the two flags live in
// different namespaces (URL vs port), mirroring bitcoin-cli/bitcoind.
// Pass any qbitcoind flags after `start`.
func startDaemon(extraArgs []string) error {
	bin, err := locateQbitcoind()
	if err != nil {
		return err
	}
	args := append([]string{"--daemon"}, extraArgs...)
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// locateQbitcoind finds the qbitcoind binary. Prefers a sibling of this
// CLI binary so custom builds under build/bin/ work without $PATH
// wiring; falls back to $PATH (installed-system layout).
func locateQbitcoind() (string, error) {
	if self, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(self), "qbitcoind")
		if info, err := os.Stat(sibling); err == nil && !info.IsDir() {
			return sibling, nil
		}
	}
	if p, err := exec.LookPath("qbitcoind"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("qbitcoind not found (looked next to qbitcoin-cli and in $PATH)")
}
