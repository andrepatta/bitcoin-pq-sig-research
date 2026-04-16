// qbitcoin-miner is the external PoW miner for qbitcoind. It follows
// Bitcoin's operational model: a separate process polls
// /mining/getblocktemplate, builds the block (with its own coinbase
// paying --coinbase), grinds the header, and calls /mining/submitblock.
// The node stays out of the hash-grinding path entirely — qbitcoind no
// longer ships with an in-process miner.
//
// Required flag:
//
//	-coinbase <bech32-p2mr>   address to receive mining rewards
//
// Defaults are tuned for a single-host dev loop:
//
//	-rpc http://127.0.0.1:8334   qbitcoind RPC endpoint
//	-threads <NumCPU>            parallel grinder workers
//	-poll-interval 5s            tip-change poll cadence during a grind
//
// Auth mirrors qbitcoin-cli: explicit -rpcuser/-rpcpassword pair takes
// precedence, else cookie file at -rpccookiefile, else <datadir>/.cookie.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"qbitcoin/address"
	"qbitcoin/core"
	"qbitcoin/crypto"
	"qbitcoin/logging"
	"qbitcoin/miner"
	"qbitcoin/txn"
)

func main() {
	rpc := flag.String("rpc", "http://127.0.0.1:8334", "qbitcoind RPC endpoint")
	coinbaseFlag := flag.String("coinbase", "", "bech32 P2MR address to receive mining rewards (required)")
	threads := flag.Int("threads", runtime.NumCPU(), "parallel grinder workers")
	rpcUser := flag.String("rpcuser", "", "HTTP Basic auth user (requires -rpcpassword)")
	rpcPassword := flag.String("rpcpassword", "", "HTTP Basic auth password (requires -rpcuser)")
	rpcCookie := flag.String("rpccookiefile", "", "RPC cookie file (defaults to <datadir>/.cookie)")
	datadir := flag.String("datadir", defaultDataDir(), "datadir for cookie auth")
	poll := flag.Duration("poll-interval", 5*time.Second, "tip-change poll cadence during grind")
	templateRefresh := flag.Duration("template-refresh", 30*time.Second, "max template age before aborting the current grind to pull a fresh one (mempool churn + nTime)")
	logSpec := flag.String("log", "info", "log level spec: <default>[,<module>=<level>]...")
	logJSON := flag.Bool("log-json", false, "emit logs as JSON")
	flag.Parse()

	if err := logging.Init(*logSpec, *logJSON); err != nil {
		fmt.Fprintln(os.Stderr, "log init:", err)
		os.Exit(2)
	}
	log := logging.Module("miner")

	if *coinbaseFlag == "" {
		log.Error("--coinbase is required")
		os.Exit(2)
	}
	cbAddr, err := address.DecodeBech32(*coinbaseFlag)
	if err != nil {
		log.Error("--coinbase invalid", "err", err)
		os.Exit(2)
	}
	if *threads < 1 {
		*threads = 1
	}

	c := &rpcClient{base: strings.TrimRight(*rpc, "/"), http: &http.Client{Timeout: 30 * time.Second}}
	if err := c.resolveAuth(*rpcUser, *rpcPassword, *rpcCookie, *datadir); err != nil {
		log.Error("RPC auth setup failed", "err", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("Shutdown: In progress")
		cancel()
	}()

	log.Info("qbitcoin-miner starting", "rpc", c.base, "coinbase", *coinbaseFlag, "threads", *threads)
	runLoop(ctx, c, cbAddr, *threads, *poll, *templateRefresh, log)
	log.Info("qbitcoin-miner stopped")
}

func runLoop(ctx context.Context, c *rpcClient, cbAddr address.P2MRAddress, threads int, pollInterval, templateRefresh time.Duration, log *slog.Logger) {
	for {
		if ctx.Err() != nil {
			return
		}
		tmpl, err := c.getBlockTemplate(ctx)
		if err != nil {
			log.Warn("getblocktemplate failed", "err", err)
			if !waitOrCancel(ctx, 2*time.Second) {
				return
			}
			continue
		}
		header, block, err := assembleBlock(tmpl, cbAddr)
		if err != nil {
			log.Error("block assembly failed", "err", err)
			if !waitOrCancel(ctx, 2*time.Second) {
				return
			}
			continue
		}

		// Two-role watchdog on pollInterval cadence:
		//   1. Tip change → abort so we don't grind on a stale parent.
		//   2. Template age ≥ templateRefresh → abort so we refetch with
		//      current mempool + curtime. Matches Bitcoin Core's habit of
		//      pushing a fresh job every ~30 s via stratum.notify.
		quit := make(chan struct{})
		var once sync.Once
		closeQuit := func() { once.Do(func() { close(quit) }) }
		watchDone := make(chan struct{})
		templateStarted := time.Now()
		go func() {
			defer close(watchDone)
			t := time.NewTicker(pollInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					closeQuit()
					return
				case <-quit:
					return
				case <-t.C:
					if time.Since(templateStarted) >= templateRefresh {
						log.Debug("template refresh interval elapsed; pulling new template", "age", time.Since(templateStarted))
						closeQuit()
						return
					}
					newTip, err := c.getBestBlockHash(ctx)
					if err != nil {
						continue
					}
					if newTip != tmpl.PrevHash {
						log.Info("tip changed; aborting stale grind",
							"old", crypto.DisplayHex(tmpl.PrevHash),
							"new", crypto.DisplayHex(newTip))
						closeQuit()
						return
					}
				}
			}
		}()

		started := time.Now()
		log.Info("CreateNewBlock: grinding", "height", tmpl.Height, "bits", fmt.Sprintf("%08x", tmpl.Bits), "txs", len(block.Txns), "threads", threads)
		solved := miner.Grind(&header, threads, quit)
		closeQuit()
		<-watchDone

		if !solved {
			log.Debug("template preempted", "elapsed", time.Since(started))
			continue
		}
		block.Header = header
		raw := block.Serialize()
		log.Info("proof-of-work found", "height", tmpl.Height, "elapsed", time.Since(started), "nonce", header.Nonce)
		reason, err := c.submitBlock(ctx, raw)
		if err != nil {
			log.Warn("submitblock failed", "err", err)
			continue
		}
		if reason == "" {
			h := header.Hash()
			log.Info("block accepted", "hash", crypto.DisplayHex(h), "height", tmpl.Height)
		} else {
			log.Warn("block rejected", "reason", reason)
		}
	}
}

func assembleBlock(tmpl *blockTemplate, cbAddr address.P2MRAddress) (core.BlockHeader, core.Block, error) {
	txs := make([]txn.Transaction, 0, len(tmpl.Transactions)+1)
	coinbase := miner.BuildCoinbase(uint32(tmpl.Height), cbAddr, tmpl.CoinbaseValue)
	txs = append(txs, coinbase)
	for i, t := range tmpl.Transactions {
		raw, err := hex.DecodeString(t.Data)
		if err != nil {
			return core.BlockHeader{}, core.Block{}, fmt.Errorf("tx[%d] data decode: %w", i, err)
		}
		tx, _, err := txn.DeserializeTx(raw)
		if err != nil {
			return core.BlockHeader{}, core.Block{}, fmt.Errorf("tx[%d] parse: %w", i, err)
		}
		txs = append(txs, *tx)
	}
	ids := make([][32]byte, len(txs))
	for i := range txs {
		ids[i] = txs[i].TxID()
	}
	header := core.BlockHeader{
		Version:    uint32(tmpl.Version),
		PrevHash:   tmpl.PrevHash,
		MerkleRoot: crypto.MerkleRoot(ids),
		Timestamp:  tmpl.CurTime,
		Bits:       tmpl.Bits,
		Nonce:      0,
	}
	return header, core.Block{Header: header, Txns: txs}, nil
}

// --- BIP-22 template wire types ---

type blockTemplate struct {
	Version       uint32
	PrevHash      [32]byte
	Transactions  []templateTx
	CoinbaseValue uint64
	Bits          uint32
	CurTime       uint64
	Height        uint32
}

type templateTx struct {
	Data string // hex-encoded tx body
}

// rawTemplate mirrors the JSON shape qbitcoind emits. We parse into this
// then decode hashes/bits into fixed-width fields on blockTemplate so
// the rest of the miner works with typed values.
type rawTemplate struct {
	Version           uint32          `json:"version"`
	PreviousBlockHash string          `json:"previousblockhash"`
	Transactions      []rawTemplateTx `json:"transactions"`
	CoinbaseValue     uint64          `json:"coinbasevalue"`
	Bits              string          `json:"bits"`
	CurTime           uint64          `json:"curtime"`
	Height            uint32          `json:"height"`
}

type rawTemplateTx struct {
	Data string `json:"data"`
}

func parseTemplate(b []byte) (*blockTemplate, error) {
	var raw rawTemplate
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("template JSON: %w", err)
	}
	prev, err := decodeDisplayHash(raw.PreviousBlockHash)
	if err != nil {
		return nil, fmt.Errorf("previousblockhash: %w", err)
	}
	bits, err := strconv.ParseUint(raw.Bits, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("bits: %w", err)
	}
	txs := make([]templateTx, len(raw.Transactions))
	for i, t := range raw.Transactions {
		txs[i] = templateTx(t)
	}
	return &blockTemplate{
		Version:       raw.Version,
		PrevHash:      prev,
		Transactions:  txs,
		CoinbaseValue: raw.CoinbaseValue,
		Bits:          uint32(bits),
		CurTime:       raw.CurTime,
		Height:        raw.Height,
	}, nil
}

// decodeDisplayHash reverses qbitcoind's display-hex (Bitcoin-style
// byte-reversed) encoding back to natural memory order.
func decodeDisplayHash(s string) ([32]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = raw[31-i]
	}
	return out, nil
}

// --- RPC client (Basic-auth over HTTP/JSON) ---

type rpcClient struct {
	base       string
	user, pass string
	http       *http.Client
}

func (c *rpcClient) resolveAuth(user, pass, cookieFile, datadir string) error {
	if (user == "") != (pass == "") {
		return errors.New("-rpcuser and -rpcpassword must be set together")
	}
	if user != "" {
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
		// Absent cookie is not fatal — requests will 401 and the
		// server's WWW-Authenticate hint surfaces that cleanly.
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

func (c *rpcClient) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func (c *rpcClient) getBlockTemplate(ctx context.Context) (*blockTemplate, error) {
	b, err := c.do(ctx, "GET", "/mining/getblocktemplate", nil)
	if err != nil {
		return nil, err
	}
	return parseTemplate(b)
}

// submitBlock returns the server's bare-JSON response. Empty string ("")
// corresponds to Bitcoin's `null` — accepted. Any other value is a
// rejection reason ("duplicate", "inconclusive", validation error).
func (c *rpcClient) submitBlock(ctx context.Context, rawBlock []byte) (string, error) {
	body, _ := json.Marshal(map[string]string{"hexdata": hex.EncodeToString(rawBlock)})
	resp, err := c.do(ctx, "POST", "/mining/submitblock", body)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(string(resp))
	if trimmed == "null" || trimmed == "" {
		return "", nil
	}
	var s string
	if err := json.Unmarshal([]byte(trimmed), &s); err == nil {
		return s, nil
	}
	return trimmed, nil
}

// getBestBlockHash pulls /chain/info and returns the tip hash in natural
// byte order. Used by the stale-template watchdog.
func (c *rpcClient) getBestBlockHash(ctx context.Context) ([32]byte, error) {
	b, err := c.do(ctx, "GET", "/chain/info", nil)
	if err != nil {
		return [32]byte{}, err
	}
	var m struct {
		BestBlockHash string `json:"bestblockhash"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return [32]byte{}, err
	}
	return decodeDisplayHash(m.BestBlockHash)
}

// --- misc helpers ---

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".qbitcoin"
	}
	return filepath.Join(home, ".qbitcoin")
}

// waitOrCancel sleeps for d or returns false if ctx is cancelled first.
func waitOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
