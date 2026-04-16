package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"qbitcoin/address"
	"qbitcoin/core"
	"qbitcoin/crypto"
	"qbitcoin/logging"
	"qbitcoin/mempool"
	"qbitcoin/miner"
	"qbitcoin/p2p"
	"qbitcoin/storage"
	"qbitcoin/txn"
	"qbitcoin/wallet"
)

// log is set after logging.Init so it picks up the configured spec.
var log *slog.Logger

func main() {
	datadir := flag.String("datadir", defaultDataDir(), "storage directory")
	port := flag.Int("port", 8333, "P2P listen port")
	connect := flag.String("connect", "", "bootstrap peer host:port (e.g. 127.0.0.1:8333)")
	bootnodes := flag.String("bootnodes", "", "comma-separated host:port entries overriding p2p.DefaultBootnodes (use \"none\" to disable)")
	rpcPort := flag.Int("rpc", 8334, "HTTP RPC port")
	rpcBind := flag.String("rpcbind", "127.0.0.1", "RPC listen address; 127.0.0.1 keeps RPC on loopback, 0.0.0.0 exposes on all interfaces")
	rpcUser := flag.String("rpcuser", "", "HTTP Basic auth user for RPC (requires -rpcpassword; disables cookie auth)")
	rpcPassword := flag.String("rpcpassword", "", "HTTP Basic auth password for RPC (requires -rpcuser; disables cookie auth)")
	logSpec := flag.String("log", "info", "log level spec: <default>[,<module>=<level>]... (e.g. info,p2p=debug)")
	logJSON := flag.Bool("log-json", false, "emit logs as JSON")
	daemon := flag.Bool("daemon", false, "run in the background as a daemon and return the pid (logs to <datadir>/qbitcoind.log)")
	flag.Parse()

	// Daemonize BEFORE opening the data dir / db / logging: the child
	// re-enters main() with daemonSentinelEnv set and opens them itself.
	// Doing it here avoids inheriting the pebble lock into the child.
	if *daemon && os.Getenv(daemonSentinelEnv) != "1" {
		if err := daemonize(*datadir); err != nil {
			fmt.Fprintf(os.Stderr, "daemonize: %v\n", err)
			os.Exit(2)
		}
		return
	}

	if err := logging.Init(*logSpec, *logJSON); err != nil {
		fmt.Fprintf(os.Stderr, "log init: %v\n", err)
		os.Exit(2)
	}
	log = logging.Module("node")

	// nodeCtx is cancelled on SIGINT/SIGTERM and threaded into every
	// long-running operation owned by this process: chain.AddBlock from
	// the miner / p2p ingress, wallet keygen, periodic rebroadcast.
	// Per-RPC requests use r.Context() instead so individual clients can
	// time out without taking down node-internal work.
	nodeCtx, cancelNodeCtx := context.WithCancel(context.Background())
	defer cancelNodeCtx()

	if err := os.MkdirAll(*datadir, 0o700); err != nil {
		logging.Fatal("node", "mkdir datadir failed", "err", err)
	}
	db, err := storage.Open(*datadir)
	if err != nil {
		logging.Fatal("node", "open db failed", "err", err)
	}
	defer db.Close()

	chain, err := core.NewBlockchain(db)
	if err != nil {
		logging.Fatal("node", "init chain failed", "err", err)
	}
	pool := mempool.New()

	// Fee estimator: Bitcoin Core's CBlockPolicyEstimator port. Tracks
	// arrival→confirmation samples across three time horizons, answers
	// estimatesmartfee queries. Persisted to <datadir>/fee_estimates.dat
	// on shutdown; loaded on startup. Initialized to the chain tip so
	// txs observed before the first block connect get a sensible
	// validHeight anchor.
	estimator := mempool.NewBlockPolicyEstimator()
	feeDatPath := filepath.Join(*datadir, "fee_estimates.dat")
	if f, err := os.Open(feeDatPath); err == nil {
		if err := estimator.Load(f); err != nil {
			log.Warn("Failed to read fee_estimates.dat, continuing anyway", "err", err)
			estimator = mempool.NewBlockPolicyEstimator()
		}
		_ = f.Close()
	}
	estimator.SetBestHeight(chain.Height())
	pool.SetEstimator(estimator)

	// Evict confirmed txs from the mempool when a block is connected,
	// otherwise the miner keeps including them in the next template and
	// the resulting block fails validation on the now-missing UTXO.
	// RemoveForBlock also notifies the fee estimator so confAvg/txCtAvg
	// accumulate correctly.
	chain.OnBlockConnected(func(b core.Block, height uint32) {
		// Coinbase is not in the mempool and is irrelevant to fee
		// stats; skip it. Non-coinbase txids flow to both the
		// mempool eviction and the estimator.
		ids := make([][32]byte, 0, len(b.Txns))
		for _, tx := range b.Txns {
			if tx.IsCoinbase() {
				continue
			}
			ids = append(ids, tx.TxID())
		}
		pool.RemoveForBlock(height, ids)
		nh, nt := chain.NextBlockContext()
		for _, id := range ids {
			pool.ProcessOrphansForParent(id, chain.ChainUTXO(), nh, nt)
		}
	})

	// On reorg disconnect: notify the fee estimator so tracked
	// confirmations from the disconnected block are forgotten, then
	// attempt to re-admit each non-coinbase tx to the mempool. Txs that
	// were double-spent by the new branch get rejected here (missing
	// input after the new branch's UTXO set took effect — this callback
	// runs after the reorg's atomic commit, so ChainUTXO already
	// reflects the new tip). Matches Bitcoin Core semantics: reorged-
	// out txs come back as fresh mempool arrivals.
	chain.OnBlockDisconnected(func(b core.Block, height uint32) {
		ids := make([][32]byte, 0, len(b.Txns))
		for _, tx := range b.Txns {
			if tx.IsCoinbase() {
				continue
			}
			ids = append(ids, tx.TxID())
		}
		if est := pool.Estimator(); est != nil {
			est.ProcessDisconnect(height, ids)
		}
		// Re-inject non-coinbase txs in block order so intra-block tx
		// chains (child spending parent) reconnect successfully — the
		// parent's pool.Add must run before the child's Add sees its
		// input. Not gossipped: these txs were already relayed before
		// being mined the first time.
		nh, nt := chain.NextBlockContext()
		u := chain.ChainUTXO()
		for _, tx := range b.Txns {
			if tx.IsCoinbase() {
				continue
			}
			if err := pool.Add(tx, u, nh, nt); err != nil {
				// Expected: double-spend vs new branch, min-relay, RBF
				// conflict with a pending mempool tx. Nothing to do —
				// the tx simply doesn't rejoin the pool.
				id := tx.TxID()
				log.Debug("reorg: re-inject skipped",
					"txid", crypto.DisplayHex(id), "err", err)
			}
		}
	})

	// Start P2P. Listen on all interfaces at the configured port; no
	// transport-level identity (we authenticate by IP at the ban-manager
	// level, not by cryptographic peer ID).
	listenAddr := fmt.Sprintf("0.0.0.0:%d", *port)
	node, err := p2p.NewNode(listenAddr, chain, pool, db)
	if err != nil {
		logging.Fatal("node", "p2p start failed", "err", err)
	}
	if err := node.Start(); err != nil {
		logging.Fatal("node", "p2p start failed", "err", err)
	}
	defer node.Stop()
	for _, a := range node.SelfAddrs() {
		log.Info("Bound to", "addr", a)
	}

	// Multi-wallet Registry: the sole owner of wallet state. A fresh
	// node comes up with zero wallets; `qbitcoin-cli createwallet
	// <name>` (→ POST /wallet/create) is the only way to materialize
	// one. Previously loaded wallets listed in
	// <datadir>/wallets.autoload are auto-loaded (encrypted ones come
	// up locked).
	registry := wallet.NewRegistry(filepath.Join(*datadir, "wallets"))
	if errs := registry.LoadAutoload(nodeCtx); len(errs) > 0 {
		for _, e := range errs {
			log.Warn("wallet autoload failed", "err", e)
		}
	}
	defer registry.Close()
	for _, info := range registry.List() {
		log.Info("Loaded wallet", "name", info.Name, "encrypted", info.Encrypted, "locked", info.Locked, "address", info.Address)
	}

	if *connect != "" {
		log.Info("bootstrap peer", "addr", *connect)
		go func() {
			if err := node.Connect(*connect); err != nil {
				log.Warn("bootstrap connect failed", "addr", *connect, "err", err)
			}
		}()
	}
	for _, addr := range resolveBootnodes(*bootnodes) {
		addr := addr
		log.Info("bootnode", "addr", addr)
		go func() {
			if err := node.Connect(addr); err != nil {
				log.Warn("bootnode connect failed", "addr", addr, "err", err)
			}
		}()
	}
	// Redial any persisted peers (in parallel with the bootstrap peer).
	node.DialPersistedPeers()

	// Replay wallet-pending txs into the mempool (post-restart) and
	// register a chain hook to drop entries once they confirm. Pending
	// txs are also rebroadcast every WalletRebroadcastInterval below.
	// Works across every wallet in the Registry — locked encrypted
	// wallets are fine because pending-tx files are plaintext
	// (already-broadcast, non-secret artifacts).
	wireWalletPending(nodeCtx, chain, pool, node, registry)

	// Resolve RPC credentials. Static flag pair takes precedence over
	// the auto-generated cookie — matches Bitcoin Core's precedence
	// exactly. If neither is set, the cookie is (re)written on every
	// boot and removed on clean shutdown.
	rpcAuthUser, rpcAuthPass, cookieCleanup, err := resolveRPCAuth(*rpcUser, *rpcPassword, *datadir)
	if err != nil {
		logging.Fatal("node", "RPC auth init failed", "err", err)
	}
	if cookieCleanup != nil {
		defer cookieCleanup()
	}

	// Start RPC.
	startedAt := time.Now()
	go runRPC(*rpcBind, *rpcPort, rpcAuthUser, rpcAuthPass, chain, pool, node, registry, startedAt)

	log.Info("node started", "p2p_port", *port, "rpc_port", *rpcPort, "datadir", *datadir)
	log.Info("Loaded best chain", "height", chain.Height())
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			tracked, bestH := estimator.Stats()
			log.Info("status", "height", chain.Height(), "peers", node.PeerCount(), "mempool", pool.Size(), "est_tracked", tracked, "est_best", bestH)
		}
	}()

	// Periodic fee-estimator persistence: save every 10 minutes so a
	// SIGKILL / OOM crash loses at most ~10 minutes of history.
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for range t.C {
			if err := saveEstimator(estimator, feeDatPath); err != nil {
				log.Warn("fee estimator: periodic save failed", "err", err)
			}
		}
	}()

	// Graceful shutdown: cancel nodeCtx so the miner / rebroadcast /
	// p2p loops bail out, then save estimator state.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Info("Shutdown: In progress", "signal", sig.String())
	cancelNodeCtx()
	if err := saveEstimator(estimator, feeDatPath); err != nil {
		log.Warn("fee estimator: shutdown save failed", "err", err)
	}
}

// saveEstimator writes the estimator to a temp file then renames, so a
// mid-write crash doesn't leave a partial file that fails to load on
// next startup.
func saveEstimator(e *mempool.BlockPolicyEstimator, path string) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := e.Save(f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WalletRebroadcastInterval is how often we re-gossip our pending txs.
// 5 minutes mirrors Bitcoin's RelayWalletTransactions cadence.
const WalletRebroadcastInterval = 5 * time.Minute

// wireWalletPending replays wallet-pending txs into the mempool on
// startup, hooks block-connect to evict confirmed entries from every
// loaded wallet, and starts the rebroadcast ticker. ctx is the
// node-lifetime context — the rebroadcast goroutine exits when ctx is
// cancelled.
//
// Multi-wallet aware: pending-tx files are plaintext regardless of
// wallet encryption (the contained txs are already-broadcast, non-
// secret artifacts). Rebroadcast works for locked encrypted wallets
// too — no MEK access is needed.
func wireWalletPending(ctx context.Context, chain *core.Blockchain, pool *mempool.Mempool, node *p2p.Node, reg *wallet.Registry) {
	// Startup replay across every currently-loaded wallet.
	nh, nt := chain.NextBlockContext()
	var replayed int
	for _, info := range reg.List() {
		w, err := reg.Get(info.Name)
		if err != nil {
			continue
		}
		pend, err := w.PendingTxs(ctx)
		if err != nil {
			log.Warn("wallet: list pending failed", "wallet", info.Name, "err", err)
			continue
		}
		for _, tx := range pend {
			if err := pool.Add(tx, chain.ChainUTXO(), nh, nt); err != nil {
				log.Debug("wallet: pending re-add failed", "wallet", info.Name, "txid", crypto.DisplayHex(tx.TxID()), "err", err)
				continue
			}
			node.BroadcastTx(tx)
			replayed++
		}
	}
	if replayed > 0 {
		log.Info("wallet: replayed pending txs", "count", replayed)
	}

	// On each block, sweep every loaded wallet for confirmed txs.
	chain.OnBlockConnected(func(b core.Block, _ uint32) {
		for _, info := range reg.List() {
			w, err := reg.Get(info.Name)
			if err != nil {
				continue
			}
			for _, tx := range b.Txns {
				w.ClearPending(tx.TxID())
			}
		}
	})

	go func() {
		t := time.NewTicker(WalletRebroadcastInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			var rebroadcast int
			for _, info := range reg.List() {
				w, err := reg.Get(info.Name)
				if err != nil {
					continue
				}
				pend, err := w.PendingTxs(ctx)
				if err != nil || len(pend) == 0 {
					continue
				}
				// Only rebroadcast txs that are still in our own
				// mempool. Pending entries absent from the pool (RBF-
				// evicted, startup policy reject, etc.) are cleaned up
				// so the pending directory doesn't grow unbounded.
				for _, tx := range pend {
					id := tx.TxID()
					if pool.Get(id) == nil {
						w.ClearPending(id)
						continue
					}
					node.BroadcastTx(tx)
					rebroadcast++
				}
			}
			if rebroadcast > 0 {
				log.Debug("wallet: rebroadcast", "count", rebroadcast)
			}
		}
	}()
}

// resolveBootnodes returns the bootnode host:port entries to dial. An
// empty flag uses p2p.DefaultBootnodes; "none" disables bootnodes
// entirely; any other value is parsed as a comma-separated override
// list.
func resolveBootnodes(flagVal string) []string {
	v := strings.TrimSpace(flagVal)
	if v == "" {
		return p2p.DefaultBootnodes
	}
	if strings.EqualFold(v, "none") {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".qbitcoin"
	}
	return filepath.Join(home, ".qbitcoin")
}

// daemonSentinelEnv guards against infinite re-fork: the parent sets it
// before spawning the child, and the child short-circuits the daemonize
// path when it sees the variable.
const daemonSentinelEnv = "QBITCOIND_DAEMONIZED"

// daemonize re-execs this binary as a detached child process and exits
// the parent. The child:
//   - inherits the full original argv (so `-daemon` stays visible in
//     `ps`, and any other flag still applies),
//   - starts a new session via Setsid so it survives the controlling
//     terminal closing,
//   - has stdin redirected to /dev/null and stdout+stderr redirected to
//     <datadir>/qbitcoind.log (slog writes to stderr by default, so this
//     is where node logs will land).
//
// Matches bitcoind's `-daemon` shape: the parent prints the child pid
// on stdout so scripts can capture it.
func daemonize(datadir string) error {
	if err := os.MkdirAll(datadir, 0o700); err != nil {
		return fmt.Errorf("mkdir datadir: %w", err)
	}
	logPath := filepath.Join(datadir, "qbitcoind.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", logPath, err)
	}
	defer logFile.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}

	proc, err := os.StartProcess(exe, os.Args, &os.ProcAttr{
		Env:   append(os.Environ(), daemonSentinelEnv+"=1"),
		Files: []*os.File{devNull, logFile, logFile},
		Sys:   &syscall.SysProcAttr{Setsid: true},
	})
	if err != nil {
		return fmt.Errorf("spawn child: %w", err)
	}
	// Capture Pid before Release — on recent Go versions Release zeroes
	// it out as part of detaching the handle from the parent.
	pid := proc.Pid
	if err := proc.Release(); err != nil {
		return fmt.Errorf("release child: %w", err)
	}
	fmt.Printf("qbitcoind started (pid=%d, log=%s)\n", pid, logPath)
	return nil
}

// --- miner ---

// --- RPC ---

// resolveRPCAuth picks the credentials the RPC server will require.
// Returns a cleanup function only when a cookie file was written
// (static credentials leave nothing behind to remove). Empty-only flag
// values are treated as "unset"; mixing one without the other is an
// error so an operator can't accidentally ship an empty-password
// install by forgetting to set both.
func resolveRPCAuth(user, pass, datadir string) (string, string, func(), error) {
	cliUserSet := user != ""
	cliPassSet := pass != ""
	if cliUserSet != cliPassSet {
		return "", "", nil, fmt.Errorf("-rpcuser and -rpcpassword must be set together")
	}
	if cliUserSet {
		return user, pass, nil, nil
	}
	u, p, cleanup, err := writeCookie(datadir)
	if err != nil {
		return "", "", nil, err
	}
	return u, p, cleanup, nil
}

func runRPC(bindAddr string, port int, user, pass string, chain *core.Blockchain, pool *mempool.Mempool, node *p2p.Node, registry *wallet.Registry, startedAt time.Time) {
	mux := http.NewServeMux()
	registerWalletAdminHandlers(mux, registry, chainAddressActivity{chain: chain})

	// --- chain / block ---

	// /chain/info → getblockchaininfo: rolled-up chain state the same
	// keys bitcoin-cli clients look for (chain, blocks, bestblockhash,
	// difficulty, chainwork, mediantime).
	mux.HandleFunc("/chain/info", func(rw http.ResponseWriter, r *http.Request) {
		hash, h := chain.Tip()
		work := chain.CumulativeWork(hash)
		writeJSON(rw, map[string]interface{}{
			"chain":                ChainName,
			"blocks":               h,
			"headers":              h,
			"bestblockhash":        crypto.DisplayHex(hash),
			"difficulty":           bitsToDifficulty(chain.CurrentBits()),
			"mediantime":           chain.MedianTimeOfBlock(hash),
			"verificationprogress": 1.0,
			"initialblockdownload": false,
			"chainwork":            workHex(work),
			"size_on_disk":         0,
			"pruned":               false,
			"warnings":             "",
		})
	})

	// /block/best → getbestblockhash: bare JSON string.
	mux.HandleFunc("/block/best", func(rw http.ResponseWriter, r *http.Request) {
		hash, _ := chain.Tip()
		writeJSON(rw, crypto.DisplayHex(hash))
	})

	// /block/latest is a qbitcoin-specific convenience summary of the
	// tip block. Bitcoin callers should use getbestblockhash + getblock.
	mux.HandleFunc("/block/latest", func(rw http.ResponseWriter, r *http.Request) {
		hash, _ := chain.Tip()
		blk, err := chain.GetBlock(r.Context(), hash)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		writeJSON(rw, blockJSON(chain, blk, hash))
	})

	// /block/<hash> → getblock. verbosity 0 = raw hex (bare JSON string),
	// 1 = JSON header+txids, 2 = JSON with full tx objects.
	mux.HandleFunc("/block/", func(rw http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			http.Error(rw, "bad path", 400)
			return
		}
		hexH := parts[2]
		if hexH == "latest" || hexH == "best" {
			http.NotFound(rw, r)
			return
		}
		h, err := crypto.ParseDisplayHex(hexH)
		if err != nil {
			http.Error(rw, "bad hash", 400)
			return
		}
		blk, err := chain.GetBlock(r.Context(), h)
		if err != nil {
			http.Error(rw, err.Error(), 404)
			return
		}
		verbosity := 1
		if v := r.URL.Query().Get("verbosity"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				http.Error(rw, "bad verbosity", 400)
				return
			}
			verbosity = n
		}
		if verbosity == 0 {
			writeJSON(rw, hex.EncodeToString(blk.Serialize()))
			return
		}
		obj := blockJSON(chain, blk, h)
		if verbosity >= 2 {
			txs := make([]map[string]interface{}, len(blk.Txns))
			for i := range blk.Txns {
				txs[i] = txJSON(chain, &blk.Txns[i], &h, chain.Height())
			}
			obj["tx"] = txs
		}
		writeJSON(rw, obj)
	})

	// /blockhash/<height> → getblockhash: bare JSON string.
	mux.HandleFunc("/blockhash/", func(rw http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 || parts[2] == "" {
			http.Error(rw, "bad path", 400)
			return
		}
		ht, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			http.Error(rw, "bad height", 400)
			return
		}
		h, ok := chain.BlockHashAtHeight(uint32(ht))
		if !ok {
			http.Error(rw, "height above tip", 404)
			return
		}
		writeJSON(rw, crypto.DisplayHex(h))
	})
	mux.HandleFunc("/utxo/", func(rw http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			http.Error(rw, "bad path", 400)
			return
		}
		addr, err := address.DecodeBech32(parts[2])
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		keys, outs, err := chain.ChainUTXO().AllForAddress(addr)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		var bal uint64
		arr := []map[string]interface{}{}
		for i, o := range outs {
			bal += o.Value
			arr = append(arr, map[string]interface{}{
				"txid":  crypto.DisplayHex(keys[i].TxID),
				"index": keys[i].Index,
				"value": BTCFromSats(o.Value),
			})
		}
		writeJSON(rw, map[string]interface{}{"balance": BTCFromSats(bal), "utxos": arr})
	})

	// /tx/broadcast → sendrawtransaction. Registered before the prefix
	// /tx/ handler so ServeMux routes the exact match here.
	mux.HandleFunc("/tx/broadcast", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		b := make([]byte, 1<<20)
		n, _ := r.Body.Read(b)
		raw, err := hex.DecodeString(strings.TrimSpace(string(b[:n])))
		if err != nil {
			http.Error(rw, "bad hex", 400)
			return
		}
		tx, _, err := txn.DeserializeTx(raw)
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		nh, nt := chain.NextBlockContext()
		if err := pool.Add(*tx, chain.ChainUTXO(), nh, nt); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		node.BroadcastTx(*tx)
		id := tx.TxID()
		writeJSON(rw, crypto.DisplayHex(id))
	})

	// /tx/decode → decoderawtransaction. POST hex in body; returns
	// decoded tx in the same shape as getrawtransaction verbose.
	mux.HandleFunc("/tx/decode", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		b := make([]byte, 1<<20)
		n, _ := r.Body.Read(b)
		raw, err := hex.DecodeString(strings.TrimSpace(string(b[:n])))
		if err != nil {
			http.Error(rw, "bad hex", 400)
			return
		}
		tx, _, err := txn.DeserializeTx(raw)
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		writeJSON(rw, txJSON(chain, tx, nil, 0))
	})

	// /tx/<txid> → getrawtransaction. Default verbose=true returns the
	// decoded JSON object; verbose=false returns the raw hex as a bare
	// JSON string.
	mux.HandleFunc("/tx/", func(rw http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			http.Error(rw, "bad path", 400)
			return
		}
		sub := parts[2]
		if sub == "broadcast" || sub == "decode" || sub == "" {
			http.NotFound(rw, r)
			return
		}
		id, err := crypto.ParseDisplayHex(sub)
		if err != nil {
			http.Error(rw, "bad txid", 400)
			return
		}
		verbose := true
		if v := r.URL.Query().Get("verbose"); v != "" {
			verbose, err = strconv.ParseBool(v)
			if err != nil {
				http.Error(rw, "bad verbose", 400)
				return
			}
		}
		// Mempool first (unconfirmed — no block context).
		if mtx := pool.Get(id); mtx != nil {
			if !verbose {
				writeJSON(rw, hex.EncodeToString(mtx.Serialize()))
				return
			}
			writeJSON(rw, txJSON(chain, mtx, nil, 0))
			return
		}
		tx, blockHash, height, found, err := chain.FindTx(r.Context(), id)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		if !found {
			http.NotFound(rw, r)
			return
		}
		if !verbose {
			writeJSON(rw, hex.EncodeToString(tx.Serialize()))
			return
		}
		writeJSON(rw, txJSON(chain, &tx, &blockHash, height))
	})

	// /network/info → getnetworkinfo. Mixes data we have (peer count,
	// subversion via ProtocolID) with zeros for fields that don't apply
	// (localservices mask, timeoffset). relayfee/incrementalfee are in
	// BTC/kvB like Bitcoin reports them.
	mux.HandleFunc("/network/info", func(rw http.ResponseWriter, r *http.Request) {
		peers := node.Peers()
		inbound, outbound := 0, 0
		for _, p := range peers {
			if p.Inbound {
				inbound++
			} else {
				outbound++
			}
		}
		writeJSON(rw, map[string]interface{}{
			"version":         p2p.ProtocolVer,
			"subversion":      fmt.Sprintf("/qbitcoin:%d/", p2p.ProtocolVer),
			"protocolversion": p2p.ProtocolVer,
			"localservices":   "0000000000000000",
			"localrelay":      true,
			"timeoffset":      0,
			"networkactive":   true,
			"connections":     len(peers),
			"connections_in":  inbound,
			"connections_out": outbound,
			"networks":        []map[string]interface{}{},
			"relayfee":        satPerByteAsBTCPerKvB(float64(mempool.MinRelayFeeRate)),
			"incrementalfee":  satPerByteAsBTCPerKvB(float64(mempool.IncrementalRelayFeeRate)),
			"localaddresses":  node.SelfAddrs(),
			"warnings":        "",
		})
	})

	mux.HandleFunc("/peers", func(rw http.ResponseWriter, r *http.Request) {
		peers := node.Peers()
		out := make([]map[string]interface{}, len(peers))
		for i, p := range peers {
			out[i] = map[string]interface{}{
				"id":                i,
				"addr":              p.Addr,
				"network":           "ipv4",
				"services":          "0000000000000000",
				"relaytxes":         true,
				"lastsend":          0,
				"lastrecv":          p.LastSeen.Unix(),
				"bytessent":         0,
				"bytesrecv":         0,
				"conntime":          0,
				"timeoffset":        0,
				"pingtime":          0.0,
				"minping":           0.0,
				"version":           p2p.ProtocolVer,
				"subver":            fmt.Sprintf("/qbitcoin:%d/", p2p.ProtocolVer),
				"inbound":           p.Inbound,
				"startingheight":    p.Height,
				"synced_headers":    p.Height,
				"synced_blocks":     p.Height,
				"inflight":          []uint32{},
				"permissions":       []string{},
				"handshakecomplete": p.Handshake,
			}
		}
		writeJSON(rw, out)
	})
	// /mempool/info → getmempoolinfo.
	mux.HandleFunc("/mempool/info", func(rw http.ResponseWriter, r *http.Request) {
		entries := pool.Entries()
		totalBytes := 0
		var totalFee uint64
		for _, e := range entries {
			totalBytes += e.Size
			totalFee += e.Fee
		}
		writeJSON(rw, map[string]interface{}{
			"loaded":              true,
			"size":                len(entries),
			"bytes":               totalBytes,
			"usage":               totalBytes,
			"total_fee":           BTCFromSats(totalFee),
			"maxmempool":          300_000_000,
			"mempoolminfee":       satPerByteAsBTCPerKvB(float64(mempool.MinRelayFeeRate)),
			"minrelaytxfee":       satPerByteAsBTCPerKvB(float64(mempool.MinRelayFeeRate)),
			"incrementalrelayfee": satPerByteAsBTCPerKvB(float64(mempool.IncrementalRelayFeeRate)),
			"unbroadcastcount":    0,
			"fullrbf":             false,
		})
	})

	// /mempool → getrawmempool. Default returns array of txids; with
	// ?verbose=true returns object keyed by txid with per-entry stats.
	mux.HandleFunc("/mempool", func(rw http.ResponseWriter, r *http.Request) {
		entries := pool.Entries()
		verbose := false
		if v := r.URL.Query().Get("verbose"); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				http.Error(rw, "bad verbose", 400)
				return
			}
			verbose = b
		}
		if !verbose {
			ids := make([]string, len(entries))
			for i, e := range entries {
				id := e.Tx.TxID()
				ids[i] = crypto.DisplayHex(id)
			}
			writeJSON(rw, ids)
			return
		}
		out := make(map[string]interface{}, len(entries))
		height := chain.Height()
		for _, e := range entries {
			id := e.Tx.TxID()
			out[crypto.DisplayHex(id)] = map[string]interface{}{
				"vsize":              e.Size,
				"weight":             e.Size * 4,
				"time":               0,
				"height":             height,
				"descendantcount":    1,
				"descendantsize":     e.Size,
				"ancestorcount":      1,
				"ancestorsize":       e.Size,
				"wtxid":              crypto.DisplayHex(id),
				"fees":               map[string]interface{}{"base": BTCFromSats(e.Fee), "modified": BTCFromSats(e.Fee), "ancestor": BTCFromSats(e.Fee), "descendant": BTCFromSats(e.Fee)},
				"depends":            []string{},
				"spentby":            []string{},
				"bip125-replaceable": true,
			}
		}
		writeJSON(rw, out)
	})

	// /mining/info → getmininginfo. Read-only chain-state snapshot. Under
	// the external-miner model qbitcoind no longer owns a mining loop, so
	// the old `mining` / `threads` fields were dropped — hashrate and
	// worker count are the external miner's concern.
	mux.HandleFunc("/mining/info", func(rw http.ResponseWriter, r *http.Request) {
		bits := chain.CurrentBits()
		writeJSON(rw, map[string]interface{}{
			"blocks":        chain.Height(),
			"difficulty":    bitsToDifficulty(bits),
			"networkhashps": 0,
			"pooledtx":      pool.Size(),
			"chain":         ChainName,
			"warnings":      "",
			"bits":          fmt.Sprintf("%08x", bits),
		})
	})

	// /mining/getblocktemplate → BIP-22 block template. The external
	// miner (`qbitcoin-miner` or any BIP-22 client) pulls this, assembles
	// a coinbase paying its own address, grinds the header, and submits
	// via /mining/submitblock.
	//
	// PQBC deviations from Bitcoin's field set:
	//   - no `weight` / `weightlimit`: no segwit
	//   - `hash` equals `txid` per transaction: no wtxid split
	//   - `noncerange` is 16 bytes (64-bit nonce) rather than Bitcoin's 8
	//   - `rules` / `vbavailable` are empty: no softfork deployments
	//
	// `longpollid` returns the current tip hash. BIP-22 longpoll is not
	// implemented server-side — miners poll on their own cadence. The
	// token still identifies the template generation so a cautious miner
	// can compare it across calls.
	mux.HandleFunc("/mining/getblocktemplate", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "POST" {
			http.Error(rw, "GET or POST required", http.StatusMethodNotAllowed)
			return
		}
		entries := pool.GetTemplateEntries(900_000, core.MaxBlockSigOpsCost)
		nextHeight := chain.Height() + 1
		prev := chain.BestHash()
		bits := chain.CurrentBits()
		ts := uint64(time.Now().Unix())
		if min := chain.MinNextTimestamp(); ts < min {
			ts = min
		}
		target := core.BitsToTarget(bits)
		var fees uint64
		txsOut := make([]map[string]interface{}, len(entries))
		for i, e := range entries {
			fees += e.Fee
			txid := e.Tx.TxID()
			txsOut[i] = map[string]interface{}{
				"data":    hex.EncodeToString(e.Tx.Serialize()),
				"txid":    crypto.DisplayHex(txid),
				"hash":    crypto.DisplayHex(txid),
				"depends": []int{},
				"fee":     e.Fee,
				"sigops":  txn.SigOpCost(e.Tx),
			}
		}
		writeJSON(rw, map[string]interface{}{
			"capabilities":      []string{"proposal"},
			"version":           1,
			"rules":             []string{},
			"vbavailable":       map[string]int{},
			"vbrequired":        0,
			"previousblockhash": crypto.DisplayHex(prev),
			"transactions":      txsOut,
			"coinbaseaux":       map[string]string{"flags": ""},
			"coinbasevalue":     miner.CoinbaseValue(nextHeight, fees),
			"longpollid":        crypto.DisplayHex(prev),
			"target":            crypto.DisplayHex([32]byte(target)),
			"mintime":           chain.MinNextTimestamp(),
			"mutable":           []string{"time", "transactions", "prevblock"},
			"noncerange":        "0000000000000000ffffffffffffffff",
			"sigoplimit":        core.MaxBlockSigOpsCost,
			"sizelimit":         core.MaxBlockSize,
			"curtime":           ts,
			"bits":              fmt.Sprintf("%08x", bits),
			"height":            nextHeight,
		})
	})

	// /mining/submitblock → BIP-22 submitblock. Accepts a hex-encoded
	// full block, validates, adds to chain, broadcasts.
	//
	// Response follows Bitcoin's submitblock convention:
	//   null            — accepted (main chain or valid side chain)
	//   "duplicate"     — already known
	//   "inconclusive"  — parent unknown (orphan)
	//   "<reason>"      — rejected; string is the validation error
	mux.HandleFunc("/mining/submitblock", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Hexdata string `json:"hexdata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		raw, err := hex.DecodeString(req.Hexdata)
		if err != nil {
			writeJSON(rw, "decode-failed: "+err.Error())
			return
		}
		blk, err := core.DeserializeBlock(raw)
		if err != nil {
			writeJSON(rw, "deserialize-failed: "+err.Error())
			return
		}
		outcome, _, err := chain.AddBlock(r.Context(), *blk)
		if err != nil {
			writeJSON(rw, err.Error())
			return
		}
		switch outcome {
		case core.OutcomeDuplicate:
			writeJSON(rw, "duplicate")
		case core.OutcomeOrphan:
			writeJSON(rw, "inconclusive")
		case core.OutcomeExtended, core.OutcomeReorg, core.OutcomeSideChain:
			node.BroadcastBlock(*blk)
			writeJSON(rw, nil)
		default:
			writeJSON(rw, "unknown-outcome")
		}
	})

	// /mining/generatetoaddress → regtest-style mining: produce N blocks
	// paying coinbase (subsidy + template fees) to the given address and
	// return their hashes. Bitcoin Core exposes this under regtest; we
	// keep it always-on for PoC convenience. Uses the shared miner.Grind
	// path — same optimizations as the external miner, just without the
	// out-of-process hop.
	mux.HandleFunc("/mining/generatetoaddress", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Nblocks  int    `json:"nblocks"`
			Address  string `json:"address"`
			Maxtries int64  `json:"maxtries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		if req.Nblocks < 1 {
			http.Error(rw, "nblocks must be >= 1", 400)
			return
		}
		to, err := address.DecodeBech32(req.Address)
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		hashes := make([]string, 0, req.Nblocks)
		for i := 0; i < req.Nblocks; i++ {
			entries := pool.GetTemplateEntries(900_000, core.MaxBlockSigOpsCost)
			nextHeight := chain.Height() + 1
			var fees uint64
			txns := make([]txn.Transaction, len(entries))
			for j, e := range entries {
				fees += e.Fee
				txns[j] = e.Tx
			}
			cb := miner.BuildCoinbase(nextHeight, to, miner.CoinbaseValue(nextHeight, fees))
			all := append([]txn.Transaction{cb}, txns...)
			ids := make([][32]byte, len(all))
			for j := range all {
				ids[j] = all[j].TxID()
			}
			bestHash := chain.BestHash()
			ts := uint64(time.Now().Unix())
			if min := chain.MinNextTimestamp(); ts < min {
				ts = min
			}
			h := core.BlockHeader{
				Version:    1,
				PrevHash:   bestHash,
				MerkleRoot: crypto.MerkleRoot(ids),
				Timestamp:  ts,
				Bits:       chain.CurrentBits(),
				Nonce:      0,
			}
			quit := make(chan struct{})
			if !miner.Grind(&h, 1, quit) {
				http.Error(rw, "mining aborted", 500)
				return
			}
			blk := core.Block{Header: h, Txns: all}
			if _, _, err := chain.AddBlock(r.Context(), blk); err != nil {
				http.Error(rw, err.Error(), 500)
				return
			}
			node.BroadcastBlock(blk)
			hh := h.Hash()
			hashes = append(hashes, crypto.DisplayHex(hh))
		}
		writeJSON(rw, hashes)
	})

	// /node/stop → stop: Bitcoin returns a bare JSON string.
	mux.HandleFunc("/node/stop", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(rw, "qbitcoind stopping")
		// Raise SIGTERM to self so shutdown flows through the same sigCh
		// handler in main() — estimator save, nodeCtx cancel, p2p stop —
		// with no duplicated path. The short delay lets the HTTP response
		// flush before the process starts tearing down.
		go func() {
			time.Sleep(100 * time.Millisecond)
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		}()
	})

	// /node/uptime → uptime: bare number of seconds since the node RPC
	// started accepting requests.
	mux.HandleFunc("/node/uptime", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, int64(time.Since(startedAt).Seconds()))
	})

	// /node/connectioncount → getconnectioncount: bare number.
	mux.HandleFunc("/node/connectioncount", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, node.PeerCount())
	})

	// /fee/estimate → estimatesmartfee. feerate is in BTC/kvB (Bitcoin
	// convention) or omitted entirely when the estimator has no answer,
	// in which case errors is populated.
	mux.HandleFunc("/fee/estimate", func(rw http.ResponseWriter, r *http.Request) {
		est := pool.Estimator()
		if est == nil {
			http.Error(rw, "estimator not configured", http.StatusServiceUnavailable)
			return
		}
		q := r.URL.Query()
		target := uint32(6)
		if t := q.Get("target"); t != "" {
			v, err := strconv.ParseUint(t, 10, 32)
			if err != nil {
				http.Error(rw, "bad target", 400)
				return
			}
			target = uint32(v)
		}
		mode, err := mempool.ParseEstimateMode(q.Get("mode"))
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		est.SetBestHeight(chain.Height())
		fe := est.EstimateFee(target, mode)
		resp := map[string]interface{}{
			"blocks": fe.Blocks,
		}
		if fe.SatPerByte > 0 {
			resp["feerate"] = satPerByteAsBTCPerKvB(fe.SatPerByte)
		} else {
			resp["errors"] = []string{"Insufficient data or no feerate found"}
		}
		writeJSON(rw, resp)
	})
	mux.HandleFunc("/wallet/send", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		var req struct {
			To      string  `json:"to"`
			Amount  uint64  `json:"amount"`
			Fee     uint64  `json:"fee"`
			Feerate float64 `json:"feerate"` // sat/byte
			Target  uint32  `json:"target"`  // blocks, used when fee+feerate both 0
			Mode    string  `json:"mode"`    // "unset" | "economical" | "conservative"
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		to, err := address.DecodeBech32(req.To)
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		// Fee selection precedence: explicit Fee > explicit Feerate >
		// estimator-driven auto. Auto falls back to MinRelayFeeRate
		// when the estimator has no answer yet (fresh node / cold
		// start / not enough confirmation history).
		var tx *txn.Transaction
		if req.Fee > 0 {
			tx, err = w.Send(r.Context(), chain.ChainUTXO(), to, req.Amount, req.Fee)
		} else if req.Feerate > 0 {
			tx, err = w.SendAtFeerate(r.Context(), chain.ChainUTXO(), to, req.Amount, req.Feerate)
		} else {
			target := req.Target
			if target == 0 {
				target = 6
			}
			mode, perr := mempool.ParseEstimateMode(req.Mode)
			if perr != nil {
				http.Error(rw, perr.Error(), 400)
				return
			}
			feerate := float64(mempool.MinRelayFeeRate)
			if est := pool.Estimator(); est != nil {
				est.SetBestHeight(chain.Height())
				if fe := est.EstimateFee(target, mode); fe.SatPerByte > feerate {
					feerate = fe.SatPerByte
				}
			}
			tx, err = w.SendAtFeerate(r.Context(), chain.ChainUTXO(), to, req.Amount, feerate)
		}
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		nh, nt := chain.NextBlockContext()
		if err := pool.Add(*tx, chain.ChainUTXO(), nh, nt); err != nil {
			// Local mempool rejected — do NOT record pending or
			// broadcast. Recording would leave a known-invalid tx in
			// the pending file that the rebroadcast ticker would then
			// spam peers with.
			http.Error(rw, err.Error(), 400)
			return
		}
		if err := w.RecordPending(r.Context(), tx); err != nil {
			log.Warn("wallet: record pending failed", "err", err)
		}
		node.BroadcastTx(*tx)
		id := tx.TxID()
		writeJSON(rw, crypto.DisplayHex(id))
	})

	// /wallet/newaddress → getnewaddress: Bitcoin returns a bare string.
	mux.HandleFunc("/wallet/newaddress", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		addr, err := w.NewReceiveAddress(r.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		b32, err := address.EncodeBech32(addr)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		writeJSON(rw, b32)
	})
	mux.HandleFunc("/wallet/accounts", func(rw http.ResponseWriter, r *http.Request) {
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		accts, err := w.ListAccounts(r.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		u := chain.ChainUTXO()
		arr := make([]map[string]interface{}, len(accts))
		for i, a := range accts {
			b32, _ := address.EncodeBech32(a.Address)
			bal, _ := u.Balance(a.Address)
			arr[i] = map[string]interface{}{
				"index":          a.Index,
				"address":        b32,
				"balance":        BTCFromSats(bal),
				"active":         a.Active,
				"derivationpath": fmt.Sprintf("m/44'/1'/%d'", a.Index),
			}
		}
		writeJSON(rw, arr)
	})
	mux.HandleFunc("/wallet/setaccount", func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(rw, "POST required", http.StatusMethodNotAllowed)
			return
		}
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		var req struct {
			Index uint32 `json:"index"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		addr, err := w.SetActiveAccount(r.Context(), req.Index)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		b32, err := address.EncodeBech32(addr)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		writeJSON(rw, map[string]interface{}{"address": b32, "accountindex": req.Index})
	})

	// /wallet/gettransaction/<txid> → gettransaction (wallet view):
	// categorizes inputs/outputs against the wallet's own address set.
	mux.HandleFunc("/wallet/gettransaction/", func(rw http.ResponseWriter, r *http.Request) {
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 || parts[3] == "" {
			http.Error(rw, "bad path", 400)
			return
		}
		id, err := crypto.ParseDisplayHex(parts[3])
		if err != nil {
			http.Error(rw, "bad txid", 400)
			return
		}
		var tx txn.Transaction
		var blockHash [32]byte
		var height uint32
		inMempool := false
		if mtx := pool.Get(id); mtx != nil {
			tx = *mtx
			inMempool = true
		} else {
			t, bh, h, found, ferr := chain.FindTx(r.Context(), id)
			if ferr != nil {
				http.Error(rw, ferr.Error(), 500)
				return
			}
			if !found {
				http.NotFound(rw, r)
				return
			}
			tx = t
			blockHash = bh
			height = h
		}
		writeJSON(rw, walletTxJSON(chain, w, &tx, &blockHash, height, inMempool))
	})
	// /address/transactions/<bech32> → listtransactions (address-scoped).
	// Emits Bitcoin-style keys: category (receive/send/generate), amount
	// as BTC (negative for send), blockhash/blockheight/blocktime. The
	// resolver is chain-only (no wallet required), so we categorize by
	// net flow against the queried address alone.
	mux.HandleFunc("/address/transactions/", func(rw http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 || parts[3] == "" {
			http.Error(rw, "bad path", 400)
			return
		}
		addr, err := address.DecodeBech32(parts[3])
		if err != nil {
			http.Error(rw, err.Error(), 400)
			return
		}
		recs, err := chain.ListTxsForAddress(r.Context(), addr)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		tip := chain.Height()
		arr := make([]map[string]interface{}, 0, len(recs)+pool.Size())
		for _, rec := range recs {
			category := "receive"
			amount := int64(rec.Received) - int64(rec.Sent)
			if rec.Coinbase {
				if tip-rec.Height+1 >= core.CoinbaseMaturity {
					category = "generate"
				} else {
					category = "immature"
				}
			} else if amount < 0 {
				category = "send"
			}
			var blockTime uint64
			if hdr, err := chain.GetHeader(r.Context(), rec.BlockHash); err == nil {
				blockTime = hdr.Timestamp
			}
			arr = append(arr, map[string]interface{}{
				"address":            bech32OrHex(addr),
				"category":           category,
				"amount":             BTC(amount),
				"confirmations":      tip - rec.Height + 1,
				"blockhash":          crypto.DisplayHex(rec.BlockHash),
				"blockheight":        rec.Height,
				"blocktime":          blockTime,
				"txid":               crypto.DisplayHex(rec.TxID),
				"time":               blockTime,
				"timereceived":       blockTime,
				"bip125-replaceable": "no",
				"trusted":            true,
			})
		}
		// Append mempool txs paying or spending from addr. Prev-output
		// lookup tries the chain UTXO set first, then falls back to
		// other mempool entries (chained unconfirmed spends).
		mpEntries := pool.Entries()
		mpOuts := map[txn.UTXOKey]txn.TxOutput{}
		for _, e := range mpEntries {
			id := e.Tx.TxID()
			for i, o := range e.Tx.Outputs {
				mpOuts[txn.UTXOKey{TxID: id, Index: uint32(i)}] = o
			}
		}
		cu := chain.ChainUTXO()
		for _, e := range mpEntries {
			var recv uint64
			for _, o := range e.Tx.Outputs {
				if o.Address.MerkleRoot == addr.MerkleRoot {
					recv += o.Value
				}
			}
			var sent uint64
			if !e.Tx.IsCoinbase() {
				for _, in := range e.Tx.Inputs {
					k := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
					var prev *txn.TxOutput
					if po, err := cu.Get(k); err == nil && po != nil {
						prev = po
					} else if mo, ok := mpOuts[k]; ok {
						prev = &mo
					}
					if prev != nil && prev.Address.MerkleRoot == addr.MerkleRoot {
						sent += prev.Value
					}
				}
			}
			if recv == 0 && sent == 0 {
				continue
			}
			amount := int64(recv) - int64(sent)
			category := "receive"
			if amount < 0 {
				category = "send"
			}
			id := e.Tx.TxID()
			arr = append(arr, map[string]interface{}{
				"address":            bech32OrHex(addr),
				"category":           category,
				"amount":             BTC(amount),
				"confirmations":      0,
				"blockhash":          "",
				"blockheight":        0,
				"blocktime":          0,
				"txid":               crypto.DisplayHex(id),
				"time":               0,
				"timereceived":       0,
				"bip125-replaceable": "yes",
				"trusted":            false,
			})
		}
		writeJSON(rw, arr)
	})

	// /address/validate/<bech32> → validateaddress.
	mux.HandleFunc("/address/validate/", func(rw http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 || parts[3] == "" {
			http.Error(rw, "bad path", 400)
			return
		}
		s := parts[3]
		addr, err := address.DecodeBech32(s)
		if err != nil {
			writeJSON(rw, map[string]interface{}{"isvalid": false})
			return
		}
		b32, _ := address.EncodeBech32(addr)
		writeJSON(rw, map[string]interface{}{
			"isvalid":         true,
			"address":         b32,
			"scriptPubKey":    fmt.Sprintf("%x", addr.MerkleRoot),
			"isscript":        false,
			"iswitness":       true,
			"witness_version": 0,
			"witness_program": fmt.Sprintf("%x", addr.MerkleRoot),
		})
	})

	// /wallet/info → getwalletinfo.
	mux.HandleFunc("/wallet/info", func(rw http.ResponseWriter, r *http.Request) {
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		b32, _ := w.Bech32()
		bal, _ := w.Balance(chain.ChainUTXO())
		unlockedUntil := int64(0)
		if w.IsEncrypted() && !w.IsLocked() {
			unlockedUntil = -1
		}
		writeJSON(rw, map[string]interface{}{
			"walletname":           w.Name(),
			"walletversion":        1,
			"format":               "pebble",
			"balance":              BTCFromSats(bal),
			"unconfirmed_balance":  BTCFromSats(0),
			"immature_balance":     BTCFromSats(0),
			"txcount":              0,
			"keypoolsize":          0,
			"keypoololdest":        0,
			"paytxfee":             BTCFromSats(0),
			"private_keys_enabled": !w.IsLocked(),
			"avoid_reuse":          false,
			"scanning":             false,
			"unlocked_until":       unlockedUntil,
			"descriptors":          false,
			"address":              b32,
			"slothealth":           w.SlotHealth(),
			"accountindex":         w.CurrentAccountIndex(),
		})
	})

	// /wallet/balance → getbalance: bare BTC number.
	mux.HandleFunc("/wallet/balance", func(rw http.ResponseWriter, r *http.Request) {
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		bal, _ := w.Balance(chain.ChainUTXO())
		writeJSON(rw, BTCFromSats(bal))
	})

	// /wallet/status is a compact status object used by qbitcoin-cli's
	// internal `currentAddress` helper. Kept on the BTC-amount side.
	mux.HandleFunc("/wallet/status", func(rw http.ResponseWriter, r *http.Request) {
		w, status, werr := resolveWallet(r, registry)
		if werr != nil {
			http.Error(rw, werr.Error(), status)
			return
		}
		b32, _ := w.Bech32()
		bal, _ := w.Balance(chain.ChainUTXO())
		writeJSON(rw, map[string]interface{}{
			"name":         w.Name(),
			"encrypted":    w.IsEncrypted(),
			"locked":       w.IsLocked(),
			"address":      b32,
			"balance":      BTCFromSats(bal),
			"slothealth":   w.SlotHealth(),
			"accountindex": w.CurrentAccountIndex(),
		})
	})

	// /help → lists every wired command (paths) with a short tag so
	// `qbitcoin-cli help` can surface available methods.
	mux.HandleFunc("/help", func(rw http.ResponseWriter, r *http.Request) {
		writeJSON(rw, helpIndex())
	})
	rlog := logging.Module("rpc")
	addr := fmt.Sprintf("%s:%d", bindAddr, port)
	authMode := "static"
	if user == cookieUser {
		authMode = "cookie"
	}
	rlog.Info("RPC server listening", "addr", addr, "auth", authMode)
	handler := basicAuthMiddleware(user, pass, mux)
	if err := http.ListenAndServe(addr, handler); err != nil {
		rlog.Error("rpc serve failed", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	// Disable HTML-safe escaping so <, >, &, → render literally in the
	// output. Matches bitcoind's JSON output (no HTML escaping).
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// ChainName is the value emitted as getblockchaininfo.chain /
// getmininginfo.chain. The PoC runs a single testnet-flavored chain,
// so the name is fixed.
const ChainName = "qbitcoin-test"

// txJSON shapes a Transaction the way bitcoin-cli getrawtransaction
// (verbose) emits: vin/vout arrays with Bitcoin-standard keys,
// blockhash/confirmations/blocktime when the tx is confirmed.
func txJSON(chain *core.Blockchain, tx *txn.Transaction, blockHash *[32]byte, _ uint32) map[string]interface{} {
	id := tx.TxID()
	raw := tx.Serialize()
	vin := make([]map[string]interface{}, len(tx.Inputs))
	for i, in := range tx.Inputs {
		entry := map[string]interface{}{
			"sequence": 0xFFFFFFFF,
		}
		if tx.IsCoinbase() && i == 0 {
			entry["coinbase"] = fmt.Sprintf("%x", in.Spend.Witness)
		} else {
			entry["txid"] = crypto.DisplayHex(in.PrevTxID)
			entry["vout"] = in.PrevIndex
			entry["leafindex"] = in.Spend.LeafIndex
		}
		vin[i] = entry
	}
	vout := make([]map[string]interface{}, len(tx.Outputs))
	for i, o := range tx.Outputs {
		vout[i] = map[string]interface{}{
			"value": BTCFromSats(o.Value),
			"n":     i,
			"scriptPubKey": map[string]interface{}{
				"hex":             fmt.Sprintf("%x", o.Address.MerkleRoot),
				"address":         bech32OrHex(o.Address),
				"type":            "witness_p2mr",
				"witness_version": 0,
				"witness_program": fmt.Sprintf("%x", o.Address.MerkleRoot),
			},
		}
	}
	res := map[string]interface{}{
		"txid":     crypto.DisplayHex(id),
		"hash":     crypto.DisplayHex(id),
		"version":  tx.Version,
		"size":     len(raw),
		"vsize":    len(raw),
		"weight":   len(raw) * 4,
		"locktime": tx.LockTime,
		"vin":      vin,
		"vout":     vout,
		"hex":      hex.EncodeToString(raw),
	}
	if blockHash != nil && *blockHash != ([32]byte{}) {
		res["blockhash"] = crypto.DisplayHex(*blockHash)
		if chain != nil {
			if bh, ok := chain.HeightOf(*blockHash); ok {
				res["confirmations"] = chain.Height() - bh + 1
				if hdr, err := chain.GetHeader(context.Background(), *blockHash); err == nil {
					res["blocktime"] = hdr.Timestamp
					res["time"] = hdr.Timestamp
				}
			}
		}
	}
	return res
}

// walletTxJSON shapes a transaction the way bitcoin-cli's wallet
// `gettransaction` emits: amount (net against the wallet's address
// set), category, and a details[] array per affected wallet output.
func walletTxJSON(chain *core.Blockchain, w *wallet.Wallet, tx *txn.Transaction, blockHash *[32]byte, _ uint32, inMempool bool) map[string]interface{} {
	id := tx.TxID()
	raw := tx.Serialize()
	// Wallet addresses: the active address + all known accounts.
	// ListAccounts returns one entry per BIP-44 account index the
	// wallet has seen, each carrying a distinct P2MR address.
	owned := map[[32]byte]address.P2MRAddress{}
	if accts, err := w.ListAccounts(context.Background()); err == nil {
		for _, a := range accts {
			owned[a.Address.MerkleRoot] = a.Address
		}
	}
	owned[w.Address().MerkleRoot] = w.Address()

	u := chain.ChainUTXO()
	var recv int64
	var sent int64
	details := []map[string]interface{}{}
	for i, o := range tx.Outputs {
		if _, ok := owned[o.Address.MerkleRoot]; ok {
			recv += int64(o.Value)
			details = append(details, map[string]interface{}{
				"address":  bech32OrHex(o.Address),
				"category": "receive",
				"amount":   BTCFromSats(o.Value),
				"vout":     i,
			})
		}
	}
	if !tx.IsCoinbase() {
		for _, in := range tx.Inputs {
			k := txn.UTXOKey{TxID: in.PrevTxID, Index: in.PrevIndex}
			prev, err := u.Get(k)
			if err != nil || prev == nil {
				continue
			}
			if _, ok := owned[prev.Address.MerkleRoot]; ok {
				sent += int64(prev.Value)
				details = append(details, map[string]interface{}{
					"address":  bech32OrHex(prev.Address),
					"category": "send",
					"amount":   BTC(-int64(prev.Value)),
					"vout":     in.PrevIndex,
				})
			}
		}
	}
	amount := recv - sent
	var confirmations uint32
	var blockTime uint64
	if !inMempool && blockHash != nil && *blockHash != ([32]byte{}) {
		if bh, ok := chain.HeightOf(*blockHash); ok {
			confirmations = chain.Height() - bh + 1
		}
		if hdr, err := chain.GetHeader(context.Background(), *blockHash); err == nil {
			blockTime = hdr.Timestamp
		}
	}
	res := map[string]interface{}{
		"amount":             BTC(amount),
		"confirmations":      confirmations,
		"txid":               crypto.DisplayHex(id),
		"walletconflicts":    []string{},
		"time":               blockTime,
		"timereceived":       blockTime,
		"bip125-replaceable": "no",
		"details":            details,
		"hex":                hex.EncodeToString(raw),
	}
	if !inMempool && blockHash != nil && *blockHash != ([32]byte{}) {
		res["blockhash"] = crypto.DisplayHex(*blockHash)
		if bh, ok := chain.HeightOf(*blockHash); ok {
			res["blockheight"] = bh
		}
		res["blocktime"] = blockTime
	}
	return res
}

// bech32OrHex returns the bech32 encoding of a P2MR address for
// human-readable RPC output, falling back to the raw 32-byte hex if
// encoding fails (shouldn't, but never let RPC error on a display call).
func bech32OrHex(a address.P2MRAddress) string {
	if s, err := address.EncodeBech32(a); err == nil {
		return s
	}
	return fmt.Sprintf("%x", a.MerkleRoot)
}

// blockJSON shapes a Block the way bitcoin-cli getblock (verbosity=1)
// emits: flat keys with Bitcoin-standard names, size/weight/difficulty/
// chainwork/mediantime/previousblockhash/nextblockhash.
func blockJSON(chain *core.Blockchain, b *core.Block, hash [32]byte) map[string]interface{} {
	ids := make([]string, len(b.Txns))
	for i := range b.Txns {
		id := b.Txns[i].TxID()
		ids[i] = crypto.DisplayHex(id)
	}
	serialized := b.Serialize()
	size := len(serialized)
	height, _ := chain.HeightOf(hash)
	tip := chain.Height()
	confirmations := uint32(0)
	if tip >= height {
		confirmations = tip - height + 1
	}
	res := map[string]interface{}{
		"hash":              crypto.DisplayHex(hash),
		"confirmations":     confirmations,
		"size":              size,
		"strippedsize":      size,
		"weight":            size * 4,
		"height":            height,
		"version":           b.Header.Version,
		"versionHex":        fmt.Sprintf("%08x", b.Header.Version),
		"merkleroot":        crypto.DisplayHex(b.Header.MerkleRoot),
		"tx":                ids,
		"time":              b.Header.Timestamp,
		"mediantime":        chain.MedianTimeOfBlock(hash),
		"nonce":             b.Header.Nonce,
		"bits":              fmt.Sprintf("%08x", b.Header.Bits),
		"difficulty":        bitsToDifficulty(b.Header.Bits),
		"chainwork":         workHex(chain.CumulativeWork(hash)),
		"nTx":               len(b.Txns),
		"previousblockhash": crypto.DisplayHex(b.Header.PrevHash),
	}
	if next, ok := chain.NextMainChainHash(hash); ok {
		res["nextblockhash"] = crypto.DisplayHex(next)
	}
	return res
}

// bitsToDifficulty computes Bitcoin's difficulty float:
// max_target / current_target, where max_target is derived from
// GenesisBits (our PoW limit).
func bitsToDifficulty(bits uint32) float64 {
	maxT := core.TargetToBig(core.BitsToTarget(core.GenesisBits))
	curT := core.TargetToBig(core.BitsToTarget(bits))
	if curT.Sign() == 0 {
		return 0
	}
	ratio := new(big.Rat).SetFrac(maxT, curT)
	f, _ := ratio.Float64()
	return f
}

// workHex formats cumulative chainwork as a 64-char lowercase hex
// string (Bitcoin convention). nil → all-zero.
func workHex(w *big.Int) string {
	if w == nil {
		return strings.Repeat("0", 64)
	}
	hexStr := fmt.Sprintf("%x", w)
	for len(hexStr) < 64 {
		hexStr = "0" + hexStr
	}
	return hexStr
}

// satPerByteAsBTCPerKvB converts a sat/byte feerate into BTC per 1000
// vbytes — the unit Bitcoin's RPC emits for relayfee, mempoolminfee,
// and estimatesmartfee.feerate.
func satPerByteAsBTCPerKvB(satPerByte float64) float64 {
	return satPerByte * 1000 / 100_000_000
}

// helpIndex lists the HTTP-RPC endpoints and the bitcoin-cli command
// each maps to, so `qbitcoin-cli help` can surface the available
// surface without re-deriving it from CLI source.
func helpIndex() map[string]interface{} {
	return map[string]interface{}{
		"chain": []string{
			"getblockchaininfo → GET /chain/info",
			"getbestblockhash → GET /block/best",
			"getblock <hash> [verbosity] → GET /block/<hash>?verbosity=",
			"getblockhash <height> → GET /blockhash/<height>",
			"getblockcount → GET /block/best (client-computed)",
		},
		"transactions": []string{
			"getrawtransaction <txid> [verbose] → GET /tx/<txid>?verbose=",
			"sendrawtransaction <hex> → POST /tx/broadcast",
			"decoderawtransaction <hex> → POST /tx/decode",
		},
		"mempool": []string{
			"getrawmempool [verbose] → GET /mempool?verbose=",
			"getmempoolinfo → GET /mempool/info",
		},
		"mining": []string{
			"getmininginfo → GET /mining/info",
			"getblocktemplate → GET /mining/getblocktemplate (BIP-22; external miners)",
			"submitblock <hexdata> → POST /mining/submitblock (BIP-22)",
			"generatetoaddress <n> <addr> → POST /mining/generatetoaddress (regtest helper)",
		},
		"network": []string{
			"getnetworkinfo → GET /network/info",
			"getpeerinfo → GET /peers",
			"getconnectioncount → GET /node/connectioncount",
			"uptime → GET /node/uptime",
			"stop → POST /node/stop",
		},
		"fees": []string{
			"estimatesmartfee <target> [mode] → GET /fee/estimate?target=&mode=",
		},
		"address": []string{
			"validateaddress <addr> → GET /address/validate/<addr>",
			"listtransactions [addr] → GET /address/transactions/<addr>",
		},
		"wallet": []string{
			"getwalletinfo → GET /wallet/info",
			"getbalance → GET /wallet/balance",
			"getnewaddress → POST /wallet/newaddress",
			"sendtoaddress <addr> <amount> → POST /wallet/send",
			"gettransaction <txid> → GET /wallet/gettransaction/<txid>",
			"listaccounts (qbitcoin) → GET /wallet/accounts",
			"setaccount <idx> (qbitcoin) → POST /wallet/setaccount",
		},
		"wallet-admin": []string{
			"createwallet <name> → POST /wallet/create",
			"loadwallet <name> → POST /wallet/load",
			"unloadwallet <name> → POST /wallet/unload",
			"listwallets → GET /wallets",
			"encryptwallet <name> → POST /wallet/encrypt",
			"walletpassphrase <name> <sec> → POST /wallet/passphrase",
			"walletlock <name> → POST /wallet/lock",
			"walletpassphrasechange <name> → POST /wallet/passphrasechange",
		},
	}
}
