# `cmd/qbitcoind`, `cmd/qbitcoin-cli`, `cmd/qbitcoin-miner` — node, CLI, external miner

The node (`qbitcoind`) serves an HTTP RPC on `--rpc` port (default 8334), gated by HTTP Basic auth (Bitcoin Core-style cookie or static credentials). Default bind is `127.0.0.1`; use `-rpcbind 0.0.0.0` for external exposure. `qbitcoin-cli` is a thin stdlib-only client mirroring `bitcoin-cli`'s UX — every wallet operation lives in the node, the CLI just formats requests. `qbitcoin-miner` is a separate process that pulls BIP-22 templates, grinds PoW, and submits blocks — qbitcoind has no built-in miner, matching Bitcoin Core's operational model. All three binaries build into `build/bin/` via `make all`.

---

## 1. `qbitcoind` — node entrypoint

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `-datadir` | `~/.qbitcoin` | Pebble + wallet directory. |
| `-port` | 8333 | TCP listen port for the qbitcoin wire protocol. |
| `-rpc` | 8334 | HTTP RPC listen port. |
| `-rpcbind` | `127.0.0.1` | RPC listen address. `0.0.0.0` exposes on all interfaces (needed for docker port mapping). |
| `-rpcuser` | empty | Static RPC Basic auth user. When set, `-rpcpassword` must also be set; disables the cookie file. |
| `-rpcpassword` | empty | Static RPC Basic auth password. Pair with `-rpcuser`. |
| `-bootnodes` | `DefaultBootnodes` | Comma-separated `host:port` entries. `none` disables. |
| `-connect` | empty | Extra `host:port` to dial at startup. |
| `-log` | `info` | Log spec — e.g. `"info,p2p=debug,wallet=warn"`. |
| `-log-json` | false | Emit JSON log lines instead of human-readable. |
| `-daemon` | false | Re-exec detached from the terminal (`setsid` + stdio → `<datadir>/qbitcoind.log`), print `pid`, exit parent. Matches `bitcoind -daemon`. A sentinel env var (`QBITCOIND_DAEMONIZED`) guards against re-fork in the child. |

There is **no** `-mnemonic` / `-passphrase`. Wallets are explicit; create with `qbitcoin-cli createwallet <name>`. See [`wallet.md`](wallet.md) §3.

### RPC authentication

Every handler registered in `runRPC` is wrapped by `basicAuthMiddleware` (`cmd/qbitcoind/rpc_auth.go`), which enforces HTTP Basic auth with constant-time compare on both halves. Credentials resolve in this order:

1. `-rpcuser` + `-rpcpassword` flag pair. Both must be set — half-set fails at startup. No cookie file is written.
2. Auto-generated cookie at `<datadir>/.cookie`. The file is (re)written on every boot with a fresh 32-byte hex password, mode 0600, and removed on clean shutdown. A crash leaves it behind; the next boot overwrites. File format matches Bitcoin Core: `__cookie__:<hex>`.

401 responses set `WWW-Authenticate: Basic realm="qbitcoin"` so clients can tell an RPC-auth 401 apart from a domain-level 401 (wallet bad passphrase, which does **not** set the header). `qbitcoin-cli` uses this to emit a targeted hint instead of a misleading "bad passphrase".

No TLS — run behind a reverse proxy (nginx / caddy / Cloudflare Tunnel) if you need transport encryption. Docker compose keeps `-rpcbind 0.0.0.0` so host port mapping reaches the container; the cookie file on the shared `/data` volume still gates access.

### Mining

qbitcoind has no in-process miner. Mining is external: `qbitcoin-miner` (or any BIP-22 client) pulls `GET /mining/getblocktemplate`, assembles the block (coinbase paying its own `--coinbase` address), grinds the header in parallel, and submits via `POST /mining/submitblock`. Confirmed-tx eviction from the mempool flows through a `chain.OnBlockConnected` callback so subsequent templates don't re-include already-spent txs.

`generatetoaddress` stays on the node as a regtest convenience — it uses the same `miner.Grind` path but without the out-of-process hop. See [`miner.md`](miner.md) for the grinder (midstate + no-alloc hot path), the external miner binary, and BIP-22 deviations from Bitcoin (no segwit fields, 64-bit `noncerange`, wtxid=txid).

### Coinbase BIP-34-style uniqueness

`miner.BuildCoinbase` embeds the block height as 4 BE bytes in the coinbase input's `Spend.Witness[0]`. See [`core.md`](core.md) §11.

---

## 2. `qbitcoin-cli` — CLI

```
qbitcoin-cli [-rpc http://host:port] [-rpcwallet <name>]
             [-rpcuser <user> -rpcpassword <pass> | -rpccookiefile <path> | -datadir <path>]
             <command> [args]
```

### CLI auth flags

Credential precedence mirrors the daemon: explicit `-rpcuser` + `-rpcpassword` flag pair > explicit `-rpccookiefile` > default `<datadir>/.cookie` where `-datadir` defaults to `~/.qbitcoin` (same as `qbitcoind`). If none resolves, the request goes out with no `Authorization` header and the server replies 401 — the CLI maps this to a clean `RPC auth failed — check -rpcuser/-rpcpassword or the cookie file in -datadir` hint because the daemon's 401 carries `WWW-Authenticate`.

### Wallet admin (multi-wallet, Bitcoin Core-style)

| Command | Purpose |
|---|---|
| `createwallet <name> [--no-encrypt] [--autoload]` | Create a wallet. Prompts twice for passphrase (empty = unencrypted with `y/N` confirmation). `--no-encrypt` skips the prompt (scripting). `--autoload` persists the name in `wallets.autoload`. |
| `encryptwallet <name>` | Upgrade an unencrypted wallet to encrypted (one-way). |
| `loadwallet <name> [--autoload]` | Load a wallet into the node (encrypted ones come up locked). |
| `unloadwallet <name>` | Unload a wallet from the node (disk state intact). |
| `listwallets` | List loaded wallets with encrypted / locked / address. |
| `walletpassphrase <name> <seconds>` | Unlock an encrypted wallet for `<seconds>` (`0` = until explicit `walletlock`). |
| `walletlock <name>` | Zero the MEK in memory. |
| `walletpassphrasechange <name>` | Rotate the passphrase (prompts for old + new). |

### Per-wallet (route with `-rpcwallet=<name>`, or single-loaded default)

| Command | Purpose |
|---|---|
| `getbalance` | Current wallet balance + slot health + active index. |
| `getaddress` | Current wallet bech32 address. |
| `newaddress` | Advance to next account index, print new address. |
| `setaccount <index>` | Switch active wallet account to an existing/new index. |
| `listaccounts` | Known accounts (index + address + balance + active). |
| `send <addr> <amount> [fee]` | Build, sign, broadcast a tx. Omit `fee` for `estimatesmartfee target=6 unset-mode` auto-fee. |
| `listtransactions [addr]` | Tx history for an address (defaults to current wallet). |

### Chain / node state

| Command | Purpose |
|---|---|
| `estimatesmartfee <target> [mode]` | Query fee estimator; `mode = unset \| economical \| conservative`. |
| `gettransaction <txid>` | Fetch a tx by hex id (mempool or chain). |
| `getblockcount` | Current tip height. |
| `getblock <hash\|latest>` | Block by hex hash or `"latest"`. |
| `getpeers` | Connected peers. |
| `getrawmempool` | Txs currently in the mempool. |
| `getmininginfo` | Current bits + height + chain state (read-only; no miner fields). |
| `getblocktemplate` | BIP-22 template — external miners pull, assemble, grind, submit. |
| `submitblock <hexdata>` | BIP-22 submitblock. Returns `null` on accept, reason string on reject. |
| `generatetoaddress <n> <addr>` | Regtest helper: mine n blocks paying coinbase to addr. |

### Node lifecycle

| Command | Purpose |
|---|---|
| `start [qbitcoind args...]` | Launch `qbitcoind --daemon` detached; extra args are passed through verbatim (e.g. `start --datadir /tmp/qb --rpc 18334`). The binary is located next to `qbitcoin-cli` first, then `$PATH`. The CLI's own `-rpc` URL is *not* translated into the daemon's `-rpc` port — those live in separate namespaces, same as `bitcoin-cli` / `bitcoind`. |
| `stop` | Ask the running node to shut down gracefully via `POST /node/stop`. |

### Passphrase prompts

Read from stdin with no echo when stdin is a TTY (`golang.org/x/term`). Non-TTY stdin reads the first line — for scripting:

```sh
echo secret | qbitcoin-cli walletpassphrase main 300
```

---

## 3. RPC endpoints (full list)

| Method + path | Purpose |
|---|---|
| `GET  /block/latest` | Header summary of tip. |
| `GET  /block/<hex_hash>` | Full block (header + txids). |
| `GET  /tx/<hex_txid>` | Tx from mempool or chain (with block hash + height when confirmed). |
| `POST /tx/broadcast` | Raw hex body → deserialize → mempool add → gossip. |
| `GET  /utxo/<bech32>` | UTXOs + balance for an address. |
| `GET  /address/transactions/<bech32>` | Sent / received history for an address (chain + mempool). |
| `GET  /peers` | Connected peers. |
| `GET  /mempool` | Mempool contents. |
| `GET  /mining/info` | Chain tip snapshot: blocks, difficulty, bits, pooledtx, chain. No miner state. |
| `GET  /mining/getblocktemplate` | BIP-22 block template (mempool-backed, built fresh per call). |
| `POST /mining/submitblock` | JSON `{hexdata}` → validate + AddBlock + broadcast. Response: `null` accept, string reject reason. |
| `POST /mining/generatetoaddress` | JSON `{nblocks, address}` → mine n blocks in-process (regtest helper). Returns `[hash, ...]`. |
| `POST /node/stop` | Graceful shutdown. Handler responds `{"status":"qbitcoind stopping"}` then raises `SIGTERM` to self, reusing the `sigCh` shutdown path (estimator save + `nodeCtx` cancel + p2p stop). |
| `GET  /fee/estimate?target=N&mode=unset\|economical\|conservative` | `estimatesmartfee` query. |
| `GET  /wallets` | List loaded wallets `[{name, encrypted, locked, address}]`. |
| `POST /wallet/create` | JSON `{name, passphrase, mnemonic?, autoload?}` → creates and returns `{name, address, path, encrypted, mnemonic}`. When `mnemonic` is supplied (restore flow) the handler also runs BIP-44 §Account Discovery and includes `discovered_account_index` with the highest-used account it found (see `wallet.md` §2). |
| `POST /wallet/load` | JSON `{name, passphrase?, autoload?}` → load (and unlock if passphrase given). |
| `POST /wallet/unload` | JSON `{name}` → unload (disk files preserved). |
| `POST /wallet/encrypt` | JSON `{name, passphrase}` → upgrade plaintext → encrypted (one-way). |
| `POST /wallet/passphrase` | JSON `{name, passphrase, timeout_seconds}` → unlock + auto-lock timer. |
| `POST /wallet/lock` | JSON `{name}` → zero MEK. |
| `POST /wallet/passphrasechange` | JSON `{name, old, new}` → rotate KEK. |
| `GET  /wallet/status?wallet=<name>` | Address + balance + slot health + active index for named wallet. |
| `POST /wallet/send?wallet=<name>` | JSON `{to, amount, fee}` → build + sign + gossip. |
| `POST /wallet/newaddress?wallet=<name>` | Advance active account index. |
| `POST /wallet/setaccount?wallet=<name>` | JSON `{index}` → switch to any existing/new account. |
| `GET  /wallet/accounts?wallet=<name>` | List accounts (index + address + balance + active). |

`?wallet=<name>` is optional when exactly one wallet is loaded. With 0 loaded, per-wallet endpoints return `404 no wallet loaded`; with 2+ and no `wallet=`, they return `412 ambiguous default`. Encrypted + locked wallets return `423 wallet is locked` from handlers that need signing; read-only handlers (`/wallet/status`) still answer from plaintext caches.

---

## 4. Status-code conventions

`cmd/qbitcoind/wallet_rpc.go::walletErrToStatus`:

| Code | Meaning |
|---|---|
| `404` | Named wallet not loaded, or legacy store missing. |
| `409` | Would collide with existing state (duplicate `createwallet`, double `encrypt`). |
| `412` | Ambiguous default (specify `-rpcwallet`). |
| `423` | Encrypted wallet is locked. |
| `401` | Wallet bad passphrase **or** RPC auth failure. Distinguished by the presence of `WWW-Authenticate: Basic` on the response: set by `basicAuthMiddleware`, unset by wallet handlers. |
| `400` | Malformed body / invalid wallet name / `walletpassphrase` on a plaintext wallet. |

---

## 5. Out of scope

- TLS on RPC.
- RPC bearer-token / JWT auth. HTTP Basic (cookie + static) is in scope; richer schemes are not.
- `-rpcallowip` source-IP allowlisting. The binding model (`127.0.0.1` default; `0.0.0.0` opt-in) is the single knob.
- RPC rate limiting / 429.
- Prometheus `/metrics` or `/health` endpoints.
- Config file (`~/.qbitcoin/config.toml`) — flags only.
