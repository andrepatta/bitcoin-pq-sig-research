# Running a node

This page covers the things you'd actually do at a terminal: start `qbitcoind`, create / unlock wallets, send a transaction, wire up the miner. Reference docs for each subsystem live under [`../architecture/`](../architecture/).

---

## 1. Build

```sh
make all          # produces build/bin/qbitcoind + qbitcoin-cli + qbitcoin-miner
```

Outputs all three binaries into `build/bin/`. Add it to `PATH` for convenience.

---

## 2. Start a node

Minimal:

```sh
qbitcoind -datadir ~/.qbitcoin
```

Full:

```sh
qbitcoind \
    -datadir   ~/.qbitcoin \
    -port      8333 \
    -rpc       8334 \
    -bootnodes x.y.z.w:8333 \
    -log       info,p2p=debug,wallet=warn \
    -log-json
```

| Flag | Default | Notes |
|---|---|---|
| `-datadir` | `~/.qbitcoin` | Pebble DB + `wallets/` + `fee_estimates.dat` all live here. |
| `-port` | 8333 | TCP listen port for the qbitcoin wire protocol. The bound `host:port` is printed on startup. |
| `-rpc` | 8334 | HTTP RPC listen port. |
| `-rpcbind` | `127.0.0.1` | RPC listen address. Set `0.0.0.0` to expose on all interfaces. |
| `-rpcuser` / `-rpcpassword` | empty | Static RPC Basic auth. Both must be set; disables the cookie. |
| `-bootnodes` | hardcoded list | Comma-separated `host:port` entries. `none` to disable. |
| `-connect` | empty | Extra explicit `host:port` dials (additive to `-bootnodes`). |
| `-log` | `info` | Format: `<default>[,<module>=<level>]…`. Modules: `p2p`, `wallet`, `core`, `mempool`, `crypto`. Levels: `debug` / `info` / `warn` / `error`. |
| `-log-json` | false | JSON log lines instead of human-readable. |
| `-daemon` | false | Re-exec detached from the terminal; stdio goes to `<datadir>/qbitcoind.log`. Parent prints the child pid and exits. |

There are no mining flags on `qbitcoind` — mining is out-of-process. See §6.

The node never auto-creates a wallet. Empty `wallets/` directory is the clean default.

### RPC auth

Every call to the RPC needs HTTP Basic credentials. By default, `qbitcoind` writes a fresh cookie at `<datadir>/.cookie` on every boot (mode 0600, removed on clean shutdown) and `qbitcoin-cli` reads it automatically — you don't have to do anything. If you'd rather pin static credentials:

```sh
qbitcoind -rpcuser alice -rpcpassword $(openssl rand -hex 16)
```

Both flags must be set together; a half-set pair errors out at startup. With static credentials set, no cookie file is written. Pass the same pair to the CLI:

```sh
qbitcoin-cli -rpcuser alice -rpcpassword … getblockcount
```

From another machine or a different datadir, either point the CLI at the cookie explicitly:

```sh
qbitcoin-cli -rpccookiefile /path/to/.cookie getblockcount
# or
qbitcoin-cli -datadir /path/to/datadir   getblockcount
```

No TLS — run behind a reverse proxy if you need transport encryption. Default bind is `127.0.0.1` so localhost-only usage is safe out of the box.

### Run headless

Either invoke `qbitcoind -daemon` directly, or let the CLI launch it:

```sh
qbitcoin-cli start --datadir ~/.qbitcoin
# → qbitcoind started (pid=12345, log=/home/you/.qbitcoin/qbitcoind.log)
```

Extra args after `start` pass through to `qbitcoind`, so `qbitcoin-cli start --datadir /tmp/qb --rpc 18334` works. Graceful shutdown:

```sh
qbitcoin-cli stop
```

`stop` hits `POST /node/stop`, which raises `SIGTERM` to the running node so shutdown flows through the same sigCh path as an interactive `Ctrl-C` (fee-estimator save, `nodeCtx` cancel, p2p stop).

---

## 3. Create a wallet

### Plaintext (no passphrase)

```sh
qbitcoin-cli createwallet main --no-encrypt
```

Returns the bech32 address and the BIP-39 mnemonic. **Save the mnemonic** — it's the only way to recover the wallet.

### Encrypted

```sh
qbitcoin-cli createwallet main --autoload
```

Prompts twice for the passphrase (no echo). The `--autoload` flag persists the wallet name in `<datadir>/wallets.autoload` so it's loaded on every node restart (locked, awaiting `walletpassphrase`).

### From an existing mnemonic

The HTTP API supports `mnemonic` in `POST /wallet/create`:

```sh
curl -u "$(cat ~/.qbitcoin/.cookie)" \
     -X POST localhost:8334/wallet/create -d '{
  "name": "restored",
  "passphrase": "…",
  "mnemonic": "abandon abandon abandon … art",
  "autoload": true
}'
```

The CLI doesn't expose this — restoring from an existing mnemonic is rare enough that it's a curl-only path.

---

## 4. Unlock an encrypted wallet

```sh
qbitcoin-cli walletpassphrase main 600     # unlock for 600 seconds
qbitcoin-cli walletpassphrase main 0       # unlock until explicit walletlock
```

The MEK lives in memory until the timeout fires or `walletlock` zeroes it.

```sh
qbitcoin-cli walletlock main
```

---

## 5. Send a transaction

Auto-fee (estimator queries with `target=6 mode=unset`):

```sh
qbitcoin-cli send qbtc1q… 100000           # 0.001 BTC, 100,000 sat
```

Explicit fee (sat absolute, NOT sat/B):

```sh
qbitcoin-cli send qbtc1q… 100000 5000      # 5,000 sat fee
```

Explicit feerate via the HTTP RPC (don't forget Basic auth — pull the cookie or use static creds):

```sh
curl -u "$(cat ~/.qbitcoin/.cookie)" \
     -X POST localhost:8334/wallet/send \
     -d '{"to":"qbtc1q…","amount":100000,"feerate":3}'
```

Adaptive: if the actual signed tx is larger than the estimate (because the SHRINCS leaf q is high → bigger sigs), `SendAtFeerate` rebuilds + re-signs once with the corrected fee. Logged as a warn-line; consumes an extra SHRINCS slot.

---

## 6. Mine

Mining is out-of-process, matching Bitcoin Core's model. `qbitcoind` publishes BIP-22 templates and accepts `submitblock`; `qbitcoin-miner` does the grinding in a separate process.

### External miner

```sh
qbitcoin-miner \
    -rpc      http://127.0.0.1:8334 \
    -coinbase qbtc1q… \
    -threads  $(nproc)
```

`--coinbase` is always required — the node doesn't know about any wallet or fallback address. Auth resolves the same way as `qbitcoin-cli`: `-rpcuser`/`-rpcpassword` pair, or `-rpccookiefile`, or default `<datadir>/.cookie`.

The miner polls `getblocktemplate`, assembles a block paying coinbase to `--coinbase`, grinds in parallel with midstate + no-alloc hot path, and calls `submitblock`. A background watchdog re-pulls the tip every `-poll-interval` (default 5 s) so a tip change aborts the grind and the loop pulls a fresh template.

```sh
qbitcoin-cli getmininginfo                 # chain state (no miner fields)
qbitcoin-cli getblocktemplate              # raw BIP-22 template (debugging)
```

### Regtest-style helper

```sh
qbitcoin-cli generatetoaddress 10 qbtc1q…  # mine 10 blocks in-process
```

Uses the same `miner.Grind` path without the RPC hop. Pays coinbase (subsidy + template fees) to the given address and returns the new block hashes. Useful for deterministic tests.

See [`../architecture/miner.md`](../architecture/miner.md) for the grinder internals, BIP-22 wire format, and deviations from Bitcoin (no segwit fields, 64-bit `noncerange`).

---

## 7. Multi-wallet workflow

Bitcoin Core-style. Multiple wallets coexist under `<datadir>/wallets/<name>/`. Per-wallet RPCs route via `-rpcwallet=<name>`.

```sh
qbitcoin-cli createwallet alice --autoload
qbitcoin-cli createwallet bob   --autoload

qbitcoin-cli listwallets
# → alice (encrypted: false, locked: false, address: qbtc1q…)
#   bob   (encrypted: false, locked: false, address: qbtc1q…)

qbitcoin-cli -rpcwallet=alice getbalance
qbitcoin-cli -rpcwallet=bob   send qbtc1q… 50000
```

If only one wallet is loaded, `-rpcwallet` is optional — that wallet is the default. With two or more loaded and `-rpcwallet` absent, per-wallet endpoints return `412 ambiguous default`.

---

## 8. New address (advance account index)

```sh
qbitcoin-cli newaddress           # advance to next BIP-44 account index
qbitcoin-cli setaccount 7         # switch to account 7 (creating it if absent)
qbitcoin-cli listaccounts
```

There is no on-chain rotation. A new address is just a new BIP-44 account index. The 24-word mnemonic recovers all accounts forever.

---

## 9. Inspect chain state

```sh
qbitcoin-cli getblockcount
qbitcoin-cli getblock latest
qbitcoin-cli getblock <hex_hash>
qbitcoin-cli gettransaction <hex_txid>
qbitcoin-cli getrawmempool
qbitcoin-cli getpeers
qbitcoin-cli estimatesmartfee 6 conservative
```

All of these are also available as plain HTTP `GET`s — see [`../architecture/rpc.md`](../architecture/rpc.md) §3.

---

## 10. Logs

The slog-based module-tagged logger lets you crank a single subsystem to debug:

```sh
qbitcoind -log "info,p2p=debug"
```

Modules: `p2p`, `wallet`, `core`, `mempool`, `crypto`, `rpc`. Levels: `debug`, `info`, `warn`, `error`. Default level applies to everything not explicitly set.

`-log-json` switches to JSON output for piping into log-aggregation pipelines.

---

## 11. Where data lives

```
<datadir>/
  qbitcoin.db/           Pebble store (blocks, headers, utxos, peers, bans, …)
  .cookie                RPC auth cookie (0600, regenerated on every boot, removed on clean shutdown)
  fee_estimates.dat      BlockPolicyEstimator state (saved on SIGINT/SIGTERM + every 10 min)
  wallets/<name>/        per-wallet data (see ../architecture/wallet.md §8)
  wallets.autoload       newline-separated wallet names re-loaded on boot
```

There is no transport-layer identity key — peers are just `ip:port` endpoints.

Backup the `wallets/<name>/` dir + the wallet's BIP-39 mnemonic. The Pebble DB is reproducible from genesis + peer sync (`<datadir>/qbitcoin.db` is just a chain cache).
