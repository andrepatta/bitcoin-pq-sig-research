# Architecture

The package layout under `qbitcoin/` and the dependency order between modules. Each subsystem has its own deep-dive document; this page is the map.

---

## Layered view

```
                           ┌─────────────────────────┐
                           │ cmd/qbitcoind            │
                           │ cmd/qbitcoin-cli         │
                           │ cmd/mine-genesis         │
                           └────────────┬─────────────┘
                                        │
        ┌───────────────┬───────────────┼─────────────────────┐
        │               │               │                     │
   ┌────▼────┐    ┌─────▼─────┐  ┌──────▼──────┐    ┌─────────▼──────┐
   │ wallet/ │    │ p2p/      │  │ mempool/    │    │ HTTP RPC       │
   │         │    │           │  │             │    │ (in cmd/)      │
   └────┬────┘    └─────┬─────┘  └──────┬──────┘    └────────────────┘
        │               │               │
        │       ┌───────┴───────┐       │
        │       │               │       │
        │   ┌───▼───┐      ┌────▼───────▼───┐
        │   │ core/ │      │ txn/           │
        │   └───┬───┘      └─────┬──────────┘
        │       │                │
        │       └─────┬──────────┘
        │             │
        │     ┌───────▼────────┐
        │     │ address/       │
        │     └───────┬────────┘
        │             │
        │     ┌───────▼────────┐
        │     │ script/        │
        │     └───────┬────────┘
        │             │
        └─────┬───────┘
              │
        ┌─────▼─────┐    ┌──────────┐
        │ crypto/   │───▶│ storage/ │
        └─────┬─────┘    └──────────┘
              │
       ┌──────▼─────────┐
       │ crypto/hashsig │
       └────────────────┘
```

(Arrows = "depends on". `cmd/` sits at the top, `crypto/hashsig/` at the bottom; nothing imports it back.)

---

## Module dependency order

The order modules need to be built, read, or reasoned about in. Each row depends only on rows above it.

| Step | File / package | Key dependencies |
|---|---|---|
| 1 | `crypto/hash.go` | nothing |
| 2 | `crypto/merkle.go` | `hash.go` |
| 3a | `crypto/hashsig/adrs.go`, `thash.go` | stdlib `crypto/sha256` only |
| 3b | `crypto/hashsig/wots.go` | `adrs.go`, `thash.go` |
| 3c | `crypto/hashsig/xmss.go` | `wots.go` |
| 3d | `crypto/hashsig/unbalanced_xmss.go` | `xmss.go` (paper §B.3) |
| 3e | `crypto/hashsig/hypertree.go` | `xmss.go` |
| 3f | `crypto/hashsig/fors.go`, `pors.go` | `thash.go` |
| 3g | `crypto/hashsig/sphincs.go` | `hypertree.go`, `pors.go` |
| 4 | `crypto/shrincs.go` | `hashsig/unbalanced_xmss.go` (stateful) + `hashsig/sphincs.go` (stateless fallback) |
| 5 | `crypto/shrimps.go` | `hashsig/sphincs.go` (two instances: compact + fallback) |
| 6 | `crypto/state_file.go` | stdlib only — `os`, `hash/crc32` |
| 7a | `script/opcodes.go`, `num.go`, `script.go` | stdlib only |
| 7b | `script/interp.go` | `script/*.go` + `crypto/hash.go` + (interface for sig-checker) |
| 7c | `crypto/checksig.go` | `crypto/shrincs.go`, `crypto/shrimps.go` |
| 8 | `address/p2mr.go` | `crypto/merkle.go`, `script/` |
| 9 | `txn/script.go` | `crypto/`, `script/`, `address/` |
| 10 | `txn/tx.go` | `txn/script.go`, `address/` |
| 11 | `txn/utxo.go` | `txn/tx.go` |
| 12 | `storage/db.go` | `cockroachdb/pebble` only |
| 13 | `core/block.go` | `crypto/hash.go`, `crypto/merkle.go` |
| 14 | `core/pow.go` | `core/block.go`, `crypto/hash.go` |
| 15 | `core/genesis.go` | `core/block.go`, `address/`, `crypto/` |
| 16 | `core/blockchain.go` | all `core/`, `txn/`, `storage/` |
| 17a | `mempool/feerate.go` | nothing (constants + helpers) |
| 17b | `mempool/mempool.go` | `txn/`, `core/`, `feerate.go` |
| 17c | `mempool/estimator.go`, `estimator_persist.go` | `mempool/`, `txn/` |
| 18 | `p2p/messages.go` | `core/`, `txn/`, `crypto/` (Bitcoin `CMessageHeader` framer + payload codecs) |
| 18c | `p2p/bootnodes.go` | nothing (string list) |
| 18d | `p2p/banman.go` | `storage/`, stdlib `net`, `time` |
| 19 | `p2p/peer.go` | `messages.go`, stdlib `net` (one `net.Conn` per peer) |
| 20 | `p2p/node.go` | `peer.go`, `core/`, `mempool/`, `banman.go`, stdlib `net` (`net.Listen`/`net.Dialer`) |
| 21 | `wallet/mnemonic.go` | `crypto/hash.go`, `tyler-smith/go-bip39` |
| 22 | `wallet/store.go`, `encrypt.go` | stdlib `crypto/aes`, `crypto/cipher`, `crypto/pbkdf2` |
| 23 | `wallet/state_io.go` | `wallet/store.go`, `crypto/state_file.go` |
| 24 | `wallet/rotate.go` | `crypto/`, `address/`, `wallet/store.go` |
| 25 | `wallet/wallet.go` | `mnemonic.go`, `rotate.go`, `store.go`, `txn/` |
| 26 | `wallet/registry.go` | `wallet/wallet.go` |
| 27 | `cmd/qbitcoind/main.go` | everything |
| 28 | `cmd/qbitcoind/wallet_rpc.go` | `wallet/registry.go` (admin RPC handlers) |
| 29 | `cmd/qbitcoin-cli/main.go` | stdlib + `golang.org/x/term` (no-echo passphrase prompt) |
| 30 | `cmd/mine-genesis/main.go` | `core/`, `crypto/` |

The numbering is not a Go build order (Go builds bottom-up automatically) — it's the *reading* order for understanding the codebase from primitives upward.

---

## Per-subsystem deep dives

| Doc | Subsystem |
|---|---|
| [crypto.md](crypto.md) | Hashing primitives, Merkle, SipHash, CheckSig dispatch, atomic state files |
| [hashsig.md](hashsig.md) | Paper primitives — WOTS+C, XMSS / unbalanced XMSS, hypertree, FORS, PORS+FP, Octopus, SPHINCS+ |
| [shrincs.md](shrincs.md) | SHRINCS — single-device stateful + stateless fallback, 324-byte first-sig wire format, min-rule |
| [shrimps.md](shrimps.md) | SHRIMPS — multi-device, two SPHINCS+ instances, tag-byte wire dispatch |
| [script.md](script.md) | Bitcoin v0.1 opcode set, modern post-disable rules, polymorphic OP_CHECKSIG, interpreter limits |
| [address.md](address.md) | 2-leaf P2MR, leaf scripts, bech32, address derivation |
| [txn.md](txn.md) | Tx layout, sighash + chain-ID binding, UTXO set, sigops cost |
| [core.md](core.md) | Block header, PoW, Bitcoin-exact difficulty retarget, blockchain, reorg atomicity, undo records, orphan pool, genesis |
| [mempool.md](mempool.md) | Conflict tracking, BIP-125 RBF subset, min-relay, BlockPolicyEstimator |
| [p2p.md](p2p.md) | Raw TCP transport, Bitcoin `CMessageHeader` framing, handshake / ban / peer manager, BIP-152 compact blocks |
| [storage.md](storage.md) | Pebble bucket layout |
| [wallet.md](wallet.md) | Multi-wallet registry, AES-GCM encryption, BIP-32 hardened KDF, account / address management, signing flow |
| [rpc.md](rpc.md) | `qbitcoind` HTTP RPC + `qbitcoin-cli` UX |
