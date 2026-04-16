# qBitcoin

A Bitcoin-faithful proof-of-concept replica with PQ signatures swapped in — **SHRINCS** (single-device stateful, ~324 B at q=1) and **SHRIMPS** (multi-device stateful, ~2,564 B compact / ~4 KB fallback) per Kudinov & Nick, *Hash-based Signature Schemes for Bitcoin* (IACR eprint 2025/2203, Revision 2025-12-05).

The project exists to make the cost of a PQ-sig transition for Bitcoin concretely visible. Every primitive and policy that doesn't have to change has been kept identical to Bitcoin Core; the places where qBitcoin deviates exist because the signature swap mechanically forces them.

---

## What this is

| Layer | Choice |
|---|---|
| Proof of work | SHA-256d, exactly as Bitcoin |
| Block / tx hashing | SHA-256d, exactly as Bitcoin |
| Address commitment | SHA-256d over a 2-leaf Merkle root |
| Signatures | SHRINCS + SHRIMPS (hash-based) |
| Address | 2-leaf Pay-to-Merkle-Root (P2MR): leaf 0 = SHRINCS pubkey, leaf 1 = SHRIMPS pubkey |
| Wallet derivation | BIP-39 mnemonic + BIP-32 hardened HMAC-SHA512 + BIP-44 path `m/44'/1'/N'/{0',1'}` |
| Storage | `cockroachdb/pebble` |
| P2P | libp2p (TCP + QUIC, Noise XX, mplex), `/qbitcoin/1.0.0` protocol |
| RPC | plain HTTP, `qbitcoind` + `qbitcoin-cli`, mirrors `bitcoind` / `bitcoin-cli` UX |
| Address encoding | bech32 (`btcutil/bech32`) |

The deviations from Bitcoin: signatures (SHRINCS / SHRIMPS instead of ECDSA / Schnorr), addresses (2-leaf P2MR instead of P2PKH / P2WPKH / Taproot), no segwit wtxid split (PQ sigs are deterministic — no malleability to fix), no BIP-32 non-hardened derivation (no xpub / no watch-only — non-hardened needs EC point addition), and signature-internal SHA-256 / SHA-512 confined to `crypto/hashsig/` (per paper §2 and §13.3). Everything else — SHA-256d, BIP-39, BIP-32 hardened, BIP-44, bech32, BIP-125 RBF, BIP-152 compact blocks, the 2016-block difficulty retarget, the half-every-210000-blocks reward schedule — is Bitcoin-exact.

---

## Build

```sh
make all          # produces build/bin/qbitcoind  +  build/bin/qbitcoin-cli
```

## Run

```sh
qbitcoind -datadir ~/.qbitcoin
```

Or headless (detached, logs to `<datadir>/qbitcoind.log`):

```sh
qbitcoin-cli start --datadir ~/.qbitcoin
# later:
qbitcoin-cli stop
```

In another terminal:

```sh
qbitcoin-cli createwallet main --no-encrypt
qbitcoin-cli getbalance
qbitcoin-cli send qbtc1q… 100000
```

Full operations guide: [`docs/operations/running-a-node.md`](docs/operations/running-a-node.md).

---

## Documentation

Everything goes deep in [`docs/`](docs/).

| Read this | If you want to |
|---|---|
| [`docs/overview.md`](docs/overview.md) | Get the one-page version: what qBitcoin is, what it deviates from Bitcoin on, and why. |
| [`docs/invariants.md`](docs/invariants.md) | Understand the consensus / persistence / wallet rules every contributor must respect. |
| [`docs/hashing.md`](docs/hashing.md) | Know which hash function to use where. (Three families; mixing them up is a security bug.) |
| [`docs/architecture/`](docs/architecture/) | Read the per-subsystem deep dives — `crypto/`, `script/`, `core/`, `mempool/`, `p2p/`, `wallet/`, etc. |
| [`docs/parameters/`](docs/parameters/) | See how the SHRINCS / SHRIMPS parameter sets are derived and what their byte costs look like. |
| [`docs/parameters/quantum-threat-model.md`](docs/parameters/quantum-threat-model.md) | Understand why PQ is needed for signatures but **not** for SHA-256d PoW. |
| [`docs/operations/`](docs/operations/) | Run a node, manage wallets, follow the persist-before-sign rule. |
| [`docs/research/`](docs/research/) | Read the paper, run the sage scripts, or reproduce a parameter pin from scratch. |

---

## Repo layout

```
qbitcoin/
├── cmd/
│   ├── qbitcoind/        node entrypoint — chain + P2P + RPC + optional miner
│   ├── qbitcoin-cli/     HTTP client mirroring bitcoin-cli's UX
│   └── mine-genesis/     one-shot tool to mine the hardcoded genesis block at a given Bits
├── crypto/               Hash256, SipHash, Merkle, SHRINCS / SHRIMPS wrappers, CheckSig
│   └── hashsig/          paper primitives — WOTS+C, XMSS, SPHINCS+, PORS+FP, Octopus
├── script/               full Bitcoin-v0.1 opcode set, polymorphic OP_CHECKSIG
├── address/              2-leaf P2MR, leaf scripts, bech32
├── txn/                  Tx layout, sighash + chain-ID binding, UTXO set, sigops cost
├── core/                 block header, PoW, 2016-block retarget, blockchain, reorg, undo, orphan, genesis
├── mempool/              relay policy, BIP-125 RBF subset, BlockPolicyEstimator
├── p2p/                  libp2p host, /qbitcoin/1.0.0 framing, handshake / ban / peer manager, BIP-152 compact blocks
├── storage/              Pebble wrapper with bucket-prefixed keys
├── wallet/               multi-wallet registry, AES-GCM at-rest encryption, BIP-32 hardened HMAC-SHA512
├── logging/              module-tagged slog wrapper
└── docs/                 this documentation
```

Module dependency order and per-subsystem responsibilities: [`docs/architecture/README.md`](docs/architecture/README.md).

---

## License

See `LICENSE`.

## Citation

If you use qBitcoin in research, please cite the underlying signature paper:

> Mikhail Kudinov and Jonas Nick. *Hash-based Signature Schemes for Bitcoin.* IACR eprint 2025/2203, Revision 2025-12-05.
