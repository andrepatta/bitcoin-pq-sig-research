# qBitcoin Documentation

qBitcoin is a **Bitcoin-faithful proof-of-concept replica with PQ signatures swapped in** (SHRINCS / SHRIMPS, per Kudinov & Nick, *Hash-based Signature Schemes for Bitcoin*, IACR eprint 2025/2203). It exists for one reason: let researchers see what Bitcoin looks like with hash-based signatures, so the practical cost of a PQ-sig transition can be evaluated end-to-end. Every primitive, protocol, and policy matches Bitcoin Core unless hash-based signatures mechanically force a deviation.

Start here. The rest of the docs go deep.

---

## Reading order

If you're new to the project:

1. [overview.md](overview.md) — the one-page version: what qBitcoin is, what it deviates from Bitcoin on, and why.
2. [invariants.md](invariants.md) — the consensus-level rules every contributor must respect.
3. [hashing.md](hashing.md) — when to use which hash function. (qBitcoin uses three families; mixing them up is a security bug.)
4. [parameters/quantum-threat-model.md](parameters/quantum-threat-model.md) — why PQ is needed for signatures but **not** for SHA-256d PoW.

If you're looking for a specific subsystem, jump straight into [architecture/](architecture/).

If you want the math behind the SHRINCS/SHRIMPS sizes, see [research/](research/) — the paper, the authors' sage scripts, and our extensions are all there.

---

## Top-level docs

| File | What's in it |
|---|---|
| [overview.md](overview.md) | What qBitcoin is. Forced deviations from Bitcoin. PQ threat model in one paragraph. |
| [invariants.md](invariants.md) | The 12 consensus / persistence / wallet invariants. Non-negotiable. |
| [hashing.md](hashing.md) | SHA-256d vs SHA-256/SHA-512 (signature-internal) vs HMAC-SHA512 (BIP-32). Import discipline. |

## Architecture (per subsystem)

| File | Subsystem |
|---|---|
| [architecture/README.md](architecture/README.md) | Module map + dependency order |
| [architecture/crypto.md](architecture/crypto.md) | `crypto/` — Hash256, SipHash, Merkle, CheckSig dispatch |
| [architecture/hashsig.md](architecture/hashsig.md) | `crypto/hashsig/` — paper primitives (WOTS+C, XMSS, SPHINCS+, PORS+FP, Octopus) |
| [architecture/shrincs.md](architecture/shrincs.md) | SHRINCS: unbalanced-XMSS stateful + stateless fallback, 324-byte first-sig wire format |
| [architecture/shrimps.md](architecture/shrimps.md) | SHRIMPS: two SPHINCS+ instances (compact + fallback), tag-byte dispatch |
| [architecture/script.md](architecture/script.md) | `script/` — full Bitcoin-v0.1 opcode set, polymorphic OP_CHECKSIG |
| [architecture/address.md](architecture/address.md) | `address/` — 2-leaf P2MR, leaf templates, bech32 encoding |
| [architecture/txn.md](architecture/txn.md) | `txn/` — Tx layout, sighash construction, UTXO set |
| [architecture/core.md](architecture/core.md) | `core/` — block header, PoW, difficulty (Bitcoin-exact 2016-block retarget), reorgs, genesis |
| [architecture/mempool.md](architecture/mempool.md) | `mempool/` — relay policy, BIP-125 RBF subset, fee estimator (Core port) |
| [architecture/p2p.md](architecture/p2p.md) | `p2p/` — raw TCP transport, Bitcoin CMessageHeader framing, handshake, BIP-152 compact blocks, ban manager |
| [architecture/storage.md](architecture/storage.md) | `storage/` — Pebble bucket layout |
| [architecture/wallet.md](architecture/wallet.md) | `wallet/` — multi-wallet registry, AES-GCM at-rest encryption, BIP-32 hardened KDF |
| [architecture/rpc.md](architecture/rpc.md) | `cmd/qbitcoind` HTTP RPC + `cmd/qbitcoin-cli` |
| [architecture/miner.md](architecture/miner.md) | `miner/` grinder (midstate + no-alloc) + `cmd/qbitcoin-miner` external miner + BIP-22 wire format |

## Operations

| File | Topic |
|---|---|
| [operations/persist-before-sign.md](operations/persist-before-sign.md) | The state-counter rule that prevents catastrophic key reuse. |
| [operations/running-a-node.md](operations/running-a-node.md) | CLI flags, mining, wallet creation/encryption, RPC usage. |

## Parameters

| File | Topic |
|---|---|
| [parameters/README.md](parameters/README.md) | Parameter sets and their derivation. Cross-references the paper's Table 1 and the sage oracle in `research/sage/`. |
| [parameters/signature-sizes.md](parameters/signature-sizes.md) | Paper-oracle vs our implementation vs on-wire sizes. |
| [parameters/quantum-threat-model.md](parameters/quantum-threat-model.md) | Shor (signatures, broken) vs Grover (PoW, mining-economics only). |

## Research

| File | Topic |
|---|---|
| [research/README.md](research/README.md) | Index over the paper, sage scripts, sat-v0.1 reference, calibration tools. |
| [research/papers/](research/papers/) | Kudinov & Nick eprint 2025/2203 (PDF + extracted text). |
| [research/sage/](research/sage/) | The authors' sage parameter / cost / security scripts, plus our extensions. |
| [research/calibration/](research/calibration/) | `pqbc-cal` — a tiny Go program that benchmarks SHA-256d hashrate on a host and proposes `Bits` for a given target block time. |
| [research/satoshi-v0.1/](research/satoshi-v0.1/) | Satoshi Bitcoin v0.1 source (`script.h`, `main.cpp`, …). The opcode hex values in `script/opcodes.go` are derived verbatim from this code. |
| [research/references/](research/references/) | Forum threads, Blockstream quantum page, link table. |
