# Overview

qBitcoin is a Bitcoin-faithful proof-of-concept replica with PQ signatures swapped in (SHRINCS / SHRIMPS, per Kudinov & Nick, *Hash-based Signature Schemes for Bitcoin*, IACR eprint 2025/2203, Revision 2025-12-05).

The project's purpose is **to make the cost of a PQ-sig transition for Bitcoin concretely visible** — to researchers, to wallet authors, to anyone modeling what a soft-fork to hash-based signatures would actually look like in practice. To make that comparison meaningful, every primitive and policy that **doesn't have to** change has been kept identical to Bitcoin Core. The places where qBitcoin deviates are catalogued below; each one exists because the signature swap mechanically forces it.

This page is the one-pager. The rest of `docs/` goes deep. The full module map lives in [architecture/README.md](architecture/README.md).

---

## What's in the chain

| Layer | Choice |
|---|---|
| Proof of work | SHA-256d (double SHA-256), exactly as Bitcoin |
| Block / tx hashing | SHA-256d, exactly as Bitcoin |
| Address commitment | SHA-256d over the 2-leaf Merkle root |
| Signatures | **SHRINCS** (single-device stateful, ~324 B at q=1) and **SHRIMPS** (multi-device stateful, ~2,564 B compact / ~4 KB fallback) — both hash-based |
| Address | 2-leaf Pay-to-Merkle-Root: leaf 0 = SHRINCS pubkey, leaf 1 = SHRIMPS pubkey |
| Wallet derivation | BIP-39 mnemonic + BIP-32 hardened HMAC-SHA512 + BIP-44 path `m/44'/1'/N'/{0',1'}` |
| Storage | `cockroachdb/pebble` |
| P2P | libp2p (TCP + QUIC, Noise XX, mplex) |
| RPC | HTTP + Bitcoin Core-style Basic auth (cookie by default, `-rpcuser`/`-rpcpassword` optional). `qbitcoind` + `qbitcoin-cli` mirror `bitcoind` / `bitcoin-cli` UX. No TLS. |
| Address encoding | bech32 (`btcutil/bech32`) |

---

## Forced deviations from Bitcoin

These are the **only** places qBitcoin diverges from Bitcoin Core, and each one exists because the PQ-sig swap mechanically requires it. Everything else — SHA-256d, little-endian header layout, SipHash-2-4 BIP-152 short IDs, BIP-39 / BIP-32 / BIP-44, bech32, BIP-125 RBF, BIP-152 compact blocks, the 2016-block difficulty retarget, the half-every-210000-blocks reward schedule — is Bitcoin-exact.

1. **Signatures.** SHRINCS / SHRIMPS (hash-based) instead of ECDSA / Schnorr. The existential reason for the project. A future quantum computer running Shor's algorithm breaks ECDSA / Schnorr; it doesn't break SHA-256-based hash-tree signatures.
2. **Addresses.** 2-leaf P2MR commits to both a single-device (SHRINCS) and a multi-device (SHRIMPS) pubkey, per Kudinov & Nick. P2MR replaces P2PKH / P2WPKH / Taproot.
3. **No segwit wtxid split.** Hash-based sigs are deterministic (PRF-based per paper §11), so there's no malleability for segwit to fix.
4. **No BIP-32 non-hardened derivation / no xpub / no watch-only wallets.** Hardened derivation is pure HMAC-SHA512 and works exactly like Bitcoin. Non-hardened derivation requires `child_priv = parse256(I[:32]) + k_par mod n` — secp256k1 point addition that hash-based keys don't support.
5. **Signature-internal SHA-256 / SHA-512.** Inside SHRINCS / SHRIMPS, the paper uses SHA-256 for tweakable hashes (paper §2: F, H, T_l, PRF) and SHA-512 for the wide-output `H_msg` in PORS+FP (paper §13.3 — needs > 172 bits for `n > h + k·⌈log₂ t⌉`). These primitives are confined to `crypto/hashsig/` and live entirely inside the signature construction; the chain itself never sees them.

That's the full list. There are no other deviations. See [hashing.md](hashing.md) for the import discipline that keeps signature-internal hashes from leaking into chain-layer code, and [invariants.md](invariants.md) for the consensus rules.

---

## Quantum threat model — the short version

The load-bearing PQ defense in this project is the **signature scheme**, not the hash function.

| Algorithm | What it breaks | What it does to qBitcoin |
|---|---|---|
| Shor | ECDSA / Schnorr in polynomial time | Existentially forges signatures on every classical-sig blockchain. qBitcoin swaps to hash-based signatures (SHRINCS / SHRIMPS) — Shor doesn't help here. |
| Grover | Quadratic speedup against hash preimages | Mining-economics advantage on SHA-256d PoW — quantum miner finds blocks ~√N faster than a classical one, difficulty adjusts. **Not** a forgery break. SHA-256d's 128-bit post-Grover margin is still safe for commitments. |

So: SHA-256d is fine for PoW, TxID, Merkle, address commitments. ECDSA / Schnorr is not fine for signatures — and that's the only thing qBitcoin touches existentially. Full discussion in [parameters/quantum-threat-model.md](parameters/quantum-threat-model.md).

---

## Code map (one-line each)

| Package | Purpose |
|---|---|
| `crypto/` | `Hash256` (SHA-256d), `MerkleRoot`, SipHash-2-4 (BIP-152), SHRINCS/SHRIMPS wrappers, `CheckSig` dispatcher, atomic state-file IO with CRC trailer |
| `crypto/hashsig/` | Paper primitives — WOTS-TW / WOTS+C, balanced + unbalanced XMSS, XMSS^MT, FORS, PORS+FP with Octopus, SPHINCS+ |
| `script/` | Full Bitcoin-v0.1 opcode set (hex verbatim per Satoshi `script.h`), `CScriptNum`, modern Core post-disable rules, polymorphic `OP_CHECKSIG` |
| `address/` | 2-leaf P2MR Merkle root + leaf scripts (P2PK template `<pubkey> OP_CHECKSIG`) |
| `txn/` | Tx, UTXO, sighash, sigops cost |
| `core/` | Block header, PoW, Bitcoin-exact 2016-block retarget, blockchain with reorg, undo records, orphan pool, genesis |
| `mempool/` | RBF-aware pool, `MinRelayFeeRate`, BIP-125 subset, Core-port `BlockPolicyEstimator` (estimateSmartFee) |
| `p2p/` | libp2p host, `/qbitcoin/1.0.0` protocol, Bitcoin-shaped peer / handshake / ban manager, BIP-152 compact blocks |
| `storage/` | Pebble wrapper with bucket-prefixed keys |
| `wallet/` | Multi-wallet registry (Bitcoin-Core style), AES-256-GCM at-rest encryption, BIP-32 hardened HMAC-SHA512, account / address management |
| `cmd/qbitcoind/` | Node entrypoint — chain + P2P + RPC + optional miner |
| `cmd/qbitcoin-cli/` | HTTP client mirroring `bitcoin-cli`'s UX |
| `cmd/mine-genesis/` | One-shot tool to mine the hardcoded genesis block at a given `Bits` |
| `logging/` | Module-tagged `slog` wrapper |

For why each file exists, what it imports, and what it owns, see [architecture/README.md](architecture/README.md).
