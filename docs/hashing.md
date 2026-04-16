# Hashing

qBitcoin uses **three hash families**, and mixing them up is a security bug. Each one is confined to a specific part of the codebase by import discipline — enforced socially (this doc) rather than mechanically. If you need a new hash call, check this file first.

---

## The three families

| Family | Where it runs | Why it exists |
|---|---|---|
| **SHA-256d** (`crypto.Hash256`) | Chain layer (PoW, TxID, Merkle, address commitment, script hash, storage keys) | Bitcoin-exact. This is what gives qBitcoin its Bitcoin-PoC identity. |
| **SHA-256 / SHA-512** (stdlib `crypto/sha256`, `crypto/sha512`) | Inside signature construction, confined to `crypto/hashsig/` | Paper §2 tweakable hashes (F, H, T_l, PRF) use SHA-256; paper §13.3 `H_msg` for PORS+FP needs >172 bits so it uses SHA-512. Confined. |
| **HMAC-SHA512** | Wallet-side BIP-32 derivation (`wallet/mnemonic.go`) | Standard Bitcoin BIP-32. |

SipHash-2-4 is present — but it's a MAC for BIP-152 compact-block short IDs, not a hash in the Merkle / PoW sense. It lives in `crypto/siphash.go`.

---

## Which function to use

| Use case | Function | Output | File |
|---|---|---|---|
| TxID | `crypto.Hash256(tx.Serialize())` | `[32]byte` | `txn/tx.go` |
| Merkle leaf | `crypto.Hash256(txBytes)` | `[32]byte` | `crypto/merkle.go` |
| Merkle internal node | `crypto.Hash256Concat(left, right)` | `[32]byte` | `crypto/merkle.go` |
| Address commitment | `crypto.Hash256(compact_pk \|\| fallback_pk)` | `[32]byte` | `address/p2mr.go` |
| Script / leaf hash | `crypto.Hash256(leafScript)` | `[32]byte` | `address/p2mr.go` |
| Block PoW hash / block ID / storage key | `BlockHeader.Hash() = Hash256(header.Serialize())` | `[32]byte` | `core/block.go` |
| Compact-block short ID (BIP-152) | `crypto.SipHash24(k0, k1, txid)` truncated to 6 B | `[6]byte` | `crypto/siphash.go` |
| Display block / tx hash in UI (RPC / CLI / logs) | `crypto.DisplayHex(h)` — reverses byte order per Bitcoin convention | `string` | `crypto/hash.go` |
| Wallet key derivation | `wallet.DeriveHardened(parent, i)` — BIP-32 HMAC-SHA512 | `ExtKey` | `wallet/mnemonic.go` |

---

## Import discipline

Package names below are Go standard library unless noted.

### `crypto/sha256`

Allowed only in:

- `qbitcoin/crypto/hash.go` (the `Hash256` primitive itself — SHA-256d is defined as two SHA-256 invocations)
- `qbitcoin/crypto/siphash.go` (not actually sha256, but the BIP-152 per-block key derivation in this file calls `sha256.Sum256(headerBytes || nonce_le)[0:16]`)
- `qbitcoin/crypto/shrincs.go`, `qbitcoin/crypto/shrimps.go` (they're the wrappers around `hashsig/`)
- Any file under `qbitcoin/crypto/hashsig/` (paper primitives)

### `crypto/sha512`

Allowed only in:

- Files under `qbitcoin/crypto/hashsig/` — for `H_msg` in PORS+FP (paper §13.3)
- `qbitcoin/wallet/mnemonic.go` — for BIP-32 HMAC-SHA512 (standard Bitcoin)

### Chain-layer code in general

Must go through `qbitcoin/crypto.Hash256`. Don't call `sha256.Sum256` directly from `core/`, `txn/`, `mempool/`, `p2p/`, etc. — always via `crypto.Hash256`. This keeps the "chain layer is SHA-256d" invariant grep-able.

---

## Why SHA-256 inside signatures is fine even though chain PoW is SHA-256d

A reasonable question: if the chain is SHA-256d (double SHA-256), and the signature construction is SHA-256 (single), doesn't that mean a quantum attacker with Grover could attack signatures faster than the chain?

Short answer: no — because the signature's security comes from SHA-256's **second-preimage resistance**, not from the cost of inverting it. Grover offers a quadratic speedup on preimage search, which pins second-preimage at ~2^(n/2) quantum work. For the SHRINCS/SHRIMPS parameter sets we ship (n = 16 bytes = 128 bits), that's ~2^64 queries *asymptotic* — but paper §12.2 demonstrates that the real Toffoli-circuit cost for a single SHA-256 Grover iteration pushes the "effective" security up to ~2^78 quantum ops. And Grover doesn't parallelize linearly (paper §12.3): k machines get only √k wall-clock improvement.

All of that is already accounted for in the paper's choice of NIST L1 (λ = 128 bits, n = 16 B). If you're interested in the full argument, read [parameters/quantum-threat-model.md](parameters/quantum-threat-model.md) and paper §12.
