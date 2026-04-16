# Design Invariants

These rules must hold everywhere in the codebase. Never violate them, even if a deviation seems convenient.

---

## 1. Chain layer is SHA-256d, exactly like Bitcoin

All chain-level hashing goes through `crypto.Hash256` (double SHA-256). Signature-internal SHA-256 / SHA-512 is confined to `crypto/hashsig/` (per the paper). The wallet uses HMAC-SHA512 for BIP-32 derivation.

See [hashing.md](hashing.md) for the full import-discipline matrix.

## 2. Block PoW validity

`SHA-256d(header) < target`, full 32-byte comparison. The header is 88 bytes (Bitcoin's 80, extended to fit larger Timestamp + Nonce). Little-endian on integer fields, exactly as Bitcoin.

## 3. Persist-before-sign

The incremented counter MUST be written to disk atomically (write-then-rename) BEFORE computing the signature.

```
CORRECT:  persist(counter+1)  →  sign(message, counter)  →  return sig
WRONG:    sign(message, counter)  →  persist(counter+1)  →  return sig
```

- Crash between persist and sign  →  one wasted slot (acceptable).
- Crash between sign and persist  →  slot reused on restart (catastrophic key compromise).

This order is non-negotiable. Enforced in both `crypto/shrincs.go` and `crypto/shrimps.go`. See [operations/persist-before-sign.md](operations/persist-before-sign.md) for the StateIO + CRC + GCM stack that backs it.

## 4. SHRINCS auto-falls-back internally under paper §B.3's min-rule

`ShrincsKey.Sign()` emits a stateful UXMSS sig whenever it would be **strictly smaller** than the fallback SPHINCS+ sig — otherwise it falls back to stateless, even if UXMSS slots remain. This makes stateful and stateless sizes range-disjoint, which is what lets the verifier dispatch by length alone (no tag byte on the wire).

Callers see a signature either way — no `ErrCounterExhausted` reaches the wallet layer from SHRINCS. SHRIMPS does still return `ErrCounterExhausted` if both its sub-instances' accounting budgets are spent, but that's unreachable in practice at the budgets we ship (1024 compact + 1024 fallback).

See [architecture/shrincs.md](architecture/shrincs.md) for the wire format and the min-rule's range-disjointness proof sketch.

## 5. P2MR addresses are exactly 32 bytes on-chain

The address bytes are the Merkle root over two leaves. No public keys, no scripts, nothing else in the output script. This is what gives qBitcoin the same on-chain footprint as a Bitcoin Taproot output (32 bytes) while committing to a PQ pubkey set instead of an x-only Schnorr key.

See [architecture/address.md](architecture/address.md).

## 6. Serialization matches Bitcoin layout conventions

- **Block header**: little-endian integer fields (Version, Timestamp, Bits, Nonce). Wire-compatible with Bitcoin's 80-byte header shape, extended to 88 B for larger Timestamp / Nonce.
- **Other structs** (tx, UTXO, compact-block, peer record, …): big-endian length-prefixed fields internally.
- **Researcher-facing chain primitives** (header, block hash, txid display): Bitcoin-exact. Hashes are displayed reversed-byte-order via `crypto.DisplayHex`.

## 7. TxID = `Hash256(tx.Serialize())`

SHA-256d over the full serialization, with witness data included. **No segwit-style txid / wtxid distinction** — PQ sigs are deterministic (PRF-based) so there's no malleability for segwit to fix. See [overview.md](overview.md) under "Forced deviations from Bitcoin" §3.

## 8. No on-chain rotation protocol

Out of scope. Paper §14 ("Hierarchical Deterministic Wallets") specifies a wallet-side key-pool model: precompute many pubkeys from the mnemonic, hand out fresh ones as needed.

Access to old funds is preserved via SHRINCS' internal stateful → stateless fallback (invariant #4). Users who want fresh receive addresses call `Wallet.NewReceiveAddress()`, which advances the account index. No consensus code runs for rotation; a new address is just a new account.

## 9. Wallet key derivation is Bitcoin BIP-32 (hardened subset)

BIP-39 mnemonic → PBKDF2-HMAC-SHA512 seed → BIP-32 HMAC-SHA512 derivation tree. Path shape: `m/44'/1'/N'/0'` (SHRINCS seed for account N) and `m/44'/1'/N'/1'` (SHRIMPS seed). Every level hardened — non-hardened would need EC point addition.

Public API: `wallet.MasterKey`, `wallet.DeriveHardened`, `wallet.DeriveAccountKeys`. Coin type is SLIP-44 `1'` (testnet) — signals this is a research PoC, not mainnet Bitcoin.

See [architecture/wallet.md](architecture/wallet.md).

## 10. SHRINCS UXMSS tree height is a consensus constant

`crypto.ShrincsTreeHeight = 8` (`NumLeaves = 256`). The UXMSS spine-hash ADRS encodes `NumLeaves - 1 - spineIdx`, so signer and verifier must agree on `NumLeaves` to produce the same root commitment. Fixing it globally is what removes `tree_height` from the wire format and keeps the stateful sig at exactly **324 B**.

The choice of 8 tracks the useful-slot window under the paper's min-rule with the canonical stateless fallback (`spsig + 32 ≈ 4068 B`, crossover at q ≈ 234 < 256).

See [architecture/shrincs.md](architecture/shrincs.md) for the size derivation.

## 11. Wallet creation is explicit; encryption is opt-in, Bitcoin Core-style

`qbitcoind` never auto-creates a wallet. Starting with zero wallets is the clean default; multiple wallets can coexist under `<datadir>/wallets/<name>/` routed via `-rpcwallet=<name>`.

- `qbitcoin-cli createwallet <name>` (→ `POST /wallet/create`) is the only way to materialize a wallet.
- The passphrase prompt accepts an empty passphrase to create a plaintext wallet (with explicit `y/N` confirmation).
- Non-empty passphrase engages **AES-256-GCM at-rest encryption** under a PBKDF2-HMAC-SHA512-derived KEK (200k iterations, 16 B salt).
- `encryptwallet <name>` upgrades a plaintext wallet in place (one-way, matches Bitcoin Core's no-`decryptwallet` policy).
- Encryption mode and KDF parameters of each wallet are recorded in its `wallet.meta` descriptor.
- Wallets in `<datadir>/wallets.autoload` are re-loaded on node boot — encrypted ones come up locked (`POST /wallet/passphrase` unlocks for a timed window).

See [architecture/wallet.md](architecture/wallet.md).

## 12. Persist-before-sign applies through the Store boundary

SHRINCS / SHRIMPS state files route through `crypto.StateIO`, implemented by `wallet.storeStateIO` for wallet-owned keys.

The "persist" point is `StateIO.Write`. For encrypted wallets that means the ciphertext has been fsynced to disk under a new GCM nonce **before** the signature is computed.

The CRC wrap (`crypto.AppendCRC` / `StripAndVerifyCRC`) is applied to the plaintext body **before** GCM, so a bit flip between decrypt-in-memory and signing is still caught — in addition to GCM's ciphertext-tamper detection.

See [operations/persist-before-sign.md](operations/persist-before-sign.md).
