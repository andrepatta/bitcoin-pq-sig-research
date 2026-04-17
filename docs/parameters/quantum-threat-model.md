# Quantum threat model

The load-bearing PQ defense in qBitcoin is the **signature scheme**, not the hash function. This page explains why — and what changes (if anything) about Bitcoin-shape PoW under a future cryptanalytically-relevant quantum computer (CRQC).

---

## 1. Two algorithms, two completely different impacts

| Algorithm | What it does | Impact on Bitcoin / qBitcoin |
|---|---|---|
| **Shor's** | Polynomial-time discrete log on elliptic curves | Existentially forges every ECDSA / Schnorr signature on every classical-sig blockchain. **Game over** for ECDSA-based signing. Doesn't help against hash-based signatures. |
| **Grover's** | Quadratic speedup on unstructured search (preimages) | √N speedup on hash preimage / second-preimage finding. Mining-economics advantage on PoW; **no forgery break** anywhere. |

That asymmetry is the whole reason qBitcoin swaps signatures (existential break) but **not** hashes (mining-economics shift).

---

## 2. Why Shor breaks ECDSA / Schnorr

Both Bitcoin's signature schemes derive security from the hardness of the **elliptic-curve discrete logarithm problem (ECDLP)** on secp256k1: given `Q = k·G`, recover `k`. Classically infeasible at 128-bit security (~2^128 group operations).

Shor's algorithm solves the discrete logarithm in polynomial time on a sufficiently capable quantum computer. A successful CRQC attacker who can read on-chain pubkeys — including reused addresses, unspent outputs that re-expose pubkeys, and any address type that places the pubkey on-chain pre-spend — can recover the corresponding private key and sign anything.

Hash-based signatures (SHRINCS / SHRIMPS) don't have a discrete-log structure. They derive security from preimage / second-preimage / collision resistance of the underlying hash, which Shor doesn't attack.

That's the load-bearing reason qBitcoin exists.

---

## 3. Why Grover doesn't break SHA-256d PoW (or anything else here)

Grover gives a quadratic speedup on unstructured search: finding a preimage of a 256-bit hash takes ~2^128 quantum queries, vs ~2^256 classical. For Bitcoin-shape PoW (`SHA-256d(header) < target`), that means:

### A quantum miner finds blocks ~√N faster

If the network's classical hashrate is N H/s, a quantum miner with the same wall-clock budget can produce **valid PoW** at an effective rate of ~√N. So the network sees a single quantum miner as if it had √N classical hashrate. Bitcoin's difficulty-adjustment algorithm (`core.ComputeNextWorkRequired`, the 2016-block retarget) adjusts to keep the average block time at 600 s.

**This is a mining-economics issue, not a forgery break.** No one forges a block from thin air, rewrites history faster than honest hashrate, or derives a preimage in feasible time. The chain still requires real PoW work; the work is just √N cheaper for whoever has the quantum machine.

### Grover doesn't parallelize linearly (paper §12.3)

Two quantum machines don't get 2× speedup — they get √2 × ≈ 1.41×. k machines get √k × wall-clock improvement. So the "10000 quantum miners" doomsday case doesn't multiply 10000× — it multiplies 100×. Difficulty still adjusts in lockstep.

### SHA-256d's post-Grover margin on commitments is 128 bits

Second-preimage on SHA-256d under Grover: ~2^128 quantum queries. Asymptotically infeasible — even a billion-qubit machine running for the heat-death of the universe doesn't get there. Real Toffoli-circuit cost (paper §12.2 analysis of the best-known SHA-256 circuit implementations) pushes the effective per-query cost up by a constant factor of ~2^14 at NIST L1, so the practical security margin is more like 2^142.

Translation: TxIDs, Merkle roots, address commitments, and storage keys are all safe under any plausible quantum threat model. SHA-256d at the chain layer needs no defensive change.

---

## 4. NIST L1 — paper §12.4

The paper's recommendation for Bitcoin is **NIST L1**: ≥ 128-bit classical security, ≥ ~2^64 query asymptotic quantum security, ≥ ~2^78 quantum operations real-world security. We pin n = 16 B (128 bits) and adopt the parameter-set bold rows from paper Table 1 at this security level.

Higher security levels (NIST L3 = 192 bits, L5 = 256 bits) exist in the paper's parameter tables but cost ~3× to ~10× the signature size for negligible practical security gain at qBitcoin's threat model. Not worth the bytes.

---

## 5. Per-primitive summary

| Primitive | Purpose | Classical security | Post-quantum reality |
|---|---|---|---|
| SHA-256d | PoW, TxID, Merkle, address commit | 256-bit | ~128-bit (Grover). Mining-economics impact only — difficulty adjusts. |
| SHRINCS / SHRIMPS | Signatures | — | Existentially unforgeable under Shor (hash-based). |
| ECDSA / Schnorr | (not used here) | 128-bit | **Broken** by Shor. |
| HMAC-SHA512 (BIP-32) | Wallet derivation | 256-bit | ~128-bit (Grover preimage). Same situation as SHA-256d — fine. |

---

## 6. What the chain *does not* defend against

The transport layer is plain TCP with **no encryption and no peer-identity authentication** — Bitcoin Core's native shape. See [`../architecture/p2p.md`](../architecture/p2p.md) §2 for details. Practical implications:

- **No transport confidentiality, classical or quantum.** Anyone on the wire can read gossip traffic today. There is nothing for a future CRQC adversary to decrypt that they couldn't already read. We trade transport secrecy for protocol simplicity and Bitcoin parity.
- **No peer-identity unforgeability.** Nodes are identified by `ip:port`, not by a cryptographic key. An attacker on-path can pretend to be any peer. They still cannot forge blocks or transactions — those are PQ-signed at the chain layer.

Neither weakness touches consensus. The PQ defense in this project is the signature scheme, deliberately not the transport.
