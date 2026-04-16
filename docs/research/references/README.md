# External References

Quick-link table for the documents and resources cited from elsewhere in the docs.

---

## Primary

| Title | Citation / URL |
|---|---|
| **Hash-based Signature Schemes for Bitcoin** | Mikhail Kudinov, Jonas Nick. IACR eprint 2025/2203, Revision 2025-12-05. PDF + extracted text live in `docs/research/papers/`. |
| **BlockstreamResearch/SPHINCS-Parameters** | The authors' parameter-search / cost / security sage scripts. Mirrored under `docs/research/sage/`. Upstream: `github.com/BlockstreamResearch/SPHINCS-Parameters`. |
| **MehdiAbri/PORS-FP** | Source of `octopus_pmf.py` (Theorem-3 PMF for left-filled-tree Octopus auth-set sizes). MIT-licensed. Upstream: `github.com/MehdiAbri/PORS-FP`. |

## SPHINCS+ / hash-based signature ecosystem

| Title | Citation |
|---|---|
| **SPHINCS+: Submission to the NIST post-quantum cryptography standardization process** | Bernstein et al. The original SPHINCS+ specification — paper available at `sphincs.org/data/sphincs+-specification.pdf`. |
| **NIST FIPS 205 — SLH-DSA** | The standardized form of SPHINCS+. Cited for the canonical `PK = (PK.seed, PK.root)` layout that SHRINCS / SHRIMPS inherit. |
| **NIST SP 800-208 — Stateful Hash-Based Signature Schemes (LMS, XMSS)** | Background on stateful hash-based sigs and the operational requirements for state management. |

## Bitcoin protocol references

| BIP / topic | What we use it for |
|---|---|
| **BIP-39** | Mnemonic seed encoding (24 words, PBKDF2-HMAC-SHA512). Standard. |
| **BIP-32** | Hardened derivation (HMAC-SHA512). Non-hardened *not* supported — see `docs/invariants.md` #9. |
| **BIP-44** | Path shape `m/44'/coin_type'/account'/change'`. Coin type `1'` = SLIP-44 testnet. |
| **BIP-125** | Replace-by-fee. We implement the rule-4/5/6 subset (Rule 2 / 3 skipped — no in-mempool chains, no opt-in flag → full RBF). |
| **BIP-152** | Compact blocks. Per-block SipHash-2-4 short IDs, derivation `SHA256(headerBytes || nonce_le)[0:16]`. |
| **BIP-34** (concept) | Coinbase-height-in-witness for distinct coinbase txids. We embed the height as 4 BE bytes in the coinbase input's witness. |
| **CVE-2012-2459** | Merkle-tree second-preimage via duplicate sibling. Defended in `crypto.MerkleRootMutated`. |

## Forum threads

| Thread | What's in it |
|---|---|
| **delving-bitcoin.org/t/2158** | The `(m=9, z=14)` WOTS+C variant for SHRINCS — reduces digest space at the cost of grinding. We *don't* ship it (sage-oracle compatibility), see `docs/research/sage/probe_shrincs_wotsc.sage` for the empirical sweep. |
| **delving-bitcoin.org/t/2355** | SHRIMPS construction — two SPHINCS+ (W+C P+FP) instances under `H(pk_c \|\| pk_f)`, with `n_dev = 1024` per-device cap. Source for the `q_s = 2^10` compact / `q_s = 2^40` fallback split. |

## Reference UI / documentation

| Resource | Why |
|---|---|
| **blockstream.com/quantum** | The Blockstream quantum page that publicly cites SHRINCS at "324 bytes" — this is exactly the first-signature body size our wire format produces. Cross-referenced in `docs/architecture/shrincs.md`. |

---

## How to cite the paper from inside the docs

When referring to specific sections in the docs, use the form **paper §N.M** (e.g. *paper §B.3* for the unbalanced-XMSS construction). The text-extracted form is in `docs/research/papers/eprint-2025-2203-kudinov-nick.txt`; the canonical PDF is alongside it.
