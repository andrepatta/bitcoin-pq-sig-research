# Parameters

Where the magic numbers come from. Every constant in `crypto/shrincs.go`, `crypto/shrimps.go`, and the SPHINCS+ instances they wrap is grounded in a row of paper §13's Table 1 — and **the sage scripts in [`docs/research/sage/`](../research/sage/) are the authoritative oracle for every one of them**. If you ever doubt a number, the right move is `sage costs.sage --params <scheme> <q_s> <k> <a> <h> <d> <w> <S>` from that directory.

This page is the index. Two deep dives:

- [signature-sizes.md](signature-sizes.md) — paper-oracle vs our `SigSize()` vs on-wire byte counts, layered breakdown.
- [quantum-threat-model.md](quantum-threat-model.md) — Shor (broken signatures) vs Grover (mining-economics impact only).

---

## The locked parameters at a glance

NIST L1 throughout (λ = 128 bits, n = 16 B). All signature constructions use SHA-256 inside (paper §2 tweakable hashes) and SHA-512 for `H_msg` in PORS+FP (paper §13.3).

| Context | Scheme | n | w | S_{w,n} | ℓ | h | d | k | a | q_s | Ref |
|---|---|---|---|---|---|---|---|---|---|---|---|
| SHRINCS stateful OTS (per leaf) | WOTS+C | 16 | 16 | 135 | 18 | — | — | — | — | — | `shrincsWOTSPlusC()` in `crypto/shrincs.go` |
| SHRINCS UXMSS spine | unbalanced XMSS | — | — | — | — | 8 | — | — | — | 256 | `crypto.ShrincsTreeHeight` |
| SHRINCS stateless fallback | SPHINCS+ W+C P+FP | 16 | 256 | 2040 | 16 | 40 | 5 | 11 | 14 | 2^40 | paper §13.3 Table 1 (bold) |
| SHRIMPS compact | SPHINCS+ W+C P+FP | 16 | 16 | 240 | 32 | 12 | 1 | 8 | 17 | 2^10 | delving 2355 canonical row |
| SHRIMPS fallback | SPHINCS+ W+C P+FP | 16 | 256 | 2040 | 16 | 40 | 5 | 11 | 14 | 2^40 | paper §13.3 Table 1 (bold) |

`m_max` (Octopus auth-set bound) is 105 for SHRIMPS compact, 118 for SHRIMPS fallback. Both pinned via `costs.sage`.

---

## Reproducing every pin

```sh
cd docs/research/sage

# SHRINCS stateless fallback (= SHRIMPS fallback): security 128 bits, sig 4036 B
sage costs.sage --params W+C_P+FP 40 11 14 40 5 256 2040

# SHRIMPS compact: security 128 bits, sig 2548 B
sage costs.sage --params W+C_P+FP 10 8 17 12 1 16 240

# SHRINCS WOTS+C target-sum search at (l=18, w=16):
sage probe_shrincs_wotsc.sage

# Full table (matches paper §13.3 Table 1):
sage costs.sage --table
```

Output of `costs.sage --table` is a CSV the [`signature-sizes.md`](signature-sizes.md) doc cross-references row-for-row.

---

## Counter bit widths

| Where | Bits | Why |
|---|---|---|
| WOTS+C SHRINCS OTS | 32 | Expected `1/p_ν ≈ 2^24`; 32-bit counter gives ≥8-bit safety margin per paper §5.1. |
| SPHINCS+ compact `H_msg` grind | 32 | PORS+FP `m_max`-grinding cost well within 32 bits. |
| SPHINCS+ fallback `H_msg` grind | 32 | Same rationale. |

---

## Hash-to-subset bit-extraction

`pors.go::HashToSubset` reads the 64-byte SHA-512 `H_msg` output as a 512-bit integer, **big-endian**:

1. Top h bits → τ (hypertree leaf index).
2. Subsequent ⌈log₂ t⌉-bit blocks read from most-significant remaining bits.

Documented because two implementations that differ on bit order produce incompatible signatures even though both are individually paper-faithful.

---

## Per-signature randomness

Per paper §11 / sage `randomness_size = 32`: R = 2n = 32 B for both SHRIMPS instances and the SHRINCS stateless fallback. Without the wide R, multi-target attack distinguishability becomes a concern at NIST L1.

---

## Independence of SHRINCS-fallback and SHRIMPS-fallback seeds

Each scheme derives its own SPHINCS+ fallback key from a domain-separated sub-seed:

- SHRINCS: `Hash256(seed || "qbitcoin-shrincs-fallback-seed")`
- SHRIMPS: `Hash256(seed || "qbitcoin-shrimps-fallback-seed")`

They are **not** shared. Sharing would create cross-scheme observability (a signature on the SHRINCS fallback path could reveal material that might be reused by SHRIMPS). The 4 KB extra keygen cost at wallet creation is negligible.
