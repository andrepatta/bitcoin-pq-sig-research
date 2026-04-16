# Sage scripts

This directory holds the **authoritative parameter / cost / security oracles** for SHRINCS and SHRIMPS. Everything here is one of:

- A verbatim copy of a script from [BlockstreamResearch/SPHINCS-Parameters](https://github.com/BlockstreamResearch/SPHINCS-Parameters) — the parameter-search code that accompanies Kudinov & Nick (eprint 2025/2203).
- A small extension we wrote (`run_compact.sage`, `run_fallback.sage`, `probe_shrincs_wotsc.sage`, `probe_expwork.sage`, `dump_katfixtures.sage`) to query the upstream functions for the specific qBitcoin parameter sets and to emit the JSON KAT fixtures consumed by `crypto/hashsig/paper_kat_test.go`.

The whole directory is build-time-only. Normal `go build` does not run sage; you only need it if you want to regenerate fixtures or verify a parameter pin.

---

## File map

### Upstream (BlockstreamResearch/SPHINCS-Parameters)

| File | What it computes |
|---|---|
| `security.sage` | Classical bits-of-security for FORS / PORS+FP given (q_s, h, k, a). Sums over the binomial distribution of how many signatures hit any given hypertree leaf. |
| `costs.sage` | Signature size, signing-time, and verification-time in compression-function calls for SPX / W+C / W+C_F+C / W+C_P+FP variants. The full Table 1 reproduction. |
| `octopus_pmf.py` | PMF of the Octopus authentication-set size for left-filled trees (Theorem 3 of the PORS+FP paper). Used by `costs.sage` to look up `mmax` → expected grind work. |
| `original-sphincs-parameter-search.sage` | The original SPHINCS+ submission's parameter search script, updated for SageMath 9.0. Reference oracle for cross-checking the modern `costs.sage` against the SPHINCS+ submission's published numbers. |

### qBitcoin-specific extensions

| File | What it does |
|---|---|
| `dump_katfixtures.sage` | Emits `crypto/hashsig/testdata/paper_kat.json` — the KAT fixture file that `crypto/hashsig/paper_kat_test.go` cross-checks against `SPHINCSParams.SigSize()`. Two parameter sets: `shrimps_compact` (W+C P+FP, q_s=2^10) and `shrimps_fallback` (W+C P+FP, q_s=2^40). |
| `run_compact.sage` | Prints the full `compute_single` summary for the SHRIMPS compact instance: `(W+C_P+FP, q_s=2^10, h=12, d=1, a=17, k=8, w=16, S_wn=240)`. |
| `run_fallback.sage` | Prints `compute_single` for the SHRIMPS fallback instance — the **paper's bold row** `(h=40, d=5, a=14, k=11, w=256, S_wn=2040)` plus an alternate non-bold row `(h=44, d=4, a=16, k=8, w=16, S_wn=240)` for comparison. |
| `probe_shrincs_wotsc.sage` | Sweeps the WOTS+C target sum `S` from 0 to `l*(w-1)=270` at `(l=18, w=16)`, looking for an `S` where `1/p_ν` (expected counter trials) lands near 2^32. The probe demonstrates why an `(l=18, S=135)` alternative looked attractive on paper and why we still chose the canonical `(l=32, S=240)` for sage-fidelity. |
| `probe_expwork.sage` | Prints `log2(exp_work)` for the two PORS+FP grind targets: compact `(t=2^20, k=8, mmax=105)` and fallback `(t=11·2^14=180224, k=11, mmax=118)`. Cross-checks the implementation's grind budget. |

---

## Quick reproduction

All commands assume `cd docs/research/sage`.

```sh
# Regenerate the fixture file consumed by Go tests
sage dump_katfixtures.sage

# Inspect a single parameter set with full output
sage costs.sage --params W+C_P+FP 10 8 17 12 1 16 240
# Output:
#   Scheme:     W+C_P+FP
#   q_s:        2^10
#   (k,a,H,d):  (8, 17, 12, 1)
#   w:          16
#   S_wn:       240
#   l:          32
#   mmax:       105
#   Security:   128.0 bits
#   Size:       2548 bytes
#   Sign(C):    6.8M
#   Verify(C):  494
#   C/byte:     0.19

# Full Table 1 reproduction
sage costs.sage --table

# CSV output (machine-friendly)
sage costs.sage > params_table.csv
```

---

## Why `compute_size` ≠ our `SigSize()` by exactly +4 bytes

The Blockstream `compute_size` accounts for everything in the SPHINCS+ signature *except* the PORS+FP grind salt `s`. Paper §10 Algorithm 1 returns `(s, τ, indices)`; the salt is structurally required for τ-fixed inner grinding (you can't reproduce the index set on the verifier side without knowing which salt was used), but sage's size formula treats the verifier as having `s` "for free".

Our `SPHINCSParams.SigSize()` includes the salt (4 bytes for the W+C_P+FP variants we ship). So:

```
sage compute_size(...)          == 2548   bytes  (SHRIMPS compact)
ours  SPHINCSParams.SigSize()   == 2552   bytes  (= 2548 + 4)
```

This is a **deliberate**, documented difference, not a bug. The wallet wrapper adds another framing overhead on top — see `parameters/signature-sizes.md` for the full layered breakdown.

---

## Source

The upstream scripts are mirrored from [github.com/BlockstreamResearch/SPHINCS-Parameters](https://github.com/BlockstreamResearch/SPHINCS-Parameters), MIT/CC-BY licensed (per the upstream repo). They accompany Kudinov & Nick (eprint 2025/2203). `octopus_pmf.py` is from [github.com/MehdiAbri/PORS-FP](https://github.com/MehdiAbri/PORS-FP) (MIT-licensed, see the SPDX line at the top of the file).
