# Signature sizes

Three layers, three byte-counts per signature. This page lays out the layered breakdown so the gap between "paper says X bytes" and "Go test reports Y bytes" is unambiguous.

| Layer | What it counts |
|---|---|
| **Paper oracle** | `compute_size` from `docs/research/sage/costs.sage`. Excludes the PORS+FP grind salt. |
| **Our `SPHINCSParams.SigSize()`** | The `crypto/hashsig/` SPHINCS+ output. Includes the 4-byte grind salt. |
| **On-wire (with wallet wrapper)** | What hits the consensus stream — adds the SHRINCS / SHRIMPS framing (counter + sibling roots + length prefixes) and the 1-byte scheme tag. |

---

## 1. Headline numbers

All numbers at NIST L1 (n = 16 B). SHRIMPS uses paper §13.3 Table 1's bold rows; SHRINCS stateful uses paper §B.3.

| Scheme | Paper oracle | Our `SigSize()` | Wallet on-wire (consensus) |
|---|---|---|---|
| Schnorr (Bitcoin reference) | 64 B | — | — |
| SLH-DSA (NIST) | 7856 B | — | — |
| **SHRINCS stateful (q=1)** | 324 B | — | **324 B body, 340 B with 16 B sibling, 352 B with outer frame** |
| SHRINCS stateful (q-th sig) | `308 + (q+1)·16 B` | — | + 12 B outer frame |
| SHRINCS stateless fallback | 4036 B | 4040 B | 4080 B |
| **SHRIMPS compact** | 2548 B | 2552 B | **2646 B** |
| SHRIMPS fallback | 4036 B | 4040 B | 4134 B |

The consensus-level scheme tag (`crypto.SchemeShrincs = 0x00` or `crypto.SchemeShrimps = 0x01`) is **outside** the body — adds 1 byte when the sig is pushed onto the script stack. The "on-wire" numbers above are body-only; add 1 B for the tag at script-execute time.

---

## 2. Why our `SigSize()` is paper-oracle + 4

The Blockstream `compute_size` accounts for everything in the SPHINCS+ signature **except** the PORS+FP grind salt `s`. Paper §10 Algorithm 1 returns `(s, τ, indices)`; the salt is structurally required for τ-fixed inner grinding (you can't reproduce the index set on the verifier side without knowing which salt was used), but sage's size formula treats the verifier as having `s` "for free".

Our `SPHINCSParams.SigSize()` includes it. So:

```
SHRIMPS compact:    2548 (sage) + 4 (salt) = 2552 (ours)
SHRIMPS fallback:   4036 (sage) + 4 (salt) = 4040 (ours)
```

Cross-checked by `crypto/hashsig/paper_kat_test.go` against `crypto/hashsig/testdata/paper_kat.json` (which is itself emitted by `dump_katfixtures.sage` from the upstream sage code).

---

## 3. Wallet wrapper overhead (SHRIMPS)

Per signature, SHRIMPS adds:

```
[ outer scheme tag                ]   1 B (0x01 for SHRIMPS — outside the body)
[ counter_BE uint64               ]   8 B
[ uses_fallback flag              ]   1 B
[ inner instance tag              ]   1 B (0x00 = compact, 0x01 = fallback — inside the body)
[ length-prefixed sphincs_sig     ]   2552 or 4040 B + 4 B length prefix
[ length-prefixed sibling_pk_root ]    16 B + 4 B length prefix
                                    ─────
total wrapper                          ≈ 41 B
total compact on-wire                   2552 + 41 = 2593 B + tag = 2594 B body, with framing 2646 B
total fallback on-wire                  4040 + 41 = 4081 B + tag = 4082 B body, with framing 4134 B
```

The "tag byte at script-execute time" is the one byte the script interpreter consumes via `crypto.DefaultSigChecker.CheckSig` to dispatch SHRINCS vs SHRIMPS — see [`../architecture/script.md`](../architecture/script.md) §6.

---

## 4. Wallet wrapper overhead (SHRINCS)

Stateful path:

```
[ scheme tag                  ]   1 B  (0x00, outside the body)
[ counter_BE uint64           ]   8 B  (q for stateful)
[ body length BE uint32       ]   4 B
[ body                        ]   N B  (308 + (q+1)·16 — see shrincs.md)
                               ─────
total                              13 + 308 + (q+1)·16
```

For q=1: `13 + 308 + 32 = 353 B` on-wire (or 352 B if the scheme tag is counted as script-stack overhead, not sig overhead — the row in §1 above uses the latter convention).

Stateless path:

```
[ scheme tag                  ]   1 B
[ counter_BE = MaxUint64      ]   8 B  (sentinel for stateless)
[ body length BE uint32       ]   4 B
[ body                        ]   sp.SigSize() + 32 = 4068 B
                               ─────
total                              4081 B
```

(The stateless body's `+ 32` is the active 16 B PK.root + the sibling 16 B PK.root — see [`../architecture/shrincs.md`](../architecture/shrincs.md) §3.)

---

## 5. SHRINCS stateful curve (with min-rule cutoff)

Body bytes (excluding outer 12 B frame):

| q | Stateful body | Stateless body | Min-rule pick |
|---|---|---|---|
| 1   | 340 B  | 4068 B | stateful |
| 8   | 452 B  | 4068 B | stateful |
| 32  | 836 B  | 4068 B | stateful |
| 128 | 2372 B | 4068 B | stateful |
| 200 | 3524 B | 4068 B | stateful |
| 234 | 4068 B | 4068 B | first q where they're equal |
| 235 | 4084 B | 4068 B | stateless (min-rule flips here) |
| 256 | (UXMSS exhausted) | 4068 B | stateless |

With `crypto.ShrincsTreeHeight = 8` (`NumLeaves = 256`), the practical stateful window is q = 0..234. After that every signature is stateless (constant 4068 B body).

This is the "324 B → ~4 KB jump" the wallet exposes via `SlotHealth()` so UIs can warn before it happens.

---

## 6. Block-budget impact

A back-of-envelope for a max-size block:

| Tx mix | Avg sig bytes / input | Inputs / block (approx) |
|---|---|---|
| All SHRINCS at q=1 | 352 | ~2,500 |
| All SHRINCS at q=200 | 3,536 | ~250 |
| All SHRINCS stateless (q≥235) | 4,081 | ~220 |
| All SHRIMPS compact | 2,646 | ~340 |
| All SHRIMPS fallback | 4,134 | ~217 |

(Block-bytes budget = `MaxBlockSize ≈ 900 KB` after coinbase + headers.)

These rough capacity figures are why `MinRelayFeeRate = 1 sat/B` is a different economic point than Bitcoin's: per-tx absolute fees are higher because tx bytes are higher. See [`../architecture/mempool.md`](../architecture/mempool.md) §3 for the relay-fee policy that follows from this.
