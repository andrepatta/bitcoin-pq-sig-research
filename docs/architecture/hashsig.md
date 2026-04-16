# `crypto/hashsig/` — paper primitives

This is the **only** package in the codebase that implements the Kudinov–Nick paper directly. Everything above it (SHRINCS, SHRIMPS, the chain layer) is wrappers and wiring; everything below is just stdlib `crypto/sha256` and `crypto/sha512`.

The package is structured one file per paper section, in dependency order. Reading top-to-bottom mirrors the paper's progression from the OTS primitives up to full SPHINCS+.

---

## File map

| File | Paper section | What's in it |
|---|---|---|
| `adrs.go` | §2 (ADRS structure) | 32-byte tweakable-hash address: layer + tree index + key-pair index + chain index + hash-within-chain + 1-byte type tag (WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF). |
| `thash.go` | §2 (Definition 2.3) | Tweakable hash family `Th(P, T, m)` — implementations of F (single-block), H (two-block), `T_l` (variable arity), PRF, PRF_msg, H_msg. SHA-256 for the small-output variants; SHA-512 for the wide-output `H_msg` per §13.3. |
| `wots.go` | §4 (WOTS-TW) and §5 (WOTS+C) | Both Winternitz variants. WOTS+C replaces the classical checksum chains with a counter that the signer grinds until the digest's base-w digits sum to a fixed `S_{w,n}`. |
| `xmss.go` | §7 | Balanced XMSS — fixed-height Merkle tree of WOTS public keys. |
| `unbalanced_xmss.go` | §B.3 | Unbalanced XMSS for SHRINCS' stateful path: leaves at strictly increasing depths, auth path for leaf q has q sibling hashes. The spine-hash ADRS encodes `NumLeaves - 1 - spineIdx`, which is why the consensus constant `crypto.ShrincsTreeHeight = 8` (`NumLeaves = 256`) must agree across signer and verifier. |
| `hypertree.go` | §8 | XMSS^MT — a multi-level hypertree of XMSS instances. Used by the SPHINCS+ stateless path inside SHRIMPS. |
| `fors.go` | §9 (FORS) and §9.2 (FORS+C) | Forest of Random Subsets + the FORS+C variant that grinds to omit the last tree. |
| `pors.go` | §10 (PORS+FP), §C (Octopus) | The few-time signature with full positional binding that SHRIMPS' compact and fallback instances both use. Includes `HashToSubset` (§10 Algorithm 1) and the Octopus auth-set algorithm (§C Algorithm 2). Supports unbalanced trees (left-filled) for the fallback's `t = 11·2^14` non-power-of-2 leaf count. |
| `sphincs.go` | §11 | The full SPHINCS+ construction parameterized on `(n, h, d, k, a, w, q_s)`. Both SHRIMPS instances (compact + fallback) and the SHRINCS stateless fallback use this. |
| `parallel.go` | — | Goroutine-pool helpers used by keygen / treegen for the deeper hypertrees (no semantic effect, just speedup). |

---

## Key types

The paper uses Greek-letter names; the Go types use descriptive names. Translation:

| Paper | Type |
|---|---|
| `WOTS-TW` signature | `WOTSSignature` (in `wots.go`, no checksum chains for WOTS+C) |
| `WOTS+C` signature | `WOTSSignature` + `Count uint32` (the grind counter) |
| XMSS auth path | `[][16]byte` (or `[Hash]`, with `Hash = [16]byte` at NIST L1) |
| `XMSS^MT` signature | `HypertreeSignature` |
| FORS / FORS+C signature | `FORSSignature` |
| PORS+FP signature | `PORSSignature` (includes the grind salt `s`, the τ index, the k revealed leaves, and the Octopus auth set padded to `mmax`) |
| SPHINCS+ signature | `SPHINCSSignature` (R + count + PORS+FP sig + d × (WOTS+C sig + auth path)) |
| Public params (`P`) | `Params.PKSeed` (16 B at NIST L1) |
| ADRS | `ADRS` struct (32 B, see §2) |

`Params` is the central knob: `(n, h, d, k, a, w, S_wn)` plus a few derived values like `l = compute_wots_l(scheme, w)` and `mmax`.

---

## Tweakable hashes (§2)

The paper's `Th(P, T, m)` is implemented as plain SHA-256 with domain separation in the tweak `T`:

```go
// F: single-block input.
//   T = ADRS (32 B), m = 1×n B.
//   F(P,T,m) = SHA256(P || T || m)[:n]
func F(P, T []byte, m [16]byte) [16]byte

// H: two-block input.
//   T = ADRS, m = 2×n B.
//   H(P,T,m1,m2) = SHA256(P || T || m1 || m2)[:n]
func H(P, T []byte, m1, m2 [16]byte) [16]byte

// T_l: variable-arity input — used to compress (l > 2) hashes into one.
//   T = ADRS encoding the arity, m = l×n B concatenated.
//   T_l(P,T,m) = SHA256(P || T || m)[:n]
func TL(P, T []byte, ms [][16]byte) [16]byte

// PRF: secret-key derivation.
//   PRF(seed, T) = SHA256(seed || T)[:n]
func PRF(seed []byte, T []byte) [16]byte

// PRFmsg: per-signature randomness R.
//   Returns 2n bytes (paper §11) — wider than the others.
func PRFmsg(seed, opt, m []byte) [32]byte

// Hmsg: hash-to-subset for PORS+FP.
//   Returns SHA-512 output (64 B), per paper §13.3 — needed because
//   compact SHRIMPS requires n > h + k·⌈log2 t⌉ = 12 + 8·20 = 172 bits,
//   above SHA-256's 128-bit n.
func Hmsg(R, PKSeed, PKRoot, opt, m []byte) [64]byte
```

The two SHA families inside `crypto/hashsig/` are not interchangeable. SHA-256 is the tweakable-hash workhorse; SHA-512 appears **only** in `Hmsg` for PORS+FP. The split is per paper, not a design choice we can revise.

---

## WOTS+C (§5)

Standard Winternitz with one-way chains, but the message expansion replaces the classical checksum digits with a **target sum** `S_{w,n}`. The signer grinds a counter until the digest's base-w digits sum to exactly `S_{w,n}`; the verifier checks the sum during verification.

```
Sign(sk, m):
    for count := 0; count < 2^r; count++:
        d := Th(P, T*_ADRS, m || count)             // hash-to-digits
        a_1, ..., a_l := base-w digits of d
        if sum(a_i) == S_{w,n} and last z digits all zero:
            sigma_i := chain(sk_i, 0 → a_i)
            return (sigma_1, ..., sigma_l, count)

Verify(pk, m, sigma, count):
    d := Th(P, T*_ADRS, m || count)
    a_1, ..., a_l := base-w digits of d
    require sum(a_i) == S_{w,n}                      // grind check
    require last z digits all zero
    pk_i' := chain(sigma_i, a_i → w-1)
    pk' := T_l(P, T_pk, pk_1' || ... || pk_l')
    require pk' == pk
```

Probability `p_ν` of a random digest passing the sum check is `ν / w^l`, where ν is computed by `compute_nu(l, S, w)` in `costs.sage`. Expected attempts per sign: `1 / p_ν = w^l / ν`. Counter bits `r` should comfortably exceed `log2(1/p_ν)` so the grind almost always succeeds in `2^r` tries. We pin `r = 32` everywhere.

### qBitcoin's WOTS+C parameter sets

| Use | n | w | l | S_{w,n} | Per-OTS sig size | Expected grind |
|---|---|---|---|---|---|---|
| SHRINCS stateful (per leaf) | 16 | 16 | 32 | 240 | 32·16 + 4 = 516 B | `1/p_ν ≈ 2^24` |
| SHRINCS stateless fallback / SHRIMPS fallback | 16 | 256 | 16 | 2040 | 16·16 + 4 = 260 B | `1/p_ν ≈ 2^15` |
| SHRIMPS compact (per WOTS layer) | 16 | 16 | 32 | 240 | 516 B | `1/p_ν ≈ 2^24` |

An alternative `(m=9, l=18, S=135)` parameter set (per delving-bitcoin.org/t/2158) is documented in `docs/research/sage/probe_shrincs_wotsc.sage` for completeness but is **not** what we ship — the canonical paper-aligned `(l=32, S=240)` is what `costs.sage` validates and is what we use everywhere SPHINCS+ instances appear.

---

## XMSS (§7) and unbalanced XMSS (§B.3)

`xmss.go` is straight balanced XMSS — height-`h'` Merkle tree of WOTS+C public keys. Signature = `(WOTSSig, AuthPath)` where the auth path is `h'` sibling hashes.

`unbalanced_xmss.go` implements the §B.3 spine: leaves at strictly increasing depths from the root. Leaf q sits at depth q. The auth path for leaf q has exactly q sibling hashes (the `(q+1) × 16 B` figure in the SHRINCS sig size formula).

The unbalanced shape is what makes SHRINCS' stateful path size scale with `q`. At low q, the stateful sig is tiny (324 B at q=1). As q grows it accumulates 16 B per slot of auth path until the min-rule (§B.3) flips and SHRINCS falls back to the stateless SPHINCS+ instance. See [`shrincs.md`](shrincs.md).

The spine-hash ADRS encodes `NumLeaves - 1 - spineIdx`, so the signer and verifier must agree on `NumLeaves` to produce the same root. Fixed at `NumLeaves = 256` (`ShrincsTreeHeight = 8`) globally — it's a consensus constant.

---

## XMSS^MT (§8) — hypertree

A hypertree of XMSS instances. Each subtree at depth `d_layer` is a balanced XMSS of height `h' = h/d`; the leaves at the top layer sign the roots of the layer below. Used by SPHINCS+ inside SHRIMPS for both compact and fallback.

A SPHINCS+ signature includes one `(WOTSSig, AuthPath)` per layer plus the bottom-layer FTS (FORS / FORS+C / PORS+FP) signature. The hypertree gives `2^h` virtual leaves with only `O(d × 2^(h/d))` keygen work.

---

## FORS (§9) and FORS+C (§9.2)

FORS = Forest Of Random Subsets. The bottom-layer few-time signature of plain SPHINCS+. The hash-to-subset deterministically picks k FORS leaves (one per tree); the signer reveals their values.

FORS+C grinds the message hash so the last FORS tree can be omitted (k-1 trees instead of k). Saves one tree's worth of leaves + auth path.

We don't ship a SPHINCS+(W+C F+C) variant — both SHRIMPS instances and the SHRINCS stateless fallback use PORS+FP instead, which is a strict size win at the parameter sets we ship.

---

## PORS+FP (§10) + Octopus (§C)

PORS+FP collapses FORS' k separate trees into a **single tree** of `t = k·2^a` leaves with a positional-binding hash-to-subset. The signature reveals k leaves and an Octopus-compressed authentication set covering them.

```
Sign(sk, m):
    for s := random salt:
        y := H_msg(s, m)                                  // 64 B SHA-512 output
        τ := first h bits of y                            // hypertree leaf index
        X := first k distinct (h ≤ ⌈log2 t⌉)-bit blocks of y, all < t
        if |X| == k:
            auth := Octopus(sorted(X), tree_height(t))
            if |auth| ≤ mmax:
                return (s, τ, sk_x for x in X, auth_padded_to_mmax)

Verify(pk, m, sig):
    (s, τ, leaves, auth) := sig
    y := H_msg(s, m)
    require τ == first h bits of y
    X := decode k indices from y (same algorithm as signer)
    root := recompute_root(leaves, auth, X, tree_height(t))
    require root == pk
```

`mmax` is chosen by `compute_mmax` in `costs.sage` so total signing time matches FORS+C within ~11%. For our two parameter sets:

- `mmax = 105` for SHRIMPS compact (`t = 2^20, k = 8`).
- `mmax = 118` for SHRIMPS fallback (`t = 11·2^14 = 180224, k = 11`). Note `t` is **not a power of 2** — the implementation supports left-filled trees with mixed-depth Octopus paths.

Tests:

- `pors_test.go` — basic PORS+FP keygen/sign/verify.
- `octopus_dist_test.go` — empirical distribution of auth-set sizes vs the PMF computed by `octopus_pmf.py`.

### Hash-to-subset bit extraction

Bit-extraction order is **big-endian** on the SHA-512 output: read y as a 512-bit integer, take the top h bits as τ, then read subsequent ⌈log₂ t⌉-bit blocks from most-significant-remaining bits. Implemented in `pors.go::HashToSubset`. Documented because two implementations that differ on bit order produce incompatible signatures even though they're "both right per the paper".

---

## SPHINCS+ (§11)

Top-level construction:

```
KeyGen(SK.seed, PK.seed):
    # Build hypertree top-down: each layer signs the next layer's roots.
    PK.root := root(top-layer XMSS keyed by SK.seed, PK.seed)
    return ((SK.seed, PK.seed), (PK.root, PK.seed))

Sign(sk, m):
    R := PRFmsg(SK.prf, opt, m)                     # 2n B
    (PORSsig, τ, X) := PORS+FP.Sign(...)            # bottom layer FTS
    sigs := []
    for layer in reversed(hypertree layers):
        # XMSS auth path + WOTS+C signature on the next-up root
        sigs.append((WOTSsig, AuthPath))
    return (R, count_r, PORSsig, sigs)

Verify(pk, m, sig):
    # Recompute up the hypertree from the FTS leaf to PK.root.
    leaf := PORS+FP.Verify(...)
    for layer in hypertree layers:
        leaf := XMSS.Verify(WOTSsig, AuthPath, leaf)
    require leaf == pk.PK.root
```

`R` is per-signature randomness, 2n = 32 B per paper §11 / sage `randomness_size = 32`. Without the wide R, multi-target attack distinguishability becomes a concern.

The SPHINCS+ public key is `(PK.seed, PK.root)` — the seed is part of the public key, not a global protocol constant. The on-chain SHRINCS / SHRIMPS pubkey is therefore 32 bytes (PK.seed || combined_root), as `crypto.ShrincsKey.PublicKey()` and `crypto.ShrimpsKey.PublicKey()` return.

---

## KAT cross-check

`testdata/paper_kat.json` is generated by `docs/research/sage/dump_katfixtures.sage`. `paper_kat_test.go` loads it and asserts:

- `SPHINCSParams.SigSize() == sage compute_size(...) + 4`  (the +4 is the grind salt — see `docs/research/sage/README.md`).
- The (k, a, h, d, w, l, t, mmax) tuples agree.
- The reported `security_bits` agree with `compute_security(...)`.

Regenerating the fixture file requires sage; running the test does not.
