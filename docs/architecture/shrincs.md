# SHRINCS — single-device stateful + stateless fallback

SHRINCS is qBitcoin's primary signing scheme (leaf 0 of every 2-leaf P2MR address). It's a **wrapper around two SPHINCS+/XMSS variants** that the signer transparently switches between under the paper's §B.3 min-rule:

- **Stateful path**: unbalanced XMSS of WOTS+C one-time keys. Tiny sigs at low slot indices (324 B at q=1), grows ~16 B per slot used.
- **Stateless fallback**: a full SPHINCS+ instance with W+C P+FP — same instance the SHRIMPS fallback uses. Constant ~4 KB sig size.

The min-rule keeps stateful and stateless sig sizes **range-disjoint**, which is what lets the verifier dispatch by length alone (no extra tag byte on the wire). At the consensus layer above SHRINCS, the 1-byte scheme tag (`0x00 = SHRINCS`) is still required to distinguish SHRINCS from SHRIMPS — that's the `crypto.SchemeShrincs` tag from [`crypto.md`](crypto.md).

This page is the deep dive. The wire-format summary suitable for skimming lives at the end.

---

## 1. Construction

```
                         SHRINCS_pk (32 B, on-chain)
                       = PK.seed (16 B) || combined_root (16 B)
                       where combined_root = H(pk_stateful || pk_stateless)
                ___________________|___________________
               /                                       \
      pk_stateful (16 B root)                  pk_stateless (16 B root)
      = unbalanced-XMSS root                   = SPHINCS+ (W+C P+FP) root
              |                                          |
        WOTS+C leaves at                            SPHINCS+ fallback
        depths 1, 2, 3, ...                         (q_s = 2^40)
```

### PK.seed travels on-chain

Every tweakable-hash call `Th(P, T, m)` takes `PK.seed` as the first argument `P`. The verifier needs `PK.seed` to reproduce any hash in the signature chain. Paper §11 line 1057 + FIPS-205 both pin the SPHINCS+ public key as `PK.seed || PK.root`. SHRINCS inherits this: the on-chain pubkey is **32 bytes** (PK.seed || combined_root).

### Stateful path geometry — unbalanced XMSS

Per §B.3, the stateful tree is unbalanced: leaves at strictly increasing depths from the root. Leaf q sits at depth q. Auth path for leaf q is exactly q sibling hashes.

`crypto.ShrincsTreeHeight = 8` is the consensus constant — see [`docs/invariants.md`](../invariants.md) §10. `NumLeaves = 256`. The choice of 8 tracks the useful-slot window under the min-rule with the canonical stateless fallback (`spsig + 32 ≈ 4068 B`, crossover at q ≈ 234 < 256).

### WOTS+C parameters at the OTS level

Configured in `crypto/shrincs.go::shrincsWOTSPlusC()`:

| Param | Value | Why |
|---|---|---|
| n (hash output) | 16 B (128 bits) | NIST L1 |
| m (digest length) | 9 B | Paper-faithful — digit count is fixed below |
| w (Winternitz) | 16 | §13.1 standard |
| len_1 = ℓ | 18 base-w digits | `m·8 / log₂ w = 72/4 = 18` |
| z (zero-tail digits) | 0 | None — the digit reduction is via `m`, not via `z` |
| S_{w,n} | 135 | costs.sage `compute_nu(18, 135, 16) ⇒ p_ν ≈ 2^-5.6` |
| r (counter bits) | 32 | Plenty for `1/p_ν ≈ 2^24` expected trials |

OTS sig size: `len_1 · n + ⌈r/8⌉ = 18 · 16 + 4 = 292 B`.

The `m=9` choice is what makes WOTS+C digit count exactly 18 (not 32). Paper-canonical alternative `(m=16, l=32, S=240)` works too — it's what the SPHINCS+(W+C) variants in `costs.sage`'s PARAMETER_SETS use, and what we ship inside SPHINCS+ for the SHRINCS stateless fallback / SHRIMPS instances. SHRINCS' OTS at the leaves uses the smaller `(m=9, l=18)` because it dominates the stateful sig size and the project value is "smallest stateful sig at q=1" → 324 B exactly.

The UXMSS caller hashes the 16-byte sighash down to 9 bytes via `sigHashN(msg, k.uxmss.WOTS.M)` (SHA-256 truncation, paper §2 convention). TCR holds at the needed width since the input is already a domain-separated sighash digest.

### Stateless fallback

The fallback is a SPHINCS+(W+C P+FP) instance with **paper-bold q_s = 2^40 parameters**:

```
(h, d, k, a, w, S_wn) = (40, 5, 11, 14, 256, 2040)
```

Sig size: 4036 B (paper oracle). Our `SPHINCSParams.SigSize()` reports 4040 B (+4 B grind salt). On-wire SHRINCS body for the stateless path adds 32 bytes (the active 16 B PK.root + the sibling 16 B PK.root) → 4068 B body, 4080 B with the 12 B outer frame.

### Internal seed split

```go
shrincs_master_seed
     ├── Hash256(seed || "qbitcoin-shrincs-stateful-seed")  → UXMSS seed
     └── Hash256(seed || "qbitcoin-shrincs-fallback-seed")  → SPHINCS+ stateless seed
```

The fallback seed is **not shared** with SHRIMPS' fallback instance. Each scheme derives its own from a distinct domain string — sharing would create cross-scheme observability (a SHRINCS-fallback signature would reveal material that might be reused by SHRIMPS). Costs ~4 KB extra keygen at wallet creation; worth it.

---

## 2. The §B.3 min-rule

```
Sign(msg):
    q := load_counter()                                   # next stateful slot
    if q < ShrincsTreeHeight.NumLeaves:
        stateful_size := 292 + (q+1)·16 + 16              # WOTS+C + auth + sibling
        stateless_size := SPSig.SigSize() + 32            # SP sig + active root + sibling
        if stateful_size < stateless_size:
            persist_counter(q + 1)
            return sign_stateful(q, msg)                  # uses UXMSS leaf q
    return sign_stateless(msg)                            # uses SPHINCS+ fallback
```

The signer emits a stateful UXMSS sig **iff it would be strictly smaller** than the fallback SPHINCS+ sig. The moment the comparison flips — even if UXMSS slots remain — it falls back.

This is the **min-rule** of paper §B.3. Two consequences:

### (a) Stateful and stateless sig sizes are range-disjoint

Stateful size as a function of q: `f(q) = 292 + (q+1)·16 + 16 = 308 + (q+1)·16`. Strictly increasing.

Stateless size: constant `S = 4036 + 32 = 4068 B` (excluding the outer 12 B frame).

Min-rule invariant: at the q the signer would use, `f(q) < S`. So every emitted stateful sig has body length `< S`, and every emitted stateless sig has body length `= S`. The verifier dispatches on body length alone.

### (b) `ErrCounterExhausted` never reaches the wallet from SHRINCS

Whatever happens at the UXMSS leaves — slots remaining, slots exhausted, state-file unreadable, slot-too-large to satisfy the min-rule — `ShrincsKey.Sign()` always returns either a stateful or a stateless sig. No `ErrCounterExhausted` propagates from SHRINCS.

(SHRIMPS does still return `ErrCounterExhausted` if both sub-instances' accounting budgets are spent, but that's a different scheme and unreachable in practice at our budgets — see [`shrimps.md`](shrimps.md).)

---

## 3. Wire format

Per paper §B.3. Length-dispatched at the SHRINCS layer (no inner tag byte). The 1-byte scheme tag from `crypto/checksig.go` (`SchemeShrincs = 0x00`) sits **outside** this body when the sig is pushed onto the script stack — see [`crypto.md`](crypto.md).

### Stateful body

```
[ WOTS+C signature      ]  292 B  =  18 chains × 16 B + 4 B counter
[ UXMSS auth path       ]  (q+1) × 16 B  =  16, 32, 48, … as q grows
[ pk_stateless sibling  ]   16 B  (16-byte SP root, for recomputing combined_root)
                          ─────────────
size                       308 + (q+1) × 16 B
```

q is recovered on the verifier side as `(bodyLen - 308) / 16 - 1`.

Examples:

| q | Body size |
|---|---|
| 1 | 308 + 2·16 = 340 B |
| 8 | 308 + 9·16 = 452 B |
| 234 | 308 + 235·16 = 4068 B (bumps against fallback — min-rule flips here) |

### Stateless body

```
[ SPHINCS+ signature             ]  sp.SigSize() bytes  (4036 B at fallback params)
[ pk_stateless active 16-B root  ]   16 B (SPHINCS+ Hmsg binds PK.root, transmitted)
[ pk_stateful sibling 16-B root  ]   16 B
                                   ─────────────
size                                  sp.SigSize() + 32 = 4068 B
```

### Outer frame (`SerializeShrincsSig`)

12 bytes added on top:

```
[ counter_BE      ] uint64   counter = q for stateful, MaxUint64 for stateless
[ body_len_BE     ] uint32   length of the body that follows
[ body            ] N B
```

The `counter == MaxUint64` sentinel carries `ShrincsSig.IsStateful()` across the wire without an explicit tag.

### Verifier dispatch (length-based)

```go
const stateless_body_size = sp.SigSize() + 32       // 4068 B for fallback params

switch {
case len(body) == stateless_body_size:
    // stateless path
case len(body) < stateless_body_size:
    // stateful path; q := (len(body) - 308) / 16 - 1
default:
    // reject — would violate the min-rule
}
```

### Why this layout matches the paper exactly

Paper §B.3 size formula: `min(292 + q·16, sl) + 16`.

Substituting our numbers and tracking the ` + 16 sibling` term:

```
stateful:    (292 + q·16) + 16 = 308 + q·16              (paper)
ours:        (292 +(q+1)·16) + 16 = 308 + (q+1)·16       (Go code)
```

Off-by-one in q because the paper indexes leaves from 0, our `counter` indexes from 0 but stores `q+1` after persistence (so the next-to-use index is the one that was just incremented). Same total bytes per signature. The "first signature is 324 B" headline on `blockstream.com/quantum` is exactly our q=1 case + the 16 B stateless sibling: `292 + 1·16 + 16 = 324 B`.

(Note: 340 B vs 324 B for q=1 — the **324** number references the body without the 16 B stateless sibling; **340** is what hits the wire when the sibling is included. Both are paper-faithful figures; the difference is whether the sibling counts as "in the OTS" or "in the wrapper". The wallet's on-wire byte count includes the sibling.)

---

## 4. Sizes at common q values

Body bytes (excluding outer 12 B frame):

| q | Stateful | Stateless | Min-rule pick |
|---|---|---|---|
| 1   | 340 B  | 4068 B | stateful |
| 8   | 452 B  | 4068 B | stateful |
| 32  | 836 B  | 4068 B | stateful |
| 128 | 2372 B | 4068 B | stateful |
| 200 | 3524 B | 4068 B | stateful |
| 234 | 4068 B | 4068 B | (flip — first q where they're equal) |
| 235 | 4084 B | 4068 B | stateless |
| 256 | UXMSS exhausted | 4068 B | stateless |

So the practical stateful window with `ShrincsTreeHeight = 8` (`NumLeaves = 256`) is q = 0..234. After that, every signature is stateless (constant 4068 B body). A user that signs more than ~234 transactions on the same address will see their sig size jump from a few hundred B to ~4 KB — by design, no error, no on-chain rotation. The wallet exposes `Wallet.SlotHealth()` so UIs can warn before the jump.

---

## 5. State file

```
[8-byte q_be]               next stateful slot to use
[1-byte status]             0x00 = intact, 0x01 = lost (seed-restored)
[32-byte stateful_root]     cached for fast verify
[32-byte stateless_root]    cached
```

Routed through `crypto.StateIO` — for wallet-owned keys this is `wallet.storeStateIO`, which transparently encrypts under the wallet's KEK if the wallet is encrypted. CRC trailer wraps the plaintext body.

Atomic write-then-rename. Persist-before-sign is non-negotiable: see [`docs/operations/persist-before-sign.md`](../operations/persist-before-sign.md).

---

## 6. Public API

```go
type ShrincsKey struct { /* unexported */ }
type ShrincsSig  struct { Counter uint64; Body []byte }

func NewShrincsKey(ctx context.Context, seed []byte, io StateIO, name string) (*ShrincsKey, error)
func (k *ShrincsKey) Sign(ctx context.Context, msg []byte) (ShrincsSig, error)
func (k *ShrincsKey) PublicKey() [32]byte                            // PK.seed || combined_root
func (k *ShrincsKey) SlotsUsed() uint8                               // q
func (k *ShrincsKey) SlotsTotal() uint8                              // 256

func SerializeShrincsSig(s ShrincsSig) []byte
func DeserializeShrincsSig(b []byte) (ShrincsSig, error)

func VerifyShrincs(pk [32]byte, msg []byte, s ShrincsSig) bool

var ErrStateCorrupted = errors.New("shrincs: state file missing or corrupted")
// Note: NO ErrCounterExhausted at the SHRINCS layer (see §2 above).
```

`Sign` is the only entry point that performs persistence; the `ctx` allows cancellation between the persist phase and the actual signing math (cancellation surfaces at the next phase boundary, not mid-syscall). See `wallet.md` for the cancellation contract.

---

## 7. Tests

| Test file | Coverage |
|---|---|
| `crypto/shrincs_test.go` | Keygen, sign, verify round-trip across many q. |
| `crypto/shrincs_fallback_test.go` | Min-rule transition: signs near the flip point and asserts size jumps from ~stateful to exactly the stateless body length. |
| `crypto/hashsig/unbalanced_xmss_test.go` | UXMSS root computation, auth-path generation, spine-hash ADRS encoding. |
| `crypto/hashsig/wots_test.go` | WOTS+C grind correctness at our `(l, w, S)` parameters. |
| `crypto/state_file_test.go` | Atomic write semantics + CRC mismatch handling. |
