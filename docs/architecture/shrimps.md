# SHRIMPS — multi-device hash-based signature

SHRIMPS occupies leaf 1 of every 2-leaf P2MR address. Where SHRINCS is the everyday signing path (single device, small sigs), SHRIMPS is the **multi-device** path: each of up to 1024 devices sharing the same pubkey signs at most `n_dsig = 1` compact signature before falling back, giving the same address a stateful budget of 1024 compact sigs without any single device having to coordinate counter state with another.

The construction uses **two SPHINCS+ instances** under one address commitment, with a 1-byte tag on the wire selecting which instance produced the signature.

---

## 1. Construction

Per delving-bitcoin.org/t/2355 and Kudinov & Nick eprint 2025/2203.

```
                         SHRIMPS_pk (32 B, on-chain)
                       = PK.seed (16 B) || combined_root (16 B)
                       where combined_root = H(pk_compact || pk_fallback)
                ___________________|___________________
               /                                       \
       pk_compact (16 B root)                  pk_fallback (16 B root)
       SPHINCS+ (W+C P+FP)                     SPHINCS+ (W+C P+FP)
       q_s = 2^10 = 1024                       q_s = 2^40
```

Both instances share `PK.seed` (16 B) per delving 2355 footnote 1. The sibling field in a signature is therefore only `PK.root` (16 B), not the full (seed, root) pair.

### 1.1 Compact instance (~2,646 B on-wire)

Paper variant: §11 SPHINCS+ with §5 WOTS+C replacing WOTS-TW, §10 PORS+FP replacing FORS. "W+C P+FP" in delving 2355's parameter table.

| Param | Value | Source |
|---|---|---|
| q_s | 2^10 = 1024 | delving 2355 canonical row |
| k (indices per sig) | 8 | delving 2355 |
| a | 17 | delving 2355 (PORS tree height = a + log₂k = 20) |
| h (hypertree height) | 12 | delving 2355 |
| d (hypertree layers) | 1 | delving 2355 |
| w (Winternitz) | 16 | delving 2355 |
| S_{w,n} | 240 | delving 2355 — optimal for w=16, len_1=32 (≈ ℓ·(w−1)/2) |
| n | 16 | NIST L1 |
| ℓ (WOTS+C chains) | 32 | `len_1 = 32`, no z-chain reduction at this S_{w,n} |
| m_max (Octopus auth-set bound) | **105** | sage `costs.sage --params W+C_P+FP 10 8 17 12 1 16 240` (security=128.0, size=2548 B, sign=6.8M compressions) |

Paper-oracle sig size: **2548 B**. Our `SPHINCSParams.SigSize()`: 2552 B (+4 B grind salt). On-wire SHRIMPS body: 2646 B (+ 94 B wallet wrapper — see [`docs/parameters/signature-sizes.md`](../parameters/signature-sizes.md)).

### 1.2 Fallback instance (~4,134 B on-wire)

Paper §13.3 Table 1, **bold** recommended row for q_s = 2^40 W+C P+FP. Pinned via `sage costs.sage --params W+C_P+FP 40 11 14 40 5 256 2040`:

| Param | Value |
|---|---|
| q_s | 2^40 |
| h | **40** |
| d | **5** |
| a | **14** |
| k | 11 |
| w | 256 |
| S_{w,n} | 2040 |
| ℓ | **16** = `128 / log₂(256)` |
| m_max | **118** |
| Sig size (paper oracle) | **4036 B** (security=128.0, sign=6.4M compressions, verify=10.6K compressions) |

Note `t = k · 2^a = 11 · 2^14 = 180224` — **non-power-of-2** PORS tree. Implementation supports left-filled trees with mixed-depth Octopus paths (in `crypto/hashsig/pors.go`).

---

## 2. Wire format

```
σ_SHRIMPS_body = (tag_byte, sphincs_sig, sibling_pk_root_16)

where tag_byte:
    0x00 = signed via compact instance (sibling = pk_fallback.root)
    0x01 = signed via fallback instance (sibling = pk_compact.root)

sphincs_sig = (R_32, count_4, PORS+FP_sig, (WOTS+C_j, AuthPath_j)_{j=0..d-1})
```

The 1-byte instance tag (`0x00`/`0x01`) is **inside** the SHRIMPS body. **Outside** the body, when the sig is pushed onto the script stack, the consensus-level scheme tag (`crypto.SchemeShrimps = 0x01`) prefixes the whole thing — that's the byte the script interpreter dispatches on.

### Why two tag bytes?

Different concerns:

- **Outer scheme tag** (`SchemeShrincs = 0x00` / `SchemeShrimps = 0x01`, in `crypto/checksig.go`): SHRINCS vs SHRIMPS at the consensus layer. Required because their length ranges overlap — see [`crypto.md`](crypto.md).
- **Inner instance tag** (`0x00` / `0x01`, inside the SHRIMPS body): compact vs fallback within SHRIMPS. Required because the verifier needs to know which sub-instance produced the sig before it can recompute the right sibling root. The compact and fallback bodies have different lengths (2552 B vs 4040 B at our params), so length-dispatch could in principle work — but a tag is more robust against future parameter changes.

### Per-device SHRIMPS state file

```
[8-byte compact_counter]   0 if not yet used; 1 once compact sig issued
[8-byte fallback_counter]  next leaf index in fallback SPHINCS+
[1-byte status]
[32-byte compact_root]
[32-byte fallback_root]
```

One state file per device per key. `n_dsig = 1` → each device signs at most one compact signature before its `Sign()` calls fall through to the fallback instance. Per delving 2355, 1024 devices each producing 1 compact sig under the same pubkey is the canonical design budget.

---

## 3. Sign / verify

```
Sign(msg):
    if compact_counter < n_dsig:                       # n_dsig = 1
        persist_counter(compact_counter + 1)
        sphincs_sig := compact.Sign(msg)
        return (tag=0x00, sphincs_sig, fallback.PK.root)

    if fallback_counter < 2^40:                        # virtually unreachable
        persist_counter(fallback_counter + 1)
        sphincs_sig := fallback.Sign(msg)
        return (tag=0x01, sphincs_sig, compact.PK.root)

    return ErrCounterExhausted

Verify(pk, msg, sig):
    (tag, sphincs_sig, sibling) := sig
    if tag == 0x00:                                    # compact
        leaf_pk := compact.PK.root_from_sig(sphincs_sig)  # SP verify
        sibling_pk := sibling
    else:                                              # fallback
        leaf_pk := fallback.PK.root_from_sig(sphincs_sig)
        sibling_pk := sibling
    require pk.combined_root == H(leaf_pk || sibling_pk)
    require sphincs_sig verifies under leaf_pk + pk.PK.seed
```

`ErrCounterExhausted` is the only error code from SHRIMPS' Sign that propagates above `crypto/`. At ship budgets (1024 compact + 2^40 fallback) it's effectively unreachable. The wallet still surfaces `SlotHealth()` so a UI can warn before the compact budget runs out.

---

## 4. Graceful degradation past q_s

Per delving 2355's table, compact-instance security after exceeding the design budget:

| Total compact sigs across all devices | Security |
|---|---|
| 2^10 (budget) | 128.0 bits |
| 2^11 | 128.0 bits |
| 2^12 | 125.1 bits |
| 2^13 | 120.4 bits |
| 2^14 | 115.0 bits |
| 2^15 | 108.9 bits |

Exceeding `n_dev = 1024` is **slow erosion, not a break**. The fallback instance (q_s = 2^40) sits behind it as a safety net. There's no on-chain rotation: a wallet that wants to refresh its address advances the BIP-44 account index instead.

---

## 5. Key derivation

`shrimps_master_seed` is derived per BIP-44 path `m/44'/1'/N'/1'`:

```
shrimps_master_seed
     ├── Hash256(seed || "qbitcoin-shrimps-compact-seed")   → SPHINCS+ compact seed
     └── Hash256(seed || "qbitcoin-shrimps-fallback-seed")  → SPHINCS+ fallback seed
```

The fallback seed is **not** shared with SHRINCS' fallback — same rationale as `shrincs.md` §1.

---

## 6. Public API

```go
type ShrimpsKey struct { /* unexported */ }
type ShrimpsSig  struct { Counter uint64; UsesFallback bool; Body []byte }

func NewShrimpsKey(ctx context.Context, seed []byte, io StateIO, name string) (*ShrimpsKey, error)
func (k *ShrimpsKey) Sign(ctx context.Context, msg []byte) (ShrimpsSig, error)
func (k *ShrimpsKey) PublicKey() [32]byte                  // PK.seed || combined_root
func (k *ShrimpsKey) CompactSlotsUsed() uint64
func (k *ShrimpsKey) FallbackSlotsUsed() uint64

func SerializeShrimpsSig(s ShrimpsSig) []byte
func DeserializeShrimpsSig(b []byte) (ShrimpsSig, error)

func VerifyShrimps(pk [32]byte, msg []byte, s ShrimpsSig) bool

var ErrCounterExhausted = errors.New("shrimps: all signing slots exhausted")
```

---

## 7. Tests

| Test file | Coverage |
|---|---|
| `crypto/shrimps_test.go` | Keygen, sign, verify round-trip on both instances. Both tags. |
| `crypto/hashsig/sphincs_test.go` | Underlying SPHINCS+ at small demo params. |
| `crypto/hashsig/pors_test.go` | PORS+FP keygen / sign / verify. |
| `crypto/hashsig/octopus_dist_test.go` | Empirical Octopus auth-set distribution vs `octopus_pmf.py` PMF. |
| `crypto/hashsig/paper_kat_test.go` | Cross-checks `SPHINCSParams.SigSize()` against `paper_kat.json` for both instances. |
| `crypto/hashsig/bench_paper_test.go` | Slow benchmark at paper params. Skipped unless `-tags slow`. |
