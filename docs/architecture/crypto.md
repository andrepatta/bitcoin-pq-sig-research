# `crypto/` — primitives

Everything chain-facing pivots through `crypto/`. The package owns:

- **SHA-256d** (`Hash256`, `Hash256Concat`) — chain-level hashing.
- **Merkle trees** (`MerkleRoot`, `MerkleProof`, `VerifyProof`) — including the CVE-2012-2459 mutation check.
- **SipHash-2-4 + per-block key derivation** for BIP-152 compact-block short IDs.
- **SHRINCS / SHRIMPS wrappers** that wire the paper primitives in `crypto/hashsig/` to wallet- and chain-level signing flows.
- **`CheckSig` dispatcher** that turns a `(scheme_tag, sig_body)` push and a pubkey into a `bool` for the script interpreter.
- **Atomic state-file IO with a CRC trailer** so signing-counter persistence survives crashes and silent disk corruption.

The deep dives for SHRINCS and SHRIMPS live in their own files (`shrincs.md`, `shrimps.md`). This page covers everything else.

---

## `hash.go` — SHA-256d wrappers

```go
// chain-level hashing — the Bitcoin invariant.
func Hash256(data []byte) [32]byte                  // SHA256(SHA256(data))
func Hash256Concat(a, b [32]byte) [32]byte          // Hash256(a || b)

// Bitcoin-style display: byte-reversed hex, reads big-endian top-down.
func DisplayHex(h [32]byte) string
```

That's the entire chain-level hash API. Every TxID, every Merkle node, every block hash, every storage key, every script / leaf hash goes through one of these three functions. Don't `sha256.Sum256` directly from `core/`, `txn/`, `mempool/`, etc. — the import-discipline matrix in [`hashing.md`](../hashing.md) lists the exceptions.

---

## `merkle.go` — Bitcoin-shape Merkle tree + CVE-2012-2459 defense

### Standard tree

```go
func MerkleRoot(txids [][32]byte) [32]byte
func MerkleProof(txids [][32]byte, index int) [][32]byte
func VerifyProof(root, leaf [32]byte, proof [][32]byte, index int) bool
```

Leaf hash = `Hash256(txBytes)` (single hash). Internal node = `Hash256Concat(left, right)`. Odd levels: duplicate the last leaf, exactly as Bitcoin's `consensus/merkle.cpp::ComputeMerkleRoot`.

### Mutation check (CVE-2012-2459)

```go
func MerkleRootMutated(txids [][32]byte) (root [32]byte, mutated bool)
```

Walks every level checking for **equal consecutive siblings** before the odd-level duplicate-last step. If any level has `cur[i] == cur[i+1]` for the natural tree shape, the tree is malleable: an attacker can append a duplicated tx and produce a different tx-list with the same Merkle root.

`Block.ComputeMerkleRootMutated` exposes the flag; `validateAndApply` rejects with `"block: merkle tree mutated (CVE-2012-2459)"` before the ordinary bad-root path.

Test coverage: `crypto/merkle_test.go` + `core/merkle_mutation_test.go`.

---

## `siphash.go` — BIP-152 compact-block short IDs

```go
func SipHash24(k0, k1 uint64, data []byte) uint64
func SipHashKey(headerBytes []byte, nonce uint64) (k0, k1 uint64)
```

Per BIP-152 exactly. `SipHashKey` derives the per-block (k0, k1) from `SHA256(headerBytes || nonce_le)[0:16]` split into two LE uint64s. `Node.handleCmpctBlock` calls `SipHash24` over each candidate txid and truncates to 6 bytes.

Per-block keying prevents a static attacker from precomputing mempool collisions across blocks. The `nonce` is randomly chosen by the cmpct-block sender each round.

---

## `state_file.go` — atomic write + CRC trailer

The persist-before-sign rule (see [`docs/operations/persist-before-sign.md`](../operations/persist-before-sign.md)) requires a write that is **atomic** (either the new contents land or the old ones do, never partial), **durable** (survives power loss), and **verifiable** (corrupted bytes cause `ErrStateCorrupted` instead of silent reuse).

```go
type StateIO interface {
    Read(name string) ([]byte, error)
    Write(name string, body []byte) error    // atomic, fsync'd
}

type FileStateIO struct{ Dir string }        // plaintext on-disk impl

func AppendCRC(b []byte) []byte              // append CRC32-IEEE trailer
func StripAndVerifyCRC(b []byte) ([]byte, error)   // ErrStateCorrupted on mismatch

var ErrStateCorrupted = errors.New("crypto: state file corrupted")
```

Write protocol (in `FileStateIO.Write`):

1. Wrap body with CRC: `body' = append(body, crc32.ChecksumIEEE(body))`.
2. Write `body'` to `<name>.tmp`.
3. `fsync(<name>.tmp)`.
4. `rename(<name>.tmp, <name>)`.
5. `fsync(parent_dir)` so the rename is durable.

Read protocol: read full file, `StripAndVerifyCRC`, return the inner body. A corrupted file returns `ErrStateCorrupted` — SHRINCS / SHRIMPS treat this as "DO NOT sign", same as a missing state file.

The `wallet/` package layers AES-256-GCM on top via `wallet.storeStateIO` (an adapter that implements `StateIO` against the encrypted on-disk store). The CRC sits **inside** the GCM ciphertext, so a bit flip between decrypt-in-memory and signing is still detected (in addition to GCM's ciphertext-integrity check). See [`wallet.md`](wallet.md) for the encryption layer.

---

## `checksig.go` — polymorphic OP_CHECKSIG dispatch

The script interpreter doesn't know about SHRINCS or SHRIMPS — it just calls `SigChecker.CheckSig(sig, pk, sighash) → (bool, error)`. The implementation injected at consensus call sites is `crypto.DefaultSigChecker`, which lives here.

### Wire format

The signature pushed to the stack carries a 1-byte **scheme tag** as a prefix:

```
const (
    SchemeShrincs = 0x00
    SchemeShrimps = 0x01
)
```

A complete signature push is `[1-byte tag][N-byte SerializeShrincsSig | SerializeShrimpsSig output]`. Analogous to Bitcoin's `0x02` / `0x03` compressed-pubkey prefix — a single byte resolves the polymorphism.

### Why the tag and not length-based dispatch?

Tempting to dispatch on length (smaller = SHRINCS, larger = SHRIMPS) — but it breaks. With the paper-canonical parameter sets:

```
SHRINCS sig length range:  336 B  ..  4080 B
SHRIMPS sig length range: 2663 B  ..  4200 B
                          ^^^^^^^^^^^^^^^^^^
                          OVERLAP: 2663..4080
```

Any sig in the overlap window is ambiguous. The 1-byte tag eliminates the ambiguity at consensus level. (Internal SHRINCS stateful-vs-stateless dispatch *does* use length-based dispatch — see [`shrincs.md`](shrincs.md) — because the min-rule guarantees those two ranges are disjoint.)

### Cost accounting

`txn.SigOpCost(tx)` parses each input's leaf script for `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` occurrences and charges per witness scheme-tag:

```
SHRINCS verify cost = 1
SHRIMPS verify cost = 2     (two SPHINCS+ instances under one address)
unknown / absent    = 2     (defaults to the SHRIMPS worst case)
```

Block budget is `core.MaxBlockSigOpsCost = 80_000`. Standard-tx budget is `txn.MaxStandardTxSigOpsCost = 16_000`. See [`txn.md`](txn.md) and [`mempool.md`](mempool.md).

---

## Tests

| Test file | What it covers |
|---|---|
| `merkle_test.go` | Standard Merkle properties + CVE-2012-2459 second-preimage construction at multiple tree depths. |
| `shrincs_test.go` | SHRINCS keygen / sign / verify round-trip. |
| `shrincs_fallback_test.go` | Stateful → stateless transition under the min-rule, including the size jump from ~324 B to ~4 KB. |
| `shrimps_test.go` | SHRIMPS keygen / sign / verify, both compact and fallback paths. |
| `state_file_test.go` | Atomic write semantics, CRC mismatch detection. |
| `stateio_test.go` | StateIO interface contract — both `FileStateIO` and a mock. |
| `paperparams_smoke_test.go` | End-to-end smoke at paper parameters (slow; skipped unless `-tags slow`). |
| `testparams_test.go` | Small demo parameters used elsewhere in the test suite to keep test runtime sane. |
| `checksig_test.go` | Polymorphic dispatch under the 1-byte scheme tag. |
