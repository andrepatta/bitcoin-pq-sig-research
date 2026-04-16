# `script/` — Bitcoin v0.1 opcode interpreter

Full Bitcoin-v0.1 opcode set, modern Bitcoin Core post-disable rules. The hex values for every opcode are taken **verbatim** from Satoshi's `script.h` (see `docs/research/satoshi-v0.1/script.h`); the *semantic* behavior matches modern Bitcoin Core, not v0.1 (because Bitcoin Core later disabled several opcodes that v0.1 implemented). The single PQ-sig deviation is `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` polymorphism — see §6 below.

---

## 1. File map

| File | What's in it |
|---|---|
| `opcodes.go` | Every `OP_*` constant + `OpcodeName(op)` + `isDisabled(op)` + `isCountedOp(op)` (the latter for the 201-non-push-op cap). |
| `num.go` | `CScriptNum` — sign-magnitude variable-length little-endian integer with BIP-62 minimal-encoding check. Max 4 bytes for arithmetic operands. |
| `script.go` | `Script` type, `ParseOp`, `Iterate`, `NewScript`, `BuildPush` (smallest-valid-push encoder). |
| `interp.go` | The interpreter: stack + altstack + `vfExec` conditional stack + `Execute(witness, leafScript, sigChecker, sighash)`. |

---

## 2. Limits

All in `script/interp.go`:

| Constant | Value | Why |
|---|---|---|
| `MaxScriptSize` | 10_000 bytes | Bitcoin-matched. |
| `MaxStackSize` | 1_000 elements | Bitcoin-matched. |
| `MaxOpsPerScript` | 201 (non-push) | Bitcoin-matched. |
| `MaxScriptElementSize` | **8192 bytes** | **Raised** from Bitcoin's 520. Forced — SHRIMPS fallback is ~4.2 KB on the wire and would never push at 520 B. |

Element size is the only meaningful deviation from Bitcoin's interpreter limits. Everything else stays in lockstep with Core.

---

## 3. Numeric semantics — `CScriptNum`

Bitcoin's signed integer encoding: variable-length little-endian, with the high bit of the most-significant byte holding the sign. Decoder enforces minimal encoding (BIP-62) so two equivalent scripts always hash to the same value (same byte representation → same leaf hash → same Merkle root).

```go
type Num struct{ N int64 }

func (n Num) Bytes() []byte
func DecodeNum(b []byte, max int) (Num, error)   // BIP-62 minimal-encoding check
```

Arithmetic operands are capped at 4 bytes. Results can grow to 5 bytes (e.g. `INT_MAX_4B + 1`), but that result can't be re-fed to another arithmetic op without first being truncated. Bitcoin-exact.

---

## 4. The conditional stack

`vfExec` tracks `OP_IF` / `OP_NOTIF` / `OP_ELSE` / `OP_ENDIF` nesting:

- An opcode executes only if `vfExec` has no `false` entries (i.e., we're inside all-true conditional branches).
- A disabled opcode rejects **even inside an unexecuted branch** — modern Bitcoin Core behavior. v0.1 was more permissive, but post-disable Core rejects unconditionally to avoid policy ambiguity.

Disabled-but-defined opcodes (return `ErrDisabledOp` even in unexecuted branches): `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_2MUL`, `OP_2DIV`, `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT`.

---

## 5. Reserved opcodes

`OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` return `ErrReservedOp`. The paper defines no K-of-N PQ-sig construction; we don't fake one. Reserved (rather than disabled) so a future K-of-N scheme can claim the opcodes without renumbering.

`OP_CODESEPARATOR` is a no-op. qBitcoin computes the sighash externally (`txn.SigHash`) from the tx layout, so there's no subscript-based sighash to track. Bitcoin's `OP_CODESEPARATOR` truncated the script before the position; we don't need that because our sighash never re-hashes the script.

---

## 6. Polymorphic `OP_CHECKSIG` / `OP_CHECKSIGVERIFY`

The single PQ-sig deviation. The signature pushed to the stack carries a 1-byte scheme prefix:

```
[ scheme_tag                         ]  1 B   0x00 = SHRINCS, 0x01 = SHRIMPS
[ SerializeShrincsSig | SerializeShrimpsSig ]   N B
```

`crypto.DefaultSigChecker` (registered with the interpreter at consensus call sites) implements:

```go
type SigChecker interface {
    CheckSig(sig, pk []byte, sighash [32]byte) (bool, error)
}
```

Dispatch:

```go
func (DefaultSigChecker) CheckSig(sig, pk []byte, sighash [32]byte) (bool, error) {
    if len(sig) == 0 {
        return false, nil
    }
    switch sig[0] {
    case crypto.SchemeShrincs:
        s, err := crypto.DeserializeShrincsSig(sig[1:])
        if err != nil { return false, nil }
        return crypto.VerifyShrincs([32]byte(pk), sighash[:], s), nil
    case crypto.SchemeShrimps:
        s, err := crypto.DeserializeShrimpsSig(sig[1:])
        if err != nil { return false, nil }
        return crypto.VerifyShrimps([32]byte(pk), sighash[:], s), nil
    default:
        return false, nil
    }
}
```

### Why a tag byte (and not length-based dispatch)?

SHRINCS lengths range 336 B..4080 B; SHRIMPS lengths range 2663 B..4200 B. They overlap on `[2663, 4080]`. A bare-length classifier would be ambiguous in the overlap window. The 1-byte tag is consensus-clean and matches the pattern Bitcoin already uses for compressed pubkey prefixes (`0x02`, `0x03`).

### Cost accounting

`txn.SigOpCost(tx)` parses each input's leaf script for `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` occurrences and charges per witness scheme tag. SHRINCS = 1, SHRIMPS = 2 (because SHRIMPS verification involves two SPHINCS+ instances behind the H-of-PKs commitment). Unknown / absent tags default to the SHRIMPS worst case. See [`crypto.md`](crypto.md) and [`txn.md`](txn.md).

---

## 7. The canonical P2PK leaf template

`address.NewP2PKLeaf(pk)` emits:

```
[ pk          ]  32 B  (push)
OP_CHECKSIG
```

Both leaves of a 2-leaf P2MR address use this template — leaf 0 for SHRINCS, leaf 1 for SHRIMPS. Polymorphism comes from the scheme tag on the pushed sig at spend time, not from separate opcodes. See [`address.md`](address.md).

---

## 8. Interpreter contract

```go
func Execute(
    witness    [][]byte,
    leafScript Script,
    sigChecker SigChecker,
    sighash    [32]byte,
) (bool, error)
```

`witness` items are pushed on the stack in order (Bitcoin tapscript style). `leafScript` is then executed. Returns `(stack.IsTrue(), nil)` on clean exit; otherwise the first error.

The sighash is provided externally — interpreter never recomputes it. (See "OP_CODESEPARATOR is a no-op" above.)

---

## 9. Tests

| Test file | Coverage |
|---|---|
| `script/script_test.go` | `BuildPush` smallest-valid-push, `ParseOp`, `Iterate`. |
| `script/num_test.go` | `CScriptNum` round-trip + minimal-encoding rejection. |
| `script/interp_test.go` | Conditional stack, disabled-op-in-unexecuted-branch, reserved opcodes, MaxStackSize / MaxOpsPerScript / MaxScriptSize / MaxScriptElementSize boundaries. |
