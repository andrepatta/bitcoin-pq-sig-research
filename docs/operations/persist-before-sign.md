# Persist-before-sign

The single most consequential consensus-adjacent rule in qBitcoin. State-counter persistence is the only thing standing between a hash-based signing scheme and **catastrophic key compromise via slot reuse**. Every detail on this page exists for a reason.

---

## 1. The rule

```
CORRECT:  persist(counter+1)  →  sign(message, counter)  →  return sig
WRONG:    sign(message, counter)  →  persist(counter+1)  →  return sig
```

- Crash between persist and sign  →  **one slot wasted**. Acceptable. The next sign call resumes at `counter+2`, leaving slot `counter+1` permanently unused.
- Crash between sign and persist  →  **slot reused on restart**. Catastrophic — produces two valid signatures from the same one-time / few-time slot, leaking enough material to forge a third.

Enforced in `crypto/shrincs.go` and `crypto/shrimps.go`. Non-negotiable.

---

## 2. Why slot reuse is catastrophic

For WOTS+C (the per-leaf OTS in SHRINCS' stateful path), signing reveals chain elements at depths corresponding to the message's base-w digit values. Two signatures from the same slot under different messages reveal **different sets of chain elements**, and an attacker can derive sk values at intermediate depths by combining them. From there: forge any message whose digit values are bounded by the union of the revealed depths.

For PORS+FP (inside the SPHINCS+ instances of SHRIMPS and SHRINCS' stateless fallback), the failure mode is more graceful — exceeding the design budget is "slow erosion, not a break", per delving 2355's degradation table. But two sigs from the *same compact-instance counter* still reveal correlated leaf disclosures, and at q_s = 2^10 the budget is small enough that single-slot reuse measurably degrades security.

Either way: **persist before sign**, with no exceptions.

---

## 3. The on-disk write protocol

Implemented in `crypto/state_file.go::FileStateIO.Write`:

```
1. Wrap body with CRC:    body' = append(body, crc32.ChecksumIEEE(body))
2. Write body' to <name>.tmp
3. fsync(<name>.tmp)
4. rename(<name>.tmp, <name>)            ← POSIX atomic
5. fsync(parent_dir)                     ← so the rename is durable
```

Each step matters:

- **Step 1 (CRC trailer)**: catches in-memory bit flips between `Read` and the next `Sign` call. GCM (in encrypted wallets) catches ciphertext-side tamper, but by the time the signing math runs the data is plaintext in RAM. CRC is the second line of defense.
- **Steps 2–3 (write to .tmp + fsync)**: data hits stable storage before the rename.
- **Step 4 (atomic rename)**: POSIX guarantees the rename is atomic. After the rename, either the new contents are visible (success) or the old ones are (failure) — never partial.
- **Step 5 (parent-dir fsync)**: rename durability requires the parent directory's metadata to be flushed too, otherwise a power loss between rename and the next directory-metadata flush can revert the rename.

---

## 4. The full layered stack (encrypted-wallet variant)

For SHRINCS / SHRIMPS state files owned by an encrypted wallet, the in-memory body goes through:

```
plaintext counter struct
  ↓  AppendCRC                 32-bit CRC trailer
crc-wrapped plaintext
  ↓  AES-256-GCM.Seal          fresh 12-byte nonce per write
sealed bytes
  ↓  FileStateIO write          atomic write+rename+fsync (steps 2–5 above)
on-disk state file
```

`wallet.storeStateIO` (in `wallet/state_io.go`) is the adapter implementing `crypto.StateIO` against the encrypted store. SHRINCS / SHRIMPS treat it identically to `FileStateIO` — they don't know about encryption.

The CRC sits **inside** the GCM ciphertext on purpose:

| Defense | Where bit flip is caught |
|---|---|
| GCM auth tag | Anywhere in the ciphertext on disk. `Open` fails. |
| CRC | Anywhere between `Open` returning plaintext and the next `Sign` call. `StripAndVerifyCRC` returns `ErrStateCorrupted`. |

A signing call that hits either failure must **not sign** — same surface as a missing state file.

---

## 5. The persist point

The "persist" point in the rule is `StateIO.Write` returning success. For a plaintext wallet, that's the rename + parent-dir fsync. For an encrypted wallet, that's the *ciphertext* having reached durable storage under a fresh GCM nonce.

In both cases: **after `Write` returns**, the new counter is durable. Before then, no signing math is allowed to run.

```go
// crypto/shrincs.go::Sign — schematic
func (k *ShrincsKey) Sign(ctx context.Context, msg []byte) (ShrincsSig, error) {
    // 1. Load counter; pick stateful or stateless path under the min-rule.
    state, err := k.loadState()
    if err != nil { return ShrincsSig{}, err }   // ErrStateCorrupted, etc.

    // 2. Compute the sig parameters but DO NOT EMIT THE SIG.
    pickedSlot := state.Counter
    nextState  := state.advance()
    if err := ctx.Err(); err != nil { return ShrincsSig{}, err }

    // 3. *** PERSIST BEFORE SIGN ***
    if err := k.io.Write(k.name, nextState.Marshal()); err != nil {
        return ShrincsSig{}, err
    }

    // 4. Now compute the actual signature.
    sig := k.signSlot(pickedSlot, msg)
    return sig, nil
}
```

`ctx.Err()` is checked between phases so cancellation can interrupt cleanly between persist and sign, not mid-syscall. The inner SHA-256 math is uncancellable; cancellation surfaces at the next phase boundary.

---

## 6. What "atomic" means here

"Atomic" in this doc means **POSIX atomic rename**: after `rename(.tmp, .)` returns, every subsequent `open(.)` either sees the new contents or the old ones, never a partial write. The combination of:

- write to `.tmp`,
- `fsync(.tmp)` (data durable),
- `rename(.tmp, .)` (atomic visibility flip),
- `fsync(parent_dir)` (rename durable),

is what `crypto.StateIO.Write` actually does on a sane Linux filesystem. ZFS, ext4 (default `data=ordered`), and XFS all honor it.

It is *not* "atomic" in any database-transaction sense — there's no rollback once the rename has landed. Once `Write` returns, the new counter is the durable truth.

---

## 7. Failure modes

| Scenario | Outcome |
|---|---|
| Power loss after step 1, before step 4 | `.tmp` exists, original is intact. Next read uses original. **No slot consumed.** |
| Power loss after step 4, before step 5 | Filesystem-dependent. Most journaling FSes preserve the rename through their own journal even without the dir fsync. ZFS guarantees it. The dir fsync is belt-and-braces. |
| Disk corruption flips a byte in the on-disk state file | CRC mismatch on next read → `ErrStateCorrupted` → SHRINCS / SHRIMPS refuse to sign. |
| Disk corruption flips a byte in the encrypted state file | GCM auth-tag failure → `wallet.Decrypt` returns error → SHRINCS / SHRIMPS refuse to sign. |
| Bit flip in RAM between decrypt and sign | CRC mismatch in plaintext → `StripAndVerifyCRC` returns `ErrStateCorrupted`. |
| Wallet locked when sign is attempted | `wallet.ErrLocked` returned to caller; no state file touched. |

Across every scenario, the worst outcome is "this signing attempt fails" — never "we silently signed under a reused slot".

---

## 8. The rule in code

The contract is part of `crypto.StateIO`. Anything that implements it must guarantee that `Write(name, body)` returning nil means the bytes are durable on disk. That's the contract the rule depends on.

```go
type StateIO interface {
    Read(name string) ([]byte, error)
    Write(name string, body []byte) error    // atomic, fsync'd
}
```

`FileStateIO` (plaintext) and `wallet.storeStateIO` (encrypted) are the two production implementations. Both enforce the protocol. Mock `StateIO`s in tests are allowed to be looser; production code must use the real ones.
