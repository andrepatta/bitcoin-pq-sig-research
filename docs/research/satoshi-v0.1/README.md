# Satoshi Bitcoin v0.1 — reference snapshot

Verbatim copy of the original Satoshi Bitcoin v0.1 source files referenced when implementing qBitcoin's script interpreter, serialization layer, and wire protocol. They're here as the **authoritative source of truth** for any "is this Bitcoin-faithful?" question that pre-dates Bitcoin Core's modern refactors.

---

## Files

| File | Why it's here |
|---|---|
| `script.h`, `script.cpp` | **Opcode hex values verbatim.** `script/opcodes.go` derives every `OP_*` constant from `script.h`. Modern Bitcoin Core renumbers nothing, but reading directly from v0.1 makes the lineage unambiguous. |
| `main.h`, `main.cpp` | Reference for block / tx / coinbase / sighash semantics. The 2016-block retarget formula, median-of-11 timestamp rule, and coinbase-maturity = 100 blocks all come from this code. |
| `serialize.h` | The variable-int encoding (`COMPACTSIZE`), `WriteCompactSize` / `ReadCompactSize`, and the `CDataStream` shape that informs our serialization in `core/block.go` and `txn/tx.go`. |
| `net.h`, `net.cpp` | Wire-protocol message types, `version` / `verack` handshake, inv / getdata / block / tx semantics. `p2p/messages.go` ships Bitcoin's `CMessageHeader` framing (magic + 12-byte command + length + SHA256d checksum) verbatim, and the application-level message taxonomy matches one-for-one. |
| `db.h`, `db.cpp` | The original Berkeley-DB persistence layer. Not used (we ship Pebble) but the bucket-shaped key space and the way Satoshi handled atomic writes informed `storage/db.go` and `crypto/state_file.go`. |
| `key.h` | ECDSA key type. Provided here as the **direct counterpart** to qBitcoin's SHRINCS / SHRIMPS — read it side-by-side with `crypto/shrincs.go` to see what the PQ swap actually replaces. |
| `util.h`, `util.cpp`, `irc.cpp` | Bootstrap / utility code — included for completeness; not directly mirrored. |

---

## What this snapshot is *not*

It is not the latest Bitcoin Core. Several places in the qBitcoin docs say "matches Bitcoin Core" — that means modern Core's behavior, not Satoshi v0.1. Notable v0.1 → modern divergences that qBitcoin tracks **modern Core**, not v0.1, on:

- `OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_2MUL`, `OP_2DIV`, `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT` — defined in v0.1, **disabled** in modern Core. qBitcoin keeps them defined-but-disabled (returns `ErrDisabledOp` even inside an unexecuted `OP_IF` branch), matching modern Core.
- BIP-30 / BIP-34 / BIP-65 / BIP-66 / BIP-112 / BIP-141 — none of these existed in v0.1; qBitcoin implements the relevant subset (BIP-34 coinbase-height embedding for uniqueness, no BIP-141 since there's no segwit).
- Median-of-11 timestamp + `+2h` future cap — v0.1 had a weaker rule; qBitcoin matches modern Core's stricter one.

The snapshot is here so that when reading our code's "this matches Bitcoin v0.1" comments, you can verify the claim against the actual v0.1 source instead of reconstructing it from a Bitcoin Core git blame.

---

## Source

These files are from the publicly-mirrored Satoshi v0.1 release. Original copyright 2008-2009 Satoshi Nakamoto, MIT-licensed (per the SPDX-style headers in each file).
