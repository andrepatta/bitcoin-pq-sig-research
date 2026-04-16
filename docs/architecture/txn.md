# `txn/` — transactions, sighash, UTXO set

The transaction layer. Owns the on-chain serialization of inputs and outputs, the sighash construction (with chain-ID binding), the UTXO interface, and the per-input sigops accounting that the mempool and consensus layers consume.

---

## 1. Files

| File | Owns |
|---|---|
| `tx.go` | `Transaction`, `TxInput`, `TxOutput`, `Serialize` / `Deserialize`, `TxID`, `SigHash`. |
| `script.go` | Thin wrapper that calls `script.Execute` with `crypto.DefaultSigChecker`; also computes `SigOpCost` per tx. |
| `utxo.go` | `UTXOKey`, `UTXOSet` interface, Pebble-backed implementation. |

---

## 2. Tx types

```go
type TxInput struct {
    PrevTxID  [32]byte
    PrevIndex uint32
    Spend     address.P2MRSpend     // leaf + proof + witness
    Sequence  uint32                // BIP-125 RBF signaling (full RBF — any sequence)
}

type TxOutput struct {
    Value   uint64
    Address address.P2MRAddress    // 32-byte Merkle root, no pubkeys
}

type Transaction struct {
    Version  uint32
    Inputs   []TxInput
    Outputs  []TxOutput
    LockTime uint32
}

func (tx *Transaction) TxID() [32]byte           // crypto.Hash256(Serialize())
func (tx *Transaction) Serialize() []byte
func DeserializeTx(b []byte) (Transaction, error)
```

`TxID = Hash256(tx.Serialize())` with witness data **included**. No segwit-style txid/wtxid distinction — PQ sigs are deterministic, no malleability to fix. See [`docs/invariants.md`](../invariants.md) §7.

`Sequence` is parsed but qBitcoin treats every tx as RBF-eligible (full RBF). BIP-125 opt-in flag is not honored — see [`mempool.md`](mempool.md) §3 for the policy.

`LockTime` is enforced — `IsFinal(blockHeight, blockTime)` checks the standard `LockTime < threshold ? blockHeight : blockTime` comparison.

---

## 3. Sighash — with chain-ID binding

```go
const SigHashDomain = "qbitcoin-v1-sighash"     // hard-fork bump bumps the suffix

func SigHash(tx Transaction, inputIndex int) [32]byte {
    // 1. Clone tx; zero out input[inputIndex].Spend.
    // 2. Concatenate: SigHashDomain || tx.Serialize()
    // 3. return crypto.Hash256(...)
}
```

Binds the signature to:

- All outputs.
- All other inputs.
- The chain identity (`SigHashDomain`).

The chain-ID binding prevents a signature from one qBitcoin chain (or a future fork) being replayed on another. To fork the chain semantics in a way that should invalidate old sigs, bump `SigHashDomain` to `"qbitcoin-v2-sighash"`.

Equivalent to Bitcoin's `SIGHASH_ALL`. We don't ship `SIGHASH_NONE` / `SIGHASH_SINGLE` / `SIGHASH_ANYONECANPAY` — they're a Bitcoin contract-flexibility feature with no immediate research value here, and adding them would expand the signed-message surface that the wallet has to think about.

---

## 4. `txn/script.go`

```go
// Execute one input's leaf script.
func Execute(spend address.P2MRSpend, sighash [32]byte, addr address.P2MRAddress) (bool, error) {
    leafHash := crypto.Hash256(spend.LeafScript)
    if !crypto.VerifyProof(addr.MerkleRoot, leafHash, spend.MerkleProof, int(spend.LeafIndex)) {
        return false, ErrBadMerkleProof
    }
    return script.Execute(spend.Witness, spend.LeafScript, crypto.DefaultSigChecker, sighash)
}

// SigOpCost charges per-input by the witness's scheme tag.
func SigOpCost(tx Transaction) int {
    cost := 0
    for _, in := range tx.Inputs {
        opCount := countCheckSigOpcodes(in.Spend.LeafScript)
        switch witnessSchemeTag(in.Spend.Witness) {
        case crypto.SchemeShrincs: cost += opCount * ShrincsVerifyCost   // 1 per OP_CHECKSIG
        case crypto.SchemeShrimps: cost += opCount * ShrimpsVerifyCost   // 2 per OP_CHECKSIG
        default:                   cost += opCount * ShrimpsVerifyCost   // unknown → worst case
        }
    }
    return cost
}

const (
    ShrincsVerifyCost           = 1
    ShrimpsVerifyCost           = 2
    MaxStandardTxSigOpsCost     = 16_000          // per-tx mempool cap
)
```

`SigOpCost` is parsed *before* execution — it reflects the witness's intent, not the actual verification cost. A wedge-sig that pretends to be SHRINCS at parse time but holds garbage will be charged at the SHRINCS cost, then fail at execute time. Worst-case fallback = SHRIMPS cost ensures pathological inputs can't under-charge themselves.

---

## 5. UTXO set

```go
type UTXOKey struct {
    TxID  [32]byte
    Index uint32
}

func (k UTXOKey) Bytes() []byte    // 32 + 4 = 36 B, big-endian index

type UTXOEntry struct {
    Output      TxOutput
    BlockHeight uint32           // for coinbase maturity check
    IsCoinbase  bool
}

type UTXOSet interface {
    Get(key UTXOKey) (*UTXOEntry, error)
    Apply(block core.Block, height uint32) error
    Rollback(block core.Block, undo UndoRecord) error
    Balance(addr address.P2MRAddress) (uint64, error)
}
```

Backing implementation lives in `core/blockchain.go`'s `applyBlockToUTXOs` — it batches UTXO mutations into a Pebble transaction and emits an `UndoRecord` (in `BucketUndo`) so reorgs can roll back atomically. See [`core.md`](core.md).

### Coinbase maturity

`UTXOEntry.IsCoinbase` triggers the maturity check. `core.CoinbaseMaturity = 100` blocks (Bitcoin-matched). A coinbase output cannot be spent until 100 confirmations.

---

## 6. Tx layout limits

| Constant | Value | Why |
|---|---|---|
| `MaxStandardTxSigOpsCost` | 16_000 | Per-tx sigops budget at mempool-policy level. Block budget is 80_000 (`core.MaxBlockSigOpsCost`). |
| `MaxTxSize` | 100_000 B | Per-tx serialized size — prevents pathologically large txs from running away with the mempool budget. |

Bitcoin uses 100 KB for the same purpose. Larger PQ sigs *do* make individual txs heavier than a typical Bitcoin tx, but at SHRIMPS-fallback worst case (4.2 KB sig × ~20 inputs = 84 KB) we still fit comfortably under.

---

## 7. Tests

| Test file | Coverage |
|---|---|
| `txn/tx_caps_test.go` | Tx-size + input/output-count caps. |
| `txn/sighash_domain_test.go` | `SigHashDomain` is mixed in; same tx with different domains hashes differently. |
| `txn/sigops_test.go` | `SigOpCost` charges 1 for SHRINCS / 2 for SHRIMPS / 2 for unknown. |
| `txn/locktime_test.go` | `IsFinal` height vs time threshold logic. |
| `txn/utxo_entry_test.go` | UTXOEntry serialization round-trip with the coinbase flag. |
