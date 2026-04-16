# `address/` — 2-leaf Pay-to-Merkle-Root

Every qBitcoin address is a 32-byte Merkle root over **exactly two leaves**. Never one, never three. The on-chain output script is just the 32 bytes — no public keys, no scripts, no witness program. Same on-chain footprint as a Bitcoin Taproot output, different commitment structure (committing to a PQ pubkey set instead of an x-only Schnorr key).

---

## 1. The 2-leaf shape

```
Leaf 0:  <shrincs_pk>  OP_CHECKSIG   ← primary, single-device, ~324 B sigs
Leaf 1:  <shrimps_pk>  OP_CHECKSIG   ← multi-device, ~2,646 B sigs

Address = Hash256(  Hash256(leaf0_script)  ||  Hash256(leaf1_script)  )
```

Both leaves use the canonical **P2PK template** `<pubkey> OP_CHECKSIG`. Polymorphism between SHRINCS and SHRIMPS comes from the **1-byte scheme tag** on the pushed signature at spend time — not from separate opcodes per leaf. See [`script.md`](script.md) §6.

A spend reveals exactly one leaf, the corresponding witness, and a Merkle proof against the address root.

### Why not 1 leaf?

A 1-leaf address would force every wallet to commit to either SHRINCS or SHRIMPS at receive time. Recipients don't always know which signing path they'll use, and it forecloses the multi-device option for users who later want it. Two leaves is the paper's recommendation (delving-bitcoin.org/t/2355) and what Kudinov & Nick model in §14 ("HD wallets" → key-pool of `(SHRINCS, SHRIMPS)` pairs).

### Why not 3 leaves?

A 3-leaf shape with a third "recovery" leaf would re-introduce on-chain rotation logic that isn't required: SHRINCS' internal stateful → stateless fallback (invariant #4) already preserves access to old funds, and users wanting fresh receive addresses just call `Wallet.NewReceiveAddress()` to advance the BIP-44 account index. See [`docs/invariants.md`](../invariants.md) §8.

---

## 2. Files

`address/p2mr.go` — the only file in the package.

### Types

```go
type LeafScript []byte                  // Bitcoin-script bytes for one leaf

type P2MRAddress struct {
    MerkleRoot [32]byte                 // exactly 32 bytes on-chain
}

type P2MRSpend struct {
    LeafScript  LeafScript              // the leaf being spent
    LeafIndex   uint8                   // 0 or 1
    MerkleProof [][32]byte              // sibling hash chain to root (one element for 2-leaf)
    Witness     [][]byte                // [ tagged_sig ]  for the canonical P2PK template
}
```

### Builders

```go
// NewP2PKLeaf builds the canonical leaf script "<pubkey> OP_CHECKSIG".
func NewP2PKLeaf(pubkey []byte) LeafScript

// BuildTwoLeafAddress wraps the two leaves into a P2MRAddress.
func BuildTwoLeafAddress(shrincsPK, shrimpsPK []byte) P2MRAddress

// Bech32 encoding for human-readable addresses (qbtc1... HRP).
func (a P2MRAddress) String() string
func DecodeAddress(s string) (P2MRAddress, error)
```

### Verification (called from `txn.script.go::Execute`)

```go
1. leafHash := crypto.Hash256(spend.LeafScript)
2. require crypto.VerifyProof(addr.MerkleRoot, leafHash, spend.MerkleProof, int(spend.LeafIndex))
3. require script.Execute(spend.Witness, spend.LeafScript, crypto.DefaultSigChecker, txSigHash) == true
```

---

## 3. Bech32 encoding

Standard `btcutil/bech32`. HRP = `qbtc` (testnet shape; SLIP-44 coin type `1'`). Witness version `0x01` (informally — the chain has no segwit, but the bech32 format borrows the 5-bit conversion).

The 32-byte Merkle root encodes to a ~62-character bech32 string:

```
qbtc1qpz3v…   (example)
```

A wallet's `Address()` returns the bech32 string; the on-chain output script holds only the 32-byte root.

---

## 4. Bound checks (length-bomb defense)

`address/p2mr.go` enforces strict deserialization-side bounds to defeat length-bomb attacks against spend parsing:

| Constant | Value | Why |
|---|---|---|
| `MaxLeafScriptSize` | 1024 B | Caps `LeafScript` length on deserialize. |
| `MaxMerkleProofDepth` | 32 | Prevents pathological proof chains. |
| `MaxWitnessItemCount` | 16 | Caps witness-stack length. |
| `MaxWitnessItemSize` | 32 KB | Caps each witness element. SHRIMPS sigs (~2.6 KB) and SHRINCS stateless fallback (~4 KB) sit comfortably under. |

Any spend that exceeds these limits is rejected before any cryptographic work begins.

---

## 5. Public API summary

```go
type LeafScript     = []byte
type P2MRAddress    struct { MerkleRoot [32]byte }
type P2MRSpend      struct { LeafScript; LeafIndex; MerkleProof; Witness }

func NewP2PKLeaf(pubkey []byte) LeafScript
func BuildTwoLeafAddress(shrincsPK, shrimpsPK []byte) P2MRAddress
func (P2MRAddress) String() string
func DecodeAddress(s string) (P2MRAddress, error)

const (
    MaxLeafScriptSize    = 1024
    MaxMerkleProofDepth  = 32
    MaxWitnessItemCount  = 16
    MaxWitnessItemSize   = 32 * 1024
)
```

---

## 6. Tests

| Test file | Coverage |
|---|---|
| `address/p2mr_caps_test.go` | All four `Max*` limits rejected at deserialization. |
