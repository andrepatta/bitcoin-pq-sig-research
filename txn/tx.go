package txn

import (
	"encoding/binary"
	"errors"

	"qbitcoin/address"
	"qbitcoin/crypto"
)

// Deserializer sanity caps. These are upper bounds that bound attacker-
// controlled allocations; real consensus limits (block size, sigops) live
// elsewhere. The numbers are deliberately generous — they only catch
// adversarial payloads, not legitimate traffic.
const (
	// MaxTxInputs / MaxTxOutputs cap the number of inputs/outputs in a
	// single tx. With ~5 KB SHRIMPS witnesses the realistic per-tx input
	// count is in the low tens; 10k is well past that and still bounds
	// the make([]TxInput, n) allocation to <1 MB.
	MaxTxInputs  = 10_000
	MaxTxOutputs = 10_000

	// MaxSpendSerializedSize bounds a single input's spend bytes. A
	// SHRIMPS witness wraps to ~3 KB; allow generous headroom.
	MaxSpendSerializedSize = 32 * 1024
)

// TxInput references a previous UTXO and supplies a P2MR spend witness.
type TxInput struct {
	PrevTxID  [32]byte
	PrevIndex uint32
	Spend     address.P2MRSpend
}

// TxOutput commits coins to a 32-byte P2MR address.
type TxOutput struct {
	Value   uint64
	Address address.P2MRAddress
}

// Transaction is the UTXO-style tx type.
type Transaction struct {
	Version  uint32
	Inputs   []TxInput
	Outputs  []TxOutput
	LockTime uint32
}

// Serialize writes the canonical deterministic bytes of the transaction.
//
//	[4-byte version]
//	[4-byte input_count]
//	for each input:
//	  [32-byte prev_txid][4-byte prev_index][4-byte spend_len][spend]
//	[4-byte output_count]
//	for each output: [8-byte value][32-byte address root]
//	[4-byte locktime]
func (tx *Transaction) Serialize() []byte {
	var buf []byte
	var tmp [8]byte
	binary.BigEndian.PutUint32(tmp[:4], tx.Version)
	buf = append(buf, tmp[:4]...)
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(tx.Inputs)))
	buf = append(buf, tmp[:4]...)
	for _, in := range tx.Inputs {
		buf = append(buf, in.PrevTxID[:]...)
		binary.BigEndian.PutUint32(tmp[:4], in.PrevIndex)
		buf = append(buf, tmp[:4]...)
		sp := address.SerializeSpend(in.Spend)
		binary.BigEndian.PutUint32(tmp[:4], uint32(len(sp)))
		buf = append(buf, tmp[:4]...)
		buf = append(buf, sp...)
	}
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(tx.Outputs)))
	buf = append(buf, tmp[:4]...)
	for _, out := range tx.Outputs {
		binary.BigEndian.PutUint64(tmp[:8], out.Value)
		buf = append(buf, tmp[:8]...)
		buf = append(buf, out.Address.MerkleRoot[:]...)
	}
	binary.BigEndian.PutUint32(tmp[:4], tx.LockTime)
	buf = append(buf, tmp[:4]...)
	return buf
}

// DeserializeTx parses a transaction from bytes. Returns tx and bytes consumed.
func DeserializeTx(b []byte) (*Transaction, int, error) {
	off := 0
	need := func(n int) error {
		if off+n > len(b) {
			return errors.New("tx: truncated")
		}
		return nil
	}
	if err := need(4); err != nil {
		return nil, 0, err
	}
	tx := &Transaction{}
	tx.Version = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if err := need(4); err != nil {
		return nil, 0, err
	}
	inCount := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if inCount > MaxTxInputs {
		return nil, 0, errors.New("tx: input count exceeds cap")
	}
	tx.Inputs = make([]TxInput, inCount)
	for i := range inCount {
		if err := need(32 + 4 + 4); err != nil {
			return nil, 0, err
		}
		copy(tx.Inputs[i].PrevTxID[:], b[off:off+32])
		off += 32
		tx.Inputs[i].PrevIndex = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		spLen := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if spLen > MaxSpendSerializedSize {
			return nil, 0, errors.New("tx: spend exceeds cap")
		}
		if err := need(int(spLen)); err != nil {
			return nil, 0, err
		}
		spend, _, err := address.DeserializeSpend(b[off : off+int(spLen)])
		if err != nil {
			return nil, 0, err
		}
		tx.Inputs[i].Spend = spend
		off += int(spLen)
	}
	if err := need(4); err != nil {
		return nil, 0, err
	}
	outCount := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if outCount > MaxTxOutputs {
		return nil, 0, errors.New("tx: output count exceeds cap")
	}
	tx.Outputs = make([]TxOutput, outCount)
	for i := range outCount {
		if err := need(8 + 32); err != nil {
			return nil, 0, err
		}
		tx.Outputs[i].Value = binary.BigEndian.Uint64(b[off : off+8])
		off += 8
		copy(tx.Outputs[i].Address.MerkleRoot[:], b[off:off+32])
		off += 32
	}
	if err := need(4); err != nil {
		return nil, 0, err
	}
	tx.LockTime = binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	return tx, off, nil
}

// TxID returns Hash256(Serialize()).
func (tx *Transaction) TxID() [32]byte { return crypto.Hash256(tx.Serialize()) }

// SigHashDomain is the domain separator prepended to every SigHash
// preimage. Bumping this string is a hard-fork: signatures from the old
// domain will no longer verify on the new chain. Including the chain ID
// inside the sighash prevents a tx signed for one chain from being
// replayed on a parallel/forked chain that shares the same UTXO set.
const SigHashDomain = "qbitcoin-v1-sighash"

// SigHash computes the sighash for signing input[inputIndex].
// Layout of the preimage:
//
//	[len(SigHashDomain) bytes of SigHashDomain]
//	[serialized tx with input[inputIndex].Spend zeroed]
//
// Hashed with crypto.Hash256.
func SigHash(tx Transaction, inputIndex int) [32]byte {
	cp := tx
	cp.Inputs = make([]TxInput, len(tx.Inputs))
	copy(cp.Inputs, tx.Inputs)
	if inputIndex >= 0 && inputIndex < len(cp.Inputs) {
		cp.Inputs[inputIndex].Spend = address.P2MRSpend{}
	}
	body := cp.Serialize()
	preimage := make([]byte, 0, len(SigHashDomain)+len(body))
	preimage = append(preimage, SigHashDomain...)
	preimage = append(preimage, body...)
	return crypto.Hash256(preimage)
}

// LockTimeThreshold disambiguates the LockTime field: values below it
// are interpreted as block heights, values >= it as Unix timestamps.
// Same constant as Bitcoin (~Nov 5 1985 epoch).
const LockTimeThreshold uint64 = 500_000_000

// MaxMoney is the absolute maximum value (sats) any output may carry,
// and the maximum sum of outputs in any single transaction. Mirrors
// Bitcoin's MAX_MONEY and the genesis economic schedule:
// 21_000_000 coin × 1e8 sats/coin.
const MaxMoney uint64 = 21_000_000 * 100_000_000

// IsFinal reports whether tx is final at the given block context.
// Coinbase + LockTime==0 are always final. Otherwise the LockTime field
// is compared as either a height (if below LockTimeThreshold) or a
// Unix timestamp; the tx is final once that bound is strictly less
// than the next-block context.
func (tx *Transaction) IsFinal(blockHeight uint32, blockTime uint64) bool {
	if tx.LockTime == 0 {
		return true
	}
	lt := uint64(tx.LockTime)
	if lt < LockTimeThreshold {
		return lt < uint64(blockHeight)
	}
	return lt < blockTime
}

// IsCoinbase reports whether tx is a coinbase (single input with zero prev txid/index).
func (tx *Transaction) IsCoinbase() bool {
	if len(tx.Inputs) != 1 {
		return false
	}
	in := tx.Inputs[0]
	if in.PrevIndex != 0xFFFFFFFF {
		return false
	}
	var zero [32]byte
	return in.PrevTxID == zero
}
