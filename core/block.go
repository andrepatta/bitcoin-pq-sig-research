package core

import (
	"encoding/binary"
	"errors"

	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// BlockHeader is fixed-size, serialized deterministically.
type BlockHeader struct {
	Version    uint32
	PrevHash   [32]byte
	MerkleRoot [32]byte
	Timestamp  uint64
	Bits       uint32
	Nonce      uint64
}

// Block contains the header and full transaction list.
type Block struct {
	Header BlockHeader
	Txns   []txn.Transaction
}

// HeaderSize is the fixed serialized size of a BlockHeader: 4+32+32+8+4+8 = 88 bytes.
const HeaderSize = 88

// MaxBlockSize bounds the total serialized block size accepted by
// DeserializeBlock and validation. PQ signatures are larger than
// classical Bitcoin's, so 4 MiB is the working ceiling. MVP9 makes the
// consensus-level enforcement explicit; this constant is the parsing
// guard.
const MaxBlockSize = 4 * 1024 * 1024

// MaxBlockTxCount bounds the per-block transaction count. Even at the
// smallest tx size (~100 B with one SHRINCS input) a 4 MiB block holds
// ~40k txs; 100k is well past that.
const MaxBlockTxCount = 100_000

// MaxBlockSigOpsCost bounds the summed signature-verification cost of
// every input across a block — Bitcoin's MAX_BLOCK_SIGOPS_COST analog.
// Each input contributes txn.ShrincsVerifyCost or txn.ShrimpsVerifyCost
// depending on its leaf-script opcode. 80_000 mirrors Bitcoin's segwit
// cap; at PQBC block sizes (~5700 1-input SHRINCS txs or ~1500 1-input
// SHRIMPS txs per 4 MiB block) it's a wide DoS ceiling rather than a
// near-miss on real traffic.
const MaxBlockSigOpsCost = 80_000

// Serialize returns the canonical 88-byte header. Little-endian for all
// integer fields to match Bitcoin's header layout.
func (h BlockHeader) Serialize() []byte {
	buf := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(buf[0:4], h.Version)
	copy(buf[4:36], h.PrevHash[:])
	copy(buf[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint64(buf[68:76], h.Timestamp)
	binary.LittleEndian.PutUint32(buf[76:80], h.Bits)
	binary.LittleEndian.PutUint64(buf[80:88], h.Nonce)
	return buf
}

// DeserializeHeader parses a canonical 88-byte header.
func DeserializeHeader(b []byte) (BlockHeader, error) {
	var h BlockHeader
	if len(b) < HeaderSize {
		return h, errors.New("header: too short")
	}
	h.Version = binary.LittleEndian.Uint32(b[0:4])
	copy(h.PrevHash[:], b[4:36])
	copy(h.MerkleRoot[:], b[36:68])
	h.Timestamp = binary.LittleEndian.Uint64(b[68:76])
	h.Bits = binary.LittleEndian.Uint32(b[76:80])
	h.Nonce = binary.LittleEndian.Uint64(b[80:88])
	return h, nil
}

// Hash returns the 32-byte SHA-256d PoW hash of the header — also serves
// as the block ID / storage key.
func (h BlockHeader) Hash() [32]byte { return crypto.Hash256(h.Serialize()) }

// SerializeBlock writes header + 4-byte tx count + each tx [4-byte len][tx bytes].
func (b *Block) Serialize() []byte {
	out := make([]byte, 0, HeaderSize+4+len(b.Txns)*128)
	out = append(out, b.Header.Serialize()...)
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], uint32(len(b.Txns)))
	out = append(out, tmp[:]...)
	for i := range b.Txns {
		tb := b.Txns[i].Serialize()
		binary.BigEndian.PutUint32(tmp[:], uint32(len(tb)))
		out = append(out, tmp[:]...)
		out = append(out, tb...)
	}
	return out
}

// DeserializeBlock parses a block.
func DeserializeBlock(b []byte) (*Block, error) {
	if len(b) > MaxBlockSize {
		return nil, errors.New("block: exceeds MaxBlockSize")
	}
	if len(b) < HeaderSize+4 {
		return nil, errors.New("block: too short")
	}
	h, err := DeserializeHeader(b[:HeaderSize])
	if err != nil {
		return nil, err
	}
	off := HeaderSize
	count := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if count > MaxBlockTxCount {
		return nil, errors.New("block: tx count exceeds cap")
	}
	txns := make([]txn.Transaction, count)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(b) {
			return nil, errors.New("block: tx len truncated")
		}
		n := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if n > MaxBlockSize {
			return nil, errors.New("block: tx body exceeds cap")
		}
		if off+int(n) > len(b) {
			return nil, errors.New("block: tx body truncated")
		}
		tx, _, err := txn.DeserializeTx(b[off : off+int(n)])
		if err != nil {
			return nil, err
		}
		txns[i] = *tx
		off += int(n)
	}
	return &Block{Header: h, Txns: txns}, nil
}

// ComputeMerkleRoot computes the Merkle root over the block's tx IDs.
func (b *Block) ComputeMerkleRoot() [32]byte {
	root, _ := b.ComputeMerkleRootMutated()
	return root
}

// ComputeMerkleRootMutated also reports CVE-2012-2459 mutation. Block
// validators must reject when mutated=true: a mutated tree admits a
// shorter tx list producing the same root, so a peer could relay a
// block with a disguised tx set.
func (b *Block) ComputeMerkleRootMutated() ([32]byte, bool) {
	ids := make([][32]byte, len(b.Txns))
	for i := range b.Txns {
		ids[i] = b.Txns[i].TxID()
	}
	return crypto.MerkleRootMutated(ids)
}
