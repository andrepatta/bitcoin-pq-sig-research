package txn

import (
	"encoding/binary"
	"errors"
	"sync"

	"qbitcoin/address"
)

// UTXOKey is the composite key used to index a UTXO.
type UTXOKey struct {
	TxID  [32]byte
	Index uint32
}

// Bytes returns the canonical 36-byte big-endian key.
func (k UTXOKey) Bytes() []byte {
	b := make([]byte, 36)
	copy(b[:32], k.TxID[:])
	binary.BigEndian.PutUint32(b[32:], k.Index)
	return b
}

// ParseUTXOKey reparses the 36-byte encoded key.
func ParseUTXOKey(b []byte) (UTXOKey, error) {
	if len(b) != 36 {
		return UTXOKey{}, errors.New("utxo key: wrong length")
	}
	var k UTXOKey
	copy(k.TxID[:], b[:32])
	k.Index = binary.BigEndian.Uint32(b[32:])
	return k, nil
}

// UTXOEntrySize is the on-disk byte size of a serialized UTXO entry:
//
//	[8 B value][32 B address root][1 B coinbase flag][4 B birth height]
//
// The coinbase flag and height are storage-side metadata stamped at apply
// time; they are NOT part of the transaction wire format (see
// Transaction.Serialize, which writes only value+root).
const UTXOEntrySize = 8 + 32 + 1 + 4

// SerializeOutput writes the on-disk UTXO entry. `coinbase` and `height`
// describe the *containing* transaction (for coinbase maturity checks).
func SerializeOutput(o TxOutput, coinbase bool, height uint32) []byte {
	b := make([]byte, UTXOEntrySize)
	binary.BigEndian.PutUint64(b[:8], o.Value)
	copy(b[8:40], o.Address.MerkleRoot[:])
	if coinbase {
		b[40] = 1
	}
	binary.BigEndian.PutUint32(b[41:45], height)
	return b
}

// DeserializeOutput parses SerializeOutput output and returns the
// stamped coinbase flag + birth height alongside the TxOutput.
func DeserializeOutput(b []byte) (TxOutput, bool, uint32, error) {
	if len(b) != UTXOEntrySize {
		return TxOutput{}, false, 0, errors.New("output: wrong length")
	}
	var o TxOutput
	o.Value = binary.BigEndian.Uint64(b[:8])
	copy(o.Address.MerkleRoot[:], b[8:40])
	coinbase := b[40] == 1
	height := binary.BigEndian.Uint32(b[41:45])
	return o, coinbase, height, nil
}

// UTXOSet is the interface used by the blockchain and mempool.
type UTXOSet interface {
	Get(key UTXOKey) (*TxOutput, error)
	Put(key UTXOKey, out TxOutput) error
	Delete(key UTXOKey) error
	Has(key UTXOKey) (bool, error)
	Balance(addr address.P2MRAddress) (uint64, error)
	AllForAddress(addr address.P2MRAddress) ([]UTXOKey, []TxOutput, error)
}

// MemUTXOSet is an in-memory implementation (useful for tests + mempool validation).
type MemUTXOSet struct {
	mu sync.RWMutex
	m  map[[36]byte]TxOutput
}

// NewMemUTXOSet returns a new empty in-memory set.
func NewMemUTXOSet() *MemUTXOSet {
	return &MemUTXOSet{m: map[[36]byte]TxOutput{}}
}

func keyToArr(k UTXOKey) [36]byte {
	var a [36]byte
	copy(a[:], k.Bytes())
	return a
}

// Get returns the output at key or nil.
func (u *MemUTXOSet) Get(k UTXOKey) (*TxOutput, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	v, ok := u.m[keyToArr(k)]
	if !ok {
		return nil, nil
	}
	return &v, nil
}

// Put stores an output.
func (u *MemUTXOSet) Put(k UTXOKey, o TxOutput) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.m[keyToArr(k)] = o
	return nil
}

// Delete removes a UTXO.
func (u *MemUTXOSet) Delete(k UTXOKey) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.m, keyToArr(k))
	return nil
}

// Has reports presence.
func (u *MemUTXOSet) Has(k UTXOKey) (bool, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	_, ok := u.m[keyToArr(k)]
	return ok, nil
}

// Balance sums value for outputs that match addr.
func (u *MemUTXOSet) Balance(addr address.P2MRAddress) (uint64, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	var total uint64
	for _, v := range u.m {
		if v.Address.MerkleRoot == addr.MerkleRoot {
			total += v.Value
		}
	}
	return total, nil
}

// AllForAddress returns all UTXOs for an address.
func (u *MemUTXOSet) AllForAddress(addr address.P2MRAddress) ([]UTXOKey, []TxOutput, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	var keys []UTXOKey
	var outs []TxOutput
	for k, v := range u.m {
		if v.Address.MerkleRoot == addr.MerkleRoot {
			kk, err := ParseUTXOKey(k[:])
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, kk)
			outs = append(outs, v)
		}
	}
	return keys, outs, nil
}
