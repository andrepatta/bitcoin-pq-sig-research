package txn

import (
	"encoding/binary"
	"testing"
)

// TestDeserializeTx_InputCountCap rejects a tx claiming MaxTxInputs+1
// inputs without trying to allocate the slice.
func TestDeserializeTx_InputCountCap(t *testing.T) {
	var b [8]byte
	binary.BigEndian.PutUint32(b[0:4], 1)             // version
	binary.BigEndian.PutUint32(b[4:8], MaxTxInputs+1) // input count
	if _, _, err := DeserializeTx(b[:]); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}

// TestDeserializeTx_OutputCountCap mirrors the above for outputs.
func TestDeserializeTx_OutputCountCap(t *testing.T) {
	b := make([]byte, 4+4+4)
	binary.BigEndian.PutUint32(b[0:4], 1)               // version
	binary.BigEndian.PutUint32(b[4:8], 0)               // 0 inputs
	binary.BigEndian.PutUint32(b[8:12], MaxTxOutputs+1) // output count
	if _, _, err := DeserializeTx(b); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}

// TestDeserializeTx_SpendLenCap rejects an input whose spend-length
// exceeds MaxSpendSerializedSize.
func TestDeserializeTx_SpendLenCap(t *testing.T) {
	b := make([]byte, 4+4+32+4+4)
	binary.BigEndian.PutUint32(b[0:4], 1) // version
	binary.BigEndian.PutUint32(b[4:8], 1) // 1 input
	// prev txid b[8:40] = zero
	binary.BigEndian.PutUint32(b[40:44], 0)                        // prev index
	binary.BigEndian.PutUint32(b[44:48], MaxSpendSerializedSize+1) // spLen
	if _, _, err := DeserializeTx(b); err == nil {
		t.Fatal("expected cap rejection, got nil")
	}
}
