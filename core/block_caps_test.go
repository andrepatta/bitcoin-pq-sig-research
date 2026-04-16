package core

import (
	"encoding/binary"
	"testing"
)

// TestDeserializeBlock_TooLarge rejects a payload exceeding MaxBlockSize
// without ever inspecting its contents.
func TestDeserializeBlock_TooLarge(t *testing.T) {
	b := make([]byte, MaxBlockSize+1)
	if _, err := DeserializeBlock(b); err == nil {
		t.Fatal("expected MaxBlockSize rejection, got nil")
	}
}

// TestDeserializeBlock_TxCountCap rejects a header-only block claiming
// over-cap tx count without allocating the txns slice.
func TestDeserializeBlock_TxCountCap(t *testing.T) {
	b := make([]byte, HeaderSize+4)
	// header bytes left zero — DeserializeHeader accepts any 88 B.
	binary.BigEndian.PutUint32(b[HeaderSize:HeaderSize+4], MaxBlockTxCount+1)
	if _, err := DeserializeBlock(b); err == nil {
		t.Fatal("expected MaxBlockTxCount rejection, got nil")
	}
}

// TestDeserializeBlock_TxBodyCap rejects a block whose declared per-tx
// length exceeds MaxBlockSize.
func TestDeserializeBlock_TxBodyCap(t *testing.T) {
	b := make([]byte, HeaderSize+4+4)
	binary.BigEndian.PutUint32(b[HeaderSize:HeaderSize+4], 1) // 1 tx
	binary.BigEndian.PutUint32(b[HeaderSize+4:HeaderSize+8], MaxBlockSize+1)
	if _, err := DeserializeBlock(b); err == nil {
		t.Fatal("expected per-tx cap rejection, got nil")
	}
}
