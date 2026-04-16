package core

import (
	"encoding/binary"
	"testing"
)

// TestDeserializeUndo_SpentCap rejects a persisted record claiming
// more spent entries than maxUndoEntries.
func TestDeserializeUndo_SpentCap(t *testing.T) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], maxUndoEntries+1)
	if _, err := deserializeUndo(b[:]); err == nil {
		t.Fatal("expected spent-cap rejection")
	}
}

// TestDeserializeUndo_CreatedCap rejects a record where the spent
// block ends but the created count is over-cap.
func TestDeserializeUndo_CreatedCap(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 0)                // 0 spent
	binary.BigEndian.PutUint32(b[4:8], maxUndoEntries+1) // created overflow
	if _, err := deserializeUndo(b); err == nil {
		t.Fatal("expected created-cap rejection")
	}
}
