package p2p

import (
	"encoding/binary"
	"testing"
)

// TestDecodeInv_CountCap rejects a payload claiming more than
// MaxInvItems without performing the allocation.
func TestDecodeInv_CountCap(t *testing.T) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], MaxInvItems+1)
	if _, err := DecodeInv(b[:]); err == nil {
		t.Fatal("expected inv count-cap rejection")
	}
}

// TestDecodeInv_OverflowSafe catches the uint32-wrap vulnerability:
// a count crafted so `33*count` overflows to a small value would
// otherwise sneak past the length gate and trigger a huge make().
// Post-fix the count cap rejects it first; this guards the arithmetic
// path in case the cap is ever relaxed above the wrap threshold.
func TestDecodeInv_OverflowSafe(t *testing.T) {
	// 4_294_967_295 / 33 ≈ 130_150_524 → 33*n wraps uint32.
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], 130_150_525)
	if _, err := DecodeInv(b[:]); err == nil {
		t.Fatal("expected rejection; overflowed size check would allocate GB")
	}
}

// TestDecodeInv_RoundTrip confirms the cap doesn't reject realistic batches.
func TestDecodeInv_RoundTrip(t *testing.T) {
	in := []InvItem{
		{Type: InvTx, Hash: [32]byte{0x01}},
		{Type: InvBlock, Hash: [32]byte{0x02}},
	}
	out, err := DecodeInv(EncodeInv(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("count: got %d want %d", len(out), len(in))
	}
}

// TestDecodeGetBlocks_CountCap rejects a locator exceeding MaxLocatorHashes.
func TestDecodeGetBlocks_CountCap(t *testing.T) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], MaxLocatorHashes+1)
	if _, err := DecodeGetBlocks(b[:]); err == nil {
		t.Fatal("expected locator cap rejection")
	}
}

// TestDecodeGetBlocks_OverflowSafe guards the uint64 size math against
// a uint32-wrap that would bypass the length check.
func TestDecodeGetBlocks_OverflowSafe(t *testing.T) {
	// 2^32 / 32 = 134_217_728 → 32*n wraps uint32 to 0.
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], 134_217_728)
	if _, err := DecodeGetBlocks(b[:]); err == nil {
		t.Fatal("expected rejection; overflowed size check would allocate GB")
	}
}

// TestDecodePeerRecord_RejectsShort ensures a truncated record is
// caught before any out-of-bounds read. The new peer-record layout is
// fixed-size (18-byte NetAddr), so the old variable-count cap no
// longer applies; what we defend against is an undersized buffer.
func TestDecodePeerRecord_RejectsShort(t *testing.T) {
	if _, err := decodePeerRecord([]byte{0x00}); err == nil {
		t.Fatal("expected truncation rejection")
	}
}
