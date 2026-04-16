package p2p

import (
	"testing"
)

// TestEncodeDecodeAddr_RoundTrip ensures the wire format survives a
// round-trip and DecodeAddr's caps don't reject realistic payloads.
func TestEncodeDecodeAddr_RoundTrip(t *testing.T) {
	mk := func(s string) NetAddr {
		a, ok := NetAddrFromHostPort(s)
		if !ok {
			t.Fatalf("NetAddrFromHostPort(%q)", s)
		}
		return a
	}
	in := []AddrEntry{
		{Timestamp: 1700000000, Addr: mk("192.168.0.1:8333")},
		{Timestamp: 1700000001, Addr: mk("10.0.0.1:8333")},
	}
	out, err := DecodeAddr(EncodeAddr(in))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Timestamp != in[i].Timestamp || out[i].Addr != in[i].Addr {
			t.Fatalf("entry %d mismatch: %+v vs %+v", i, out[i], in[i])
		}
	}
}

// TestDecodeAddr_RejectsOverlargeCount fires the safety cap.
func TestDecodeAddr_RejectsOverlargeCount(t *testing.T) {
	b := []byte{0x00, 0x00, 0x10, 0x01} // count = 4097
	if _, err := DecodeAddr(b); err == nil {
		t.Fatal("expected count cap rejection")
	}
}
