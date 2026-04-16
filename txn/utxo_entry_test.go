package txn

import (
	"testing"

	"qbitcoin/address"
)

// TestUTXOEntry_RoundTrip ensures the on-disk encoding preserves the
// coinbase flag and birth height that consensus uses for maturity gating.
func TestUTXOEntry_RoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		out      TxOutput
		coinbase bool
		height   uint32
	}{
		{"non-coinbase", TxOutput{Value: 1000, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xAA}}}, false, 42},
		{"coinbase block 0", TxOutput{Value: 5_000_000_000, Address: address.P2MRAddress{MerkleRoot: [32]byte{0xBB}}}, true, 0},
		{"coinbase max-height", TxOutput{Value: 1, Address: address.P2MRAddress{}}, true, ^uint32(0)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := SerializeOutput(tc.out, tc.coinbase, tc.height)
			if len(b) != UTXOEntrySize {
				t.Fatalf("encoded size %d, want %d", len(b), UTXOEntrySize)
			}
			out, cb, h, err := DeserializeOutput(b)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if out.Value != tc.out.Value || out.Address.MerkleRoot != tc.out.Address.MerkleRoot {
				t.Fatalf("output mismatch: %+v", out)
			}
			if cb != tc.coinbase {
				t.Fatalf("coinbase flag: got %v want %v", cb, tc.coinbase)
			}
			if h != tc.height {
				t.Fatalf("height: got %d want %d", h, tc.height)
			}
		})
	}
}

// TestUTXOEntry_RejectsLegacyLength ensures the new format fails fast on
// a 40-byte legacy entry rather than silently misparsing.
func TestUTXOEntry_RejectsLegacyLength(t *testing.T) {
	legacy := make([]byte, 40) // value+root only
	if _, _, _, err := DeserializeOutput(legacy); err == nil {
		t.Fatal("expected length rejection on legacy 40 B entry")
	}
}
