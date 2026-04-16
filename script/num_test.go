package script

import (
	"bytes"
	"testing"
)

// TestNumEncodeKnownAnswers pins the byte layout against a table of
// hand-verified fixtures. These are the values Bitcoin Core's
// CScriptNum emits for the same inputs, so any divergence would break
// cross-implementation scripts.
func TestNumEncodeKnownAnswers(t *testing.T) {
	cases := []struct {
		n    Num
		want []byte
	}{
		{0, nil},
		{1, []byte{0x01}},
		{-1, []byte{0x81}},
		{127, []byte{0x7F}},
		{-127, []byte{0xFF}},
		{128, []byte{0x80, 0x00}},  // MSB-set magnitude → pad positive with 0x00
		{-128, []byte{0x80, 0x80}}, // ... or with 0x80 for negative
		{255, []byte{0xFF, 0x00}},
		{-255, []byte{0xFF, 0x80}},
		{256, []byte{0x00, 0x01}},
		{-256, []byte{0x00, 0x81}},
		{32767, []byte{0xFF, 0x7F}},
		{-32767, []byte{0xFF, 0xFF}},
		{32768, []byte{0x00, 0x80, 0x00}},
		{-32768, []byte{0x00, 0x80, 0x80}},
		{2147483647, []byte{0xFF, 0xFF, 0xFF, 0x7F}},
		{-2147483647, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		got := tc.n.Encode()
		if !bytes.Equal(got, tc.want) {
			t.Errorf("Encode(%d) = %x, want %x", tc.n, got, tc.want)
		}
	}
}

// TestDecodeNumRoundTrip asserts Encode∘Decode = id across a wide
// numeric range. Any break here means CScriptNum isn't canonical.
func TestDecodeNumRoundTrip(t *testing.T) {
	samples := []Num{
		0, 1, -1, 127, -127, 128, -128, 255, -255, 256, -256,
		65535, -65535, 65536, -65536, 16_777_215, -16_777_215,
		2_147_483_647, -2_147_483_647,
	}
	for _, n := range samples {
		b := n.Encode()
		back, err := DecodeNum(b, MaxScriptNumLen)
		if err != nil {
			t.Errorf("DecodeNum(%x): %v", b, err)
			continue
		}
		if back != n {
			t.Errorf("round-trip %d → %x → %d", n, b, back)
		}
	}
}

// TestDecodeNumRejectsOverlong rejects operand byte-strings that exceed
// maxLen. The arithmetic ops pass MaxScriptNumLen=4; any operand from
// a previous op that encoded to >4 bytes fails here.
func TestDecodeNumRejectsOverlong(t *testing.T) {
	// 5-byte operand — valid encoding, but >MaxScriptNumLen.
	b := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	if _, err := DecodeNum(b, MaxScriptNumLen); err == nil {
		t.Fatal("expected overlong reject")
	}
}

// TestDecodeNumRejectsNonMinimal rejects trailing-zero encodings of
// values that fit in fewer bytes. Matches BIP-62 minimal-encoding rule.
func TestDecodeNumRejectsNonMinimal(t *testing.T) {
	bad := [][]byte{
		{0x00},             // zero should be empty
		{0x01, 0x00},       // 1 should be [0x01]
		{0x80, 0x00, 0x00}, // 128-with-extra-pad
		{0x01, 0x80},       // -1 should be [0x81] (extra byte just flips sign)
	}
	for _, b := range bad {
		if _, err := DecodeNum(b, MaxScriptNumLen); err == nil {
			t.Errorf("expected non-minimal reject for %x", b)
		}
	}
}

// TestDecodeNumBoundaryNonMinimal confirms the one case where trailing
// 0x00 IS allowed: when removing it would flip the sign bit of the
// byte below. E.g. [0x80,0x00] = 128, not rejected because stripping
// the 0x00 would turn it into [0x80] = -0 (different value).
func TestDecodeNumBoundaryNonMinimal(t *testing.T) {
	got, err := DecodeNum([]byte{0x80, 0x00}, MaxScriptNumLen)
	if err != nil {
		t.Fatalf("[0x80,0x00]: %v", err)
	}
	if got != 128 {
		t.Fatalf("[0x80,0x00] = %d, want 128", got)
	}
}

// TestCastToBool pins the conversion from raw stack bytes to a boolean.
// -0 (0x80 alone, or prefixed with zeros) must read false.
func TestCastToBool(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{nil, false},
		{[]byte{}, false},
		{[]byte{0x00}, false},
		{[]byte{0x00, 0x00}, false},
		{[]byte{0x80}, false},       // -0
		{[]byte{0x00, 0x80}, false}, // longer -0
		{[]byte{0x01}, true},
		{[]byte{0x00, 0x01}, true},
		{[]byte{0x81}, true}, // -1 is truthy
		{[]byte{0xFF}, true},
	}
	for _, tc := range cases {
		if got := CastToBool(tc.in); got != tc.want {
			t.Errorf("CastToBool(%x) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
