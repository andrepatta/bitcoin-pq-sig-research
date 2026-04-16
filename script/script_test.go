package script

import (
	"bytes"
	"testing"
)

// TestBuildPushMinimality pins that BuildPush always picks the smallest
// legal encoding for a given payload. Matching BIP-62 is what lets
// txid be stable across implementations.
func TestBuildPushMinimality(t *testing.T) {
	cases := []struct {
		data    []byte
		wantOp  byte
		wantLen int
	}{
		{[]byte{}, OP_0, 1},
		{[]byte{0x81}, OP_1NEGATE, 1},
		{[]byte{0x01}, OP_1, 1},
		{[]byte{0x10}, OP_16, 1},
		{[]byte{0x11}, 0x01, 2},              // 1-byte push
		{make([]byte, 75), 0x4B, 76},         // max raw push
		{make([]byte, 76), OP_PUSHDATA1, 78}, // PUSHDATA1 crossover
		{make([]byte, 255), OP_PUSHDATA1, 257},
		{make([]byte, 256), OP_PUSHDATA2, 259},
		{make([]byte, 65535), OP_PUSHDATA2, 65538},
		{make([]byte, 65536), OP_PUSHDATA4, 65541},
	}
	for _, tc := range cases {
		out := BuildPush(tc.data)
		if out[0] != tc.wantOp {
			t.Errorf("BuildPush(len=%d) opcode = 0x%02X, want 0x%02X", len(tc.data), out[0], tc.wantOp)
		}
		if len(out) != tc.wantLen {
			t.Errorf("BuildPush(len=%d) len = %d, want %d", len(tc.data), len(out), tc.wantLen)
		}
	}
}

// TestParseOpRoundTrip walks BuildPush output back through ParseOp and
// confirms the payload is recovered byte-identical.
func TestParseOpRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{},
		{0x00},
		{0x42, 0x55},
		bytes.Repeat([]byte{0xCC}, 75),
		bytes.Repeat([]byte{0xDD}, 76),
		bytes.Repeat([]byte{0xEE}, 1000),
		bytes.Repeat([]byte{0xFF}, 65_536),
	}
	for _, p := range payloads {
		s := Script(BuildPush(p))
		op, off, err := ParseOp(s, 0)
		if err != nil {
			t.Errorf("ParseOp(len=%d): %v", len(p), err)
			continue
		}
		if off != len(s) {
			t.Errorf("ParseOp(len=%d) consumed %d, want %d", len(p), off, len(s))
		}
		if !bytes.Equal(op.Data, p) {
			t.Errorf("ParseOp(len=%d) payload mismatch", len(p))
		}
	}
}

// TestParseOpTruncated catches every truncation path: bare push byte,
// PUSHDATA1 with missing length, PUSHDATA2/4 with missing length
// bytes, and a declared length that overruns the script.
func TestParseOpTruncated(t *testing.T) {
	cases := []struct {
		name string
		s    Script
	}{
		{"raw push overruns", Script{0x05, 0x01, 0x02}}, // says push 5, have 2
		{"PUSHDATA1 missing len", Script{OP_PUSHDATA1}},
		{"PUSHDATA1 overruns", Script{OP_PUSHDATA1, 0x05, 0x01}},
		{"PUSHDATA2 missing len", Script{OP_PUSHDATA2, 0x01}},
		{"PUSHDATA2 overruns", Script{OP_PUSHDATA2, 0x05, 0x00, 0x01}},
		{"PUSHDATA4 missing len", Script{OP_PUSHDATA4, 0x01, 0x02, 0x03}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ParseOp(tc.s, 0); err == nil {
				t.Fatal("expected truncation error")
			}
		})
	}
}

// TestIterateStopsOnError pins the Iterate contract: a truncated script
// surfaces the error, and a visitor error short-circuits the walk.
func TestIterateStopsOnError(t *testing.T) {
	// Truncated: single byte 0x05 saying "push 5", nothing follows.
	trunc := Script{0x05}
	if err := trunc.Iterate(func(Op) error { return nil }); err == nil {
		t.Fatal("truncated iterate should error")
	}
	// Visitor-error short-circuit.
	s := Script{OP_NOP, OP_NOP, OP_NOP}
	seen := 0
	err := s.Iterate(func(op Op) error {
		seen++
		if seen == 2 {
			return errVisitorStop
		}
		return nil
	})
	if err != errVisitorStop {
		t.Fatalf("expected visitor stop, got %v", err)
	}
	if seen != 2 {
		t.Fatalf("iterated %d ops after stop, want 2", seen)
	}
}

// errVisitorStop is a sentinel for TestIterateStopsOnError.
var errVisitorStop = testErr("visitor stop")

type testErr string

func (e testErr) Error() string { return string(e) }

// TestCountOpcodes counts only real opcode occurrences, not matching
// bytes that happen to appear inside a push payload.
func TestCountOpcodes(t *testing.T) {
	// Script: push [0xAC, 0xAC] then OP_CHECKSIG (0xAC). We want
	// CountOpcodes(OP_CHECKSIG) == 1 (the trailing opcode), not 3.
	s := Script(append(BuildPush([]byte{0xAC, 0xAC}), OP_CHECKSIG))
	n, err := s.CountOpcodes(OP_CHECKSIG)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("CountOpcodes = %d, want 1", n)
	}
}
