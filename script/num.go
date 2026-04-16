package script

import "errors"

// MaxScriptNumLen caps arithmetic-op operand byte-length to 4, matching
// Bitcoin's CScriptNum. Operations that exceed this (e.g. ADDing two
// 4-byte numbers and getting a 5-byte result) produce a value that is
// re-encoded but then fails the next arithmetic op that consumes it.
const MaxScriptNumLen = 4

// Num is a sign-magnitude little-endian variable-length integer, the
// script VM's arithmetic type. Representable range on input is
// [-2^31+1, 2^31-1] (4-byte CScriptNum); arithmetic may produce values
// slightly outside that, up to int64 during computation, and re-encode
// them in >4 bytes — subsequent arithmetic on such a value will error.
type Num int64

// Encode emits canonical CScriptNum bytes for n. Zero encodes to the
// empty byte string. Positive values encode to the minimum number of
// little-endian bytes; if the high bit of the top byte would be set
// (confusable with a negative-sign flag) an extra 0x00 pad is appended.
// Negative values flip the sign bit of the top byte after encoding.
func (n Num) Encode() []byte {
	if n == 0 {
		return nil
	}
	negative := n < 0
	absv := uint64(n)
	if negative {
		absv = uint64(-int64(n))
	}
	var b []byte
	for absv > 0 {
		b = append(b, byte(absv&0xFF))
		absv >>= 8
	}
	if b[len(b)-1]&0x80 != 0 {
		if negative {
			b = append(b, 0x80)
		} else {
			b = append(b, 0x00)
		}
	} else if negative {
		b[len(b)-1] |= 0x80
	}
	return b
}

// DecodeNum parses CScriptNum bytes and returns the integer value.
// Enforces two rules:
//   - len(b) must not exceed maxLen (caller passes MaxScriptNumLen for
//     ordinary arithmetic).
//   - The encoding must be minimal: the top byte cannot be 0x00 or 0x80
//     unless setting it to that would flip the sign bit of the byte
//     below (BIP-62 minimal-encoding rule, adopted as a consensus rule
//     for modern Bitcoin; required here so that encode/decode is a
//     bijection and two equivalent scripts always hash the same).
func DecodeNum(b []byte, maxLen int) (Num, error) {
	if len(b) > maxLen {
		return 0, errors.New("script: numeric operand exceeds length limit")
	}
	if len(b) == 0 {
		return 0, nil
	}
	last := b[len(b)-1]
	// Minimal-encoding check.
	if last&0x7F == 0 {
		if len(b) == 1 || b[len(b)-2]&0x80 == 0 {
			return 0, errors.New("script: non-minimal numeric encoding")
		}
	}
	var result uint64
	for i := 0; i < len(b)-1; i++ {
		result |= uint64(b[i]) << (8 * i)
	}
	result |= uint64(last&0x7F) << (8 * (len(b) - 1))
	if last&0x80 != 0 {
		return Num(-int64(result)), nil
	}
	return Num(result), nil
}

// CastToBool interprets raw stack bytes as a boolean, per Bitcoin:
// the value is true iff any bit is set, except for the sign bit of the
// last byte standing alone (i.e. -0 = 0x80 and 0 = [] are both false).
func CastToBool(b []byte) bool {
	for i, c := range b {
		if c == 0 {
			continue
		}
		if i == len(b)-1 && c == 0x80 {
			return false
		}
		return true
	}
	return false
}
