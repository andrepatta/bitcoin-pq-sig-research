package script

import (
	"encoding/binary"
	"errors"
)

// Script is a sequence of opcodes and embedded push-data.
type Script []byte

// Op is one parsed step of script execution: an opcode with optional
// embedded push payload.
type Op struct {
	Opcode byte
	Data   []byte // non-nil only for OP_0 / 1..0x4B / OP_PUSHDATA{1,2,4}
}

// IsPush reports whether op pushes data (no main-stack arg consumption).
func (o Op) IsPush() bool {
	return o.Opcode <= OP_16 && o.Opcode != OP_RESERVED
}

var (
	errPushTruncated = errors.New("script: push data truncated")
)

// ParseOp reads exactly one op starting at off and returns the op plus
// the new offset (one-past-end). Returns (Op{}, off, err) on truncation.
func ParseOp(s Script, off int) (Op, int, error) {
	if off < 0 || off >= len(s) {
		return Op{}, off, errors.New("script: read past end")
	}
	op := s[off]
	off++
	switch {
	case op == OP_0:
		return Op{Opcode: op, Data: []byte{}}, off, nil
	case op >= 0x01 && op <= 0x4B:
		n := int(op)
		if off+n > len(s) {
			return Op{}, off, errPushTruncated
		}
		d := make([]byte, n)
		copy(d, s[off:off+n])
		return Op{Opcode: op, Data: d}, off + n, nil
	case op == OP_PUSHDATA1:
		if off+1 > len(s) {
			return Op{}, off, errPushTruncated
		}
		n := int(s[off])
		off++
		if off+n > len(s) {
			return Op{}, off, errPushTruncated
		}
		d := make([]byte, n)
		copy(d, s[off:off+n])
		return Op{Opcode: op, Data: d}, off + n, nil
	case op == OP_PUSHDATA2:
		if off+2 > len(s) {
			return Op{}, off, errPushTruncated
		}
		n := int(binary.LittleEndian.Uint16(s[off:]))
		off += 2
		if off+n > len(s) {
			return Op{}, off, errPushTruncated
		}
		d := make([]byte, n)
		copy(d, s[off:off+n])
		return Op{Opcode: op, Data: d}, off + n, nil
	case op == OP_PUSHDATA4:
		if off+4 > len(s) {
			return Op{}, off, errPushTruncated
		}
		n := int(binary.LittleEndian.Uint32(s[off:]))
		off += 4
		if off+n > len(s) {
			return Op{}, off, errPushTruncated
		}
		d := make([]byte, n)
		copy(d, s[off:off+n])
		return Op{Opcode: op, Data: d}, off + n, nil
	}
	return Op{Opcode: op}, off, nil
}

// Iterate walks every op in s, invoking visit for each. Stops on the
// first error from ParseOp or visit. Used for static analysis (sigops
// counting, malformed-script detection) without executing the script.
func (s Script) Iterate(visit func(Op) error) error {
	for off := 0; off < len(s); {
		op, next, err := ParseOp(s, off)
		if err != nil {
			return err
		}
		if err := visit(op); err != nil {
			return err
		}
		off = next
	}
	return nil
}

// CountOpcodes returns the number of times target appears as a real
// opcode in s (not as data inside a push). Truncated scripts return
// the count of opcodes parsed before the truncation plus an error.
func (s Script) CountOpcodes(target byte) (int, error) {
	var n int
	err := s.Iterate(func(op Op) error {
		if op.Opcode == target {
			n++
		}
		return nil
	})
	return n, err
}

// NewScript is a convenience builder. Each arg is appended to the
// script: a byte/int/Op as a literal opcode, a []byte as a smallest-
// valid push of those bytes, a Num as a pushed CScriptNum encoding.
func NewScript(parts ...any) Script {
	var s Script
	for _, p := range parts {
		switch v := p.(type) {
		case byte:
			s = append(s, v)
		case int:
			s = append(s, byte(v))
		case []byte:
			s = append(s, BuildPush(v)...)
		case Num:
			s = append(s, BuildPush(v.Encode())...)
		case Op:
			s = append(s, v.Opcode)
			if len(v.Data) > 0 || v.Opcode == OP_0 {
				// trust caller's opcode; only emit the data tail (no length bytes added)
				s = append(s, v.Data...)
			}
		default:
			panic("script.NewScript: unsupported part type")
		}
	}
	return s
}

// BuildPush emits the smallest valid push operation for data:
//   - empty → OP_0
//   - 1-byte 0x81 → OP_1NEGATE
//   - 1-byte 0x01..0x10 → OP_1..OP_16
//   - 1..75 bytes → opcode N + data
//   - 76..255 → OP_PUSHDATA1 + 1 length byte + data
//   - 256..65535 → OP_PUSHDATA2 + 2 LE length bytes + data
//   - 65536..2^32-1 → OP_PUSHDATA4 + 4 LE length bytes + data
//
// "Smallest valid push" matches BIP-62 minimal-push rules so that
// encode/decode round-trips a single canonical form.
func BuildPush(data []byte) []byte {
	n := len(data)
	switch {
	case n == 0:
		return []byte{OP_0}
	case n == 1 && data[0] == 0x81:
		return []byte{OP_1NEGATE}
	case n == 1 && data[0] >= 0x01 && data[0] <= 0x10:
		return []byte{OP_1 - 1 + data[0]}
	case n <= 75:
		out := make([]byte, 1+n)
		out[0] = byte(n)
		copy(out[1:], data)
		return out
	case n <= 255:
		out := make([]byte, 2+n)
		out[0] = OP_PUSHDATA1
		out[1] = byte(n)
		copy(out[2:], data)
		return out
	case n <= 65535:
		out := make([]byte, 3+n)
		out[0] = OP_PUSHDATA2
		binary.LittleEndian.PutUint16(out[1:3], uint16(n))
		copy(out[3:], data)
		return out
	default:
		out := make([]byte, 5+n)
		out[0] = OP_PUSHDATA4
		binary.LittleEndian.PutUint32(out[1:5], uint32(n))
		copy(out[5:], data)
		return out
	}
}
