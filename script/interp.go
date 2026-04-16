package script

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/ripemd160"

	"qbitcoin/crypto"
)

// Consensus limits.
const (
	// MaxScriptSize is the maximum allowed bytes of a single script.
	MaxScriptSize = 10_000

	// MaxStackSize is the maximum combined (main+alt) stack depth.
	MaxStackSize = 1_000

	// MaxOpsPerScript bounds non-push opcodes per script execution.
	MaxOpsPerScript = 201

	// MaxScriptElementSize bounds a single pushed data item. Raised
	// from Bitcoin's 520 B to fit PQ signatures (SHRIMPS fallback on
	// the wire is ~4.2 KB + 1 B scheme tag ≈ 4201 B). 8 KiB gives
	// comfortable headroom while still bounding attacker allocations.
	MaxScriptElementSize = 8192
)

// Errors surfaced to the caller. Kept small and stable — tests match on
// these sentinels so renames ripple into test churn.
var (
	ErrScriptTooLarge  = errors.New("script: exceeds max size")
	ErrTooManyOps      = errors.New("script: exceeds max ops")
	ErrStackUnderflow  = errors.New("script: stack underflow")
	ErrStackOverflow   = errors.New("script: stack size exceeds limit")
	ErrElementTooLarge = errors.New("script: push data exceeds element size cap")
	ErrDisabledOp      = errors.New("script: disabled opcode")
	ErrReservedOp      = errors.New("script: reserved opcode")
	ErrBadOpcode       = errors.New("script: bad opcode")
	ErrUnbalancedCond  = errors.New("script: unbalanced conditional")
	ErrVerifyFailed    = errors.New("script: OP_VERIFY failed")
	ErrReturnOp        = errors.New("script: OP_RETURN terminates")
	ErrBadNumericOp    = errors.New("script: numeric operand error")
	ErrDivByZero       = errors.New("script: division by zero")
)

// stack is a LIFO []byte stack with bounds-checked ops. Elements are
// owned — push() takes ownership, pop() returns the removed element.
type stack struct{ s [][]byte }

func (st *stack) push(b []byte) { st.s = append(st.s, b) }

func (st *stack) pop() ([]byte, error) {
	if len(st.s) == 0 {
		return nil, ErrStackUnderflow
	}
	n := len(st.s) - 1
	v := st.s[n]
	st.s = st.s[:n]
	return v, nil
}

// peek returns the item at depth i (i=0 → top). Does not modify stack.
func (st *stack) peek(i int) ([]byte, error) {
	if i < 0 || i >= len(st.s) {
		return nil, ErrStackUnderflow
	}
	return st.s[len(st.s)-1-i], nil
}

// swap swaps elements at depths i and j (0 = top).
func (st *stack) swap(i, j int) error {
	if i < 0 || j < 0 || i >= len(st.s) || j >= len(st.s) {
		return ErrStackUnderflow
	}
	st.s[len(st.s)-1-i], st.s[len(st.s)-1-j] = st.s[len(st.s)-1-j], st.s[len(st.s)-1-i]
	return nil
}

// removeAt removes the element at depth i and returns it.
func (st *stack) removeAt(i int) ([]byte, error) {
	if i < 0 || i >= len(st.s) {
		return nil, ErrStackUnderflow
	}
	idx := len(st.s) - 1 - i
	v := st.s[idx]
	st.s = append(st.s[:idx], st.s[idx+1:]...)
	return v, nil
}

func (st *stack) depth() int { return len(st.s) }

// Execute runs leafScript against the stack initialized with witness
// items (bottom to top in witness-slice order) and returns true iff
// the script terminates with a truthy top-of-stack. sighash feeds
// OP_CHECKSIG / OP_CHECKSIGVERIFY. sc is the signature checker that
// dispatches SHRINCS vs SHRIMPS based on the signature's scheme-tag
// prefix; pass crypto.DefaultSigChecker in production.
//
// Contract differences from Bitcoin Core script:
//   - There is no scriptSig vs scriptPubKey split — the witness slice
//     plays the role of scriptSig's final stack state, pre-pushed
//     before executing leafScript. This matches P2MR's Merkle-revealed
//     leaf-script model: the leaf is the "pubkey script" and the
//     spender's witness is the "sig script stack".
//   - sighash is computed outside Execute (caller passes txn.SigHash)
//     rather than re-derived from tx + subscript. OP_CODESEPARATOR is
//     therefore a no-op; kept for wire/opset completeness.
//   - Disabled opcodes reject even in an unexecuted branch, matching
//     modern Bitcoin Core.
func Execute(leafScript Script, witness [][]byte, sighash [32]byte, sc SigChecker) (bool, error) {
	if len(leafScript) > MaxScriptSize {
		return false, ErrScriptTooLarge
	}

	// Static reject: any disabled opcode anywhere in the script is
	// fatal, even inside an OP_IF branch that would be skipped.
	if err := leafScript.Iterate(func(op Op) error {
		if isDisabled(op.Opcode) {
			return ErrDisabledOp
		}
		return nil
	}); err != nil {
		return false, err
	}

	main := &stack{}
	alt := &stack{}

	// Witness pre-push: bottom (index 0) goes on first.
	for _, w := range witness {
		if len(w) > MaxScriptElementSize {
			return false, ErrElementTooLarge
		}
		main.push(append([]byte(nil), w...))
	}
	if main.depth() > MaxStackSize {
		return false, ErrStackOverflow
	}

	// vfExec is the conditional-execution stack. Each entry is true iff
	// the corresponding IF/NOTIF branch should execute. We execute the
	// current op iff every entry is true (i.e. no ancestor branch is
	// skipped). Empty stack => executing.
	vfExec := make([]bool, 0, 8)

	opCount := 0

	for off := 0; off < len(leafScript); {
		op, next, err := ParseOp(leafScript, off)
		if err != nil {
			return false, err
		}
		off = next

		if isCountedOp(op.Opcode) {
			opCount++
			if opCount > MaxOpsPerScript {
				return false, ErrTooManyOps
			}
		}

		// VERIF / VERNOTIF are fatal even in unexecuted branches, per
		// Bitcoin consensus. This is the one exception to "skipped
		// branches are ignored".
		if op.Opcode == OP_VERIF || op.Opcode == OP_VERNOTIF {
			return false, ErrReservedOp
		}

		executing := allTrue(vfExec)

		// In an unexecuted branch, only IF/NOTIF/ELSE/ENDIF are processed.
		if !executing {
			switch op.Opcode {
			case OP_IF, OP_NOTIF:
				vfExec = append(vfExec, false)
			case OP_ELSE:
				if len(vfExec) == 0 {
					return false, ErrUnbalancedCond
				}
				vfExec[len(vfExec)-1] = !vfExec[len(vfExec)-1]
			case OP_ENDIF:
				if len(vfExec) == 0 {
					return false, ErrUnbalancedCond
				}
				vfExec = vfExec[:len(vfExec)-1]
			}
			continue
		}

		// Executing path.
		if err := stepOp(op, main, alt, &vfExec, sighash, sc); err != nil {
			return false, err
		}

		if main.depth()+alt.depth() > MaxStackSize {
			return false, ErrStackOverflow
		}
	}

	if len(vfExec) != 0 {
		return false, ErrUnbalancedCond
	}

	top, err := main.pop()
	if err != nil {
		return false, err
	}
	return CastToBool(top), nil
}

// allTrue reports whether every entry in vf is true.
func allTrue(vf []bool) bool {
	for _, v := range vf {
		if !v {
			return false
		}
	}
	return true
}

// stepOp executes one opcode from an executing branch. All non-push
// opcodes go through here; pushes and conditional-only ops are handled
// inline in Execute.
func stepOp(op Op, main, alt *stack, vfExec *[]bool, sighash [32]byte, sc SigChecker) error {
	switch {
	// --- Push value ---------------------------------------------------
	case op.Opcode == OP_0:
		main.push([]byte{})
	case op.Opcode >= 0x01 && op.Opcode <= 0x4B,
		op.Opcode == OP_PUSHDATA1, op.Opcode == OP_PUSHDATA2, op.Opcode == OP_PUSHDATA4:
		if len(op.Data) > MaxScriptElementSize {
			return ErrElementTooLarge
		}
		main.push(op.Data)
	case op.Opcode == OP_1NEGATE:
		main.push(Num(-1).Encode())
	case op.Opcode >= OP_1 && op.Opcode <= OP_16:
		main.push(Num(int64(op.Opcode - (OP_1 - 1))).Encode())

	// --- Reserved ---------------------------------------------------
	case op.Opcode == OP_RESERVED, op.Opcode == OP_RESERVED1, op.Opcode == OP_RESERVED2,
		op.Opcode == OP_VER:
		return ErrReservedOp

	// --- Control ----------------------------------------------------
	case op.Opcode == OP_NOP:
		// no-op
	case op.Opcode == OP_IF:
		top, err := main.pop()
		if err != nil {
			return err
		}
		*vfExec = append(*vfExec, CastToBool(top))
	case op.Opcode == OP_NOTIF:
		top, err := main.pop()
		if err != nil {
			return err
		}
		*vfExec = append(*vfExec, !CastToBool(top))
	case op.Opcode == OP_ELSE:
		if len(*vfExec) == 0 {
			return ErrUnbalancedCond
		}
		(*vfExec)[len(*vfExec)-1] = !(*vfExec)[len(*vfExec)-1]
	case op.Opcode == OP_ENDIF:
		if len(*vfExec) == 0 {
			return ErrUnbalancedCond
		}
		*vfExec = (*vfExec)[:len(*vfExec)-1]
	case op.Opcode == OP_VERIFY:
		top, err := main.pop()
		if err != nil {
			return err
		}
		if !CastToBool(top) {
			return ErrVerifyFailed
		}
	case op.Opcode == OP_RETURN:
		return ErrReturnOp

	// --- Stack ops --------------------------------------------------
	case op.Opcode == OP_TOALTSTACK:
		v, err := main.pop()
		if err != nil {
			return err
		}
		alt.push(v)
	case op.Opcode == OP_FROMALTSTACK:
		v, err := alt.pop()
		if err != nil {
			return err
		}
		main.push(v)
	case op.Opcode == OP_2DROP:
		if _, err := main.pop(); err != nil {
			return err
		}
		if _, err := main.pop(); err != nil {
			return err
		}
	case op.Opcode == OP_2DUP:
		a, err := main.peek(1)
		if err != nil {
			return err
		}
		b, err := main.peek(0)
		if err != nil {
			return err
		}
		main.push(dup(a))
		main.push(dup(b))
	case op.Opcode == OP_3DUP:
		a, err := main.peek(2)
		if err != nil {
			return err
		}
		b, err := main.peek(1)
		if err != nil {
			return err
		}
		c, err := main.peek(0)
		if err != nil {
			return err
		}
		main.push(dup(a))
		main.push(dup(b))
		main.push(dup(c))
	case op.Opcode == OP_2OVER:
		a, err := main.peek(3)
		if err != nil {
			return err
		}
		b, err := main.peek(2)
		if err != nil {
			return err
		}
		main.push(dup(a))
		main.push(dup(b))
	case op.Opcode == OP_2ROT:
		// move items at depth 5,4 to top (preserves order)
		if main.depth() < 6 {
			return ErrStackUnderflow
		}
		a, _ := main.removeAt(5)
		b, _ := main.removeAt(4) // after removeAt(5), old-depth-4 is now at depth 4
		main.push(a)
		main.push(b)
	case op.Opcode == OP_2SWAP:
		if main.depth() < 4 {
			return ErrStackUnderflow
		}
		if err := main.swap(3, 1); err != nil {
			return err
		}
		if err := main.swap(2, 0); err != nil {
			return err
		}
	case op.Opcode == OP_IFDUP:
		v, err := main.peek(0)
		if err != nil {
			return err
		}
		if CastToBool(v) {
			main.push(dup(v))
		}
	case op.Opcode == OP_DEPTH:
		main.push(Num(int64(main.depth())).Encode())
	case op.Opcode == OP_DROP:
		if _, err := main.pop(); err != nil {
			return err
		}
	case op.Opcode == OP_DUP:
		v, err := main.peek(0)
		if err != nil {
			return err
		}
		main.push(dup(v))
	case op.Opcode == OP_NIP:
		if _, err := main.removeAt(1); err != nil {
			return err
		}
	case op.Opcode == OP_OVER:
		v, err := main.peek(1)
		if err != nil {
			return err
		}
		main.push(dup(v))
	case op.Opcode == OP_PICK, op.Opcode == OP_ROLL:
		nBytes, err := main.pop()
		if err != nil {
			return err
		}
		n, err := DecodeNum(nBytes, MaxScriptNumLen)
		if err != nil {
			return err
		}
		if n < 0 || int(n) >= main.depth() {
			return ErrStackUnderflow
		}
		if op.Opcode == OP_PICK {
			v, err := main.peek(int(n))
			if err != nil {
				return err
			}
			main.push(dup(v))
		} else { // OP_ROLL
			v, err := main.removeAt(int(n))
			if err != nil {
				return err
			}
			main.push(v)
		}
	case op.Opcode == OP_ROT:
		// (x1 x2 x3) -> (x2 x3 x1); rotate depth-2 to top
		if err := main.swap(2, 1); err != nil {
			return err
		}
		if err := main.swap(1, 0); err != nil {
			return err
		}
	case op.Opcode == OP_SWAP:
		if err := main.swap(1, 0); err != nil {
			return err
		}
	case op.Opcode == OP_TUCK:
		// (x1 x2) -> (x2 x1 x2); copy top to depth-2
		v, err := main.peek(0)
		if err != nil {
			return err
		}
		// Insert copy at depth-2 (below x1).
		if main.depth() < 2 {
			return ErrStackUnderflow
		}
		idx := len(main.s) - 2
		main.s = append(main.s, nil)
		copy(main.s[idx+1:], main.s[idx:])
		main.s[idx] = dup(v)

	// --- Splice (all disabled — handled by static-pass; kept here
	//     for completeness in case static-pass ever becomes optional) ---
	case op.Opcode == OP_CAT, op.Opcode == OP_SUBSTR,
		op.Opcode == OP_LEFT, op.Opcode == OP_RIGHT:
		return ErrDisabledOp
	case op.Opcode == OP_SIZE:
		v, err := main.peek(0)
		if err != nil {
			return err
		}
		main.push(Num(int64(len(v))).Encode())

	// --- Bitwise logic ----------------------------------------------
	case op.Opcode == OP_INVERT, op.Opcode == OP_AND,
		op.Opcode == OP_OR, op.Opcode == OP_XOR:
		return ErrDisabledOp
	case op.Opcode == OP_EQUAL, op.Opcode == OP_EQUALVERIFY:
		a, err := main.pop()
		if err != nil {
			return err
		}
		b, err := main.pop()
		if err != nil {
			return err
		}
		eq := bytes.Equal(a, b)
		if op.Opcode == OP_EQUALVERIFY {
			if !eq {
				return ErrVerifyFailed
			}
		} else {
			if eq {
				main.push(Num(1).Encode())
			} else {
				main.push([]byte{})
			}
		}

	// --- Arithmetic (disabled: 2MUL/2DIV/MUL/DIV/MOD/LSHIFT/RSHIFT) ---
	case op.Opcode == OP_2MUL, op.Opcode == OP_2DIV,
		op.Opcode == OP_MUL, op.Opcode == OP_DIV, op.Opcode == OP_MOD,
		op.Opcode == OP_LSHIFT, op.Opcode == OP_RSHIFT:
		return ErrDisabledOp
	case op.Opcode == OP_1ADD, op.Opcode == OP_1SUB,
		op.Opcode == OP_NEGATE, op.Opcode == OP_ABS,
		op.Opcode == OP_NOT, op.Opcode == OP_0NOTEQUAL:
		return doUnaryNumeric(op.Opcode, main)
	case op.Opcode == OP_ADD, op.Opcode == OP_SUB,
		op.Opcode == OP_BOOLAND, op.Opcode == OP_BOOLOR,
		op.Opcode == OP_NUMEQUAL, op.Opcode == OP_NUMEQUALVERIFY,
		op.Opcode == OP_NUMNOTEQUAL,
		op.Opcode == OP_LESSTHAN, op.Opcode == OP_GREATERTHAN,
		op.Opcode == OP_LESSTHANOREQUAL, op.Opcode == OP_GREATERTHANOREQUAL,
		op.Opcode == OP_MIN, op.Opcode == OP_MAX:
		return doBinaryNumeric(op.Opcode, main)
	case op.Opcode == OP_WITHIN:
		max, err := main.pop()
		if err != nil {
			return err
		}
		min, err := main.pop()
		if err != nil {
			return err
		}
		x, err := main.pop()
		if err != nil {
			return err
		}
		xn, err := DecodeNum(x, MaxScriptNumLen)
		if err != nil {
			return err
		}
		minn, err := DecodeNum(min, MaxScriptNumLen)
		if err != nil {
			return err
		}
		maxn, err := DecodeNum(max, MaxScriptNumLen)
		if err != nil {
			return err
		}
		if xn >= minn && xn < maxn {
			main.push(Num(1).Encode())
		} else {
			main.push([]byte{})
		}

	// --- Crypto hashes ----------------------------------------------
	case op.Opcode == OP_RIPEMD160:
		v, err := main.pop()
		if err != nil {
			return err
		}
		h := ripemd160.New()
		h.Write(v)
		main.push(h.Sum(nil))
	case op.Opcode == OP_SHA1:
		v, err := main.pop()
		if err != nil {
			return err
		}
		h := sha1.Sum(v)
		main.push(h[:])
	case op.Opcode == OP_SHA256:
		v, err := main.pop()
		if err != nil {
			return err
		}
		h := sha256.Sum256(v)
		main.push(h[:])
	case op.Opcode == OP_HASH160:
		v, err := main.pop()
		if err != nil {
			return err
		}
		h1 := sha256.Sum256(v)
		h2 := ripemd160.New()
		h2.Write(h1[:])
		main.push(h2.Sum(nil))
	case op.Opcode == OP_HASH256:
		v, err := main.pop()
		if err != nil {
			return err
		}
		h := crypto.Hash256(v)
		main.push(h[:])
	case op.Opcode == OP_CODESEPARATOR:
		// No-op in PQBC: sighash is computed externally from the tx,
		// so there is no "subscript from last codeseparator" to track.
		// Opcode kept for wire/opset completeness and future use.

	// --- CHECKSIG / CHECKSIGVERIFY ---------------------------------
	case op.Opcode == OP_CHECKSIG, op.Opcode == OP_CHECKSIGVERIFY:
		pubkey, err := main.pop()
		if err != nil {
			return err
		}
		sig, err := main.pop()
		if err != nil {
			return err
		}
		ok := sc != nil && sc.CheckSig(sig, pubkey, sighash)
		if op.Opcode == OP_CHECKSIGVERIFY {
			if !ok {
				return ErrVerifyFailed
			}
		} else {
			if ok {
				main.push(Num(1).Encode())
			} else {
				main.push([]byte{})
			}
		}

	// --- CHECKMULTISIG reserved ------------------------------------
	case op.Opcode == OP_CHECKMULTISIG, op.Opcode == OP_CHECKMULTISIGVERIFY:
		return ErrReservedOp

	// --- Expansion NOPs — unconditional no-ops --------------------
	case op.Opcode == OP_NOP1, op.Opcode == OP_NOP2, op.Opcode == OP_NOP3,
		op.Opcode == OP_NOP4, op.Opcode == OP_NOP5, op.Opcode == OP_NOP6,
		op.Opcode == OP_NOP7, op.Opcode == OP_NOP8, op.Opcode == OP_NOP9,
		op.Opcode == OP_NOP10:
		// no-op — reserved for soft-fork expansion

	default:
		return ErrBadOpcode
	}
	return nil
}

// dup returns an independent copy of b. Every stack duplication goes
// through here so callers never worry about aliasing between stack
// slots after DUP/OVER/etc.
func dup(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// doUnaryNumeric pops one numeric operand and applies op.
func doUnaryNumeric(op byte, main *stack) error {
	ab, err := main.pop()
	if err != nil {
		return err
	}
	a, err := DecodeNum(ab, MaxScriptNumLen)
	if err != nil {
		return err
	}
	var out Num
	switch op {
	case OP_1ADD:
		out = a + 1
	case OP_1SUB:
		out = a - 1
	case OP_NEGATE:
		out = -a
	case OP_ABS:
		if a < 0 {
			out = -a
		} else {
			out = a
		}
	case OP_NOT:
		if a == 0 {
			out = 1
		} else {
			out = 0
		}
	case OP_0NOTEQUAL:
		if a == 0 {
			out = 0
		} else {
			out = 1
		}
	default:
		return ErrBadNumericOp
	}
	main.push(out.Encode())
	return nil
}

// doBinaryNumeric pops two numeric operands (b on top, a below) and
// applies op, pushing the result.
func doBinaryNumeric(op byte, main *stack) error {
	bb, err := main.pop()
	if err != nil {
		return err
	}
	ab, err := main.pop()
	if err != nil {
		return err
	}
	b, err := DecodeNum(bb, MaxScriptNumLen)
	if err != nil {
		return err
	}
	a, err := DecodeNum(ab, MaxScriptNumLen)
	if err != nil {
		return err
	}
	var out Num
	switch op {
	case OP_ADD:
		out = a + b
	case OP_SUB:
		out = a - b
	case OP_BOOLAND:
		if a != 0 && b != 0 {
			out = 1
		} else {
			out = 0
		}
	case OP_BOOLOR:
		if a != 0 || b != 0 {
			out = 1
		} else {
			out = 0
		}
	case OP_NUMEQUAL, OP_NUMEQUALVERIFY:
		if a == b {
			out = 1
		} else {
			out = 0
		}
		if op == OP_NUMEQUALVERIFY {
			if out == 0 {
				return ErrVerifyFailed
			}
			return nil
		}
	case OP_NUMNOTEQUAL:
		if a != b {
			out = 1
		} else {
			out = 0
		}
	case OP_LESSTHAN:
		if a < b {
			out = 1
		} else {
			out = 0
		}
	case OP_GREATERTHAN:
		if a > b {
			out = 1
		} else {
			out = 0
		}
	case OP_LESSTHANOREQUAL:
		if a <= b {
			out = 1
		} else {
			out = 0
		}
	case OP_GREATERTHANOREQUAL:
		if a >= b {
			out = 1
		} else {
			out = 0
		}
	case OP_MIN:
		if a < b {
			out = a
		} else {
			out = b
		}
	case OP_MAX:
		if a > b {
			out = a
		} else {
			out = b
		}
	default:
		return ErrBadNumericOp
	}
	main.push(out.Encode())
	return nil
}

// SigChecker verifies a (sig, pubkey, sighash) triple. Implemented by
// qbitcoin/crypto.DefaultSigChecker in production; tests can inject a
// stub to cover script-layer logic without running SPHINCS+.
type SigChecker interface {
	CheckSig(sig, pubkey []byte, sighash [32]byte) bool
}
