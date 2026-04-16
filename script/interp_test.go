package script

import (
	"bytes"
	"errors"
	"testing"
)

// nopChecker is a SigChecker whose CheckSig always returns the value
// set in `accept`. Used to cover script-layer CHECKSIG logic without
// running SPHINCS+ — the real polymorphic dispatch is tested in
// crypto/checksig_test.go.
type nopChecker struct{ accept bool }

func (n nopChecker) CheckSig(sig, pubkey []byte, sighash [32]byte) bool {
	return n.accept
}

// run executes s with the given witness and returns (ok, err).
// nopChecker(false) is used unless the case specifies otherwise.
func run(t *testing.T, s Script, witness [][]byte) (bool, error) {
	t.Helper()
	return Execute(s, witness, [32]byte{}, nopChecker{accept: true})
}

// --------------- Push value opcodes ---------------

func TestExec_PushSmallInts(t *testing.T) {
	// OP_1..OP_16 push numeric 1..16 — OP_VERIFY then consumes it.
	for i := 1; i <= 16; i++ {
		s := Script{OP_1 + byte(i-1), OP_VERIFY, OP_1}
		ok, err := run(t, s, nil)
		if err != nil || !ok {
			t.Errorf("OP_%d: ok=%v err=%v", i, ok, err)
		}
	}
}

func TestExec_Push1Negate(t *testing.T) {
	// OP_1NEGATE pushes -1, which is truthy (CastToBool on 0x81 → true).
	s := Script{OP_1NEGATE}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("OP_1NEGATE: ok=%v err=%v", ok, err)
	}
}

func TestExec_Push0IsFalse(t *testing.T) {
	// OP_0 pushes empty bytes which is false.
	s := Script{OP_0}
	ok, err := run(t, s, nil)
	if err != nil {
		t.Fatalf("OP_0: %v", err)
	}
	if ok {
		t.Fatal("OP_0 terminal stack should be false")
	}
}

func TestExec_PushDataOpcodes(t *testing.T) {
	// All three PUSHDATA variants push identical payloads; confirm
	// each terminates with a truthy stack when we push the byte 0x01.
	for _, size := range []int{1, 75, 76, 255, 256, 500} {
		data := bytes.Repeat([]byte{0x01}, size)
		s := Script(BuildPush(data))
		ok, err := run(t, s, nil)
		if err != nil || !ok {
			t.Errorf("push len=%d: ok=%v err=%v", size, ok, err)
		}
	}
}

func TestExec_PushDataSizeCap(t *testing.T) {
	// Pushing > MaxScriptElementSize must reject.
	big := bytes.Repeat([]byte{0xAA}, MaxScriptElementSize+1)
	s := Script(BuildPush(big))
	_, err := run(t, s, nil)
	if err == nil {
		t.Fatal("expected element-size cap rejection")
	}
}

// --------------- Reserved / bad opcodes ---------------

func TestExec_ReservedOpcodesReject(t *testing.T) {
	for _, op := range []byte{OP_RESERVED, OP_VER, OP_RESERVED1, OP_RESERVED2} {
		s := Script{op}
		_, err := run(t, s, nil)
		if !errors.Is(err, ErrReservedOp) {
			t.Errorf("0x%02X should reject as reserved, got %v", op, err)
		}
	}
}

func TestExec_VerifAlwaysRejects(t *testing.T) {
	// OP_VERIF / OP_VERNOTIF reject even inside an unexecuted branch.
	s := Script{OP_0, OP_IF, OP_VERIF, OP_ENDIF}
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrReservedOp) {
		t.Errorf("OP_VERIF in skipped branch should still reject: %v", err)
	}
	s = Script{OP_0, OP_IF, OP_VERNOTIF, OP_ENDIF}
	_, err = run(t, s, nil)
	if !errors.Is(err, ErrReservedOp) {
		t.Errorf("OP_VERNOTIF in skipped branch should still reject: %v", err)
	}
}

func TestExec_BadOpcode(t *testing.T) {
	// Opcode 0xC0 (post-NOP10, below template sentinels) is undefined.
	s := Script{OP_1, 0xBA}
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrBadOpcode) {
		t.Fatalf("expected ErrBadOpcode, got %v", err)
	}
}

// --------------- Disabled opcodes ---------------

func TestExec_DisabledOpcodesRejectEverywhere(t *testing.T) {
	// Every disabled opcode, even inside an unexecuted branch,
	// causes a static reject.
	disabled := []byte{
		OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,
		OP_INVERT, OP_AND, OP_OR, OP_XOR,
		OP_2MUL, OP_2DIV,
		OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
	}
	for _, op := range disabled {
		s := Script{OP_0, OP_IF, op, OP_ENDIF, OP_1}
		_, err := run(t, s, nil)
		if !errors.Is(err, ErrDisabledOp) {
			t.Errorf("disabled 0x%02X (%s) in skipped branch: %v", op, OpcodeName(op), err)
		}
	}
}

// --------------- Control flow ---------------

func TestExec_IfElseTaken(t *testing.T) {
	// OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF → stack top = 2 → truthy.
	s := Script{OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("IF-taken: ok=%v err=%v", ok, err)
	}
	// And the else side executes under OP_0.
	s = Script{OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF}
	ok, err = run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("IF-else: ok=%v err=%v", ok, err)
	}
}

func TestExec_NotIf(t *testing.T) {
	// OP_0 OP_NOTIF OP_2 OP_ENDIF → 2 is pushed (condition inverted).
	s := Script{OP_0, OP_NOTIF, OP_2, OP_ENDIF}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("NOTIF-taken: ok=%v err=%v", ok, err)
	}
}

func TestExec_NestedIf(t *testing.T) {
	// OP_1 OP_IF OP_1 OP_IF OP_3 OP_ELSE OP_4 OP_ENDIF OP_ENDIF → 3
	s := Script{OP_1, OP_IF, OP_1, OP_IF, OP_3, OP_ELSE, OP_4, OP_ENDIF, OP_ENDIF}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("nested IF: %v %v", ok, err)
	}
	// Inner-else branch: OP_1 OP_IF OP_0 OP_IF OP_3 OP_ELSE OP_4 OP_ENDIF OP_ENDIF → 4
	s = Script{OP_1, OP_IF, OP_0, OP_IF, OP_3, OP_ELSE, OP_4, OP_ENDIF, OP_ENDIF}
	ok, err = run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("nested IF inner-else: %v %v", ok, err)
	}
}

func TestExec_UnbalancedConditional(t *testing.T) {
	cases := []struct {
		name string
		s    Script
	}{
		{"dangling IF", Script{OP_1, OP_IF, OP_2}},
		{"extra ENDIF", Script{OP_1, OP_ENDIF}},
		{"ELSE outside IF", Script{OP_ELSE, OP_1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := run(t, tc.s, nil)
			if !errors.Is(err, ErrUnbalancedCond) && !errors.Is(err, ErrStackUnderflow) {
				t.Fatalf("expected unbalanced/underflow, got %v", err)
			}
		})
	}
}

func TestExec_Verify(t *testing.T) {
	// OP_1 OP_VERIFY OP_1 → script succeeds (VERIFY consumes the 1,
	// leaves nothing, then OP_1 pushes a truthy value).
	s := Script{OP_1, OP_VERIFY, OP_1}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("VERIFY-success: %v %v", ok, err)
	}
	// OP_0 OP_VERIFY must fail.
	s = Script{OP_0, OP_VERIFY, OP_1}
	_, err = run(t, s, nil)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("VERIFY-fail: expected ErrVerifyFailed, got %v", err)
	}
}

func TestExec_Return(t *testing.T) {
	// OP_RETURN terminates execution with an error, regardless of what
	// follows.
	s := Script{OP_1, OP_RETURN, OP_1}
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrReturnOp) {
		t.Fatalf("expected ErrReturnOp, got %v", err)
	}
}

// --------------- Stack ops ---------------

func TestExec_AltStackRoundTrip(t *testing.T) {
	// TOALTSTACK pops top off main, pushes onto alt; FROMALTSTACK reverses.
	s := Script{OP_3, OP_TOALTSTACK, OP_1, OP_FROMALTSTACK, OP_ADD, OP_4, OP_NUMEQUAL}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("alt roundtrip: %v %v", ok, err)
	}
}

func TestExec_AltStackUnderflow(t *testing.T) {
	s := Script{OP_FROMALTSTACK}
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrStackUnderflow) {
		t.Fatalf("expected underflow, got %v", err)
	}
}

func TestExec_Dup(t *testing.T) {
	// DUP copies top; 5 DUP EQUAL should be true.
	s := Script{OP_5, OP_DUP, OP_EQUAL}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("DUP: %v %v", ok, err)
	}
}

func TestExec_DepthAfterWitness(t *testing.T) {
	// Witness = 3 items. OP_DEPTH should encode 3.
	s := Script{OP_DEPTH, OP_3, OP_EQUAL}
	ok, err := run(t, s, [][]byte{{1}, {2}, {3}})
	if err != nil || !ok {
		t.Fatalf("DEPTH: %v %v", ok, err)
	}
}

func TestExec_Drop2DropNipOver(t *testing.T) {
	// Witness [7,8,9] top=9. DROP → [7,8]. OVER → [7,8,7]. NIP → [7,7].
	// EQUAL → true.
	s := Script{OP_DROP, OP_OVER, OP_NIP, OP_EQUAL}
	ok, err := run(t, s, [][]byte{{7}, {8}, {9}})
	if err != nil || !ok {
		t.Fatalf("DROP+OVER+NIP+EQUAL: %v %v", ok, err)
	}
	// 2DROP drops two.
	s = Script{OP_2DROP, OP_1}
	ok, err = run(t, s, [][]byte{{1}, {2}})
	if err != nil || !ok {
		t.Fatalf("2DROP: %v %v", ok, err)
	}
	// NIP removes the second-from-top.
	s = Script{OP_NIP, OP_9, OP_EQUAL}
	ok, err = run(t, s, [][]byte{{8}, {9}})
	if err != nil || !ok {
		t.Fatalf("NIP: %v %v", ok, err)
	}
}

func TestExec_Swap(t *testing.T) {
	// Witness [3,7] top=7. SWAP → [7,3]. 3 EQUAL true.
	s := Script{OP_SWAP, OP_3, OP_EQUAL}
	ok, err := run(t, s, [][]byte{{3}, {7}})
	if err != nil || !ok {
		t.Fatalf("SWAP: %v %v", ok, err)
	}
}

func TestExec_Rot(t *testing.T) {
	// [1,2,3] ROT → [2,3,1]. Top=1 truthy.
	s := Script{OP_ROT}
	ok, err := run(t, s, [][]byte{{1}, {2}, {3}})
	if err != nil || !ok {
		t.Fatalf("ROT: %v %v", ok, err)
	}
	// And the middle element should now be 3.
	s = Script{OP_ROT, OP_DROP, OP_3, OP_EQUAL}
	ok, err = run(t, s, [][]byte{{1}, {2}, {3}})
	if err != nil || !ok {
		t.Fatalf("ROT layout: %v %v", ok, err)
	}
}

func TestExec_PickAndRoll(t *testing.T) {
	// [a,b,c,d,e] push 2 PICK → [a,b,c,d,e,c]. Equal top with third-from-top-original.
	s := Script{OP_2, OP_PICK, OP_3, OP_EQUAL}
	ok, err := run(t, s, [][]byte{{5}, {4}, {3}, {2}, {1}})
	if err != nil || !ok {
		t.Fatalf("PICK: %v %v", ok, err)
	}
	// ROLL removes from depth and pushes to top.
	s = Script{OP_2, OP_ROLL, OP_3, OP_EQUAL}
	ok, err = run(t, s, [][]byte{{5}, {4}, {3}, {2}, {1}})
	if err != nil || !ok {
		t.Fatalf("ROLL: %v %v", ok, err)
	}
}

func TestExec_PickBoundsCheck(t *testing.T) {
	// PICK with n >= depth must fail.
	s := Script{OP_3, OP_PICK}
	_, err := run(t, s, [][]byte{{1}, {2}})
	if !errors.Is(err, ErrStackUnderflow) {
		t.Fatalf("PICK out of bounds: %v", err)
	}
}

func TestExec_IfDup(t *testing.T) {
	// IFDUP duplicates top iff it's truthy.
	s := Script{OP_1, OP_IFDUP, OP_ADD, OP_2, OP_EQUAL}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("IFDUP(1): %v %v", ok, err)
	}
	// IFDUP on 0 does not duplicate → stack [0, 1 (from trailing)].
	s = Script{OP_0, OP_IFDUP, OP_1}
	ok, err = run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("IFDUP(0): %v %v", ok, err)
	}
}

func TestExec_2Dup3Dup2Over2Rot2Swap(t *testing.T) {
	// 2DUP: [a,b] → [a,b,a,b]. Test a!=b, top = b.
	s := Script{OP_2DUP, OP_EQUAL, OP_VERIFY, OP_EQUAL}
	ok, err := run(t, s, [][]byte{{3}, {5}})
	if ok || err == nil {
		t.Fatal("2DUP layout expectation: stack layout check via EQUAL should fail when items differ")
	}
	// 2DUP on [a,a] → all equal.
	s = Script{OP_2DUP, OP_EQUAL, OP_VERIFY, OP_EQUAL}
	ok, err = run(t, s, [][]byte{{3}, {3}})
	if err != nil || !ok {
		t.Fatalf("2DUP on equal: %v %v", ok, err)
	}
	// 3DUP on [a,b,c] → [a,b,c,a,b,c]. Top = c.
	s = Script{OP_3DUP, OP_DROP, OP_DROP, OP_DROP}
	if _, err := run(t, s, [][]byte{{1}, {2}, {3}}); err != nil {
		t.Fatalf("3DUP: %v", err)
	}
	// 2SWAP: (x1 x2 x3 x4) → (x3 x4 x1 x2). Witness [3,4,1,2] →
	// stack [3,4,1,2] → after 2SWAP [1,2,3,4]. Top=4, then 3.
	s = Script{OP_2SWAP, OP_4, OP_EQUAL, OP_VERIFY, OP_3, OP_EQUAL}
	ok, err = run(t, s, [][]byte{{3}, {4}, {1}, {2}})
	if err != nil || !ok {
		t.Fatalf("2SWAP: %v %v", ok, err)
	}
}

func TestExec_Tuck(t *testing.T) {
	// TUCK: (x1 x2) → (x2 x1 x2). After TUCK [1,2] → [2,1,2].
	// NIP removes the middle (x1), giving [2,2]; EQUAL → true.
	s := Script{OP_TUCK, OP_NIP, OP_EQUAL}
	ok, err := run(t, s, [][]byte{{1}, {2}})
	if err != nil || !ok {
		t.Fatalf("TUCK: %v %v", ok, err)
	}
}

// --------------- Splice ---------------

func TestExec_Size(t *testing.T) {
	// Witness = [0xAA,0xBB,0xCC]. SIZE pushes 3; stack = [0xAABBCC, 3]. EQUAL fails unless 3 is top.
	s := Script{OP_SIZE, OP_3, OP_EQUAL, OP_VERIFY, OP_1}
	ok, err := run(t, s, [][]byte{{0xAA, 0xBB, 0xCC}})
	if err != nil || !ok {
		t.Fatalf("SIZE: %v %v", ok, err)
	}
}

// --------------- Bitwise / equality ---------------

func TestExec_Equal(t *testing.T) {
	s := Script{OP_1, OP_1, OP_EQUAL}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("EQUAL: %v %v", ok, err)
	}
	s = Script{OP_1, OP_2, OP_EQUAL}
	ok, err = run(t, s, nil)
	if err != nil {
		t.Fatalf("EQUAL: %v", err)
	}
	if ok {
		t.Fatal("EQUAL 1 vs 2 must be false")
	}
}

func TestExec_EqualVerify(t *testing.T) {
	// OP_1 OP_1 OP_EQUALVERIFY consumes two 1s (ok), leaves empty → then OP_1 truthy.
	s := Script{OP_1, OP_1, OP_EQUALVERIFY, OP_1}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("EQUALVERIFY(pass): %v %v", ok, err)
	}
	s = Script{OP_1, OP_2, OP_EQUALVERIFY}
	_, err = run(t, s, nil)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("EQUALVERIFY(fail): %v", err)
	}
}

// --------------- Arithmetic ---------------

func TestExec_UnaryArith(t *testing.T) {
	cases := []struct {
		name string
		in   Num
		op   byte
		want Num
	}{
		{"1ADD(5)", 5, OP_1ADD, 6},
		{"1ADD(-1)", -1, OP_1ADD, 0},
		{"1SUB(5)", 5, OP_1SUB, 4},
		{"NEGATE(3)", 3, OP_NEGATE, -3},
		{"NEGATE(-3)", -3, OP_NEGATE, 3},
		{"ABS(-7)", -7, OP_ABS, 7},
		{"ABS(7)", 7, OP_ABS, 7},
		{"NOT(0)", 0, OP_NOT, 1},
		{"NOT(7)", 7, OP_NOT, 0},
		{"0NOTEQUAL(0)", 0, OP_0NOTEQUAL, 0},
		{"0NOTEQUAL(7)", 7, OP_0NOTEQUAL, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Script(append(BuildPush(tc.in.Encode()), tc.op, 0x00))
			s = Script(append(s[:len(s)-1], BuildPush(tc.want.Encode())...))
			s = append(s, OP_EQUAL)
			ok, err := run(t, s, nil)
			if err != nil || !ok {
				t.Fatalf("%s: ok=%v err=%v", tc.name, ok, err)
			}
		})
	}
}

func TestExec_BinaryArith(t *testing.T) {
	cases := []struct {
		name string
		a, b Num
		op   byte
		want Num
	}{
		{"ADD", 3, 5, OP_ADD, 8},
		{"SUB", 10, 3, OP_SUB, 7},
		{"BOOLAND(1,1)", 1, 1, OP_BOOLAND, 1},
		{"BOOLAND(1,0)", 1, 0, OP_BOOLAND, 0},
		{"BOOLOR(0,0)", 0, 0, OP_BOOLOR, 0},
		{"BOOLOR(0,1)", 0, 1, OP_BOOLOR, 1},
		{"NUMEQUAL", 42, 42, OP_NUMEQUAL, 1},
		{"NUMNOTEQUAL", 42, 43, OP_NUMNOTEQUAL, 1},
		{"LESSTHAN", 2, 5, OP_LESSTHAN, 1},
		{"GREATERTHAN", 5, 2, OP_GREATERTHAN, 1},
		{"LESSTHANOREQUAL", 5, 5, OP_LESSTHANOREQUAL, 1},
		{"GREATERTHANOREQUAL", 5, 5, OP_GREATERTHANOREQUAL, 1},
		{"MIN", 2, 5, OP_MIN, 2},
		{"MAX", 2, 5, OP_MAX, 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Script{}
			s = append(s, BuildPush(tc.a.Encode())...)
			s = append(s, BuildPush(tc.b.Encode())...)
			s = append(s, tc.op)
			s = append(s, BuildPush(tc.want.Encode())...)
			s = append(s, OP_EQUAL)
			ok, err := run(t, s, nil)
			if err != nil || !ok {
				t.Fatalf("%s(%d,%d): ok=%v err=%v", tc.name, tc.a, tc.b, ok, err)
			}
		})
	}
}

func TestExec_NumEqualVerify(t *testing.T) {
	s := Script{OP_5, OP_5, OP_NUMEQUALVERIFY, OP_1}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("NUMEQUALVERIFY(pass): %v %v", ok, err)
	}
	s = Script{OP_5, OP_6, OP_NUMEQUALVERIFY}
	_, err = run(t, s, nil)
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("NUMEQUALVERIFY(fail): %v", err)
	}
}

func TestExec_Within(t *testing.T) {
	// 5 WITHIN(3,10) → 1
	s := Script{OP_5, OP_3, OP_10, OP_WITHIN}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("WITHIN(5,3,10): %v %v", ok, err)
	}
	// 10 WITHIN(3,10) → 0 (upper bound exclusive)
	s = Script{OP_10, OP_3, OP_10, OP_WITHIN}
	ok, err = run(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("10 WITHIN(3,10) should be exclusive-upper → 0")
	}
}

func TestExec_ArithOverlongOperand(t *testing.T) {
	// Five-byte operand to ADD must reject.
	overlong := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x7F}
	s := Script(append(append(BuildPush(overlong), BuildPush([]byte{1})...), OP_ADD))
	_, err := run(t, s, nil)
	if err == nil {
		t.Fatal("expected numeric-overflow reject")
	}
}

// --------------- Crypto hash ops ---------------

func TestExec_HashOps(t *testing.T) {
	// Witness = empty. OP_SHA256 over empty = known digest.
	empty256 := []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	}
	s := Script{}
	s = append(s, OP_0, OP_SHA256)
	s = append(s, BuildPush(empty256)...)
	s = append(s, OP_EQUAL)
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("SHA256(''): %v %v", ok, err)
	}

	// OP_SHA1 over "abc" = a9993e364706816aba3e25717850c26c9cd0d89d
	sha1abc := []byte{0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d}
	s = Script{}
	s = append(s, BuildPush([]byte("abc"))...)
	s = append(s, OP_SHA1)
	s = append(s, BuildPush(sha1abc)...)
	s = append(s, OP_EQUAL)
	ok, err = run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("SHA1('abc'): %v %v", ok, err)
	}

	// OP_RIPEMD160 over empty = 9c1185a5c5e9fc54612808977ee8f548b2258d31
	rmEmpty := []byte{0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31}
	s = Script{}
	s = append(s, OP_0, OP_RIPEMD160)
	s = append(s, BuildPush(rmEmpty)...)
	s = append(s, OP_EQUAL)
	ok, err = run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("RIPEMD160(''): %v %v", ok, err)
	}
}

func TestExec_Hash256IsDoubleSHA(t *testing.T) {
	// HASH256(x) = SHA256(SHA256(x)). Compare in-script vs a raw
	// SHA256 SHA256 sequence — OP_HASH256 should match.
	s := Script{}
	s = append(s, BuildPush([]byte("qbitcoin"))...)
	s = append(s, OP_HASH256)
	s = append(s, BuildPush([]byte("qbitcoin"))...)
	s = append(s, OP_SHA256, OP_SHA256)
	s = append(s, OP_EQUAL)
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("HASH256 ≠ SHA256∘SHA256: %v %v", ok, err)
	}
}

func TestExec_Hash160IsRipeSha(t *testing.T) {
	// HASH160(x) = RIPEMD160(SHA256(x)).
	s := Script{}
	s = append(s, BuildPush([]byte("qbitcoin"))...)
	s = append(s, OP_HASH160)
	s = append(s, BuildPush([]byte("qbitcoin"))...)
	s = append(s, OP_SHA256, OP_RIPEMD160)
	s = append(s, OP_EQUAL)
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("HASH160 ≠ RIPEMD160∘SHA256: %v %v", ok, err)
	}
}

func TestExec_CodeSeparatorNoop(t *testing.T) {
	// OP_CODESEPARATOR is a no-op in PQBC; it must not consume stack or
	// alter behaviour.
	s := Script{OP_1, OP_CODESEPARATOR, OP_1, OP_EQUAL}
	ok, err := run(t, s, nil)
	if err != nil || !ok {
		t.Fatalf("CODESEPARATOR: %v %v", ok, err)
	}
}

// --------------- CHECKSIG (stubbed checker) ---------------

func TestExec_CheckSigAcceptReject(t *testing.T) {
	// With a stubbed checker set to accept: push sig, push pk, CHECKSIG
	// → truthy.
	s := Script{}
	s = append(s, BuildPush([]byte{0x00, 0x11, 0x22})...) // sig
	s = append(s, BuildPush([]byte{0xAA, 0xBB})...)       // pk
	s = append(s, OP_CHECKSIG)
	ok, err := Execute(s, nil, [32]byte{}, nopChecker{accept: true})
	if err != nil || !ok {
		t.Fatalf("CHECKSIG accept: %v %v", ok, err)
	}
	// Rejecting checker → CHECKSIG pushes 0 → final stack false.
	ok, err = Execute(s, nil, [32]byte{}, nopChecker{accept: false})
	if err != nil {
		t.Fatalf("CHECKSIG reject: %v", err)
	}
	if ok {
		t.Fatal("CHECKSIG reject should push false")
	}
}

func TestExec_CheckSigVerify(t *testing.T) {
	s := Script{}
	s = append(s, BuildPush([]byte{0x00})...)
	s = append(s, BuildPush([]byte{0xAA})...)
	s = append(s, OP_CHECKSIGVERIFY, OP_1)
	// Accepting → OK
	ok, err := Execute(s, nil, [32]byte{}, nopChecker{accept: true})
	if err != nil || !ok {
		t.Fatalf("CHECKSIGVERIFY accept: %v %v", ok, err)
	}
	// Rejecting → ErrVerifyFailed
	_, err = Execute(s, nil, [32]byte{}, nopChecker{accept: false})
	if !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("CHECKSIGVERIFY reject: %v", err)
	}
}

func TestExec_CheckMultisigReserved(t *testing.T) {
	s := Script{OP_CHECKMULTISIG}
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrReservedOp) {
		t.Fatalf("CHECKMULTISIG should reject as reserved: %v", err)
	}
}

// --------------- NOP expansion opcodes ---------------

func TestExec_NopsAreNoOps(t *testing.T) {
	// OP_NOP1..OP_NOP10 should not affect the stack.
	for op := OP_NOP1; op <= OP_NOP10; op++ {
		s := Script{OP_1, op}
		ok, err := run(t, s, nil)
		if err != nil || !ok {
			t.Errorf("%s disturbed stack: %v %v", OpcodeName(op), ok, err)
		}
	}
	// OP_NOP itself too.
	if ok, err := run(t, Script{OP_1, OP_NOP}, nil); err != nil || !ok {
		t.Errorf("OP_NOP: %v %v", ok, err)
	}
}

// --------------- Limits ---------------

func TestExec_MaxScriptSize(t *testing.T) {
	big := make(Script, MaxScriptSize+1)
	for i := range big {
		big[i] = OP_NOP
	}
	_, err := run(t, big, nil)
	if !errors.Is(err, ErrScriptTooLarge) {
		t.Fatalf("expected ErrScriptTooLarge, got %v", err)
	}
}

func TestExec_MaxOpsPerScript(t *testing.T) {
	// Build 202 counted ops; first 201 fine, 202nd must trip the cap.
	// OP_NOP is the cheapest counted op.
	s := make(Script, 0, MaxOpsPerScript+2)
	for i := 0; i < MaxOpsPerScript+1; i++ {
		s = append(s, OP_NOP)
	}
	s = append(s, OP_1) // terminal truthy; reached only if cap miscounts
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrTooManyOps) {
		t.Fatalf("expected ErrTooManyOps, got %v", err)
	}
}

func TestExec_StackOverflow(t *testing.T) {
	// OP_1..OP_16 pushes are uncounted (op <= OP_16), so pushing N of
	// them is the cheapest way to exceed MaxStackSize without tripping
	// MaxOpsPerScript first. MaxStackSize + 1 pushes is one too many.
	s := make(Script, 0, MaxStackSize+1)
	for range MaxStackSize + 1 {
		s = append(s, OP_1)
	}
	_, err := run(t, s, nil)
	if !errors.Is(err, ErrStackOverflow) {
		t.Fatalf("expected overflow, got %v", err)
	}
}

func TestExec_WitnessOverSizeCap(t *testing.T) {
	// A witness item larger than MaxScriptElementSize should be rejected
	// during the initial pre-push.
	w := bytes.Repeat([]byte{0xAA}, MaxScriptElementSize+1)
	_, err := run(t, Script{OP_1}, [][]byte{w})
	if !errors.Is(err, ErrElementTooLarge) {
		t.Fatalf("expected ErrElementTooLarge, got %v", err)
	}
}

func TestExec_EmptyScriptFailsAtFinal(t *testing.T) {
	// Empty script with empty witness terminates with empty stack →
	// stack-underflow at the final-pop.
	_, err := run(t, Script{}, nil)
	if !errors.Is(err, ErrStackUnderflow) {
		t.Fatalf("expected final-pop underflow, got %v", err)
	}
}

// --------------- Combined / P2PK-shaped ---------------

func TestExec_P2PKTemplate(t *testing.T) {
	// The canonical 2-leaf P2MR leaf: <pubkey> OP_CHECKSIG, with the
	// signature pushed via the witness.
	pubkey := []byte{0x01, 0x02, 0x03, 0x04}
	leaf := Script(append(BuildPush(pubkey), OP_CHECKSIG))
	sig := []byte{0xAA, 0xBB}

	ok, err := Execute(leaf, [][]byte{sig}, [32]byte{}, nopChecker{accept: true})
	if err != nil || !ok {
		t.Fatalf("P2PK accept: %v %v", ok, err)
	}
	ok, err = Execute(leaf, [][]byte{sig}, [32]byte{}, nopChecker{accept: false})
	if err != nil {
		t.Fatalf("P2PK reject: %v", err)
	}
	if ok {
		t.Fatal("P2PK with rejecting checker should be false")
	}
}

func TestExec_CleanStackAfterCheckSig(t *testing.T) {
	// After a successful CHECKSIG the stack must have exactly one item
	// (the 1 that CHECKSIG pushed). If witness carries extra items, the
	// final stack has those leftover — the final CastToBool still looks
	// at the top, but leftover items underneath don't fail. Document
	// this (lax) cleanstack policy by checking a multi-witness case.
	pubkey := []byte{0x01}
	leaf := Script(append(BuildPush(pubkey), OP_CHECKSIG))
	ok, err := Execute(leaf, [][]byte{{0xAA}, {0xBB}}, [32]byte{}, nopChecker{accept: true})
	if err != nil {
		t.Fatalf("lax cleanstack: %v", err)
	}
	if !ok {
		t.Fatal("top-of-stack should be truthy (1 from CHECKSIG)")
	}
}

func TestExec_NilSigCheckerFailsCheckSig(t *testing.T) {
	// If the caller forgets to pass a SigChecker, CHECKSIG returns false
	// (no panic, no crash) — consensus code never hits this path but
	// defensive callers should be safe.
	pubkey := []byte{0x01}
	leaf := Script(append(BuildPush(pubkey), OP_CHECKSIG))
	ok, err := Execute(leaf, [][]byte{{0xAA}}, [32]byte{}, nil)
	if err != nil {
		t.Fatalf("nil checker should push false, not error: %v", err)
	}
	if ok {
		t.Fatal("nil checker should cause CHECKSIG to push false")
	}
}
