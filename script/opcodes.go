// Package script is the PQBC leaf-script interpreter. Opcode numbering
// and semantics track Satoshi v0.1 (trottier/original-bitcoin src/script.h)
// as augmented by modern Bitcoin Core's post-disable rules: the splice
// ops (CAT/SUBSTR/LEFT/RIGHT), bitwise logic (INVERT/AND/OR/XOR),
// 2MUL/2DIV, and MUL/DIV/MOD/LSHIFT/RSHIFT are defined but reject at
// execute time (errDisabled), matching modern consensus even though
// Satoshi's original source enabled them.
//
// The single PQ-sig deviation: OP_CHECKSIG / OP_CHECKSIGVERIFY are
// polymorphic over SHRINCS vs SHRIMPS. The top-of-stack signature
// carries a 1-byte scheme prefix (SchemeShrincs=0x00 / SchemeShrimps=0x01,
// defined in qbitcoin/crypto) so the verifier dispatches without a
// separate opcode per scheme, analogous to Bitcoin's 0x02/0x03
// compressed-pubkey prefix. OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
// are wired as reserved (execute-time reject) — the paper ships no
// K-of-N PQ-sig construction and we leave the opcodes for future soft-
// fork expansion.

package script

// Opcodes, hex values verbatim from Satoshi v0.1 script.h.
const (
	// Push value
	OP_0         byte = 0x00
	OP_FALSE          = OP_0
	OP_PUSHDATA1 byte = 0x4C
	OP_PUSHDATA2 byte = 0x4D
	OP_PUSHDATA4 byte = 0x4E
	OP_1NEGATE   byte = 0x4F
	OP_RESERVED  byte = 0x50
	OP_1         byte = 0x51
	OP_TRUE           = OP_1
	OP_2         byte = 0x52
	OP_3         byte = 0x53
	OP_4         byte = 0x54
	OP_5         byte = 0x55
	OP_6         byte = 0x56
	OP_7         byte = 0x57
	OP_8         byte = 0x58
	OP_9         byte = 0x59
	OP_10        byte = 0x5A
	OP_11        byte = 0x5B
	OP_12        byte = 0x5C
	OP_13        byte = 0x5D
	OP_14        byte = 0x5E
	OP_15        byte = 0x5F
	OP_16        byte = 0x60

	// Control flow
	OP_NOP      byte = 0x61
	OP_VER      byte = 0x62 // reserved — fails if executed
	OP_IF       byte = 0x63
	OP_NOTIF    byte = 0x64
	OP_VERIF    byte = 0x65 // reserved — fails even in an unexecuted branch
	OP_VERNOTIF byte = 0x66 // reserved — fails even in an unexecuted branch
	OP_ELSE     byte = 0x67
	OP_ENDIF    byte = 0x68
	OP_VERIFY   byte = 0x69
	OP_RETURN   byte = 0x6A

	// Stack ops
	OP_TOALTSTACK   byte = 0x6B
	OP_FROMALTSTACK byte = 0x6C
	OP_2DROP        byte = 0x6D
	OP_2DUP         byte = 0x6E
	OP_3DUP         byte = 0x6F
	OP_2OVER        byte = 0x70
	OP_2ROT         byte = 0x71
	OP_2SWAP        byte = 0x72
	OP_IFDUP        byte = 0x73
	OP_DEPTH        byte = 0x74
	OP_DROP         byte = 0x75
	OP_DUP          byte = 0x76
	OP_NIP          byte = 0x77
	OP_OVER         byte = 0x78
	OP_PICK         byte = 0x79
	OP_ROLL         byte = 0x7A
	OP_ROT          byte = 0x7B
	OP_SWAP         byte = 0x7C
	OP_TUCK         byte = 0x7D

	// Splice — all disabled
	OP_CAT    byte = 0x7E
	OP_SUBSTR byte = 0x7F
	OP_LEFT   byte = 0x80
	OP_RIGHT  byte = 0x81
	OP_SIZE   byte = 0x82

	// Bitwise logic
	OP_INVERT      byte = 0x83 // disabled
	OP_AND         byte = 0x84 // disabled
	OP_OR          byte = 0x85 // disabled
	OP_XOR         byte = 0x86 // disabled
	OP_EQUAL       byte = 0x87
	OP_EQUALVERIFY byte = 0x88
	OP_RESERVED1   byte = 0x89 // reserved — fails if executed
	OP_RESERVED2   byte = 0x8A // reserved — fails if executed

	// Arithmetic
	OP_1ADD               byte = 0x8B
	OP_1SUB               byte = 0x8C
	OP_2MUL               byte = 0x8D // disabled
	OP_2DIV               byte = 0x8E // disabled
	OP_NEGATE             byte = 0x8F
	OP_ABS                byte = 0x90
	OP_NOT                byte = 0x91
	OP_0NOTEQUAL          byte = 0x92
	OP_ADD                byte = 0x93
	OP_SUB                byte = 0x94
	OP_MUL                byte = 0x95 // disabled
	OP_DIV                byte = 0x96 // disabled
	OP_MOD                byte = 0x97 // disabled
	OP_LSHIFT             byte = 0x98 // disabled
	OP_RSHIFT             byte = 0x99 // disabled
	OP_BOOLAND            byte = 0x9A
	OP_BOOLOR             byte = 0x9B
	OP_NUMEQUAL           byte = 0x9C
	OP_NUMEQUALVERIFY     byte = 0x9D
	OP_NUMNOTEQUAL        byte = 0x9E
	OP_LESSTHAN           byte = 0x9F
	OP_GREATERTHAN        byte = 0xA0
	OP_LESSTHANOREQUAL    byte = 0xA1
	OP_GREATERTHANOREQUAL byte = 0xA2
	OP_MIN                byte = 0xA3
	OP_MAX                byte = 0xA4
	OP_WITHIN             byte = 0xA5

	// Crypto
	OP_RIPEMD160           byte = 0xA6
	OP_SHA1                byte = 0xA7
	OP_SHA256              byte = 0xA8
	OP_HASH160             byte = 0xA9
	OP_HASH256             byte = 0xAA
	OP_CODESEPARATOR       byte = 0xAB // retained for wire compatibility; no-op (no subscript hashing in PQBC)
	OP_CHECKSIG            byte = 0xAC
	OP_CHECKSIGVERIFY      byte = 0xAD
	OP_CHECKMULTISIG       byte = 0xAE // reserved (no PQ K-of-N defined)
	OP_CHECKMULTISIGVERIFY byte = 0xAF // reserved

	// Expansion NOPs
	OP_NOP1  byte = 0xB0
	OP_NOP2  byte = 0xB1
	OP_NOP3  byte = 0xB2
	OP_NOP4  byte = 0xB3
	OP_NOP5  byte = 0xB4
	OP_NOP6  byte = 0xB5
	OP_NOP7  byte = 0xB6
	OP_NOP8  byte = 0xB7
	OP_NOP9  byte = 0xB8
	OP_NOP10 byte = 0xB9

	// Template matching — sentinels only, never real opcodes on the wire
	OP_PUBKEYHASH    byte = 0xFD
	OP_PUBKEY        byte = 0xFE
	OP_INVALIDOPCODE byte = 0xFF
)

// OpcodeName returns a human-readable name for an opcode byte. Used in
// error messages and logs. Falls back to hex for unnamed opcodes.
func OpcodeName(op byte) string {
	if name, ok := opcodeNames[op]; ok {
		return name
	}
	if op >= 0x01 && op <= 0x4B {
		return "OP_DATA"
	}
	return "OP_UNKNOWN"
}

var opcodeNames = map[byte]string{
	OP_0:                   "OP_0",
	OP_PUSHDATA1:           "OP_PUSHDATA1",
	OP_PUSHDATA2:           "OP_PUSHDATA2",
	OP_PUSHDATA4:           "OP_PUSHDATA4",
	OP_1NEGATE:             "OP_1NEGATE",
	OP_RESERVED:            "OP_RESERVED",
	OP_1:                   "OP_1",
	OP_2:                   "OP_2",
	OP_3:                   "OP_3",
	OP_4:                   "OP_4",
	OP_5:                   "OP_5",
	OP_6:                   "OP_6",
	OP_7:                   "OP_7",
	OP_8:                   "OP_8",
	OP_9:                   "OP_9",
	OP_10:                  "OP_10",
	OP_11:                  "OP_11",
	OP_12:                  "OP_12",
	OP_13:                  "OP_13",
	OP_14:                  "OP_14",
	OP_15:                  "OP_15",
	OP_16:                  "OP_16",
	OP_NOP:                 "OP_NOP",
	OP_VER:                 "OP_VER",
	OP_IF:                  "OP_IF",
	OP_NOTIF:               "OP_NOTIF",
	OP_VERIF:               "OP_VERIF",
	OP_VERNOTIF:            "OP_VERNOTIF",
	OP_ELSE:                "OP_ELSE",
	OP_ENDIF:               "OP_ENDIF",
	OP_VERIFY:              "OP_VERIFY",
	OP_RETURN:              "OP_RETURN",
	OP_TOALTSTACK:          "OP_TOALTSTACK",
	OP_FROMALTSTACK:        "OP_FROMALTSTACK",
	OP_2DROP:               "OP_2DROP",
	OP_2DUP:                "OP_2DUP",
	OP_3DUP:                "OP_3DUP",
	OP_2OVER:               "OP_2OVER",
	OP_2ROT:                "OP_2ROT",
	OP_2SWAP:               "OP_2SWAP",
	OP_IFDUP:               "OP_IFDUP",
	OP_DEPTH:               "OP_DEPTH",
	OP_DROP:                "OP_DROP",
	OP_DUP:                 "OP_DUP",
	OP_NIP:                 "OP_NIP",
	OP_OVER:                "OP_OVER",
	OP_PICK:                "OP_PICK",
	OP_ROLL:                "OP_ROLL",
	OP_ROT:                 "OP_ROT",
	OP_SWAP:                "OP_SWAP",
	OP_TUCK:                "OP_TUCK",
	OP_CAT:                 "OP_CAT",
	OP_SUBSTR:              "OP_SUBSTR",
	OP_LEFT:                "OP_LEFT",
	OP_RIGHT:               "OP_RIGHT",
	OP_SIZE:                "OP_SIZE",
	OP_INVERT:              "OP_INVERT",
	OP_AND:                 "OP_AND",
	OP_OR:                  "OP_OR",
	OP_XOR:                 "OP_XOR",
	OP_EQUAL:               "OP_EQUAL",
	OP_EQUALVERIFY:         "OP_EQUALVERIFY",
	OP_RESERVED1:           "OP_RESERVED1",
	OP_RESERVED2:           "OP_RESERVED2",
	OP_1ADD:                "OP_1ADD",
	OP_1SUB:                "OP_1SUB",
	OP_2MUL:                "OP_2MUL",
	OP_2DIV:                "OP_2DIV",
	OP_NEGATE:              "OP_NEGATE",
	OP_ABS:                 "OP_ABS",
	OP_NOT:                 "OP_NOT",
	OP_0NOTEQUAL:           "OP_0NOTEQUAL",
	OP_ADD:                 "OP_ADD",
	OP_SUB:                 "OP_SUB",
	OP_MUL:                 "OP_MUL",
	OP_DIV:                 "OP_DIV",
	OP_MOD:                 "OP_MOD",
	OP_LSHIFT:              "OP_LSHIFT",
	OP_RSHIFT:              "OP_RSHIFT",
	OP_BOOLAND:             "OP_BOOLAND",
	OP_BOOLOR:              "OP_BOOLOR",
	OP_NUMEQUAL:            "OP_NUMEQUAL",
	OP_NUMEQUALVERIFY:      "OP_NUMEQUALVERIFY",
	OP_NUMNOTEQUAL:         "OP_NUMNOTEQUAL",
	OP_LESSTHAN:            "OP_LESSTHAN",
	OP_GREATERTHAN:         "OP_GREATERTHAN",
	OP_LESSTHANOREQUAL:     "OP_LESSTHANOREQUAL",
	OP_GREATERTHANOREQUAL:  "OP_GREATERTHANOREQUAL",
	OP_MIN:                 "OP_MIN",
	OP_MAX:                 "OP_MAX",
	OP_WITHIN:              "OP_WITHIN",
	OP_RIPEMD160:           "OP_RIPEMD160",
	OP_SHA1:                "OP_SHA1",
	OP_SHA256:              "OP_SHA256",
	OP_HASH160:             "OP_HASH160",
	OP_HASH256:             "OP_HASH256",
	OP_CODESEPARATOR:       "OP_CODESEPARATOR",
	OP_CHECKSIG:            "OP_CHECKSIG",
	OP_CHECKSIGVERIFY:      "OP_CHECKSIGVERIFY",
	OP_CHECKMULTISIG:       "OP_CHECKMULTISIG",
	OP_CHECKMULTISIGVERIFY: "OP_CHECKMULTISIGVERIFY",
	OP_NOP1:                "OP_NOP1",
	OP_NOP2:                "OP_NOP2",
	OP_NOP3:                "OP_NOP3",
	OP_NOP4:                "OP_NOP4",
	OP_NOP5:                "OP_NOP5",
	OP_NOP6:                "OP_NOP6",
	OP_NOP7:                "OP_NOP7",
	OP_NOP8:                "OP_NOP8",
	OP_NOP9:                "OP_NOP9",
	OP_NOP10:               "OP_NOP10",
	OP_PUBKEYHASH:          "OP_PUBKEYHASH",
	OP_PUBKEY:              "OP_PUBKEY",
	OP_INVALIDOPCODE:       "OP_INVALIDOPCODE",
}

// isDisabled reports whether the opcode is disabled under modern Bitcoin
// Core rules: if it appears anywhere in the script (even in a branch
// that wouldn't execute), the script is invalid.
func isDisabled(op byte) bool {
	switch op {
	case OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT,
		OP_INVERT, OP_AND, OP_OR, OP_XOR,
		OP_2MUL, OP_2DIV,
		OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT:
		return true
	}
	return false
}

// isCountedOp reports whether op counts against MaxOpsPerScript. Per
// Bitcoin consensus, pushes (opcode <= OP_16) do not count.
func isCountedOp(op byte) bool { return op > OP_16 }
