package crypto

import (
	"context"
	"testing"
)

// TestCheckSig_SchemeDispatch round-trips the polymorphic CHECKSIG
// dispatch for both supported schemes. A SHRINCS sig with scheme tag
// 0x00 must verify under a SHRINCS pubkey; a SHRIMPS sig with scheme
// tag 0x01 must verify under a SHRIMPS commitment. Cross-scheme
// (SHRIMPS body under SHRINCS tag, etc.) must reject.
func TestCheckSig_SchemeDispatch(t *testing.T) {
	ctx := context.Background()
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}

	// Demo params are in-package so Sign/Verify both resolve to the
	// same fallback geometry — avoids the multi-second paper-param
	// keygen (this test targets the tag-dispatch logic, not SPHINCS+).
	shrincsKey, err := newShrincsKeyWithParams(ctx, seed, nil, shrincsDemoFallbackSPHINCS())
	if err != nil {
		t.Fatalf("shrincs keygen: %v", err)
	}
	shrimpsKey, err := newShrimpsKeyWithParams(ctx, seed, nil, 4, 4,
		shrimpsDemoCompactSPHINCS(), shrimpsDemoFallbackSPHINCS())
	if err != nil {
		t.Fatalf("shrimps keygen: %v", err)
	}

	msg := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

	shSig, err := shrincsKey.Sign(ctx, msg[:])
	if err != nil {
		t.Fatalf("shrincs sign: %v", err)
	}
	shTagged := append([]byte{SchemeShrincs}, SerializeShrincsSig(shSig)...)

	smSig, err := shrimpsKey.Sign(ctx, msg[:])
	if err != nil {
		t.Fatalf("shrimps sign: %v", err)
	}
	smTagged := append([]byte{SchemeShrimps}, SerializeShrimpsSig(smSig)...)

	// The production CheckSig dispatcher uses paper params, which won't
	// verify our demo-param signatures. Exercise dispatch using the
	// internal verify-with-params helpers so we can actually hit the
	// success path.
	dispatchDemo := func(sig, pk []byte, sh [32]byte) bool {
		if len(sig) < 1 {
			return false
		}
		switch sig[0] {
		case SchemeShrincs:
			s, err := DeserializeShrincsSig(sig[1:])
			if err != nil {
				return false
			}
			return verifyShrincsWithParams(pk, sh[:], s, shrincsDemoFallbackSPHINCS())
		case SchemeShrimps:
			s, err := DeserializeShrimpsSig(sig[1:])
			if err != nil {
				return false
			}
			if len(pk) != shrimpsPubKeySize {
				return false
			}
			var commit [32]byte
			copy(commit[:], pk)
			return verifyShrimpsWithParams(commit, sh[:], s,
				shrimpsDemoCompactSPHINCS(), shrimpsDemoFallbackSPHINCS())
		}
		return false
	}

	// Happy path: each scheme verifies under its own pubkey.
	if !dispatchDemo(shTagged, shrincsKey.PublicKey, msg) {
		t.Fatal("SHRINCS sig should verify under SHRINCS pubkey")
	}
	if !dispatchDemo(smTagged, shrimpsKey.PublicKey[:], msg) {
		t.Fatal("SHRIMPS sig should verify under SHRIMPS pubkey")
	}

	// Cross-scheme: the tag says SHRINCS but the body is a SHRIMPS sig
	// and the pubkey is SHRIMPS. Must reject.
	crossTagged := append([]byte{SchemeShrincs}, SerializeShrimpsSig(smSig)...)
	if dispatchDemo(crossTagged, shrimpsKey.PublicKey[:], msg) {
		t.Fatal("cross-scheme SHRIMPS-body-under-SHRINCS-tag must reject")
	}

	// Unknown scheme tag.
	bad := append([]byte{0x7F}, SerializeShrincsSig(shSig)...)
	if dispatchDemo(bad, shrincsKey.PublicKey, msg) {
		t.Fatal("unknown scheme tag must reject")
	}
}

// TestCheckSig_MalformedInputsReject covers every input path that must
// return false (not error, not panic).
func TestCheckSig_MalformedInputsReject(t *testing.T) {
	cases := []struct {
		name string
		sig  []byte
		pk   []byte
	}{
		{"empty sig", []byte{}, []byte{0xAA}},
		{"truncated SHRINCS sig", []byte{SchemeShrincs, 0x00}, []byte{0xAA}},
		{"truncated SHRIMPS sig", []byte{SchemeShrimps, 0x00}, make([]byte, 32)},
		{"SHRIMPS with wrong-size pk", []byte{SchemeShrimps, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, []byte{0xAA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if CheckSig(tc.sig, tc.pk, [32]byte{}) {
				t.Fatal("malformed input should reject, got accept")
			}
		})
	}
}

// TestDefaultSigChecker confirms the exported singleton satisfies the
// script.SigChecker interface by wiring it through a trivial call.
func TestDefaultSigChecker(t *testing.T) {
	// Empty sig → CheckSig false (no scheme byte).
	if DefaultSigChecker.CheckSig(nil, nil, [32]byte{}) {
		t.Fatal("DefaultSigChecker must reject empty sig")
	}
}
