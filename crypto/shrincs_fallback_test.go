package crypto

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// TestShrincsStatelessFallbackTransition exercises the stateful →
// stateless transition triggered by paper §B.3's `min(stateful, sl)`
// rule: once the UXMSS auth path would make a stateful sig non-smaller
// than the stateless one, `Sign()` transparently emits a fallback
// SPHINCS+ signature that verifies under the same public key.
//
// Uses demo fallback params to keep the size crossover at a small q
// (paper fallback pushes it out to q≈234; demo params drop it to ~70).
// Paper-params coverage lives in TestPaperParamsKeygen.
func TestShrincsStatelessFallbackTransition(t *testing.T) {
	k, err := newShrincsKeyWithParams(t.Context(), testSeed(0xFB), NewShrincsFileIO(tmpStateFile(t)), shrincsDemoFallbackSPHINCS())
	if err != nil {
		t.Fatalf("newShrincsKeyWithParams: %v", err)
	}

	pub := k.PublicKey
	threshold := k.statelessBodyLen()

	type signOutcome struct {
		sig        *ShrincsSig
		wireLen    int
		isStateful bool
		signTime   time.Duration
	}
	var outcomes []signOutcome
	sawFallback := false

	// Iterate until we've observed at least one stateful AND one stateless
	// signature. Safety cap matches ShrincsNumLeaves so we can't spin.
	for i := 0; i < ShrincsNumLeaves && (!sawFallback || len(outcomes) < 2); i++ {
		msg := []byte(fmt.Sprintf("exhaust-test-%d", i))
		start := time.Now()
		sig, err := k.Sign(t.Context(), msg)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Sign iter %d: %v", i, err)
		}
		wire := SerializeShrincsSig(sig)
		outcomes = append(outcomes, signOutcome{
			sig:        sig,
			wireLen:    len(wire),
			isStateful: sig.IsStateful(),
			signTime:   elapsed,
		})
		if !sig.IsStateful() {
			sawFallback = true
		}
		parsed, err := DeserializeShrincsSig(wire)
		if err != nil {
			t.Fatalf("round-trip deserialize iter %d: %v", i, err)
		}
		if !verifyTestShrincs(pub, msg, parsed) {
			t.Fatalf("verify rejected valid sig iter %d (isStateful=%v)", i, parsed.IsStateful())
		}
	}
	if !sawFallback {
		t.Fatal("never observed fallback sig within tree budget")
	}

	// Paper's min-rule invariant: every stateful body < threshold; the
	// fallback body == threshold exactly.
	for i, o := range outcomes {
		bodyLen := len(o.sig.SphincsIG)
		if o.isStateful && bodyLen >= threshold {
			t.Fatalf("iter %d: stateful body %d ≥ threshold %d — violates min-rule", i, bodyLen, threshold)
		}
		if !o.isStateful && bodyLen != threshold {
			t.Fatalf("iter %d: stateless body %d != threshold %d", i, bodyLen, threshold)
		}
		t.Logf("iter %d: stateful=%v body=%d wire=%d sign=%s",
			i, o.isStateful, bodyLen, o.wireLen, o.signTime)
	}

	// Tamper the fallback sig and confirm verify rejects.
	fallback := outcomes[len(outcomes)-1].sig
	if fallback.IsStateful() {
		t.Fatal("expected last outcome to be fallback")
	}
	bad := append([]byte{}, fallback.SphincsIG...)
	bad[len(bad)/2] ^= 0x01
	badSig := &ShrincsSig{Counter: fallback.Counter, SphincsIG: bad}
	if verifyTestShrincs(pub, []byte("exhaust-test-0"), badSig) {
		t.Fatal("verify accepted tampered fallback sig")
	}
	_ = bytes.Equal
}
