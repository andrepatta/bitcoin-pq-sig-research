package hashsig

import (
	"bytes"
	"testing"
)

// Smoke tests: the tweakable hash family must be deterministic, produce
// n-byte outputs, and domain-separate via ADRS. These cover structural
// invariants; known-answer tests against costs.sage live in separate fixtures.

func testParams() *Params {
	return &Params{
		N:      16,
		PKSeed: bytes.Repeat([]byte{0xAA}, 16),
	}
}

func TestFDeterministic(t *testing.T) {
	p := testParams()
	var a ADRS
	a.SetType(AddrTypeWOTSHash)
	a.SetKeyPair(7)
	a.SetChain(3)
	a.SetHash(5)
	m := bytes.Repeat([]byte{0x42}, 16)

	y1 := p.F(a, m)
	y2 := p.F(a, m)
	if !bytes.Equal(y1, y2) {
		t.Fatal("F not deterministic")
	}
	if len(y1) != 16 {
		t.Fatalf("F output size: got %d want 16", len(y1))
	}
}

func TestFDomainSeparation(t *testing.T) {
	p := testParams()
	var a1, a2 ADRS
	a1.SetType(AddrTypeWOTSHash)
	a1.SetChain(1)
	a2.SetType(AddrTypeWOTSHash)
	a2.SetChain(2) // only chain index differs
	m := bytes.Repeat([]byte{0x42}, 16)

	if bytes.Equal(p.F(a1, m), p.F(a2, m)) {
		t.Fatal("F failed to domain-separate on chain index")
	}
}

func TestHTwoInput(t *testing.T) {
	p := testParams()
	var a ADRS
	a.SetType(AddrTypeTree)
	l := bytes.Repeat([]byte{0x11}, 16)
	r := bytes.Repeat([]byte{0x22}, 16)

	// H(M1||M2) must differ from H(M2||M1) — argument order matters.
	if bytes.Equal(p.H(a, l, r), p.H(a, r, l)) {
		t.Fatal("H not order-sensitive")
	}
	// H should equal T_l with two inputs.
	if !bytes.Equal(p.H(a, l, r), p.Tl(a, l, r)) {
		t.Fatal("H diverges from T_l on two inputs")
	}
}

func TestTlVariableArity(t *testing.T) {
	p := testParams()
	var a ADRS
	a.SetType(AddrTypeWOTSPK)
	inputs := make([][]byte, 32)
	for i := range inputs {
		inputs[i] = bytes.Repeat([]byte{byte(i)}, 16)
	}
	y := p.Tl(a, inputs...)
	if len(y) != 16 {
		t.Fatalf("T_l output size: got %d want 16", len(y))
	}
}

func TestPRFSeparatesOnADRS(t *testing.T) {
	p := testParams()
	sk := bytes.Repeat([]byte{0x55}, 16)
	var a1, a2 ADRS
	a1.SetType(AddrTypeWOTSPRF)
	a1.SetKeyPair(10)
	a2.SetType(AddrTypeWOTSPRF)
	a2.SetKeyPair(11)

	if bytes.Equal(p.PRF(sk, a1), p.PRF(sk, a2)) {
		t.Fatal("PRF failed to domain-separate on ADRS")
	}
}

func TestHmsg512Bit(t *testing.T) {
	r := bytes.Repeat([]byte{1}, 16)
	seed := bytes.Repeat([]byte{2}, 16)
	root := bytes.Repeat([]byte{3}, 16)
	msg := []byte("transfer 10 PQBC to alice")
	d := Hmsg(r, seed, root, msg)
	if len(d) != 64 {
		t.Fatalf("Hmsg digest size: got %d want 64", len(d))
	}
	// Different R must produce different digest.
	r2 := bytes.Repeat([]byte{9}, 16)
	if bytes.Equal(d, Hmsg(r2, seed, root, msg)) {
		t.Fatal("Hmsg did not respond to R change")
	}
}

func TestADRSCompressedSize(t *testing.T) {
	var a ADRS
	a.SetLayer(1)
	a.SetTree(0xDEADBEEFCAFE)
	a.SetType(AddrTypeFORSTree)
	a.SetKeyPair(42)
	b := a.Bytes()
	if len(b) != 22 {
		t.Fatalf("compressed ADRS size: got %d want 22", len(b))
	}
	if b[0] != 1 || b[9] != byte(AddrTypeFORSTree) {
		t.Fatal("compressed ADRS layout mismatch at fixed offsets")
	}
}

func TestADRSCloneIndependence(t *testing.T) {
	var a ADRS
	a.SetChain(5)
	b := a.Clone()
	b.SetChain(9)
	if a.Bytes() == b.Bytes() {
		t.Fatal("Clone did not produce an independent copy")
	}
}
