package crypto

import "context"

// Test helpers that drive SHRINCS / SHRIMPS through the small demo
// SPHINCS+ parameters. The public constructors (NewShrincsKey /
// NewShrimpsKey) use paper params per docs/parameters/; with those,
// keygen takes seconds and the full test suite would balloon to minutes.
// These helpers invoke the internal *WithParams workhorses instead.
// Crucially, the verifier helpers below must use the same demo params —
// otherwise Verify would re-derive with paper params and reject sigs
// produced under demo geometry.

// newTestShrincsKey constructs a ShrincsKey with the demo fallback
// SPHINCS+ instance. Equivalent to NewShrincsKey but orders of magnitude
// faster; unsuitable for anything on-chain.
func newTestShrincsKey(seed [32]byte, stateFile string) (*ShrincsKey, error) {
	return newShrincsKeyWithParams(context.Background(), seed, NewShrincsFileIO(stateFile), shrincsDemoFallbackSPHINCS())
}

// verifyTestShrincs verifies a sig produced by a newTestShrincsKey key.
// Uses the same demo SPHINCS+ instance so the fallback (tag 0x01) path
// reaches the right hypertree geometry.
func verifyTestShrincs(pubKey []byte, msg []byte, sig *ShrincsSig) bool {
	return verifyShrincsWithParams(pubKey, msg, sig, shrincsDemoFallbackSPHINCS())
}

// newTestShrimpsKey constructs a ShrimpsKey with demo SPHINCS+ params
// on both the compact and fallback instances.
func newTestShrimpsKey(seed [32]byte, stateFile string, nDev, nDsig uint32) (*ShrimpsKey, error) {
	return newShrimpsKeyWithParams(context.Background(), seed, NewShrimpsFileIO(stateFile), nDev, nDsig,
		shrimpsDemoCompactSPHINCS(), shrimpsDemoFallbackSPHINCS())
}

// verifyTestShrimps verifies a sig produced by a newTestShrimpsKey key.
func verifyTestShrimps(commitment [32]byte, msg []byte, sig *ShrimpsSig) bool {
	return verifyShrimpsWithParams(commitment, msg, sig,
		shrimpsDemoCompactSPHINCS(), shrimpsDemoFallbackSPHINCS())
}
