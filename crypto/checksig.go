package crypto

// CheckSig glue for the script interpreter. The script VM is scheme-
// agnostic — it pops a (sig, pubkey) pair from the stack and hands them
// to a SigChecker. This package supplies the default checker that
// dispatches SHRINCS vs SHRIMPS by parsing a 1-byte scheme tag prefixed
// to the signature bytes.
//
// Why a scheme-tag prefix instead of length-dispatch: the two schemes'
// on-wire sizes overlap at paper params (SHRINCS stateless ≈ 4080 B
// straddles SHRIMPS compact ≈ 2663 B up to SHRIMPS fallback ≈ 4200 B),
// so a consensus-critical verifier cannot tell them apart by length
// alone. A leading byte costs one stack byte per signature and makes
// dispatch unambiguous — analogous to Bitcoin's 0x02/0x03 compressed-
// pubkey prefix.

// Signature scheme-tag constants. These are the first byte of every
// signature pushed to the script stack for OP_CHECKSIG to consume.
const (
	SchemeShrincs byte = 0x00
	SchemeShrimps byte = 0x01
)

// CheckSig verifies sig over sighash under pubkey. sig's first byte
// selects the scheme; remaining bytes are the SerializeShrincsSig /
// SerializeShrimpsSig output.
//
// Returns false (never an error) on any malformed input — matches
// Bitcoin's OP_CHECKSIG contract where an invalid signature produces a
// false stack push, not a consensus failure.
func CheckSig(sig, pubkey []byte, sighash [32]byte) bool {
	if len(sig) < 1 {
		return false
	}
	scheme := sig[0]
	body := sig[1:]
	switch scheme {
	case SchemeShrincs:
		s, err := DeserializeShrincsSig(body)
		if err != nil {
			return false
		}
		return VerifyShrincs(pubkey, sighash[:], s)
	case SchemeShrimps:
		s, err := DeserializeShrimpsSig(body)
		if err != nil {
			return false
		}
		if len(pubkey) != shrimpsPubKeySize {
			return false
		}
		var commit [32]byte
		copy(commit[:], pubkey)
		return VerifyShrimps(commit, sighash[:], s)
	}
	return false
}

// DefaultSigChecker is the production SigChecker supplied to the script
// interpreter. Wraps the package-level CheckSig into a type satisfying
// script.SigChecker (avoids an import cycle — script imports crypto,
// so crypto supplies the concrete value).
type defaultSigChecker struct{}

// CheckSig satisfies script.SigChecker.
func (defaultSigChecker) CheckSig(sig, pubkey []byte, sighash [32]byte) bool {
	return CheckSig(sig, pubkey, sighash)
}

// DefaultSigChecker is a stateless instance of the production checker.
// Pass this to script.Execute at consensus call sites.
var DefaultSigChecker = defaultSigChecker{}
