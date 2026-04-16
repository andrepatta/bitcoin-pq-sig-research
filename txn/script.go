package txn

import (
	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/script"
)

// Per-CHECKSIG signature-verification cost. One "sigop" in PQBC is one
// PQ signature verification; SHRINCS is a single path while SHRIMPS is
// structurally two SPHINCS+ instances under one commitment. These
// constants feed both the per-block cap (core.MaxBlockSigOpsCost) and
// the mempool budget.
const (
	ShrincsVerifyCost = 1
	ShrimpsVerifyCost = 2
)

// MaxStandardTxSigOpsCost bounds the sigop cost of any single tx
// accepted into the mempool — Bitcoin's MAX_STANDARD_TX_SIGOPS_COST
// analog (MaxBlockSigOpsCost / 5). Prevents one tx from monopolising
// a block's verification budget.
const MaxStandardTxSigOpsCost = 80_000 / 5

// SigOpCost returns the total signature-verification cost of tx,
// summed across every input's leaf-script CHECKSIG operations. Coinbase
// inputs contribute 0 (never script-executed).
//
// Per-CHECKSIG cost is determined by the witness's scheme-tag byte:
// SchemeShrincs → ShrincsVerifyCost, SchemeShrimps → ShrimpsVerifyCost.
// When the witness is empty or the scheme is unknown, we conservatively
// charge the max (ShrimpsVerifyCost) so policy checks can't be
// under-budgeted by malformed witnesses.
func SigOpCost(tx Transaction) int {
	if tx.IsCoinbase() {
		return 0
	}
	var sum int
	for i := range tx.Inputs {
		in := tx.Inputs[i]
		nCheckSig, err := countCheckSig(in.Spend.LeafScript)
		if err != nil || nCheckSig == 0 {
			continue
		}
		costPer := ShrimpsVerifyCost
		if len(in.Spend.Witness) > 0 && len(in.Spend.Witness[0]) >= 1 {
			switch in.Spend.Witness[0][0] {
			case crypto.SchemeShrincs:
				costPer = ShrincsVerifyCost
			case crypto.SchemeShrimps:
				costPer = ShrimpsVerifyCost
			}
		}
		sum += nCheckSig * costPer
	}
	return sum
}

// countCheckSig counts OP_CHECKSIG + OP_CHECKSIGVERIFY occurrences in a
// leaf script. A malformed script returns (n, err) where n reflects
// opcodes successfully parsed before the truncation.
func countCheckSig(leaf address.LeafScript) (int, error) {
	var n int
	err := script.Script(leaf).Iterate(func(op script.Op) error {
		if op.Opcode == script.OP_CHECKSIG || op.Opcode == script.OP_CHECKSIGVERIFY {
			n++
		}
		return nil
	})
	return n, err
}

// Execute runs the leaf script against the supplied witness stack and
// sighash under the script interpreter. Thin wrapper around
// script.Execute wiring the crypto package's default SigChecker (which
// dispatches SHRINCS vs SHRIMPS on the signature's 1-byte scheme tag).
func Execute(leaf address.LeafScript, witness [][]byte, txSigHash [32]byte) (bool, error) {
	return script.Execute(script.Script(leaf), witness, txSigHash, crypto.DefaultSigChecker)
}
