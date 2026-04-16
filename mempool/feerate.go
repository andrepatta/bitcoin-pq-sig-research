package mempool

// Fee policy parameters. Per-byte rates rather than Bitcoin's per-vbyte
// because PQBC has no segwit and no witness discount. These are package
// vars so tests can flip them; production tuning would surface them via
// flags.
var (
	// MinRelayFeeRate is the floor (sats/byte) for accepting a tx into
	// the mempool. Bitcoin's analog is -minrelaytxfee = 1 sat/vB.
	// PQ-sig txs are large (~700 B SHRINCS, ~2.6 KB SHRIMPS), so absolute
	// per-tx fees run higher than Bitcoin's at the same rate.
	MinRelayFeeRate uint64 = 1

	// IncrementalRelayFeeRate is BIP-125 rule 4: an RBF replacement must
	// pay at least (incremental_rate * replacement_size) more in absolute
	// fee than the sum of the txs it evicts. Default 1 sat/B (Core's
	// -incrementalrelayfee).
	IncrementalRelayFeeRate uint64 = 1
)

// MaxRBFConflicts caps how many in-pool txs a single RBF replacement
// may evict (BIP-125 rule 5). Without a cap, a single big-fee tx could
// evict the entire mempool in one call.
const MaxRBFConflicts = 100

// meetsFeeRate reports whether fee >= rate * size, integer-only so we
// avoid division and float precision loss.
func meetsFeeRate(fee uint64, size int, rate uint64) bool {
	return fee >= rate*uint64(size)
}

// feeRateGreater reports whether a's fee-rate is strictly greater than
// b's, comparing (fee_a/size_a) > (fee_b/size_b) via cross-multiplication.
// Both sizes must be > 0.
func feeRateGreater(feeA uint64, sizeA int, feeB uint64, sizeB int) bool {
	return feeA*uint64(sizeB) > feeB*uint64(sizeA)
}
