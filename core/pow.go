package core

import (
	"bytes"
	"math/big"
)

// Target is a 32-byte big-endian difficulty target.
type Target [32]byte

// BitsToTarget converts Bitcoin-style compact bits to a 32-byte target.
// Compact: 1-byte exponent | 3-byte mantissa.
func BitsToTarget(bits uint32) Target {
	exp := uint8(bits >> 24)
	mant := bits & 0x00FFFFFF
	var t Target
	if exp <= 3 {
		mant >>= 8 * (3 - uint(exp))
		t[29] = byte(mant >> 16)
		t[30] = byte(mant >> 8)
		t[31] = byte(mant)
		return t
	}
	if exp > 32 {
		// Cap exp to fit into 32-byte target.
		exp = 32
	}
	off := int(exp) - 3
	// mantissa occupies bytes [32-exp..32-exp+3], i.e. starting at off.
	idx := 32 - int(exp)
	if idx < 0 {
		idx = 0
	}
	_ = off
	if idx+3 <= 32 {
		t[idx] = byte(mant >> 16)
		t[idx+1] = byte(mant >> 8)
		t[idx+2] = byte(mant)
	}
	return t
}

// TargetToBig returns the target as a big.Int.
func TargetToBig(t Target) *big.Int { return new(big.Int).SetBytes(t[:]) }

// MaxTargetBig is 2^256.
func MaxTargetBig() *big.Int {
	x := big.NewInt(1)
	return x.Lsh(x, 256)
}

// WorkFromBits returns an approximation of work (2^256 / (target+1)) as big.Int.
func WorkFromBits(bits uint32) *big.Int {
	t := BitsToTarget(bits)
	tb := TargetToBig(t)
	one := big.NewInt(1)
	return new(big.Int).Div(MaxTargetBig(), new(big.Int).Add(tb, one))
}

// CheckProof returns true iff SHA-256d(header) < target.
func CheckProof(header BlockHeader) bool {
	hash := header.Hash()
	target := BitsToTarget(header.Bits)
	return bytes.Compare(hash[:], target[:]) < 0
}

// Mining lives in the `miner` package — see miner.Grind. Callers that
// need to produce a valid PoW (regtest generatetoaddress, the external
// `qbitcoin-miner` binary, cmd/mine-genesis) import it directly.

// --- difficulty adjustment: Bitcoin DAA ---
//
// Every RetargetInterval (2016) blocks, retarget using the time it took the
// previous window to mine. Between retarget boundaries, bits are inherited
// unchanged from the parent. Formula (Bitcoin Core `pow.cpp`):
//
//     actualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime
//     actualTimespan clamped to [targetTimespan/4, targetTimespan*4]
//     newTarget = oldTarget * actualTimespan / targetTimespan
//     newTarget clamped to powLimit
//
// `pindexLast` is the block being built upon; `nFirstBlockTime` is the
// timestamp of the block at height `pindexLast.height - 2015` (the Bitcoin
// off-by-one: 2015 intervals over 2016 blocks is part of consensus).

// TargetBlockTimeSec is the ideal block spacing in seconds.
const TargetBlockTimeSec = 600

// RetargetInterval is the number of blocks between difficulty retargets.
const RetargetInterval = 2016

// TargetTimespanSec is the ideal duration of one retarget window.
const TargetTimespanSec = RetargetInterval * TargetBlockTimeSec // 1_209_600 s (2 weeks)

// ComputeNextWorkRequired returns the Bits for the block at `nextHeight`,
// being built on top of a parent with `parentBits` and `lastTimestamp`.
// `firstTimestamp` is the timestamp of the block at `nextHeight - RetargetInterval`
// and is ignored on non-boundary heights (pass 0).
func ComputeNextWorkRequired(nextHeight uint64, parentBits uint32, lastTimestamp uint64, firstTimestamp uint64) uint32 {
	if nextHeight%RetargetInterval != 0 || nextHeight == 0 {
		return parentBits
	}
	actual := int64(lastTimestamp) - int64(firstTimestamp)
	minTimespan := int64(TargetTimespanSec / 4)
	maxTimespan := int64(TargetTimespanSec * 4)
	if actual < minTimespan {
		actual = minTimespan
	}
	if actual > maxTimespan {
		actual = maxTimespan
	}
	newTarget := new(big.Int).Mul(
		TargetToBig(BitsToTarget(parentBits)),
		big.NewInt(actual),
	)
	newTarget.Div(newTarget, big.NewInt(int64(TargetTimespanSec)))
	if newTarget.Sign() == 0 {
		newTarget.SetInt64(1)
	}
	powLimit := TargetToBig(BitsToTarget(GenesisBits))
	if newTarget.Cmp(powLimit) > 0 {
		newTarget = powLimit
	}
	return BigToBits(newTarget)
}

// BigToBits encodes a 256-bit target value into compact Bits.
func BigToBits(n *big.Int) uint32 {
	if n.Sign() == 0 {
		return 0
	}
	b := n.Bytes()
	size := len(b)
	var mant uint32
	if size <= 3 {
		mant = uint32(new(big.Int).Lsh(n, uint(8*(3-size))).Uint64()) & 0x00FFFFFF
	} else {
		mant = uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	}
	// If the high bit is set in mantissa, push it down (compact form).
	if mant&0x00800000 != 0 {
		mant >>= 8
		size++
	}
	return (uint32(size) << 24) | (mant & 0x00FFFFFF)
}
