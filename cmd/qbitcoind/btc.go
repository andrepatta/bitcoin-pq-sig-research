package main

import (
	"strconv"
)

// BTC is an amount denominated in satoshis that JSON-marshals as a bare
// decimal with exactly 8 fractional digits (e.g. `1.50000000`). This
// matches bitcoind's RPC convention and lets clients that speak the
// standard Bitcoin RPC parse qbitcoind output unchanged.
//
// The underlying value is int64 so a "send" detail can be negative
// (bitcoind reports send amounts as negative in listtransactions /
// gettransaction details). A uint64-satoshi input converts cleanly via
// BTCFromSats.
type BTC int64

// BTCFromSats wraps an unsigned satoshi count as a signed BTC amount.
// Amounts that overflow int64 are clamped to int64 max — no qbitcoin
// chain value can exceed that in practice (21M * 1e8 = 2.1e15 < 2^63).
func BTCFromSats(sats uint64) BTC {
	if sats > (1<<63)-1 {
		return BTC((1 << 63) - 1)
	}
	return BTC(sats)
}

// MarshalJSON emits the amount as `<int>.<8-digit-frac>`. Negative
// amounts carry a leading `-`. No scientific notation, no trimming of
// trailing zeros — bitcoind's output is stable-width for ledger diffs.
func (b BTC) MarshalJSON() ([]byte, error) {
	n := int64(b)
	neg := n < 0
	if neg {
		n = -n
	}
	whole := n / 100_000_000
	frac := n % 100_000_000
	buf := make([]byte, 0, 24)
	if neg {
		buf = append(buf, '-')
	}
	buf = strconv.AppendInt(buf, whole, 10)
	buf = append(buf, '.')
	// Zero-pad the fractional part to 8 digits.
	fracStr := strconv.FormatInt(frac, 10)
	for i := len(fracStr); i < 8; i++ {
		buf = append(buf, '0')
	}
	buf = append(buf, fracStr...)
	return buf, nil
}
