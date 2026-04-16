package core

import "testing"

// TestIsImmatureCoinbase pins the truth table that drives both
// consensus rejection (validateAndApply) and wallet filtering
// (chainUTXO.Balance / AllForAddress). Mutating CoinbaseMaturity is a
// hard fork; this test fails loudly if the constant changes silently.
func TestIsImmatureCoinbase(t *testing.T) {
	bc := &Blockchain{}
	cases := []struct {
		name     string
		tip      uint32
		coinbase bool
		birth    uint32
		want     bool
	}{
		{"non-coinbase always mature", 0, false, 0, false},
		{"coinbase same block", 5, true, 5, true},
		{"coinbase 1 conf", 6, true, 5, true},
		{"coinbase 99 conf", 5 + CoinbaseMaturity - 1, true, 5, true},
		{"coinbase 100 conf (mature)", 5 + CoinbaseMaturity, true, 5, false},
		{"coinbase 101 conf", 5 + CoinbaseMaturity + 1, true, 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bc.tipHeight = tc.tip
			if got := bc.isImmatureCoinbase(tc.coinbase, tc.birth); got != tc.want {
				t.Fatalf("isImmatureCoinbase(coinbase=%v, birth=%d) at tip=%d: got %v want %v",
					tc.coinbase, tc.birth, tc.tip, got, tc.want)
			}
		})
	}
}

// TestCoinbaseMaturityConstant guards against accidental tweaks; the
// value mirrors Bitcoin's COINBASE_MATURITY = 100.
func TestCoinbaseMaturityConstant(t *testing.T) {
	if CoinbaseMaturity != 100 {
		t.Fatalf("CoinbaseMaturity = %d, want 100 (changing this is a hard fork)", CoinbaseMaturity)
	}
}
