//go:build ignore
package main

import (
	"fmt"
	"math/big"
	"qbitcoin/core"
)

func main() {
	rate := 10e6
	want := 600.0
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	denom := new(big.Int).SetUint64(uint64(rate * want))
	target := new(big.Int).Div(two256, denom)
	bits := core.BigToBits(target)
	fmt.Printf("rate:   %.0f H/s\n", rate)
	fmt.Printf("target: %064x\n", target)
	fmt.Printf("bits:   0x%08x\n", bits)
	// Predicted mean block time sanity check.
	pred := new(big.Float).Quo(
		new(big.Float).SetInt(two256),
		new(big.Float).Mul(new(big.Float).SetInt(target), big.NewFloat(rate)),
	)
	secs, _ := pred.Float64()
	fmt.Printf("predicted mean: %.1fs\n", secs)
}
