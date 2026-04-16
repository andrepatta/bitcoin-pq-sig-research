//go:build ignore
package main

import (
	"fmt"
	"math/big"
	"qbitcoin/core"
)

func main() {
	bits := uint32(0x1d00dddd)
	target := core.TargetToBig(core.BitsToTarget(bits))
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	fmt.Printf("bits:    0x%08x\n", bits)
	fmt.Printf("target:  %064x\n", target)
	fmt.Printf("canonical bits: 0x%08x\n", core.BigToBits(target))

	// mean block time at various hashrates
	for _, rate := range []float64{10e6, 40e6, 87e6} {
		mean := new(big.Float).Quo(
			new(big.Float).SetInt(two256),
			new(big.Float).Mul(new(big.Float).SetInt(target), big.NewFloat(rate)),
		)
		secs, _ := mean.Float64()
		fmt.Printf("  at %6.0f MH/s: mean block = %6.1fs  (%.2f min)\n", rate/1e6, secs, secs/60)
	}
}
