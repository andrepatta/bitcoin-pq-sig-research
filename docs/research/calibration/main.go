package main

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"qbitcoin/core"
)

func main() {
	threads := runtime.NumCPU()
	duration := 5 * time.Second

	var hashes uint64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hdr := core.BlockHeader{Version: 1, Nonce: uint64(id)}
			var local uint64
			for {
				select {
				case <-stop:
					atomic.AddUint64(&hashes, local)
					return
				default:
				}
				for j := 0; j < 1024; j++ {
					hdr.Hash()
					hdr.Nonce++
					local++
				}
			}
		}(i)
	}
	time.Sleep(duration)
	close(stop)
	wg.Wait()

	rate := float64(hashes) / duration.Seconds()
	fmt.Printf("threads:      %d\n", threads)
	fmt.Printf("hashes:       %d in %s\n", hashes, duration)
	fmt.Printf("hashrate:     %.2f H/s  (%.2f MH/s)\n", rate, rate/1e6)

	// target ≈ 2^256 / (hashrate * 600)
	want := 600.0
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	denom := new(big.Int).SetUint64(uint64(rate * want))
	target := new(big.Int).Div(two256, denom)

	// Cap at powLimit (GenesisBits target).
	powLimit := core.TargetToBig(core.BitsToTarget(core.GenesisBits))
	clamped := false
	if target.Cmp(powLimit) > 0 {
		target = powLimit
		clamped = true
	}
	bits := core.BigToBits(target)

	fmt.Printf("target block: %.0fs\n", want)
	fmt.Printf("target (hex): %064x\n", target)
	fmt.Printf("bits:         0x%08x%s\n", bits, map[bool]string{true: "  (clamped to powLimit — your machine is slower than the current GenesisBits — keep GenesisBits as-is)", false: ""}[clamped])

	// Sanity: how long would a block take on this machine at the proposed bits?
	expected := new(big.Float).Quo(
		new(big.Float).SetInt(two256),
		new(big.Float).Mul(
			new(big.Float).SetInt(target),
			big.NewFloat(rate),
		),
	)
	secs, _ := expected.Float64()
	fmt.Printf("predicted mean block time at these bits: %.1fs\n", secs)
}
