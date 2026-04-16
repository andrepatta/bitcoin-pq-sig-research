//go:build ignore

// bench.go — calibrate against the production grinder path (midstate +
// no-alloc inner loop), not the naive core.BlockHeader.Hash() path that
// main.go uses. The main.go benchmark undercounts real miner throughput
// by ~33% because it pays the full 3-compression serialize-then-hash
// cost per nonce, while miner.grindStride uses a cached midstate and
// only does 2 compressions.
//
// Run:   go run -tags whatever bench.go
package main

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"qbitcoin/core"
)

const headerSize = 88

func main() {
	threadsFlag := flag.Int("threads", runtime.NumCPU(), "worker threads")
	flag.Parse()
	threads := *threadsFlag
	duration := 5 * time.Second

	// Use an unsolvable target so the loop runs through the whole window.
	var hdr core.BlockHeader
	hdr.Version = 1
	hdr.Bits = 0x03000001 // target ≈ 1

	var hashes uint64
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(start uint64) {
			defer wg.Done()
			local := hdr

			var buf [headerSize]byte
			binary.LittleEndian.PutUint32(buf[0:4], local.Version)
			copy(buf[4:36], local.PrevHash[:])
			copy(buf[36:68], local.MerkleRoot[:])
			binary.LittleEndian.PutUint64(buf[68:76], local.Timestamp)
			binary.LittleEndian.PutUint32(buf[76:80], local.Bits)
			binary.LittleEndian.PutUint64(buf[80:88], start)

			sha := sha256.New()
			sha.Write(buf[:64])
			marsh := sha.(encoding.BinaryMarshaler)
			unmarsh := sha.(encoding.BinaryUnmarshaler)
			mid, _ := marsh.MarshalBinary()

			var firstHash [32]byte
			nonce := start
			var localHashes uint64
			const checkEvery = 1 << 14
			counter := 0
			for {
				counter++
				if counter >= checkEvery {
					counter = 0
					select {
					case <-stop:
						atomic.AddUint64(&hashes, localHashes)
						return
					default:
					}
				}
				binary.LittleEndian.PutUint64(buf[80:88], nonce)
				_ = unmarsh.UnmarshalBinary(mid)
				sha.Write(buf[64:88])
				sha.Sum(firstHash[:0])
				_ = sha256.Sum256(firstHash[:])
				localHashes++
				nonce += uint64(threads)
			}
		}(uint64(i))
	}

	time.Sleep(duration)
	close(stop)
	wg.Wait()

	rate := float64(hashes) / duration.Seconds()
	fmt.Printf("threads:      %d\n", threads)
	fmt.Printf("hashes:       %d in %s  (grinder midstate path)\n", hashes, duration)
	fmt.Printf("hashrate:     %.2f H/s  (%.2f MH/s)\n", rate, rate/1e6)

	want := 600.0
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	denom := new(big.Int).SetUint64(uint64(rate * want))
	target := new(big.Int).Div(two256, denom)

	powLimit := core.TargetToBig(core.BitsToTarget(core.GenesisBits))
	clamped := false
	if target.Cmp(powLimit) > 0 {
		target = powLimit
		clamped = true
	}
	bits := core.BigToBits(target)

	fmt.Printf("target block: %.0fs\n", want)
	fmt.Printf("target (hex): %064x\n", target)
	fmt.Printf("bits:         0x%08x%s\n", bits, map[bool]string{true: "  (clamped to powLimit)", false: ""}[clamped])

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
