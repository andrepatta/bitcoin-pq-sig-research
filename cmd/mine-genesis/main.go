// mine-genesis mines the genesis block once so its Nonce and Timestamp can
// be pinned as consensus constants in core/genesis.go, skipping the
// one-time mining step on every fresh node startup.
//
// Usage:
//
//	go run ./cmd/mine-genesis [-threads N] [-timestamp T]
//
// The output is the exact Go constant line to paste into core/genesis.go.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"qbitcoin/address"
	"qbitcoin/core"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

func main() {
	threads := flag.Int("threads", runtime.NumCPU(), "miner threads")
	ts := flag.Uint64("timestamp", core.GenesisTimestamp, "genesis timestamp (unix seconds) — must match GenesisTimestamp in core/genesis.go")
	flag.Parse()

	if *ts != core.GenesisTimestamp {
		fmt.Fprintf(os.Stderr, "warning: -timestamp %d != core.GenesisTimestamp %d. Update the constant too.\n", *ts, core.GenesisTimestamp)
	}

	// Reconstruct the exact coinbase + header buildGenesis() builds.
	coinbase := txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0xFFFFFFFF,
			Spend:     address.P2MRSpend{},
		}},
		Outputs: []txn.TxOutput{{
			Value:   5_000_000_000,
			Address: core.GenesisAddress(),
		}},
		LockTime: 0,
	}
	h := core.BlockHeader{
		Version:    1,
		PrevHash:   [32]byte{},
		MerkleRoot: crypto.MerkleRoot([][32]byte{coinbase.TxID()}),
		Timestamp:  *ts,
		Bits:       core.GenesisBits,
		Nonce:      0,
	}

	fmt.Printf("mining genesis:\n")
	fmt.Printf("  bits:       0x%08x\n", h.Bits)
	fmt.Printf("  timestamp:  %d\n", h.Timestamp)
	fmt.Printf("  merkleRoot: %x\n", h.MerkleRoot)
	fmt.Printf("  threads:    %d\n", *threads)

	started := time.Now()
	h = mineWithProgress(h, *threads)
	elapsed := time.Since(started)
	hash := h.Hash()

	fmt.Printf("\nfound in %s\n", elapsed)
	fmt.Printf("  nonce:      %d  (0x%x)\n", h.Nonce, h.Nonce)
	fmt.Printf("  timestamp:  %d  (may have incremented past nonce wrap)\n", h.Timestamp)
	fmt.Printf("  hash:       %x\n", hash)
	fmt.Printf("  display:    %s\n", crypto.DisplayHex(hash))

	fmt.Printf("\n--- paste into core/genesis.go ---\n")
	fmt.Printf("const GenesisTimestamp uint64 = %d\n", h.Timestamp)
	fmt.Printf("const GenesisBits      uint32 = 0x%08x\n", h.Bits)
	fmt.Printf("const GenesisNonce     uint64 = %d\n", h.Nonce)
}

// mineWithProgress is a parallel nonce scanner + a 2-second progress
// ticker printing elapsed time, aggregate hashrate, and best-seen
// leading-zero bits (a rough "how close are we?" signal). Uses a local
// scan rather than the miner package so we can wire the custom progress
// reporter without polluting the shared grinder's hot path.
func mineWithProgress(header core.BlockHeader, threads int) core.BlockHeader {
	if threads < 1 {
		threads = 1
	}
	var totalHashes uint64
	var bestZeros uint32 // high watermark of leading zero bits seen
	var wg sync.WaitGroup
	found := make(chan core.BlockHeader, 1)
	stop := make(chan struct{})

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(start uint64) {
			defer wg.Done()
			local := header
			local.Nonce = start
			var localHashes uint64
			for {
				select {
				case <-stop:
					atomic.AddUint64(&totalHashes, localHashes)
					return
				default:
				}
				for b := 0; b < 4096; b++ {
					hash := local.Hash()
					localHashes++
					if core.CheckProof(local) {
						atomic.AddUint64(&totalHashes, localHashes)
						select {
						case found <- local:
						default:
						}
						return
					}
					if z := leadingZeroBits(hash); z > atomic.LoadUint32(&bestZeros) {
						atomic.StoreUint32(&bestZeros, z)
					}
					next := local.Nonce + uint64(threads)
					if next < local.Nonce {
						local.Timestamp++
						local.Nonce = start
					} else {
						local.Nonce = next
					}
				}
				atomic.AddUint64(&totalHashes, localHashes)
				localHashes = 0
			}
		}(uint64(i))
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	start := time.Now()

	for {
		select {
		case h := <-found:
			close(stop)
			wg.Wait()
			return h
		case <-ticker.C:
			hashes := atomic.LoadUint64(&totalHashes)
			elapsed := time.Since(start).Seconds()
			rate := float64(hashes) / elapsed
			targetBits := core.BitsToTarget(header.Bits)
			targetZeros := leadingZeroBits(targetBits)
			fmt.Printf("  [%6.1fs] %12d hashes  %6.2f MH/s  best=%dz  need≈%dz\n",
				elapsed, hashes, rate/1e6, atomic.LoadUint32(&bestZeros), targetZeros)
		}
	}
}

func leadingZeroBits(b [32]byte) uint32 {
	var n uint32
	for _, x := range b {
		if x == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<bit) != 0 {
				return n
			}
			n++
		}
		return n
	}
	return n
}
