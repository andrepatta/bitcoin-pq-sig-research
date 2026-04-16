package miner

import (
	"testing"
	"time"

	"qbitcoin/core"
)

// easyBits is a low-difficulty target so the tests finish instantly:
// exponent 0x1f, mantissa 0x7fffff → target ≈ 2^255, expected hashes to
// solve ≈ 2. Small enough that even single-threaded Grind returns
// within microseconds.
const easyBits uint32 = 0x1f7fffff

func fixtureHeader(nonceSeed uint64) core.BlockHeader {
	var prev, merkle [32]byte
	for i := range prev {
		prev[i] = byte(i)
		merkle[i] = byte(31 - i)
	}
	return core.BlockHeader{
		Version:    1,
		PrevHash:   prev,
		MerkleRoot: merkle,
		Timestamp:  1_700_000_000 + nonceSeed,
		Bits:       easyBits,
		Nonce:      0,
	}
}

func TestGrindSingleThreadSolves(t *testing.T) {
	h := fixtureHeader(0)
	quit := make(chan struct{})
	if !Grind(&h, 1, quit) {
		t.Fatal("single-thread Grind failed to solve easy target")
	}
	if !core.CheckProof(h) {
		t.Fatal("grinder returned header that fails core.CheckProof")
	}
}

func TestGrindParallelSolves(t *testing.T) {
	h := fixtureHeader(1)
	quit := make(chan struct{})
	if !Grind(&h, 4, quit) {
		t.Fatal("parallel Grind failed to solve easy target")
	}
	if !core.CheckProof(h) {
		t.Fatal("parallel grinder returned header that fails core.CheckProof")
	}
}

// TestGrindQuitAborts checks that closing quit makes parallel Grind
// return false within a short window. Uses a near-impossible target so
// no worker finds a solution before the timeout fires.
func TestGrindQuitAborts(t *testing.T) {
	h := fixtureHeader(2)
	h.Bits = 0x03000001 // target ≈ 1, essentially unsolvable
	quit := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		done <- Grind(&h, 4, quit)
	}()
	time.Sleep(20 * time.Millisecond)
	close(quit)
	select {
	case got := <-done:
		if got {
			t.Fatal("Grind reported solved on unsolvable target")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Grind did not return within 2s of quit")
	}
}

func BenchmarkGrindSingle(b *testing.B) {
	h := fixtureHeader(0)
	h.Bits = 0x1d00ffff // harder target so the loop runs through the benchmark
	quit := make(chan struct{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hLocal := h
		hLocal.Nonce = uint64(i) * 10_000
		// Cap iterations via quit so the benchmark terminates even if
		// no solution is found.
		go func() {
			time.Sleep(50 * time.Millisecond)
			close(quit)
		}()
		_ = Grind(&hLocal, 1, quit)
		quit = make(chan struct{})
	}
}
