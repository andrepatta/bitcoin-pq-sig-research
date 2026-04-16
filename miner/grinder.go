// Package miner is the shared mining pipeline: parallel PoW grinder and
// coinbase construction. Consumed by the external `qbitcoin-miner` binary
// (the primary mining path) and by the in-process `generatetoaddress` RPC
// (the regtest convenience).
//
// The grinder uses two Bitcoin-tradition optimizations:
//
//   - Midstate. Each worker precomputes SHA-256 over the first 64 B of
//     the 88 B header once — Version + PrevHash + MerkleRoot[0:28] never
//     change within a template. Per-nonce work is one compression over
//     the 24 B tail (MerkleRoot[28:32] + Timestamp + Bits + Nonce) plus
//     the outer SHA-256 wrap of the first hash. 2 compressions/nonce
//     instead of 3 — ~33% off the hashing cost.
//
//   - No hot-path allocation. Each worker holds one *sha256.Hash, one
//     stack-resident 88 B header buffer, and one marshaled midstate
//     blob. `Sum` writes into a `[32]byte` on the stack via `buf[:0]`.
//     Nothing touches the heap inside the nonce loop.
//
// Workers scan disjoint nonce strides (worker i starts at nonce i, steps
// by `threads`) so no two workers ever test the same (timestamp, nonce)
// pair. If a worker's stride wraps uint64 — ~3.7 trillion years at
// MH/s — it bumps timestamp and restarts at `start`; the midstate stays
// valid because Timestamp sits in chunk 2.
package miner

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"sync"
	"time"

	"qbitcoin/core"
)

// channelCheckEvery bounds how often each worker polls stop/quit. At
// ~10 MH/s/core this is ~1.6 ms of latency to abort after a new block
// arrives or after another worker wins — cheap insurance against the
// select-per-nonce runtime overhead that dominated the old miner loop.
const channelCheckEvery = 1 << 14

// Grind mines the template header in-place. On success, `*h` holds the
// winning Nonce (and, rarely, a bumped Timestamp) and Grind returns
// true. If `quit` closes first Grind returns false and `*h` is
// untouched. `threads <= 1` runs a single-worker scan.
func Grind(h *core.BlockHeader, threads int, quit <-chan struct{}) bool {
	if threads < 1 {
		threads = 1
	}
	if threads == 1 {
		return grindSingle(h, quit)
	}
	var wg sync.WaitGroup
	found := make(chan core.BlockHeader, 1)
	stop := make(chan struct{})
	tpl := *h
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(start uint64) {
			defer wg.Done()
			if solved, out := grindStride(tpl, start, uint64(threads), stop, quit); solved {
				select {
				case found <- out:
				default:
				}
			}
		}(uint64(i))
	}
	select {
	case solved := <-found:
		close(stop)
		*h = solved
		wg.Wait()
		return true
	case <-quit:
		close(stop)
		wg.Wait()
		return false
	}
}

func grindSingle(h *core.BlockHeader, quit <-chan struct{}) bool {
	solved, out := grindStride(*h, 0, 1, nil, quit)
	if solved {
		*h = out
	}
	return solved
}

// grindStride is the hot loop. `stop` may be nil (single-worker case).
func grindStride(local core.BlockHeader, start, stride uint64, stop, quit <-chan struct{}) (bool, core.BlockHeader) {
	var buf [core.HeaderSize]byte
	writeHeader(&buf, &local)

	sha := sha256.New()
	sha.Write(buf[:64])
	marsh := sha.(encoding.BinaryMarshaler)
	unmarsh := sha.(encoding.BinaryUnmarshaler)
	mid, err := marsh.MarshalBinary()
	if err != nil {
		// sha256's MarshalBinary never errors; kept defensive so a future
		// stdlib change doesn't silently corrupt PoW.
		return false, local
	}

	target := core.BitsToTarget(local.Bits)
	local.Nonce = start
	counter := 0

	var firstHash [32]byte
	for {
		counter++
		if counter >= channelCheckEvery {
			counter = 0
			select {
			case <-stop:
				return false, local
			case <-quit:
				return false, local
			default:
			}
			// nTime roll: bump Timestamp to wall clock as it advances —
			// matches Bitcoin Core's UpdateTime in miner.cpp. Keeps the
			// header within MAX_FUTURE_BLOCK_TIME on long grinds and
			// expands the search space without a template refetch. The
			// midstate stays valid because Timestamp is in chunk 2.
			if now := uint64(time.Now().Unix()); now > local.Timestamp {
				local.Timestamp = now
				binary.LittleEndian.PutUint64(buf[68:76], local.Timestamp)
			}
		}
		binary.LittleEndian.PutUint64(buf[80:88], local.Nonce)

		_ = unmarsh.UnmarshalBinary(mid)
		sha.Write(buf[64:88])
		sha.Sum(firstHash[:0])

		second := sha256.Sum256(firstHash[:])

		if bytes.Compare(second[:], target[:]) < 0 {
			return true, local
		}

		next := local.Nonce + stride
		if next < local.Nonce {
			// Stride wrapped; bump timestamp and restart at `start`.
			// Midstate stays valid because Timestamp is in chunk 2.
			local.Timestamp++
			binary.LittleEndian.PutUint64(buf[68:76], local.Timestamp)
			local.Nonce = start
		} else {
			local.Nonce = next
		}
	}
}

// writeHeader lays out the 88 B header into buf. Nonce at [80:88] is
// overwritten per iteration; the rest is a template constant.
func writeHeader(buf *[core.HeaderSize]byte, h *core.BlockHeader) {
	binary.LittleEndian.PutUint32(buf[0:4], h.Version)
	copy(buf[4:36], h.PrevHash[:])
	copy(buf[36:68], h.MerkleRoot[:])
	binary.LittleEndian.PutUint64(buf[68:76], h.Timestamp)
	binary.LittleEndian.PutUint32(buf[76:80], h.Bits)
	binary.LittleEndian.PutUint64(buf[80:88], h.Nonce)
}
