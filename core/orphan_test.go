package core

import (
	"testing"
	"time"
)

// TestOrphanPool_BufferAndCount exercises the bookkeeping without going
// through PoW (we drive bufferOrphan + processOrphans directly).
func TestOrphanPool_BufferAndCount(t *testing.T) {
	bc := newOrphanTestChain()
	parent := [32]byte{0xAA}
	child := mkBlock(parent, [32]byte{0xC1})
	grand := mkBlock(child.Header.Hash(), [32]byte{0xC2})

	bc.bufferOrphan(child)
	bc.bufferOrphan(grand)
	if got := bc.OrphanCount(); got != 2 {
		t.Fatalf("OrphanCount=%d want 2", got)
	}
	missing := bc.MissingOrphanParents()
	if len(missing) == 0 {
		t.Fatal("MissingOrphanParents should report at least one")
	}
}

// TestOrphanPool_TTLEvictsExpired forces a stale received timestamp and
// confirms gcOrphansLocked drops it.
func TestOrphanPool_TTLEvictsExpired(t *testing.T) {
	bc := newOrphanTestChain()
	parent := [32]byte{0xBB}
	b := mkBlock(parent, [32]byte{0xD1})
	bc.bufferOrphan(b)
	hash := b.Header.Hash()
	bc.orphanMu.Lock()
	e := bc.orphans[hash]
	e.received = time.Now().Add(-2 * OrphanTTL)
	bc.orphans[hash] = e
	bc.gcOrphansLocked()
	bc.orphanMu.Unlock()
	if bc.OrphanCount() != 0 {
		t.Fatalf("expected GC to drop expired orphan, count=%d", bc.OrphanCount())
	}
}

// TestOrphanPool_CapEvicts ensures the LRU-ish bound on size holds.
func TestOrphanPool_CapEvicts(t *testing.T) {
	bc := newOrphanTestChain()
	parent := [32]byte{0xCC}
	for i := 0; i < MaxOrphanBlocks+5; i++ {
		nonce := [32]byte{}
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		b := mkBlock(parent, nonce)
		bc.bufferOrphan(b)
	}
	if got := bc.OrphanCount(); got > MaxOrphanBlocks {
		t.Fatalf("orphan count %d exceeds cap %d", got, MaxOrphanBlocks)
	}
}

// --- helpers ---

func newOrphanTestChain() *Blockchain {
	return &Blockchain{
		orphans:         map[[32]byte]orphanEntry{},
		orphansByParent: map[[32]byte][][32]byte{},
		headersHts:      map[[32]byte]uint32{},
		knownHdrs:       map[[32]byte]BlockHeader{},
	}
}

// mkBlock builds a Block with a given parent and a "nonce" applied to
// the merkle root so each call produces a unique hash without mining.
func mkBlock(prev [32]byte, nonce [32]byte) Block {
	return Block{Header: BlockHeader{PrevHash: prev, MerkleRoot: nonce}}
}
