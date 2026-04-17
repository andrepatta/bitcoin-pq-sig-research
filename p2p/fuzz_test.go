package p2p

import (
	"bytes"
	"testing"
)

// FuzzDecodeVersion asserts the version payload decoder never panics.
func FuzzDecodeVersion(f *testing.F) {
	f.Add(EncodeVersion(1, 0, NetAddr{}, 0, [32]byte{}))
	f.Add(EncodeVersion(1, 42, NetAddr{Port: 8333}, 0xdeadbeef, [32]byte{7}))
	f.Add([]byte{})
	f.Add(make([]byte, 7))
	f.Add(make([]byte, 33))
	f.Add(make([]byte, 65))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, _, _ = DecodeVersion(data)
	})
}

// FuzzDecodeInv covers the hand-rolled inv decoder.
func FuzzDecodeInv(f *testing.F) {
	f.Add(EncodeInv(nil))
	f.Add(EncodeInv([]InvItem{{Type: InvTx, Hash: [32]byte{1}}}))
	f.Add(EncodeInv([]InvItem{{Type: InvBlock, Hash: [32]byte{}}, {Type: InvTx, Hash: [32]byte{2}}}))
	f.Add([]byte{})
	f.Add(make([]byte, 3))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // count = 2^32-1 — must reject via cap

	f.Fuzz(func(t *testing.T, data []byte) {
		items, err := DecodeInv(data)
		if err != nil {
			return
		}
		if len(items) > MaxInvItems {
			t.Fatalf("inv count %d exceeds cap", len(items))
		}
		if got := EncodeInv(items); !bytes.Equal(got, data[:len(got)]) {
			t.Fatalf("inv round-trip mismatch on prefix:\n got:  %x\n data: %x", got, data[:len(got)])
		}
	})
}

// FuzzDecodeGetBlocks asserts the locator decoder never panics and round-trips.
func FuzzDecodeGetBlocks(f *testing.F) {
	f.Add(EncodeGetBlocks(nil))
	f.Add(EncodeGetBlocks([][32]byte{{}}))
	f.Add(EncodeGetBlocks([][32]byte{{1}, {2}, {3}}))
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // count = 2^32-1 — must reject via cap

	f.Fuzz(func(t *testing.T, data []byte) {
		locs, err := DecodeGetBlocks(data)
		if err != nil {
			return
		}
		if len(locs) > MaxLocatorHashes {
			t.Fatalf("locator count %d exceeds cap", len(locs))
		}
		if got := EncodeGetBlocks(locs); !bytes.Equal(got, data[:len(got)]) {
			t.Fatalf("getblocks round-trip mismatch on prefix")
		}
	})
}

// FuzzDecodeAddr hammers the gossip decoder (variable-length TLVs
// inside an outer count).
func FuzzDecodeAddr(f *testing.F) {
	f.Add(EncodeAddr(nil))
	f.Add(EncodeAddr([]AddrEntry{{Timestamp: 42, Addr: NetAddr{Port: 8333}}}))
	f.Add([]byte{})
	f.Add(make([]byte, 4))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeAddr(data)
	})
}

// FuzzDecodePing covers the 8-byte nonce payload.
func FuzzDecodePing(f *testing.F) {
	f.Add(EncodePing(0))
	f.Add(EncodePing(42))
	f.Add([]byte{})
	f.Add(make([]byte, 7))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodePing(data)
	})
}

// FuzzDecodeGetBlockTxn covers the BIP-152 getblocktxn request decoder.
func FuzzDecodeGetBlockTxn(f *testing.F) {
	f.Add(EncodeGetBlockTxn([32]byte{}, nil))
	f.Add(EncodeGetBlockTxn([32]byte{7}, []uint32{0, 1, 2}))
	f.Add([]byte{})
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeGetBlockTxn(data)
	})
}

// FuzzDecodeCmpctBlock covers the BIP-152 compact-block decoder.
func FuzzDecodeCmpctBlock(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 88))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeCmpctBlock(data)
	})
}

// FuzzDecodeBlockTxn covers the BIP-152 blocktxn response decoder.
func FuzzDecodeBlockTxn(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 32))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeBlockTxn(data)
	})
}

// FuzzReadFrame hammers the framer itself — magic/checksum/length gates
// are the first thing an attacker-controlled byte stream hits, so
// they're the priority attack surface.
func FuzzReadFrame(f *testing.F) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, CmdVersion, EncodeVersion(1, 0, NetAddr{}, 0, [32]byte{}))
	f.Add(buf.Bytes())
	f.Add([]byte{})
	f.Add(make([]byte, 23)) // short header
	f.Add(make([]byte, 24)) // header only, zero magic

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadFrame(bytes.NewReader(data))
	})
}
