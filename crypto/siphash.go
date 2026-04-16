package crypto

import (
	"crypto/sha256"
	"encoding/binary"
)

// SipHash24 computes SipHash-2-4 over data with 128-bit key (k0, k1).
// Reference: Aumasson & Bernstein, "SipHash: a fast short-input PRF"
// (2012). Used for BIP-152 compact-block short IDs.
func SipHash24(k0, k1 uint64, data []byte) uint64 {
	v0 := k0 ^ 0x736f6d6570736575
	v1 := k1 ^ 0x646f72616e646f6d
	v2 := k0 ^ 0x6c7967656e657261
	v3 := k1 ^ 0x7465646279746573

	i := 0
	for ; i+8 <= len(data); i += 8 {
		m := binary.LittleEndian.Uint64(data[i : i+8])
		v3 ^= m
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
		v0 ^= m
	}

	// Final block: remaining bytes + length in top byte.
	last := uint64(len(data)) << 56
	rem := data[i:]
	for j, b := range rem {
		last |= uint64(b) << (8 * uint(j))
	}
	v3 ^= last
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= last

	v2 ^= 0xff
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)

	return v0 ^ v1 ^ v2 ^ v3
}

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = v1<<13 | v1>>51
	v1 ^= v0
	v0 = v0<<32 | v0>>32

	v2 += v3
	v3 = v3<<16 | v3>>48
	v3 ^= v2

	v0 += v3
	v3 = v3<<21 | v3>>43
	v3 ^= v0

	v2 += v1
	v1 = v1<<17 | v1>>47
	v1 ^= v2
	v2 = v2<<32 | v2>>32
	return v0, v1, v2, v3
}

// SipHashKeyFromBlock derives the BIP-152 SipHash key pair for a block.
// Key = SHA256(headerBytes || nonce_le)[0:16], split into two LE uint64s.
// headerBytes must be the wire-serialized block header.
func SipHashKeyFromBlock(headerBytes []byte, nonce uint64) (k0, k1 uint64) {
	buf := make([]byte, 0, len(headerBytes)+8)
	buf = append(buf, headerBytes...)
	var nb [8]byte
	binary.LittleEndian.PutUint64(nb[:], nonce)
	buf = append(buf, nb[:]...)
	sum := sha256.Sum256(buf)
	k0 = binary.LittleEndian.Uint64(sum[0:8])
	k1 = binary.LittleEndian.Uint64(sum[8:16])
	return
}
