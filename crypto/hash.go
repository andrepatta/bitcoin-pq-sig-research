// Package crypto provides chain-layer cryptographic primitives.
//
// Chain-layer hashing is Bitcoin-exact: SHA-256d (double SHA-256) everywhere
// the consensus layer sees — block PoW, TxID, Merkle tree, address
// commitments, script/leaf hashes, storage keys. This file is the only
// place SHA-256 is imported for chain use; signature-internal SHA-256 and
// SHA-512 are confined to crypto/hashsig/ per the Kudinov–Nick paper.
//
// Key derivation uses BIP-32 HMAC-SHA512 (hardened subset) in wallet/ —
// not this package.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Hash256 returns the Bitcoin-standard double-SHA256 of data.
func Hash256(data []byte) [32]byte {
	first := sha256.Sum256(data)
	return sha256.Sum256(first[:])
}

// Hash256Concat is Hash256(a || b) for 32-byte inputs — used for Merkle
// internal nodes.
func Hash256Concat(a, b [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	return Hash256(buf[:])
}

// DisplayHex formats a 32-byte hash in Bitcoin's display convention:
// reversed byte order, lowercase hex. Internal storage and comparisons
// use natural order; only UI surfaces (RPC JSON, CLI, logs) should
// reverse on display.
func DisplayHex(h [32]byte) string {
	const hexchars = "0123456789abcdef"
	var out [64]byte
	for i := 0; i < 32; i++ {
		b := h[31-i]
		out[i*2] = hexchars[b>>4]
		out[i*2+1] = hexchars[b&0x0f]
	}
	return string(out[:])
}

// ParseDisplayHex is the inverse of DisplayHex: it accepts a 64-char
// lowercase hex string in Bitcoin display order (reversed) and returns
// the natural-order 32-byte value used for storage and lookups.
func ParseDisplayHex(s string) ([32]byte, error) {
	var h [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return h, err
	}
	if len(raw) != 32 {
		return h, fmt.Errorf("ParseDisplayHex: want 32 bytes, got %d", len(raw))
	}
	for i := 0; i < 32; i++ {
		h[i] = raw[31-i]
	}
	return h, nil
}
