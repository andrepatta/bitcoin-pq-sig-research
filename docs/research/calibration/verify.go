//go:build ignore
package main

import (
	"fmt"
	"qbitcoin/core"
	"qbitcoin/crypto"
)

func main() {
	g := core.Genesis()
	fmt.Printf("genesis hash (display): %s\n", crypto.DisplayHex(g.Header.Hash()))
	fmt.Printf("nonce=%d timestamp=%d bits=0x%08x\n", g.Header.Nonce, g.Header.Timestamp, g.Header.Bits)
	fmt.Printf("PoW valid: %v\n", core.CheckProof(g.Header))
}
