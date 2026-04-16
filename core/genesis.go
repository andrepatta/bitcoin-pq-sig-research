package core

import (
	"sync"
	"time"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// GenesisTimestamp is the hardcoded creation time of block 0.
const GenesisTimestamp uint64 = 1776246858

// GenesisBits calibrated for ~10-minute mean block time at ~34.8 MH/s of
// midstate-grinder SHA-256d throughput (4 threads, measured via
// docs/research/calibration). target ≈ 2^256 / (hashrate · 600).
// Change this and the genesis block hash changes — wipe datadirs.
const GenesisBits uint32 = 0x1c34cda9

// GenesisNonce is the pre-mined PoW nonce for the genesis header, produced
// by `go run ./cmd/mine-genesis`. If 0, the node mines genesis on first
// startup (slow — single-threaded for determinism). Once you pin a nonzero
// value here, every fresh node loads genesis instantly and verifies PoW.
// Changing GenesisBits, GenesisTimestamp, or GenesisAddr invalidates this
// nonce — re-run the tool.
const GenesisNonce uint64 = 1786873983

// GenesisAddr is the consensus-constant recipient of the block-0 coinbase.
// Hardcoded to all-zero bytes, which serves two purposes:
//
//  1. Provably unspendable. A 2-leaf P2MR address is the merkle root over
//     two leaf scripts; all-zero bytes has no known preimage, so no wallet
//     can ever produce a valid P2MRSpend for it. The 5 PQBC at genesis is
//     burned by construction.
//  2. Impossible to accidentally fork on. Earlier revisions derived this
//     address from a deterministic zero-seed wallet, making genesis
//     consensus-dependent on the current SHRINCS/SHRIMPS paper params and
//     seed derivation. Any refactor of either risked silently producing a
//     different genesis on rebuilt nodes — they'd be on a chain-of-one
//     without an obvious error. Burning to zero removes that foot-gun.
var GenesisAddr = address.P2MRAddress{}

var (
	genesisOnce  sync.Once
	genesisBlock Block
)

// buildGenesis populates the package-level genesis block once.
func buildGenesis() {
	coinbase := txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0xFFFFFFFF,
			Spend:     address.P2MRSpend{},
		}},
		Outputs: []txn.TxOutput{{
			Value:   5_000_000_000,
			Address: GenesisAddr,
		}},
		LockTime: 0,
	}
	h := BlockHeader{
		Version:    1,
		PrevHash:   [32]byte{},
		MerkleRoot: crypto.MerkleRoot([][32]byte{coinbase.TxID()}),
		Timestamp:  GenesisTimestamp,
		Bits:       GenesisBits,
		Nonce:      0,
	}
	// Preferred path: GenesisNonce is pinned from `cmd/mine-genesis`. Just
	// set the nonce and verify PoW — no mining, no nondeterminism.
	//
	// Fallback: if the constant is still 0, mine it once deterministically
	// (single-threaded, starting at nonce=0) so every node converges on the
	// same first-valid nonce. The production miner (miner.Grind) isn't
	// used here — importing it would cycle core→miner→core, and this path
	// runs once at bootstrap, not on a hot path.
	if GenesisNonce != 0 {
		h.Nonce = GenesisNonce
		if !CheckProof(h) {
			log.Error("genesis: hardcoded nonce fails PoW — regenerate with `go run ./cmd/mine-genesis`",
				"bits", h.Bits, "timestamp", h.Timestamp, "nonce", h.Nonce)
			panic("genesis: GenesisNonce does not satisfy GenesisBits")
		}
		log.Info("genesis: loaded pre-mined header", "nonce", h.Nonce, "timestamp", h.Timestamp)
	} else {
		log.Info("genesis: mining (one-time, single-threaded for determinism — run `go run ./cmd/mine-genesis` once and pin GenesisNonce to skip this)",
			"bits", h.Bits)
		started := time.Now()
		for !CheckProof(h) {
			h.Nonce++
			if h.Nonce == 0 {
				h.Timestamp++
			}
		}
		log.Info("genesis: mined", "elapsed", time.Since(started), "nonce", h.Nonce, "timestamp", h.Timestamp)
	}
	genesisBlock = Block{Header: h, Txns: []txn.Transaction{coinbase}}
}

// Genesis returns the hardcoded-by-construction genesis block.
func Genesis() Block {
	genesisOnce.Do(buildGenesis)
	return genesisBlock
}

// GenesisAddress returns the genesis coinbase recipient (consensus constant).
func GenesisAddress() address.P2MRAddress {
	return GenesisAddr
}

// BlockReward returns the mined coinbase value at a given height.
func BlockReward(height int) uint64 {
	reward := uint64(5_000_000_000)
	halvings := height / 210_000
	if halvings >= 64 {
		return 0
	}
	return reward >> uint(halvings)
}
