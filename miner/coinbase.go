package miner

import (
	"encoding/binary"

	"qbitcoin/address"
	"qbitcoin/core"
	"qbitcoin/txn"
)

// BuildCoinbase constructs the coinbase tx paying `value` to `to` and
// embedding `height` in the input witness (BIP-34 analog).
//
// Callers pass `value` as block subsidy + sum of fees from the template
// transactions. Keeping fee summation in the caller (rather than taking
// a template slice here) lets the RPC handler and the external miner
// binary each source fees the way that suits them — the RPC has direct
// mempool access, the external miner gets them via getblocktemplate.
func BuildCoinbase(height uint32, to address.P2MRAddress, value uint64) txn.Transaction {
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], height)
	return txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  [32]byte{},
			PrevIndex: 0xFFFFFFFF,
			Spend: address.P2MRSpend{
				Witness: [][]byte{hb[:]},
			},
		}},
		Outputs: []txn.TxOutput{{
			Value:   value,
			Address: to,
		}},
		LockTime: 0,
	}
}

// CoinbaseValue is the standard subsidy-plus-fees total for a coinbase
// at `height`, given the fee budget collected from the template's
// non-coinbase txs.
func CoinbaseValue(height uint32, fees uint64) uint64 {
	return core.BlockReward(int(height)) + fees
}
