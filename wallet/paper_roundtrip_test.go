package wallet

import (
	"bytes"
	"testing"
	"time"

	"qbitcoin/address"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// TestPaperParamsWalletRoundTrip exercises the full
//
//	wallet → sign → txn.SigHash → script.Execute → Verify
//
// path at paper SPHINCS+ parameters, for both leaves of the 2-leaf P2MR
// address (SHRINCS primary, SHRIMPS multi-device). Skipped under
// -short because SHRIMPS compact sign at paper params costs ~1.4 s.
//
// The hashsig KATs assert shape; this round-trip confirms the wallet
// layer's sighash framing, P2MRSpend layout, and script interpreter
// all agree with the (R=2N, PORS+FP grind salt) sig layout.
func TestPaperParamsWalletRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("paper SHRIMPS compact Sign ~1.4 s; skipped under -short")
	}

	dir := t.TempDir()
	var seed [64]byte
	for i := range seed {
		seed[i] = byte(0xA0 + i%16)
	}

	// Build a plaintext store for the test — BuildAccount now routes
	// SHRINCS/SHRIMPS state through a Store so encrypted-at-rest is
	// a caller option.
	store, err := CreateStore(dir, nil)
	if err != nil {
		t.Fatalf("CreateStore: %v", err)
	}

	start := time.Now()
	acct, err := BuildAccount(t.Context(), seed, 0, store)
	if err != nil {
		t.Fatalf("BuildAccount: %v", err)
	}
	t.Logf("BuildAccount (paper params): %s", time.Since(start))

	// Minimal tx: one input (we synthesize the prev-outpoint; the
	// script interpreter here only checks the sig, not UTXO presence),
	// one output back to the same address.
	tx := &txn.Transaction{
		Version: 1,
		Inputs: []txn.TxInput{{
			PrevTxID:  [32]byte{0xDE, 0xAD, 0xBE, 0xEF},
			PrevIndex: 0,
		}},
		Outputs:  []txn.TxOutput{{Value: 12345, Address: acct.Address}},
		LockTime: 0,
	}

	// Each leaf: compute sighash, sign with the matching key, attach a
	// P2MRSpend, confirm post-attach sighash is stable (SigHash must zero
	// the Spend of the signing input), and verify via the script.
	for _, tc := range []struct {
		name     string
		leafIdx  uint32
		signFn   func(sighash []byte) ([]byte, error)
		sigBytes int
	}{
		{
			name:    "SHRINCS_leaf0",
			leafIdx: 0,
			signFn: func(h []byte) ([]byte, error) {
				s, err := acct.ShrincsKey.Sign(t.Context(), h)
				if err != nil {
					return nil, err
				}
				return append([]byte{crypto.SchemeShrincs}, crypto.SerializeShrincsSig(s)...), nil
			},
		},
		{
			name:    "SHRIMPS_leaf1",
			leafIdx: 1,
			signFn: func(h []byte) ([]byte, error) {
				s, err := acct.ShrimpsKey.Sign(t.Context(), h)
				if err != nil {
					return nil, err
				}
				return append([]byte{crypto.SchemeShrimps}, crypto.SerializeShrimpsSig(s)...), nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pre := txn.SigHash(*tx, 0)
			start := time.Now()
			sigBytes, err := tc.signFn(pre[:])
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			t.Logf("sign %d B in %s", len(sigBytes), time.Since(start))

			// Attach spend.
			leafHashes := make([][32]byte, len(acct.Leaves))
			for i, l := range acct.Leaves {
				leafHashes[i] = address.LeafHash(l)
			}
			proof := crypto.MerkleProof(leafHashes, int(tc.leafIdx))
			tx.Inputs[0].Spend = address.P2MRSpend{
				LeafScript:  acct.Leaves[tc.leafIdx],
				LeafIndex:   tc.leafIdx,
				MerkleProof: proof,
				Witness:     [][]byte{sigBytes},
			}

			// SigHash must be stable: it zeroes the Spend of the
			// signing input, so attaching a spend and recomputing must
			// yield the same sighash we signed.
			post := txn.SigHash(*tx, 0)
			if pre != post {
				t.Fatalf("sighash changed after Spend attach: pre=%x post=%x", pre, post)
			}

			leaf := acct.Leaves[tc.leafIdx]

			// Verify via the leaf script.
			ok, err := txn.Execute(leaf, tx.Inputs[0].Spend.Witness, post)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if !ok {
				t.Fatal("Execute returned false for a valid signature")
			}

			// Tamper detection: flip a byte in the sig and require
			// Execute to reject (either with ok=false or an error).
			bad := append([]byte(nil), sigBytes...)
			bad[len(bad)/2] ^= 0x01
			tx.Inputs[0].Spend.Witness = [][]byte{bad}
			ok2, err2 := txn.Execute(leaf, tx.Inputs[0].Spend.Witness, post)
			if ok2 && err2 == nil {
				t.Fatal("Execute accepted tampered signature")
			}
			// Restore witness for the next subtest.
			tx.Inputs[0].Spend.Witness = [][]byte{sigBytes}
			_ = bytes.Equal
		})
	}
}
