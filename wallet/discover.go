package wallet

import (
	"context"
	"errors"

	"qbitcoin/address"
)

// AccountDiscoveryGapLimit is the BIP-44 §Account Discovery gap: the
// number of consecutive unused account indices scanned before concluding
// the mnemonic has no further on-chain history. Exposed as a var (not
// const) so tests can shrink it — BuildAccount keygen at paper params is
// seconds per index, and a fresh empty mnemonic would otherwise pay
// AccountDiscoveryGapLimit × (~1s) on every restore test run.
var AccountDiscoveryGapLimit = 20

// AddressActivity reports whether a P2MR address has any on-chain
// receive or spend history. Used during mnemonic-restore discovery so
// the wallet can advance its active account index past every
// previously-used account without the user having to remember how many
// fresh addresses they had generated.
//
// The wallet package deliberately does not import core/blockchain;
// callers (cmd/qbitcoind) adapt `chain.ListTxsForAddress` into this
// interface.
type AddressActivity interface {
	HasActivity(ctx context.Context, addr address.P2MRAddress) (bool, error)
}

// DiscoverAccounts performs BIP-44 §Account Discovery over the wallet's
// mnemonic-derived account space. For each index 0, 1, 2, … it derives
// the 2-leaf P2MR address and asks `activity` whether it has any
// on-chain history. The scan stops when AccountDiscoveryGapLimit
// consecutive indices come back unused; the active index is advanced to
// the highest-used one found (or left at 0 if nothing was used).
//
// Each derived account writes its state file + addr cache, so the scan
// doubles as keypool pre-derivation. Requires the wallet to be
// unlocked.
//
// Cost: one full SHRINCS + SHRIMPS keygen per scanned index (~1s at
// paper params). A fresh restore with no prior activity scans exactly
// AccountDiscoveryGapLimit indices; a wallet with K used accounts
// scans K + AccountDiscoveryGapLimit.
func (w *Wallet) DiscoverAccounts(ctx context.Context, activity AddressActivity) (uint32, error) {
	if activity == nil {
		return 0, errors.New("wallet: DiscoverAccounts requires non-nil AddressActivity")
	}
	gap := AccountDiscoveryGapLimit
	if gap <= 0 {
		return 0, errors.New("wallet: AccountDiscoveryGapLimit must be positive")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.requireUnlockedLocked(); err != nil {
		return 0, err
	}

	var (
		highestUsed uint32
		haveUsed    bool
		gapSeen     int
	)
	var lastAcct *Account
	for idx := uint32(0); ; idx++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		acct, err := BuildAccount(ctx, w.masterSeed, idx, w.store)
		if err != nil {
			return 0, err
		}
		lastAcct = acct
		used, err := activity.HasActivity(ctx, acct.Address)
		if err != nil {
			return 0, err
		}
		if used {
			highestUsed = idx
			haveUsed = true
			gapSeen = 0
			continue
		}
		gapSeen++
		if gapSeen >= gap {
			break
		}
	}

	active := uint32(0)
	if haveUsed {
		active = highestUsed
	}
	// Only rebuild the target account if the scan left us with a
	// different one cached. BuildAccount re-runs full keygen — avoid the
	// second hit when we already have the right Account in hand.
	if lastAcct == nil || lastAcct.Index != active {
		acct, err := BuildAccount(ctx, w.masterSeed, active, w.store)
		if err != nil {
			return 0, err
		}
		lastAcct = acct
	}
	w.current = lastAcct
	w.activeIdx = active
	if err := writeAccountIndex(w.store.Dir(), active); err != nil {
		return 0, err
	}
	log.Info("wallet: account discovery complete",
		"wallet", w.name,
		"highest_used", active,
		"had_activity", haveUsed,
		"gap_limit", gap)
	w.signalKeypool()
	return active, nil
}
