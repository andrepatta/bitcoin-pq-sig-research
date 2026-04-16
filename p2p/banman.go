package p2p

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"qbitcoin/storage"
)

// Bitcoin Core's misbehavior model, ported and simplified. A peer
// accumulates a per-IP score; when it reaches BanThreshold the node
// disconnects and refuses to dial/accept that IP for BanDuration.
// Score decays linearly at BanScoreDecayPerHour points per hour so
// isolated, low-cost mistakes don't compound into a ban over a
// long-lived connection.
//
// Scoring is keyed by IP address, matching Bitcoin Core's
// CAddrMan/CBanEntry semantics — not by host:port — so an attacker
// cycling through ephemeral outbound ports cannot reset their score by
// reconnecting.
//
// These are vars (not consts) so tests can shorten them; production
// callers must not mutate them at runtime.
var (
	BanThreshold         = 100
	BanDuration          = 24 * time.Hour
	BanScoreDecayPerHour = 1.0
)

// BanEntry is a snapshot returned by ListBans for diagnostics.
type BanEntry struct {
	IP     string // dotted-quad or "[v6]"
	Expiry time.Time
	Reason string
}

// scoreState tracks one IP's accumulated misbehavior score plus the
// timestamp of the last update (used for lazy decay).
type scoreState struct {
	score     float64
	lastTouch time.Time
}

// BanManager scores per-IP misbehavior and persists active bans.
//
// The map of active bans is the source of truth for IsBanned checks
// and is loaded from BucketBans on construction. A nil DB is allowed
// (in-memory only) so tests can run without storage wiring.
type BanManager struct {
	db *storage.DB

	mu     sync.Mutex
	scores map[string]*scoreState
	bans   map[string]BanEntry
}

// canonIP normalizes an IP string (dotted-quad or IPv6) into its
// parsed form, returning the canonical text rendering. Returns "" on
// parse failure so callers silently skip unknown forms rather than
// banning a garbage-string key.
func canonIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// NewBanManager constructs a BanManager and loads any persisted bans
// from db. Expired entries are pruned from disk during load. A nil db
// gives a purely in-memory manager.
func NewBanManager(db *storage.DB) (*BanManager, error) {
	bm := &BanManager{
		db:     db,
		scores: map[string]*scoreState{},
		bans:   map[string]BanEntry{},
	}
	if db == nil {
		return bm, nil
	}
	now := time.Now()
	type pruneItem struct{ key []byte }
	var toPrune []pruneItem
	err := db.ForEach([]byte(storage.BucketBans), func(k, v []byte) error {
		ipStr := canonIP(string(k))
		if ipStr == "" {
			toPrune = append(toPrune, pruneItem{key: append([]byte(nil), k...)})
			return nil
		}
		entry, err := decodeBanEntry(v)
		if err != nil {
			toPrune = append(toPrune, pruneItem{key: append([]byte(nil), k...)})
			return nil
		}
		entry.IP = ipStr
		if !entry.Expiry.After(now) {
			toPrune = append(toPrune, pruneItem{key: append([]byte(nil), k...)})
			return nil
		}
		bm.bans[ipStr] = entry
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range toPrune {
		_ = db.Delete([]byte(storage.BucketBans), p.key)
	}
	return bm, nil
}

// IsBanned reports whether ip has an unexpired ban.
func (b *BanManager) IsBanned(ip string) bool {
	ip = canonIP(ip)
	if ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.bans[ip]
	if !ok {
		return false
	}
	if time.Now().After(entry.Expiry) {
		delete(b.bans, ip)
		if b.db != nil {
			_ = b.db.Delete([]byte(storage.BucketBans), []byte(ip))
		}
		return false
	}
	return true
}

// Misbehaving applies score to ip's running total (decayed since the
// last update) and returns true if this call crossed BanThreshold and
// produced a fresh ban. Already-banned IPs return true without further
// accumulation so the caller still disconnects.
func (b *BanManager) Misbehaving(ip string, score int, reason string) bool {
	if score <= 0 {
		return false
	}
	ip = canonIP(ip)
	if ip == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if entry, ok := b.bans[ip]; ok {
		if time.Now().Before(entry.Expiry) {
			return true
		}
		// Stale ban — fall through to fresh accounting.
		delete(b.bans, ip)
		if b.db != nil {
			_ = b.db.Delete([]byte(storage.BucketBans), []byte(ip))
		}
	}

	now := time.Now()
	s, ok := b.scores[ip]
	if !ok {
		s = &scoreState{lastTouch: now}
		b.scores[ip] = s
	} else {
		hours := now.Sub(s.lastTouch).Hours()
		if hours > 0 {
			s.score -= hours * BanScoreDecayPerHour
			if s.score < 0 {
				s.score = 0
			}
		}
	}
	s.score += float64(score)
	s.lastTouch = now

	// Round before threshold compare so float decay over microseconds
	// can't shave a fractional epsilon off an exact score (e.g. 60+40
	// becoming 99.999999998 because Hours() returned ~10^-9).
	if math.Round(s.score) < float64(BanThreshold) {
		return false
	}
	delete(b.scores, ip)
	expiry := now.Add(BanDuration)
	entry := BanEntry{IP: ip, Expiry: expiry, Reason: reason}
	b.bans[ip] = entry
	if b.db != nil {
		_ = b.db.Put([]byte(storage.BucketBans), []byte(ip), encodeBanEntry(entry))
	}
	return true
}

// Score returns ip's current decayed misbehavior score (best-effort,
// for diagnostics). Banned IPs return BanThreshold.
func (b *BanManager) Score(ip string) int {
	ip = canonIP(ip)
	if ip == "" {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, banned := b.bans[ip]; banned {
		return BanThreshold
	}
	s, ok := b.scores[ip]
	if !ok {
		return 0
	}
	now := time.Now()
	hours := now.Sub(s.lastTouch).Hours()
	cur := s.score - hours*BanScoreDecayPerHour
	if cur < 0 {
		return 0
	}
	return int(math.Round(cur))
}

// Unban removes any ban for ip. No-op if not banned.
func (b *BanManager) Unban(ip string) {
	ip = canonIP(ip)
	if ip == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.bans, ip)
	delete(b.scores, ip)
	if b.db != nil {
		_ = b.db.Delete([]byte(storage.BucketBans), []byte(ip))
	}
}

// ListBans returns a snapshot of currently active bans.
func (b *BanManager) ListBans() []BanEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	out := make([]BanEntry, 0, len(b.bans))
	for ip, e := range b.bans {
		if now.After(e.Expiry) {
			continue
		}
		e.IP = ip
		out = append(out, e)
	}
	return out
}

// Wire format: [8 B BE expiry-unix-nano][2 B BE reason-len][reason]
//
// 8 bytes for nanos comfortably exceeds the lifetime of any sane ban;
// reason length is capped at 64 KiB by the uint16, which is plenty for
// short tags ("bad block payload", "bad version", etc.) and bounds
// memory if a future writer puts garbage in.

func encodeBanEntry(e BanEntry) []byte {
	r := e.Reason
	if len(r) > 0xFFFF {
		r = r[:0xFFFF]
	}
	out := make([]byte, 8+2+len(r))
	binary.BigEndian.PutUint64(out[0:8], uint64(e.Expiry.UnixNano()))
	binary.BigEndian.PutUint16(out[8:10], uint16(len(r)))
	copy(out[10:], r)
	return out
}

func decodeBanEntry(b []byte) (BanEntry, error) {
	if len(b) < 10 {
		return BanEntry{}, errors.New("ban entry: truncated header")
	}
	expiry := time.Unix(0, int64(binary.BigEndian.Uint64(b[0:8])))
	rl := int(binary.BigEndian.Uint16(b[8:10]))
	if 10+rl > len(b) {
		return BanEntry{}, errors.New("ban entry: truncated reason")
	}
	return BanEntry{Expiry: expiry, Reason: string(b[10 : 10+rl])}, nil
}
