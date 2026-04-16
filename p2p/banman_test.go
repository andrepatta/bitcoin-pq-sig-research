package p2p

import (
	"fmt"
	"net"
	"testing"
	"time"

	"qbitcoin/core"
	"qbitcoin/mempool"
	"qbitcoin/storage"
)

// makeIP returns a deterministic, unique-per-call IPv4 address string
// for a test. We don't care about the actual value, only that each
// test gets a distinct ban-key so independent test cases don't
// accidentally share state when run in parallel.
var testIPCounter = 0

func makeIP(t *testing.T) string {
	t.Helper()
	testIPCounter++
	return fmt.Sprintf("192.0.2.%d", testIPCounter&0xFF)
}

// withShortBanDecay accelerates decay so tests can observe it within
// the test budget. Restores the original on cleanup.
func withShortBanDecay(t *testing.T, perHour float64) {
	t.Helper()
	orig := BanScoreDecayPerHour
	BanScoreDecayPerHour = perHour
	t.Cleanup(func() { BanScoreDecayPerHour = orig })
}

// withShortBanDuration shortens the ban TTL so expiry tests stay fast.
func withShortBanDuration(t *testing.T, d time.Duration) {
	t.Helper()
	orig := BanDuration
	BanDuration = d
	t.Cleanup(func() { BanDuration = orig })
}

// TestBan_BelowThresholdDoesNotBan — incrementing score under the
// threshold must not flip IsBanned and must not produce a ban entry.
func TestBan_BelowThresholdDoesNotBan(t *testing.T) {
	bm, err := NewBanManager(nil)
	if err != nil {
		t.Fatalf("NewBanManager: %v", err)
	}
	ip := makeIP(t)

	if got := bm.Misbehaving(ip, 50, "small"); got {
		t.Fatal("first sub-threshold misbehavior reported as ban")
	}
	if got := bm.Misbehaving(ip, 49, "still small"); got {
		t.Fatal("99 < 100 reported as ban")
	}
	if bm.IsBanned(ip) {
		t.Fatal("IsBanned at score 99")
	}
	if s := bm.Score(ip); s != 99 {
		t.Fatalf("Score = %d, want 99", s)
	}
}

// TestBan_CrossingThresholdBans — the call that pushes score >=
// threshold returns true and the peer becomes IsBanned.
func TestBan_CrossingThresholdBans(t *testing.T) {
	bm, _ := NewBanManager(nil)
	ip := makeIP(t)

	bm.Misbehaving(ip, 60, "first")
	if banned := bm.Misbehaving(ip, 40, "tipping"); !banned {
		t.Fatal("crossing threshold did not return true")
	}
	if !bm.IsBanned(ip) {
		t.Fatal("IsBanned false after threshold crossed")
	}
	if s := bm.Score(ip); s != BanThreshold {
		t.Fatalf("Score = %d, want %d", s, BanThreshold)
	}
}

// TestBan_AlreadyBannedReturnsTrue — calling Misbehaving on an already-
// banned peer reports true so the caller still disconnects.
func TestBan_AlreadyBannedReturnsTrue(t *testing.T) {
	bm, _ := NewBanManager(nil)
	ip := makeIP(t)

	bm.Misbehaving(ip, 100, "instant")
	if !bm.IsBanned(ip) {
		t.Fatal("not banned after 100-point hit")
	}
	if banned := bm.Misbehaving(ip, 1, "again"); !banned {
		t.Fatal("already-banned peer did not report banned")
	}
}

// TestBan_ScoreDecays — leaving a peer alone for long enough drops the
// score back below the threshold so a second offense does not ban.
func TestBan_ScoreDecays(t *testing.T) {
	withShortBanDecay(t, 5_000_000.0)
	bm, _ := NewBanManager(nil)
	ip := makeIP(t)

	bm.Misbehaving(ip, 50, "first")
	time.Sleep(100 * time.Millisecond)
	bm.Misbehaving(ip, 1, "tickle")
	if s := bm.Score(ip); s > 5 {
		t.Fatalf("Score = %d after decay, want near 0", s)
	}
}

// TestBan_ExpiryClearsBan — after BanDuration elapses, IsBanned must
// return false again and the entry must be evicted.
func TestBan_ExpiryClearsBan(t *testing.T) {
	withShortBanDuration(t, 50*time.Millisecond)
	bm, _ := NewBanManager(nil)
	ip := makeIP(t)

	bm.Misbehaving(ip, 100, "instant")
	if !bm.IsBanned(ip) {
		t.Fatal("not banned after 100-point hit")
	}
	time.Sleep(75 * time.Millisecond)
	if bm.IsBanned(ip) {
		t.Fatal("ban not cleared after BanDuration elapsed")
	}
}

// TestBan_Unban — explicit Unban removes both the score state and any
// active ban entry.
func TestBan_Unban(t *testing.T) {
	bm, _ := NewBanManager(nil)
	ip := makeIP(t)

	bm.Misbehaving(ip, 100, "instant")
	bm.Unban(ip)
	if bm.IsBanned(ip) {
		t.Fatal("IsBanned after Unban")
	}
	if s := bm.Score(ip); s != 0 {
		t.Fatalf("Score = %d after Unban, want 0", s)
	}
}

// TestBan_PersistRoundTrip — bans written via one BanManager are
// recovered on restart via a fresh NewBanManager bound to the same DB.
func TestBan_PersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer db.Close()

	ip := makeIP(t)
	bm1, err := NewBanManager(db)
	if err != nil {
		t.Fatalf("NewBanManager: %v", err)
	}
	bm1.Misbehaving(ip, 100, "persist-me")
	if !bm1.IsBanned(ip) {
		t.Fatal("not banned in original manager")
	}

	bm2, err := NewBanManager(db)
	if err != nil {
		t.Fatalf("NewBanManager after restart: %v", err)
	}
	if !bm2.IsBanned(ip) {
		t.Fatal("ban not restored after restart")
	}
	bans := bm2.ListBans()
	if len(bans) != 1 || bans[0].IP != ip || bans[0].Reason != "persist-me" {
		t.Fatalf("ListBans = %+v", bans)
	}
}

// TestBan_PersistDropsExpired — entries past their expiry must be
// pruned during Load and not surface as active bans afterward.
func TestBan_PersistDropsExpired(t *testing.T) {
	withShortBanDuration(t, 25*time.Millisecond)
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer db.Close()

	ip := makeIP(t)
	bm1, _ := NewBanManager(db)
	bm1.Misbehaving(ip, 100, "doomed")
	time.Sleep(60 * time.Millisecond)

	bm2, err := NewBanManager(db)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if bm2.IsBanned(ip) {
		t.Fatal("expired entry reloaded as banned")
	}
	if got := bm2.ListBans(); len(got) != 0 {
		t.Fatalf("ListBans after expiry = %+v, want empty", got)
	}
	bm3, _ := NewBanManager(db)
	if got := bm3.ListBans(); len(got) != 0 {
		t.Fatalf("ListBans after disk prune = %+v, want empty", got)
	}
}

// TestBan_NodeRejectsBannedInbound — the Node-level integration: an
// inbound TCP connection from a banned peer is closed before any
// Peer wrapper is constructed.
func TestBan_NodeRejectsBannedInbound(t *testing.T) {
	dir := t.TempDir()
	db, err := storage.Open(dir)
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	defer db.Close()
	chain, err := core.NewBlockchain(db)
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	pool := mempool.New()

	n, err := NewNode("127.0.0.1:0", chain, pool, db)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Stop()

	// Dial from a known local IP. Ban that IP first.
	listenHost, listenPort, _ := net.SplitHostPort(n.listener.Addr().String())
	bm := n.BanManager()
	bm.Misbehaving("127.0.0.1", 100, "test-ban")
	if !bm.IsBanned("127.0.0.1") {
		t.Fatal("setup: 127.0.0.1 not banned")
	}

	// Dial and expect the connection to be closed quickly.
	target := net.JoinHostPort(listenHost, listenPort)
	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		// If the listener refuses entirely, that's also a valid "rejected".
		return
	}
	defer conn.Close()

	// Give onInbound time to close us.
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 32)
	_, _ = conn.Read(buf)

	time.Sleep(50 * time.Millisecond)
	n.mu.RLock()
	count := len(n.peers)
	n.mu.RUnlock()
	if count != 0 {
		t.Fatalf("banned peer admitted: count=%d", count)
	}
}
