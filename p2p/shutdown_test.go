package p2p

import (
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"qbitcoin/core"
	"qbitcoin/mempool"
	"qbitcoin/storage"
)

// newShutdownTestNode builds a Node with a real chain + mempool + DB so
// the production paths (addPeer → Send(MsgVersion) reads chain.Height,
// scheduler reads chain state) don't blow up. Cleanup is registered on
// the test.
func newShutdownTestNode(t *testing.T) *Node {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	chain, err := core.NewBlockchain(db)
	if err != nil {
		t.Fatalf("NewBlockchain: %v", err)
	}
	pool := mempool.New()
	n, err := NewNode("127.0.0.1:0", chain, pool, db)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	return n
}

// dialInto opens a TCP connection to the node's listener and writes
// one well-formed MsgVersion so the accept path registers a Peer.
func dialInto(t *testing.T, n *Node) net.Conn {
	t.Helper()
	addr := n.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := WriteFrame(conn, CmdVersion, EncodeVersion(ProtocolVer, 0, NetAddr{}, 0x1234, n.genesisHash)); err != nil {
		t.Fatalf("write version frame: %v", err)
	}
	return conn
}

// waitForPeer polls n.PeerCount until at least one peer is registered
// or the deadline expires.
func waitForPeer(t *testing.T, n *Node, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if n.PeerCount() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no peer registered within %s", within)
}

// runWithDeadline runs fn in a goroutine and fails the test if it
// doesn't return within d.
func runWithDeadline(t *testing.T, d time.Duration, label string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		buf := make([]byte, 1<<16)
		nstk := runtime.Stack(buf, true)
		t.Fatalf("%s did not finish within %s; stacks:\n%s", label, d, buf[:nstk])
	}
}

// TestShutdown_StopIsIdempotent — Stop() must tolerate being called more
// than once without close-of-closed-channel panics.
func TestShutdown_StopIsIdempotent(t *testing.T) {
	n := newShutdownTestNode(t)
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	runWithDeadline(t, 5*time.Second, "first Stop()", n.Stop)
	runWithDeadline(t, 1*time.Second, "second Stop()", n.Stop)
}

// TestShutdown_DrainsScheduler — Start() spawns the scheduler goroutine
// via n.spawn(); Stop() must wait for it to exit before returning.
func TestShutdown_DrainsScheduler(t *testing.T) {
	n := newShutdownTestNode(t)
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(20 * time.Millisecond)

	runWithDeadline(t, 5*time.Second, "Stop with scheduler running", n.Stop)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		n.wg.Wait()
		wg.Done()
	}()
	runWithDeadline(t, 1*time.Second, "n.wg.Wait after Stop", wg.Wait)
}

// TestShutdown_DrainsConnectedPeer — when a peer is live, Stop() must
// block until that peer's four goroutines have exited.
func TestShutdown_DrainsConnectedPeer(t *testing.T) {
	n := newShutdownTestNode(t)
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	c := dialInto(t, n)
	t.Cleanup(func() { _ = c.Close() })

	waitForPeer(t, n, 2*time.Second)

	// Snapshot the peer so we can confirm its goroutines exited.
	n.mu.RLock()
	var peer *Peer
	for _, p := range n.peers {
		peer = p
		break
	}
	n.mu.RUnlock()
	if peer == nil {
		t.Fatal("snapshot peer missing")
	}

	runWithDeadline(t, 10*time.Second, "Stop with live peer", n.Stop)
	runWithDeadline(t, 1*time.Second, "peer.Wait after Stop", peer.Wait)
}

// TestShutdown_RejectsAddPeerAfterStop — once Stop() has closed n.quit,
// any addPeer call (e.g. an accept that raced shutdown) must close
// the conn and not spawn peer goroutines.
func TestShutdown_RejectsAddPeerAfterStop(t *testing.T) {
	n := newShutdownTestNode(t)
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	runWithDeadline(t, 5*time.Second, "Stop", n.Stop)

	// Drive addPeer directly with a fresh pipe pair (listener is gone).
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	n.addPeer(a, "test:0", "inbound")
	if got := n.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after post-stop addPeer = %d, want 0", got)
	}
	done := make(chan struct{})
	go func() { n.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("addPeer post-Stop registered a tracker: n.wg.Wait blocked")
	}
}

// TestShutdown_StopFinishesEvenWithBlockedWriter — Stop() must finish
// even when a peer's writeLoop is queued with many frames.
func TestShutdown_StopFinishesEvenWithBlockedWriter(t *testing.T) {
	n := newShutdownTestNode(t)
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	c := dialInto(t, n)
	t.Cleanup(func() { _ = c.Close() })

	waitForPeer(t, n, 2*time.Second)

	n.mu.RLock()
	var peer *Peer
	for _, p := range n.peers {
		peer = p
		break
	}
	n.mu.RUnlock()
	for i := 0; i < 128; i++ {
		peer.Send(CmdPing, EncodePing(uint64(i)))
	}

	runWithDeadline(t, 10*time.Second, "Stop with busy writer", n.Stop)
}
