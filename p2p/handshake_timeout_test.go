package p2p

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newPipeConns returns an in-memory pair of net.Conns. Both ends are
// bidirectional and support deadlines (net.Pipe's deadlines are real).
// Good enough for every peer-lifecycle test since those exercise
// framing + goroutine teardown, not kernel socket behavior.
func newPipeConns(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// withShortHandshakeTimeout swaps in a test-friendly timeout for the
// duration of a subtest and restores it afterward.
func withShortHandshakeTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := HandshakeTimeout
	HandshakeTimeout = d
	t.Cleanup(func() { HandshakeTimeout = orig })
}

// noopCallbacks are passed to NewPeer when the test only cares about
// lifecycle, not message handling.
func noopCallbacks() (func(*Peer, Message), func(*Peer)) {
	return func(*Peer, Message) {}, func(*Peer) {}
}

// drainConn drains bytes from c in the background so writes on the
// other end don't block.
func drainConn(t *testing.T, c net.Conn) {
	t.Helper()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}()
}

// newTestPeer builds a Peer with a drained pipe partner. The returned
// key is a stable stand-in for RemoteAddr().String().
func newTestPeer(t *testing.T, onMsg func(*Peer, Message), onClose func(*Peer)) *Peer {
	t.Helper()
	a, b := newPipeConns(t)
	drainConn(t, b)
	return NewPeer(a, "1.2.3.4:8333", onMsg, onClose)
}

// TestHandshake_BothMarksComplete verifies the two Mark* helpers close
// handshakeDone exactly once, regardless of arrival order.
func TestHandshake_BothMarksComplete(t *testing.T) {
	cases := []struct {
		name  string
		order []func(*Peer)
	}{
		{"version_then_verack", []func(*Peer){(*Peer).MarkVersionReceived, (*Peer).MarkVerAckReceived}},
		{"verack_then_version", []func(*Peer){(*Peer).MarkVerAckReceived, (*Peer).MarkVersionReceived}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withShortHandshakeTimeout(t, time.Hour) // prevent watchdog firing
			onMsg, onClose := noopCallbacks()
			p := newTestPeer(t, onMsg, onClose)
			defer p.Close()

			if p.HandshakeComplete() {
				t.Fatal("complete before any mark")
			}
			tc.order[0](p)
			if p.HandshakeComplete() {
				t.Fatal("complete after only one mark")
			}
			tc.order[1](p)
			if !p.HandshakeComplete() {
				t.Fatal("not complete after both marks")
			}
			select {
			case <-p.handshakeDone:
			case <-time.After(100 * time.Millisecond):
				t.Fatal("handshakeDone not closed")
			}
		})
	}
}

// TestHandshake_MarkIdempotent guards against double-close on
// handshakeDone when a mark helper is called repeatedly.
func TestHandshake_MarkIdempotent(t *testing.T) {
	withShortHandshakeTimeout(t, time.Hour)
	onMsg, onClose := noopCallbacks()
	p := newTestPeer(t, onMsg, onClose)
	defer p.Close()

	p.MarkVersionReceived()
	p.MarkVersionReceived()
	p.MarkVerAckReceived()
	p.MarkVerAckReceived()
	p.MarkVersionReceived()
	p.MarkVerAckReceived()
	if !p.HandshakeComplete() {
		t.Fatal("not complete")
	}
}

// TestHandshake_TimeoutClosesPeer — a peer that never completes the
// Version/VerAck exchange gets dropped after HandshakeTimeout.
func TestHandshake_TimeoutClosesPeer(t *testing.T) {
	withShortHandshakeTimeout(t, 150*time.Millisecond)

	var closed atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	p := newTestPeer(t, func(*Peer, Message) {}, func(*Peer) {
		closed.Store(true)
		wg.Done()
	})

	waitCh := make(chan struct{})
	go func() { wg.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not closed after handshake timeout")
	}
	if !closed.Load() {
		t.Fatal("onClose not invoked")
	}
	select {
	case <-p.quit:
	default:
		t.Fatal("peer.quit not closed after timeout")
	}
}

// TestHandshake_VersionOnlyStillTimesOut — a peer that sends Version but
// never VerAck still gets reaped.
func TestHandshake_VersionOnlyStillTimesOut(t *testing.T) {
	withShortHandshakeTimeout(t, 150*time.Millisecond)
	var closed atomic.Bool
	done := make(chan struct{})
	p := newTestPeer(t, func(*Peer, Message) {}, func(*Peer) {
		closed.Store(true)
		close(done)
	})
	p.MarkVersionReceived()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("peer not closed after handshake timeout (version-only)")
	}
	if !closed.Load() {
		t.Fatal("onClose not invoked")
	}
	if p.HandshakeComplete() {
		t.Fatal("handshake should still be incomplete")
	}
}

// TestHandshake_CompletesBeforeTimeoutKeepsPeerOpen — a peer that
// finishes the exchange promptly must NOT be closed by the watchdog.
func TestHandshake_CompletesBeforeTimeoutKeepsPeerOpen(t *testing.T) {
	withShortHandshakeTimeout(t, 100*time.Millisecond)

	var closedCount atomic.Int32
	p := newTestPeer(t, func(*Peer, Message) {}, func(*Peer) {
		closedCount.Add(1)
	})
	defer p.Close()

	p.MarkVersionReceived()
	p.MarkVerAckReceived()

	time.Sleep(300 * time.Millisecond)

	if closedCount.Load() != 0 {
		t.Fatalf("watchdog closed a handshake-complete peer: count=%d", closedCount.Load())
	}
	select {
	case <-p.quit:
		t.Fatal("peer.quit closed despite completed handshake")
	default:
	}
}

// TestHandshake_CloseCancelsWatchdog — closing the peer externally must
// unblock the watchdog goroutine without waiting for the timer.
func TestHandshake_CloseCancelsWatchdog(t *testing.T) {
	withShortHandshakeTimeout(t, time.Hour)
	p := newTestPeer(t, func(*Peer, Message) {}, func(*Peer) {})

	p.Close()
	time.Sleep(50 * time.Millisecond)
	select {
	case <-p.quit:
	default:
		t.Fatal("quit not closed after Close()")
	}
}

// TestHandshake_PreHandshakeMessageGate — exercises the predicate that
// Node's handleMsg relies on to drop non-handshake traffic pre-verack.
func TestHandshake_PreHandshakeMessageGate(t *testing.T) {
	withShortHandshakeTimeout(t, time.Hour)
	p := newTestPeer(t, func(*Peer, Message) {}, func(*Peer) {})
	defer p.Close()

	if p.HandshakeComplete() {
		t.Fatal("gate open before any mark")
	}
	p.MarkVersionReceived()
	if p.HandshakeComplete() {
		t.Fatal("gate open after version only — would admit pre-verack traffic")
	}
	p.MarkVerAckReceived()
	if !p.HandshakeComplete() {
		t.Fatal("gate still closed after both marks")
	}
}

// TestHandshake_WatchdogResetOnCloseIsRaceSafe — stress the race between
// Close() and the watchdog timer firing.
func TestHandshake_WatchdogResetOnCloseIsRaceSafe(t *testing.T) {
	withShortHandshakeTimeout(t, 5*time.Millisecond)

	const N = 32
	peers := make([]*Peer, 0, N)
	for i := 0; i < N; i++ {
		peers = append(peers, newTestPeer(t, func(*Peer, Message) {}, func(*Peer) {}))
	}
	for i, p := range peers {
		if i%2 == 0 {
			go p.Close()
		}
	}
	time.Sleep(50 * time.Millisecond)
	for _, p := range peers {
		select {
		case <-p.quit:
		default:
			t.Fatalf("peer %s quit not closed", shortPeerKey(p.Key()))
		}
	}
}
