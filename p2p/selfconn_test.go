package p2p

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"qbitcoin/core"
	"qbitcoin/mempool"
	"qbitcoin/storage"
)

// newSelfConnTestNode builds a listening Node backed by real chain +
// mempool + DB so the handshake path (which reads chain.Height) works.
func newSelfConnTestNode(t *testing.T) *Node {
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
	if err := n.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(n.Stop)
	return n
}

// TestSelfConn_NonceEchoDisconnects — the core self-dial guard: when
// the remote end sends a version carrying a nonce we just issued, we
// identify the connection as a loopback-to-self and disconnect.
//
// We open a raw TCP connection to the node's listener, read the
// version the node sends first, then echo its nonce back in our own
// version frame — mimicking exactly what would happen if the node
// dialed its own public IP and then received its own version from the
// accept side.
func TestSelfConn_NonceEchoDisconnects(t *testing.T) {
	n := newSelfConnTestNode(t)
	target := n.listener.Addr().String()

	conn, err := net.DialTimeout("tcp", target, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Node should have registered us as an inbound peer by now and
	// sent its version. Read it.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("read version: %v", err)
	}
	if m.Command != CmdVersion {
		t.Fatalf("got command %q, want version", m.Command)
	}
	_, _, _, nonce, _, err := DecodeVersion(m.Payload)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if nonce == 0 {
		t.Fatal("node sent a zero nonce — self-detection can't work")
	}

	// Echo the same nonce back: this is what the node would see on
	// the other side of a dial-to-self.
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if err := WriteFrame(conn, CmdVersion, EncodeVersion(ProtocolVer, 0, NetAddr{}, nonce, n.genesisHash)); err != nil {
		t.Fatalf("write version: %v", err)
	}

	// The node should disconnect us within a short window.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n.PeerCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("PeerCount after nonce echo = %d, want 0", n.PeerCount())
}

// TestSelfConn_LoopbackPreGuard — Connect to 127.0.0.1:<self-port>
// must be refused before any socket opens. This is the cheap pre-TCP
// short-circuit the nonce path also covers but only after handshake.
func TestSelfConn_LoopbackPreGuard(t *testing.T) {
	n := newSelfConnTestNode(t)
	target := n.listener.Addr().String()

	if err := n.Connect(target); err == nil {
		t.Fatal("expected self-dial refusal; got no error")
	}
	if got := n.PeerCount(); got != 0 {
		t.Fatalf("PeerCount after refused self-dial = %d, want 0", got)
	}
}

// TestSelfConn_KnownSelfSkipsAbsorbAddrs — once an address is recorded
// as self, an addr gossip entry for that address must not trigger a
// dial or even a write to BucketPeers.
func TestSelfConn_KnownSelfSkipsAbsorbAddrs(t *testing.T) {
	n := newSelfConnTestNode(t)
	selfHP := "10.1.2.3:8333"
	n.rememberSelfAddr(selfHP)

	na, ok := NetAddrFromHostPort(selfHP)
	if !ok {
		t.Fatalf("NetAddrFromHostPort(%q) failed", selfHP)
	}
	n.absorbAddrs([]AddrEntry{{Timestamp: 0, Addr: na}})

	count := 0
	_ = n.db.ForEach([]byte(storage.BucketPeers), func(k, v []byte) error {
		count++
		return nil
	})
	if count != 0 {
		t.Fatalf("BucketPeers should be empty after known-self absorbAddrs; got %d rows", count)
	}
}

// TestSelfConn_NonceTTL — stale entries are GC'd so the sent-nonces
// table can't grow unbounded.
func TestSelfConn_NonceTTL(t *testing.T) {
	n := newSelfConnTestNode(t)
	nonce := n.issueVersionNonce()
	n.selfMu.Lock()
	n.sentNonces[nonce] = time.Now().Add(-2 * nonceTTL)
	n.selfMu.Unlock()

	n.gcNonces()

	n.selfMu.Lock()
	_, still := n.sentNonces[nonce]
	n.selfMu.Unlock()
	if still {
		t.Fatal("gcNonces did not evict stale entry")
	}
}
