package p2p

import (
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

// Bitcoin Core's tx-inv "trickle" parameters, ported here. Each peer
// accumulates tx invs and flushes the batch on a Poisson-distributed
// timer with these means. Outbound peers are slower (longer mean) so
// our own wallet txs aren't trivially fingerprintable to inbound
// observers tracking arrival timing.
const (
	txInvMeanInbound  = 2 * time.Second
	txInvMeanOutbound = 5 * time.Second
)

// HandshakeTimeout bounds how long a peer may hold a slot before
// completing the Version/VerAck exchange. Bitcoin Core uses 60s for its
// verack timeout; we match. Exposed as a var so tests can shorten it.
var HandshakeTimeout = 60 * time.Second

// PeerKey uniquely identifies a connected peer in the node's peer map.
// For both directions it is the canonical host:port from
// conn.RemoteAddr() — an inbound peer's ephemeral outbound port gives
// each inbound a distinct key (two inbounds from the same source IP
// coexist, matching Bitcoin Core's CNode id model).
type PeerKey = string

// shortPeerKey renders a host:port for compact log output. Short keys
// (<= 22 chars) are returned as-is; longer ones (e.g. IPv6) are
// middle-elided.
func shortPeerKey(k PeerKey) string {
	if len(k) <= 22 {
		return k
	}
	return k[:10] + ".." + k[len(k)-10:]
}

// Peer wraps a net.Conn with read/write loops and qbitcoin-level
// message framing. One Peer = one open TCP connection.
type Peer struct {
	conn net.Conn
	key  PeerKey // canonical host:port of the remote end

	height uint32

	sendCh chan Message
	quit   chan struct{}
	once   sync.Once
	// wg tracks the four goroutines started by NewPeer so Wait() can
	// drain them at shutdown — required for graceful Node.Stop(): the
	// node must not return (and the caller must not Close the DB) while
	// readLoop is mid-handleMsg → mid-AddBlock.
	wg sync.WaitGroup

	// dir + suppressMapDelete + quietClose are owned by p2p.Node; Peer
	// just carries them so dup-resolution and self-conn teardown don't
	// need parallel maps.
	//
	// suppressMapDelete: skip the peer-map removal in onPeerClose (set
	//                    when a newer peer has taken this key's slot).
	// quietClose:        skip the INFO "peer disconnected" log (set on
	//                    self-connection teardowns where the noise
	//                    isn't actionable).
	dir               string
	suppressMapDelete bool
	quietClose        bool

	LastSeen        time.Time
	lastGetBlocksAt time.Time
	txInvQ          map[[32]byte]struct{}
	mu              sync.Mutex

	// Handshake state. Both flags flip true under mu; when both are set,
	// handshakeDone is closed exactly once and the watchdog exits.
	versionRecv   bool
	verackRecv    bool
	handshakeDone chan struct{}
	// connectedLogged guards the one-shot "peer connected" INFO so
	// it fires exactly once per peer, at the moment HandshakeComplete
	// flips to true — whether that happens via MarkVersionReceived or
	// MarkVerAckReceived. Guarded by mu.
	connectedLogged bool

	// advertisedAddr is the peer's self-reported listen endpoint from
	// MsgVersion's addr_from (Bitcoin Core's CAddress of the sender).
	// This is what persistPeer writes to BucketPeers for inbound peers —
	// the TCP RemoteAddr for an inbound connection is the sender's
	// ephemeral outbound port, which isn't dialable.
	advertisedAddr NetAddr
}

// SetAdvertisedAddr records the peer's self-reported listen endpoint
// under p.mu. Called once from the MsgVersion handler.
func (p *Peer) SetAdvertisedAddr(a NetAddr) {
	p.mu.Lock()
	p.advertisedAddr = a
	p.mu.Unlock()
}

// AdvertisedAddr returns the peer's self-reported listen endpoint, or a
// zero value if the peer sent none.
func (p *Peer) AdvertisedAddr() NetAddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.advertisedAddr
}

// HandshakeComplete reports whether the peer has exchanged both Version
// and VerAck (in either order).
func (p *Peer) HandshakeComplete() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.versionRecv && p.verackRecv
}

// ClaimConnectedLog atomically checks whether the handshake is complete
// AND this is the first caller to claim the "peer connected" INFO
// log. Returns true at most once per peer. Used so Version and VerAck
// arrivals can race without double-logging.
func (p *Peer) ClaimConnectedLog() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.versionRecv || !p.verackRecv || p.connectedLogged {
		return false
	}
	p.connectedLogged = true
	return true
}

// MarkVersionReceived records inbound MsgVersion, closing handshakeDone
// if this completes the exchange.
func (p *Peer) MarkVersionReceived() {
	p.mu.Lock()
	if p.versionRecv {
		p.mu.Unlock()
		return
	}
	p.versionRecv = true
	done := p.versionRecv && p.verackRecv
	p.mu.Unlock()
	if done {
		p.signalHandshakeDone()
	}
}

// MarkVerAckReceived records inbound MsgVerAck.
func (p *Peer) MarkVerAckReceived() {
	p.mu.Lock()
	if p.verackRecv {
		p.mu.Unlock()
		return
	}
	p.verackRecv = true
	done := p.versionRecv && p.verackRecv
	p.mu.Unlock()
	if done {
		p.signalHandshakeDone()
	}
}

func (p *Peer) signalHandshakeDone() {
	select {
	case <-p.handshakeDone:
	default:
		close(p.handshakeDone)
	}
}

// handshakeWatchdog closes the peer if the Version/VerAck exchange does
// not finish within HandshakeTimeout. A slow or silent peer would
// otherwise hold an inbound/outbound slot forever pre-verack.
func (p *Peer) handshakeWatchdog(timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-p.handshakeDone:
		return
	case <-p.quit:
		return
	case <-t.C:
		log.Warn("version handshake timeout", "peer", shortPeerKey(p.key), "after", timeout)
		p.Close()
	}
}

// QueueTxInv defers a tx inv until the next trickle flush. Dedupes
// repeated queues for the same hash within one flush window.
func (p *Peer) QueueTxInv(hash [32]byte) {
	p.mu.Lock()
	if p.txInvQ == nil {
		p.txInvQ = make(map[[32]byte]struct{})
	}
	p.txInvQ[hash] = struct{}{}
	p.mu.Unlock()
}

// txInvLoop drains the pending tx-inv set on a Poisson-distributed
// schedule. It exits when the peer's quit channel closes.
func (p *Peer) txInvLoop() {
	for {
		select {
		case <-p.quit:
			return
		case <-time.After(p.nextTxInvDelay()):
		}
		p.flushTxInvs()
	}
}

// nextTxInvDelay returns an exponentially-distributed delay until the
// next flush, with a mean that depends on connection direction.
func (p *Peer) nextTxInvDelay() time.Duration {
	mean := txInvMeanOutbound
	if p.Dir() == "inbound" {
		mean = txInvMeanInbound
	}
	u := rand.Float64()
	if u <= 0 {
		u = 1e-9
	}
	return time.Duration(-math.Log(u) * float64(mean))
}

// flushTxInvs sends the accumulated set as a single MsgInv batch.
func (p *Peer) flushTxInvs() {
	p.mu.Lock()
	if len(p.txInvQ) == 0 {
		p.mu.Unlock()
		return
	}
	items := make([]InvItem, 0, len(p.txInvQ))
	for h := range p.txInvQ {
		items = append(items, InvItem{Type: InvTx, Hash: h})
	}
	p.txInvQ = nil
	p.mu.Unlock()
	p.Send(CmdInv, EncodeInv(items))
}

// MaybeRequestBlocks sends a getblocks to this peer with the given locator
// only if we haven't asked them within minGap. Returns true if the request
// was actually queued. Caller-supplied gap keeps callers honest about per-
// peer pacing without a global ticker.
func (p *Peer) MaybeRequestBlocks(payload []byte, minGap time.Duration) bool {
	p.mu.Lock()
	if !p.lastGetBlocksAt.IsZero() && time.Since(p.lastGetBlocksAt) < minGap {
		p.mu.Unlock()
		return false
	}
	p.lastGetBlocksAt = time.Now()
	p.mu.Unlock()
	p.Send(CmdGetBlocks, payload)
	return true
}

// NewPeer wraps a conn into a Peer and starts read/write loops. key is
// the canonical host:port identifier (for outbound: the dialed target;
// for inbound: conn.RemoteAddr() — the sender's ephemeral port, which
// makes each inbound unique).
func NewPeer(conn net.Conn, key PeerKey, onMsg func(*Peer, Message), onClose func(*Peer)) *Peer {
	p := &Peer{
		conn:          conn,
		key:           key,
		sendCh:        make(chan Message, 64),
		quit:          make(chan struct{}),
		handshakeDone: make(chan struct{}),
		LastSeen:      time.Now(),
	}
	// Capture HandshakeTimeout in the calling goroutine. Tests swap the
	// global via withShortHandshakeTimeout's t.Cleanup, which would race
	// reads from inside a freshly-launched goroutine.
	hsto := HandshakeTimeout
	p.wg.Add(4)
	go func() { defer p.wg.Done(); p.writeLoop() }()
	go func() { defer p.wg.Done(); p.readLoop(onMsg, onClose) }()
	go func() { defer p.wg.Done(); p.txInvLoop() }()
	go func() { defer p.wg.Done(); p.handshakeWatchdog(hsto) }()
	return p
}

// Wait blocks until all four goroutines started by NewPeer have
// returned. Callers MUST have already invoked Close() (otherwise
// readLoop will block on the underlying conn until its 90s read
// deadline expires).
func (p *Peer) Wait() { p.wg.Wait() }

// Done returns a channel that is closed when the peer has been Close'd.
// Used by Node's per-peer shutdown tracker so a node-level quit signal
// can propagate Close() into peers that were added after Stop()'s
// snapshot.
func (p *Peer) Done() <-chan struct{} { return p.quit }

// Dir returns the connection direction ("inbound" / "outbound") under
// p.mu. txInvLoop and outboundCount run concurrently with addPeer's
// initial assignment, so the race detector requires a guarded read.
func (p *Peer) Dir() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dir
}

// setDir assigns the connection direction under p.mu. addPeer is the
// only writer; the lock pairs with Dir() reads.
func (p *Peer) setDir(d string) {
	p.mu.Lock()
	p.dir = d
	p.mu.Unlock()
}

// Key returns the canonical host:port identifier used to index this
// peer in the node's peer map.
func (p *Peer) Key() PeerKey { return p.key }

// Addr is an alias for Key — retained so callers that formerly asked
// for the peer's stable string identifier keep working.
func (p *Peer) Addr() string { return p.key }

// RemoteIP returns just the IP portion of the peer's RemoteAddr, or ""
// if it can't be parsed. Used by the ban manager.
func (p *Peer) RemoteIP() string {
	host, _, err := net.SplitHostPort(p.key)
	if err != nil {
		return ""
	}
	return host
}

// Height returns the peer's last known height.
func (p *Peer) Height() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.height
}

// SetHeight updates the remote height.
func (p *Peer) SetHeight(h uint32) {
	p.mu.Lock()
	p.height = h
	p.mu.Unlock()
}

// Send queues a message for delivery; drops on back-pressure.
func (p *Peer) Send(cmd string, payload []byte) {
	select {
	case p.sendCh <- Message{Command: cmd, Payload: payload}:
	case <-p.quit:
	default:
		// drop
	}
}

// Close stops the peer.
func (p *Peer) Close() {
	p.once.Do(func() {
		close(p.quit)
		_ = p.conn.Close()
	})
}

func (p *Peer) writeLoop() {
	for {
		select {
		case <-p.quit:
			return
		case m := <-p.sendCh:
			_ = p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := WriteFrame(p.conn, m.Command, m.Payload); err != nil {
				// During peer teardown the conn is already closed and
				// every pending send surfaces as an error here. Only
				// the first one is useful; demote to debug after quit
				// has fired so self-conn / disconnect scenarios don't
				// pepper the logs with "broken pipe".
				select {
				case <-p.quit:
					log.Debug("write after close", "peer", shortPeerKey(p.key), "cmd", m.Command, "err", err)
				default:
					log.Warn("socket send error", "peer", shortPeerKey(p.key), "cmd", m.Command, "err", err)
				}
				p.Close()
				return
			}
		}
	}
}

func (p *Peer) readLoop(onMsg func(*Peer, Message), onClose func(*Peer)) {
	defer func() {
		if onClose != nil {
			onClose(p)
		}
		p.Close()
	}()
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		m, err := ReadFrame(p.conn)
		if err != nil {
			log.Debug("socket closed", "peer", shortPeerKey(p.key), "err", err)
			return
		}
		p.mu.Lock()
		p.LastSeen = time.Now()
		p.mu.Unlock()
		if onMsg != nil {
			onMsg(p, m)
		}
	}
}
