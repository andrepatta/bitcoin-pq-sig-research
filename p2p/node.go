package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"qbitcoin/core"
	"qbitcoin/crypto"
	"qbitcoin/logging"
	"qbitcoin/mempool"
	"qbitcoin/storage"
	"qbitcoin/txn"
)

var log = logging.Module("p2p")

// Limits. Matches Bitcoin Core's defaults: 8 outbound full-relay slots
// and a total cap of 125 connections (MAX_OUTBOUND_FULL_RELAY_CONNECTIONS
// + DEFAULT_MAX_PEER_CONNECTIONS-derived inbound). Core additionally
// reserves slots for block-relay-only and feeler connections; we don't
// distinguish those sub-classes, so MaxOutbound covers every outbound.
const (
	MaxOutbound    = 8
	MaxInbound     = 117
	ProtocolVer    = 1
	BlocksPerBatch = 500
)

// AskedTTL is how long a getdata request stays "in flight" before we
// allow asking another peer for the same hash.
const AskedTTL = 2 * time.Minute

// Scheduler cadence — Bitcoin's SendMessages analog.
const (
	PingInterval          = 60 * time.Second
	AddrGossipInterval    = 30 * time.Minute
	OutboundRetryInterval = 30 * time.Second
)

// GetBlocksMinGap throttles per-peer getblocks bursts.
const (
	GetBlocksMinGap  = 500 * time.Millisecond
	SyncTickInterval = 1 * time.Second
)

// MaxAddrsPerMessage caps the number of peer entries in one MsgAddr
// payload (mirrors Bitcoin's MAX_ADDR_TO_SEND / 1000).
const MaxAddrsPerMessage = 1000

// CmpctReconstructTTL bounds how long we wait for a peer's BlockTxn
// before giving up on a partial reconstruction.
const CmpctReconstructTTL = 30 * time.Second

// DialTimeout is how long an outbound TCP connect may take.
const DialTimeout = 10 * time.Second

// pendingCmpct tracks a CmpctBlock whose reconstruction is still
// missing some full txs (waiting on a BlockTxn from `sender`).
type pendingCmpct struct {
	header   core.BlockHeader
	txs      []*txn.Transaction // indexed slots, nil = still missing
	missing  []uint32           // indices we asked sender for
	sender   *Peer
	deadline time.Time
}

// Node coordinates peer connections and block/tx relay over raw TCP.
type Node struct {
	mu    sync.RWMutex
	chain *core.Blockchain
	pool  *mempool.Mempool
	db    *storage.DB

	// listener is the TCP accept socket. Owned by the Node; closed in Stop.
	listener net.Listener
	// listenPort is the TCP port we actually bound; 0 on listener-less
	// test Nodes. selfAddr() uses this to fill in addr_from for peers
	// we dial (so an inbound peer on the far side learns our listen port).
	listenPort uint16

	// ctx is the node-lifetime context: cancelled by Stop() so any
	// in-flight chain.AddBlock / chain.GetBlock under handleMsg short-
	// circuits.
	ctx       context.Context
	cancelCtx context.CancelFunc
	peers     map[PeerKey]*Peer
	// dialing holds peer keys with an in-flight outbound Connect.
	dialing map[PeerKey]struct{}
	banman  *BanManager
	quit    chan struct{}

	stopOnce sync.Once
	wg       sync.WaitGroup

	askedMu sync.Mutex
	asked   map[[32]byte]time.Time

	cmpctMu      sync.Mutex
	cmpctPending map[[32]byte]*pendingCmpct

	// Self-connection detection (Bitcoin Core's pchMessageStart-nonce
	// trick). Every outbound version we send carries a random u64
	// nonce; a received version with a nonce we sent means we dialed
	// ourselves. nonceTTL bounds the table size — stale entries get
	// GC'd by the scheduler.
	selfMu     sync.Mutex
	sentNonces map[uint64]time.Time // our sent version nonces → issuance time
	selfAddrs  map[string]struct{}  // host:port keys known to reach us

	// genesisHash is our compiled-in block-0 hash, included in every
	// outbound version and compared against inbound versions. Cached
	// once at construction so we don't rehash genesis per handshake.
	genesisHash [32]byte
}

// nonceTTL is how long a sent version nonce stays eligible to catch a
// self-connection echo. 2 minutes easily covers a normal handshake
// round-trip; stale entries are GC'd by the scheduler.
const nonceTTL = 2 * time.Minute

// NewNode constructs a Node that will accept inbound connections on
// listenAddr (e.g. "0.0.0.0:8333"). Pass "" to create a Node with no
// listener (test-only; Connect still works).
func NewNode(listenAddr string, chain *core.Blockchain, pool *mempool.Mempool, db *storage.DB) (*Node, error) {
	bm, err := NewBanManager(db)
	if err != nil {
		log.Warn("ban manager init failed; running without persistence", "err", err)
		bm, _ = NewBanManager(nil)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Node{
		chain:        chain,
		pool:         pool,
		db:           db,
		ctx:          ctx,
		cancelCtx:    cancel,
		peers:        map[PeerKey]*Peer{},
		dialing:      map[PeerKey]struct{}{},
		banman:       bm,
		quit:         make(chan struct{}),
		asked:        map[[32]byte]time.Time{},
		cmpctPending: map[[32]byte]*pendingCmpct{},
		sentNonces:   map[uint64]time.Time{},
		selfAddrs:    map[string]struct{}{},
		genesisHash:  core.Genesis().Header.Hash(),
	}
	if listenAddr != "" {
		l, err := net.Listen("tcp", listenAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen %q: %w", listenAddr, err)
		}
		n.listener = l
		if tcp, ok := l.Addr().(*net.TCPAddr); ok {
			n.listenPort = uint16(tcp.Port)
		}
	}
	return n, nil
}

// BanManager returns the node's ban manager (for RPC / diagnostics).
func (n *Node) BanManager() *BanManager { return n.banman }

// ListenPort returns the TCP port this node is actually listening on
// (resolves :0 into the concrete OS-assigned port). Zero if no
// listener.
func (n *Node) ListenPort() uint16 { return n.listenPort }

// misbehave records a scored violation against p and disconnects them
// if the violation pushed their accumulated score across BanThreshold.
func (n *Node) misbehave(p *Peer, score int, reason string) {
	if n.banman == nil {
		return
	}
	ip := p.RemoteIP()
	if ip == "" {
		return
	}
	if banned := n.banman.Misbehaving(ip, score, reason); banned {
		log.Warn("banned peer",
			"peer", shortPeerKey(p.Key()),
			"reason", reason,
			"duration", BanDuration)
		p.Close()
	}
}

// Start begins accepting inbound connections and runs the scheduler.
func (n *Node) Start() error {
	log.Debug("p2p started", "listen", n.listenString())
	n.spawn(n.runScheduler)
	if n.listener != nil {
		n.spawn(n.acceptLoop)
	}
	return nil
}

// listenString renders the listener address for logs.
func (n *Node) listenString() string {
	if n.listener == nil {
		return ""
	}
	return n.listener.Addr().String()
}

// acceptLoop runs one goroutine per accepted inbound connection. Exits
// when the listener is closed (Stop).
func (n *Node) acceptLoop() {
	for {
		c, err := n.listener.Accept()
		if err != nil {
			select {
			case <-n.quit:
				return
			default:
			}
			// Transient accept errors (e.g. EMFILE) shouldn't kill the
			// loop — back off briefly and retry.
			log.Debug("socket error accept failed", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		n.onInbound(c)
	}
}

// spawn runs fn in a new goroutine tracked by n.wg.
func (n *Node) spawn(fn func()) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		fn()
	}()
}

// runScheduler is Bitcoin's SendMessages analog.
func (n *Node) runScheduler() {
	pingT := time.NewTicker(PingInterval)
	addrT := time.NewTicker(AddrGossipInterval)
	syncT := time.NewTicker(SyncTickInterval)
	outboundT := time.NewTicker(OutboundRetryInterval)
	defer pingT.Stop()
	defer addrT.Stop()
	defer syncT.Stop()
	defer outboundT.Stop()
	for {
		select {
		case <-n.quit:
			return
		case <-pingT.C:
			n.sendPings()
		case <-addrT.C:
			n.gossipAddr(nil)
		case <-syncT.C:
			n.tickSync()
			n.gcCmpctPending()
			n.gcNonces()
		case <-outboundT.C:
			n.maintainOutbound()
		}
	}
}

// maintainOutbound redials persisted peers when we're below MaxOutbound.
func (n *Node) maintainOutbound() {
	if n.outboundCount() >= MaxOutbound {
		return
	}
	n.DialPersistedPeers()
}

// tickSync nudges sync forward by sending getblocks to any peer whose
// reported height is still ahead of our tip.
func (n *Node) tickSync() {
	ourHeight := n.chain.Height()
	loc := n.chain.Locator()
	payload := EncodeGetBlocks(loc)
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, p := range n.peers {
		if p.Height() > ourHeight {
			p.MaybeRequestBlocks(payload, GetBlocksMinGap)
		}
	}
}

func (n *Node) sendPings() {
	nonce := uint64(time.Now().UnixNano())
	payload := EncodePing(nonce)
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, p := range n.peers {
		p.Send(CmdPing, payload)
	}
}

// Stop signals the scheduler + every per-peer goroutine to exit,
// closes the listener, tears down peers, and waits for everything to
// drain. Idempotent.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		n.cancelCtx()
		n.mu.Lock()
		close(n.quit)
		peers := make([]*Peer, 0, len(n.peers))
		for _, p := range n.peers {
			peers = append(peers, p)
		}
		n.mu.Unlock()

		if n.listener != nil {
			_ = n.listener.Close()
		}
		for _, p := range peers {
			p.Close()
		}
		n.wg.Wait()
	})
}

// SelfAddrs returns the host:port dial strings peers should use to
// reach this node. When the node listens on 0.0.0.0 we return a
// single "0.0.0.0:PORT" — callers (logs, tests) that need a concrete
// interface can iterate local interfaces themselves.
func (n *Node) SelfAddrs() []string {
	if n.listener == nil {
		return nil
	}
	return []string{n.listener.Addr().String()}
}

// Connect dials a peer by host:port and performs the handshake. DNS
// names are resolved via net.Dialer.
func (n *Node) Connect(addr string) error {
	// Normalize: accept plain "host:port" — anything with a /p2p/ or
	// multiaddr prefix is rejected so stale configs fail loudly rather
	// than silently losing a dial.
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("parse addr %q: empty host", addr)
	}
	if _, err := strconv.ParseUint(portStr, 10, 16); err != nil {
		return fmt.Errorf("parse addr %q: bad port", addr)
	}

	// Short-circuit on previously-confirmed self-addresses. The
	// nonce-echo path in MsgVersion is the source of truth; this is
	// just a pre-TCP optimization so we don't repeatedly open and
	// immediately tear down sockets to our own listen endpoint.
	if n.isKnownSelfAddr(addr) {
		return errors.New("refusing to dial self (known)")
	}

	// Self-dial is ultimately caught by the nonce-echo in MsgVersion.
	// We keep an additional cheap pre-handshake short-circuit for the
	// obvious loopback case. This MUST run before we dial: otherwise
	// the listener's accept side races in and registers the peer as
	// inbound before we can close the outbound socket.
	if n.listener != nil && portStr == strconv.Itoa(int(n.listenPort)) && isLoopbackHost(host) {
		return errors.New("refusing to dial self (loopback)")
	}

	// Resolve once so the canonical map key matches the connection's
	// RemoteAddr; ban-check on the resolved IP.
	d := net.Dialer{Timeout: DialTimeout}
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %q: %w", addr, err)
	}
	remote := conn.RemoteAddr().String()
	if n.isKnownSelfAddr(remote) {
		_ = conn.Close()
		return errors.New("refusing to dial self (resolved)")
	}
	ip, _, _ := net.SplitHostPort(remote)
	if n.banman != nil && n.banman.IsBanned(ip) {
		_ = conn.Close()
		return fmt.Errorf("refusing to dial banned ip %s", ip)
	}

	// Dedup: key by conn.RemoteAddr (ip:port). Two simultaneous dials
	// resolving the same remote will produce the same key.
	n.mu.Lock()
	_, already := n.peers[remote]
	_, inflight := n.dialing[remote]
	count := len(n.peers)
	if already || inflight {
		n.mu.Unlock()
		_ = conn.Close()
		return nil
	}
	if count >= MaxOutbound+MaxInbound {
		n.mu.Unlock()
		_ = conn.Close()
		return errors.New("peer slots full")
	}
	n.dialing[remote] = struct{}{}
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.dialing, remote)
		n.mu.Unlock()
	}()

	log.Debug("outbound connected", "peer", shortPeerKey(remote), "dial", addr)
	n.addPeer(conn, remote, "outbound")
	return nil
}

// isLoopbackHost reports whether the textual host is 127.* / ::1 /
// "localhost". Used only for the self-dial short-circuit.
func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// onInbound handles a freshly-accepted TCP connection: ban check,
// capacity check, then addPeer.
func (n *Node) onInbound(c net.Conn) {
	remote := c.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remote)
	if n.banman != nil && n.banman.IsBanned(ip) {
		log.Warn("connection from peer dropped (banned)", "peer", shortPeerKey(remote))
		_ = c.Close()
		return
	}
	n.mu.RLock()
	full := len(n.peers) >= MaxInbound+MaxOutbound
	_, dup := n.peers[remote]
	n.mu.RUnlock()
	if full {
		log.Warn("connection from peer dropped (full)", "peer", shortPeerKey(remote))
		_ = c.Close()
		return
	}
	if dup {
		// Same ip:port already tracked — tear the new one down.
		log.Debug("inbound dup connection", "peer", shortPeerKey(remote))
		_ = c.Close()
		return
	}
	log.Debug("accepted connection", "peer", shortPeerKey(remote))
	n.addPeer(c, remote, "inbound")
}

// addPeer wires up a net.Conn into a Peer, registers it in the peers
// map under key, and kicks off the handshake by sending our Version.
func (n *Node) addPeer(c net.Conn, key PeerKey, dir string) {
	// Reserve a tracker slot under the same lock that Stop() holds
	// when it closes n.quit. After Stop() runs, n.quit is closed
	// before further addPeer calls can pass this gate, so every peer
	// that ever becomes "live" is accounted for in n.wg.
	n.mu.Lock()
	select {
	case <-n.quit:
		n.mu.Unlock()
		_ = c.Close()
		return
	default:
	}
	n.wg.Add(1)
	n.mu.Unlock()

	p := NewPeer(c, key, n.handleMsg, n.onPeerClose)
	p.setDir(dir)

	// Per-peer shutdown tracker: hold the n.wg slot until all four of
	// the peer's goroutines have exited.
	go func() {
		defer n.wg.Done()
		select {
		case <-p.Done():
		case <-n.quit:
			p.Close()
		}
		p.Wait()
	}()

	n.mu.Lock()
	if existing, exists := n.peers[key]; exists {
		// Rare: can only happen if a dial and an inbound racing here
		// both resolve to the same key, which shouldn't be possible
		// since inbound-peers get ephemeral remote ports. Close the
		// new one; keep existing.
		n.mu.Unlock()
		log.Debug("addPeer dup key", "peer", shortPeerKey(key))
		_ = existing // keep existing, drop new
		p.suppressMapDelete = true
		p.Close()
		return
	}
	n.peers[key] = p
	count := len(n.peers)
	n.mu.Unlock()
	log.Debug("Added connection peer", "peer", shortPeerKey(key), "dir", dir, "total", count)

	// Kick off the handshake by sending our version with our listen
	// endpoint as addr_from. Inbound peers need this to know what
	// host:port to dial us back on (their conn.RemoteAddr sees only
	// our accepted-side socket). The nonce is how the remote end —
	// or we ourselves, on a self-dial — detect self-connections.
	nonce := n.issueVersionNonce()
	p.Send(CmdVersion, EncodeVersion(ProtocolVer, n.chain.Height(), n.selfAddr(), nonce, n.genesisHash))
}

// issueVersionNonce mints a fresh 64-bit random nonce for an outbound
// MsgVersion and remembers it so we can recognize our own echo. Called
// once per addPeer, for both directions — inbound peers expect our
// version after accept, outbound peers expect it after dial.
func (n *Node) issueVersionNonce() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	nonce := binary.LittleEndian.Uint64(b[:])
	n.selfMu.Lock()
	n.sentNonces[nonce] = time.Now()
	n.selfMu.Unlock()
	return nonce
}

// isSelfNonce reports whether `nonce` is one we emitted ourselves
// within nonceTTL. A match means the peer we just connected to is us —
// disconnect and remember the target so future dials / gossip skip it.
func (n *Node) isSelfNonce(nonce uint64) bool {
	if nonce == 0 {
		return false
	}
	n.selfMu.Lock()
	defer n.selfMu.Unlock()
	t, ok := n.sentNonces[nonce]
	if !ok {
		return false
	}
	if time.Since(t) > nonceTTL {
		delete(n.sentNonces, nonce)
		return false
	}
	delete(n.sentNonces, nonce)
	return true
}

// rememberSelfAddr records a host:port that, when dialed, loops back
// to us. Consulted by Connect + absorbAddrs to short-circuit future
// self-dials before we even open a socket.
func (n *Node) rememberSelfAddr(hp string) {
	n.selfMu.Lock()
	n.selfAddrs[hp] = struct{}{}
	n.selfMu.Unlock()
}

// isKnownSelfAddr reports whether hp has previously been confirmed via
// nonce-echo as our own listen endpoint.
func (n *Node) isKnownSelfAddr(hp string) bool {
	n.selfMu.Lock()
	defer n.selfMu.Unlock()
	_, ok := n.selfAddrs[hp]
	return ok
}

// gcNonces drops sent-nonce entries past their TTL. Called from the
// scheduler alongside gcCmpctPending.
func (n *Node) gcNonces() {
	now := time.Now()
	n.selfMu.Lock()
	defer n.selfMu.Unlock()
	for k, t := range n.sentNonces {
		if now.Sub(t) > nonceTTL {
			delete(n.sentNonces, k)
		}
	}
}

// maybeLogConnected emits the one-shot "peer connected" INFO if this
// call completed the handshake (in either order) and no prior caller
// has already claimed the log. Safe to call from both Version and
// VerAck handlers.
func (n *Node) maybeLogConnected(p *Peer) {
	if !p.ClaimConnectedLog() {
		return
	}
	log.Info("New peer connected",
		"peer", shortPeerKey(p.Key()),
		"dir", p.Dir(),
		"height", p.Height(),
		"total", n.PeerCount())
}

// selfAddr returns the sender-side addr_from we put in MsgVersion. We
// don't know our routable IP (behind NAT, multi-interface, etc.), so
// we emit the zero value for the IP and let our listen port stand in —
// receivers combine that with the conn.RemoteAddr IP they observe to
// derive a dialable endpoint. Bitcoin Core does the same dance (it
// emits addrMe from CNetAddr).
func (n *Node) selfAddr() NetAddr {
	var a NetAddr
	a.Port = n.listenPort
	return a
}

// resolveAdvertised combines the observed socket IP with the sender's
// advertised listen port (from addr_from) into a dialable endpoint. If
// the advertised port is zero, returns a zero NetAddr.
func resolveAdvertised(connRemote string, advertised NetAddr) NetAddr {
	if advertised.Port == 0 {
		return NetAddr{}
	}
	host, _, err := net.SplitHostPort(connRemote)
	if err != nil {
		return NetAddr{}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return NetAddr{}
	}
	var out NetAddr
	copy(out.IP[:], ip.To16())
	out.Port = advertised.Port
	return out
}

func (n *Node) onPeerClose(p *Peer) {
	n.mu.Lock()
	if !p.suppressMapDelete {
		if cur, ok := n.peers[p.Key()]; ok && cur == p {
			delete(n.peers, p.Key())
		}
	}
	count := len(n.peers)
	n.mu.Unlock()
	// INFO disconnect lines only fire for peers that actually reached
	// "connected" (handshake complete). Pre-handshake drops — port
	// scans, aborted dials, peers that spoke to us briefly but never
	// verack'd — are routine and go to debug. This keeps the info
	// stream symmetric with "peer connected".
	switch {
	case p.suppressMapDelete:
		log.Debug("dup peer closed", "peer", shortPeerKey(p.Key()))
	case p.quietClose:
		log.Debug("peer closed (quiet)", "peer", shortPeerKey(p.Key()), "total", count)
	case !p.HandshakeComplete():
		log.Debug("peer closed (pre-handshake)", "peer", shortPeerKey(p.Key()), "total", count)
	default:
		log.Info("disconnecting peer", "peer", shortPeerKey(p.Key()), "total", count)
	}
}

func (n *Node) handleMsg(p *Peer, m Message) {
	// Gate non-handshake messages until Version/VerAck have been exchanged.
	if m.Command != CmdVersion && m.Command != CmdVerAck && !p.HandshakeComplete() {
		log.Warn("Ignoring pre-handshake message", "peer", shortPeerKey(p.Key()), "cmd", m.Command)
		n.misbehave(p, 10, "pre-handshake message")
		return
	}
	switch m.Command {
	case CmdVersion:
		_, h, addrFrom, nonce, peerGenesis, err := DecodeVersion(m.Payload)
		if err != nil {
			log.Warn("bad version", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 100, "bad version payload")
			return
		}
		// Genesis-hash check: two nodes built from different genesis
		// constants produce different block-0 hashes, which silently
		// orphan every block one sends the other. Drop the peer cleanly
		// (quietClose — configuration error, not malicious) with both
		// hashes in the log so the operator can rebuild the stale side.
		if peerGenesis != n.genesisHash {
			log.Warn("peer genesis mismatch, disconnecting",
				"peer", shortPeerKey(p.Key()),
				"our_genesis", crypto.DisplayHex(n.genesisHash),
				"peer_genesis", crypto.DisplayHex(peerGenesis))
			p.quietClose = true
			p.Close()
			return
		}
		// Self-connection detection: if this version carries a nonce
		// we sent, we dialed (or were dialed by) ourselves. Record the
		// peer key as a known-self endpoint so future dials and addr
		// gossip skip it, then drop the connection. Prune any stored
		// row in BucketPeers so restarts don't repeat the self-dial.
		// suppressMapDelete=true keeps onPeerClose quiet for the leg
		// we're tearing down (the match log below carries all info).
		if n.isSelfNonce(nonce) {
			n.rememberSelfAddr(p.Key())
			n.forgetPersistedPeer(p.Key())
			if adv := resolveAdvertised(p.Key(), addrFrom); !adv.IsZero() {
				n.rememberSelfAddr(adv.String())
				n.forgetPersistedPeer(adv.String())
			}
			// Quiet log: one line per self-detection. Debug because the
			// first line ("bootnode addr=...") already told the user we
			// tried to dial this address.
			log.Debug("connected to self, disconnecting", "peer", shortPeerKey(p.Key()))
			p.quietClose = true
			p.Close()
			return
		}
		log.Debug("receive version message", "peer", shortPeerKey(p.Key()), "peer_height", h, "our_height", n.chain.Height(), "addr_from_port", addrFrom.Port)
		p.SetHeight(h)
		// Resolve addr_from against the observed remote IP into a
		// dialable endpoint we can persist / gossip.
		if adv := resolveAdvertised(p.Key(), addrFrom); !adv.IsZero() {
			p.SetAdvertisedAddr(adv)
		}
		p.MarkVersionReceived()
		p.Send(CmdVerAck, nil)
		n.maybeLogConnected(p)
	case CmdVerAck:
		p.MarkVerAckReceived()
		n.maybeLogConnected(p)
		n.persistPeer(p)
		target := p
		n.spawn(func() {
			entries := n.collectKnownAddrs()
			if len(entries) > MaxAddrsPerMessage {
				entries = entries[:MaxAddrsPerMessage]
			}
			if len(entries) > 0 {
				target.Send(CmdAddr, EncodeAddr(entries))
			}
		})
		if p.Height() > n.chain.Height() {
			log.Info("getblocks to peer", "peer", shortPeerKey(p.Key()), "peer_height", p.Height(), "our_height", n.chain.Height())
			p.Send(CmdGetBlocks, EncodeGetBlocks(n.chain.Locator()))
		}
	case CmdPing:
		nonce, err := DecodePing(m.Payload)
		if err == nil {
			p.Send(CmdPong, EncodePing(nonce))
		}
	case CmdPong:
		// ok
	case CmdGetBlocks:
		loc, err := DecodeGetBlocks(m.Payload)
		if err != nil {
			return
		}
		hashes := n.chain.BlocksAfter(n.ctx, loc, BlocksPerBatch)
		log.Debug("received getblocks", "peer", shortPeerKey(p.Key()), "inv_items", len(hashes))
		items := make([]InvItem, len(hashes))
		for i, h := range hashes {
			items[i] = InvItem{Type: InvBlock, Hash: h}
		}
		p.Send(CmdInv, EncodeInv(items))
	case CmdInv:
		items, err := DecodeInv(m.Payload)
		if err != nil {
			return
		}
		var want []InvItem
		var wantBlocks, wantTxs int
		for _, it := range items {
			switch it.Type {
			case InvBlock:
				if !n.chain.HasBlock(it.Hash) && n.markAsked(it.Hash) {
					want = append(want, it)
					wantBlocks++
				}
			case InvTx:
				if n.pool.Get(it.Hash) == nil && n.markAsked(it.Hash) {
					want = append(want, it)
					wantTxs++
				}
			}
		}
		if len(items) > 0 {
			log.Debug("received inv", "peer", shortPeerKey(p.Key()), "items", len(items), "want_blocks", wantBlocks, "want_txs", wantTxs)
		}
		if len(want) > 0 {
			p.Send(CmdGetData, EncodeInv(want))
		}
	case CmdGetData:
		items, err := DecodeInv(m.Payload)
		if err != nil {
			return
		}
		log.Debug("received getdata", "peer", shortPeerKey(p.Key()), "items", len(items))
		for _, it := range items {
			switch it.Type {
			case InvBlock:
				b, err := n.chain.GetBlock(n.ctx, it.Hash)
				if err == nil && b != nil {
					p.Send(CmdCmpctBlock, EncodeCmpctBlock(buildCmpctBlock(b)))
				}
			case InvTx:
				tx := n.pool.Get(it.Hash)
				if tx != nil {
					p.Send(CmdTx, tx.Serialize())
				}
			}
		}
	case CmdBlock:
		b, err := core.DeserializeBlock(m.Payload)
		if err != nil {
			log.Warn("bad block payload", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 100, "bad block payload")
			return
		}
		bh := b.Header.Hash()
		n.clearAsked(bh)
		outcome, height, err := n.chain.AddBlock(n.ctx, *b)
		if err != nil {
			log.Warn("AcceptBlock failed", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "err", err)
			n.misbehave(p, 100, "invalid block")
			return
		}
		switch outcome {
		case core.OutcomeExtended:
			log.Info("received block", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "height", height, "txs", len(b.Txns))
		case core.OutcomeReorg:
			log.Debug("received block (reorg)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "height", height)
		case core.OutcomeSideChain:
			log.Debug("received block (side-chain)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "block_height", height)
		case core.OutcomeOrphan:
			log.Debug("received orphan block", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh))
		case core.OutcomeDuplicate:
			log.Debug("AlreadyHaveBlock", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh))
		}
		n.BroadcastInv(InvItem{Type: InvBlock, Hash: bh}, p)
		extended := outcome == core.OutcomeExtended || outcome == core.OutcomeReorg
		behind := p.Height() > n.chain.Height() || len(n.chain.MissingOrphanParents()) > 0
		if extended && behind {
			loc := append([][32]byte{bh}, n.chain.Locator()...)
			p.MaybeRequestBlocks(EncodeGetBlocks(loc), GetBlocksMinGap)
		}
	case CmdTx:
		tx, _, err := txn.DeserializeTx(m.Payload)
		if err != nil {
			log.Warn("bad tx payload", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 100, "bad tx payload")
			return
		}
		txid := tx.TxID()
		n.clearAsked(txid)
		nh, nt := n.chain.NextBlockContext()
		if err := n.pool.Add(*tx, n.chain.ChainUTXO(), nh, nt); err != nil {
			log.Debug("AcceptToMemoryPool failed", "peer", shortPeerKey(p.Key()), "txid", crypto.DisplayHex(txid), "err", err)
			return
		}
		log.Info("AcceptToMemoryPool: accepted", "peer", shortPeerKey(p.Key()), "txid", crypto.DisplayHex(txid))
		n.BroadcastInv(InvItem{Type: InvTx, Hash: txid}, p)
	case CmdCmpctBlock:
		cb, err := DecodeCmpctBlock(m.Payload)
		if err != nil {
			log.Warn("bad cmpctblock", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 100, "bad cmpctblock payload")
			return
		}
		n.handleCmpctBlock(p, cb)
	case CmdGetBlockTxn:
		hh, indices, err := DecodeGetBlockTxn(m.Payload)
		if err != nil {
			log.Warn("bad getblocktxn", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 100, "bad getblocktxn payload")
			return
		}
		b, err := n.chain.GetBlock(n.ctx, hh)
		if err != nil || b == nil {
			return
		}
		out := make([]PrefilledTx, 0, len(indices))
		for _, idx := range indices {
			if int(idx) >= len(b.Txns) {
				return
			}
			out = append(out, PrefilledTx{Index: idx, Tx: b.Txns[idx]})
		}
		p.Send(CmdBlockTxn, EncodeBlockTxn(hh, out))
	case CmdBlockTxn:
		hh, txs, err := DecodeBlockTxn(m.Payload)
		if err != nil {
			log.Warn("bad blocktxn", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 100, "bad blocktxn payload")
			return
		}
		n.completeCmpctBlock(p, hh, txs)
	case CmdAddr:
		entries, err := DecodeAddr(m.Payload)
		if err != nil {
			log.Debug("bad addr payload", "peer", shortPeerKey(p.Key()), "err", err)
			n.misbehave(p, 10, "bad addr payload")
			return
		}
		log.Debug("received addr", "peer", shortPeerKey(p.Key()), "entries", len(entries))
		n.absorbAddrs(entries)
	case CmdReject:
		log.Debug("Reject", "peer", shortPeerKey(p.Key()), "bytes", len(m.Payload))
	default:
		// Unknown command — ignore (Bitcoin Core drops silently too).
	}
}

// gossipAddr pushes our known peer set to all connected peers (or all
// except `except`, e.g. the peer that just sent us an addr we're
// echoing).
func (n *Node) gossipAddr(except *Peer) {
	entries := n.collectKnownAddrs()
	if len(entries) == 0 {
		return
	}
	if len(entries) > MaxAddrsPerMessage {
		entries = entries[:MaxAddrsPerMessage]
	}
	payload := EncodeAddr(entries)
	n.mu.RLock()
	defer n.mu.RUnlock()
	for _, p := range n.peers {
		if p == except {
			continue
		}
		p.Send(CmdAddr, payload)
	}
}

// collectKnownAddrs returns a list of gossipable peer endpoints.
// Sources: currently connected peers (their advertised listen addr for
// inbound, or the dialed addr for outbound) plus persisted entries in
// BucketPeers.
func (n *Node) collectKnownAddrs() []AddrEntry {
	seen := map[string]bool{}
	var out []AddrEntry
	now := time.Now().Unix()

	add := func(a NetAddr) {
		if a.IsZero() {
			return
		}
		k := a.String()
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, AddrEntry{Timestamp: now, Addr: a})
	}

	n.mu.RLock()
	for _, p := range n.peers {
		if adv := p.AdvertisedAddr(); !adv.IsZero() {
			add(adv)
			continue
		}
		// Outbound peer without addr_from: fall back to the key (the
		// address we dialed). Inbound peers without addr_from have an
		// ephemeral port, so we skip them — not dialable.
		if p.Dir() == "outbound" {
			if na, ok := NetAddrFromHostPort(p.Key()); ok {
				add(na)
			}
		}
	}
	n.mu.RUnlock()

	if n.db != nil {
		_ = n.db.ForEach([]byte(storage.BucketPeers), func(k, v []byte) error {
			addr, err := decodePeerRecord(v)
			if err != nil || addr.IsZero() {
				return nil
			}
			add(addr)
			return nil
		})
	}
	return out
}

// outboundCount returns the number of currently-connected peers we
// dialed (vs. peers that dialed us).
func (n *Node) outboundCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	c := 0
	for _, p := range n.peers {
		if p.Dir() == "outbound" {
			c++
		}
	}
	return c
}

// absorbAddrs records gossiped peer entries into BucketPeers and
// (best-effort) dials new ones up to MaxOutbound.
func (n *Node) absorbAddrs(entries []AddrEntry) {
	if n.db == nil {
		return
	}
	for _, e := range entries {
		if e.Addr.IsZero() {
			continue
		}
		// Skip self: anything nonce-echo has confirmed as our own
		// listen endpoint, plus a cheap port+loopback heuristic for
		// the startup window before the first self-dial has completed.
		if n.isKnownSelfAddr(e.Addr.String()) {
			continue
		}
		if e.Addr.Port == n.listenPort && isLoopbackIP(e.Addr.IP[:]) {
			continue
		}
		key := addrKey(e.Addr)
		_ = n.db.Put([]byte(storage.BucketPeers), key, encodePeerRecord(e.Addr))

		dial := e.Addr.String()
		n.mu.RLock()
		_, already := n.peers[dial]
		n.mu.RUnlock()
		if already || n.outboundCount() >= MaxOutbound {
			continue
		}
		s := dial
		n.spawn(func() {
			if err := n.Connect(s); err != nil {
				log.Debug("addr-driven dial failed", "addr", s, "err", err)
			}
		})
	}
}

// isLoopbackIP reports whether an IPv4-mapped IPv6 byte slice is a
// loopback. Used only for the self-filter in absorbAddrs.
func isLoopbackIP(ip16 []byte) bool {
	ip := net.IP(ip16)
	return ip.IsLoopback()
}

// markAsked records an outstanding getdata request for hash.
func (n *Node) markAsked(hash [32]byte) bool {
	now := time.Now()
	n.askedMu.Lock()
	defer n.askedMu.Unlock()
	if deadline, ok := n.asked[hash]; ok && now.Before(deadline) {
		return false
	}
	if len(n.asked) > 1024 {
		for k, d := range n.asked {
			if now.After(d) {
				delete(n.asked, k)
			}
		}
	}
	n.asked[hash] = now.Add(AskedTTL)
	return true
}

// clearAsked drops the in-flight marker once we have the data.
func (n *Node) clearAsked(hash [32]byte) {
	n.askedMu.Lock()
	delete(n.asked, hash)
	n.askedMu.Unlock()
}

// --- compact blocks ---

func buildCmpctBlock(b *core.Block) CmpctBlock {
	nonce := uint64(time.Now().UnixNano())
	headerBytes := b.Header.Serialize()
	cb := CmpctBlock{Header: b.Header, Nonce: nonce}
	for i, tx := range b.Txns {
		if i == 0 || tx.IsCoinbase() {
			cb.Prefilled = append(cb.Prefilled, PrefilledTx{Index: uint32(i), Tx: tx})
			continue
		}
		cb.ShortIDs = append(cb.ShortIDs, ComputeShortID(headerBytes, nonce, tx.TxID()))
	}
	return cb
}

func (n *Node) handleCmpctBlock(p *Peer, cb *CmpctBlock) {
	headerHash := cb.Header.Hash()
	if n.chain.HasBlock(headerHash) {
		return
	}
	n.clearAsked(headerHash)

	total := len(cb.ShortIDs) + len(cb.Prefilled)
	if total == 0 || total > core.MaxBlockTxCount {
		return
	}
	slots := make([]*txn.Transaction, total)
	prefilledAt := make(map[uint32]bool, len(cb.Prefilled))
	for i := range cb.Prefilled {
		idx := cb.Prefilled[i].Index
		if int(idx) >= total || prefilledAt[idx] {
			log.Warn("cmpctblock: bad prefilled index", "peer", shortPeerKey(p.Key()))
			n.misbehave(p, 100, "cmpctblock bad prefilled index")
			return
		}
		prefilledAt[idx] = true
		tx := cb.Prefilled[i].Tx
		slots[idx] = &tx
	}

	headerBytes := cb.Header.Serialize()
	mempoolByShort := make(map[[ShortIDLen]byte]*txn.Transaction)
	collisions := make(map[[ShortIDLen]byte]bool)
	for _, tx := range n.pool.All() {
		t := tx
		sid := ComputeShortID(headerBytes, cb.Nonce, t.TxID())
		if _, dup := mempoolByShort[sid]; dup {
			collisions[sid] = true
			continue
		}
		mempoolByShort[sid] = &t
	}

	sidIdx := 0
	var missing []uint32
	for i := 0; i < total; i++ {
		if slots[i] != nil {
			continue
		}
		if sidIdx >= len(cb.ShortIDs) {
			log.Warn("cmpctblock: short-id underflow", "peer", shortPeerKey(p.Key()))
			n.misbehave(p, 100, "cmpctblock short-id underflow")
			return
		}
		sid := cb.ShortIDs[sidIdx]
		sidIdx++
		if collisions[sid] {
			missing = append(missing, uint32(i))
			continue
		}
		if tx, ok := mempoolByShort[sid]; ok {
			slots[i] = tx
			continue
		}
		missing = append(missing, uint32(i))
	}
	if sidIdx != len(cb.ShortIDs) {
		log.Warn("cmpctblock: short-id leftover", "peer", shortPeerKey(p.Key()))
		n.misbehave(p, 100, "cmpctblock short-id leftover")
		return
	}

	if len(missing) == 0 {
		n.assembleAndAddBlock(p, cb.Header, slots)
		return
	}

	n.cmpctMu.Lock()
	n.cmpctPending[headerHash] = &pendingCmpct{
		header:   cb.Header,
		txs:      slots,
		missing:  missing,
		sender:   p,
		deadline: time.Now().Add(CmpctReconstructTTL),
	}
	n.cmpctMu.Unlock()
	log.Debug("cmpctblock: requesting missing transactions", "peer", shortPeerKey(p.Key()), "missing", len(missing), "total", total)
	p.Send(CmdGetBlockTxn, EncodeGetBlockTxn(headerHash, missing))
}

func (n *Node) completeCmpctBlock(p *Peer, headerHash [32]byte, txs []PrefilledTx) {
	n.cmpctMu.Lock()
	pc, ok := n.cmpctPending[headerHash]
	if ok {
		delete(n.cmpctPending, headerHash)
	}
	n.cmpctMu.Unlock()
	if !ok {
		return
	}
	for i := range txs {
		idx := txs[i].Index
		if int(idx) >= len(pc.txs) || pc.txs[idx] != nil {
			log.Warn("blocktxn: bad index", "peer", shortPeerKey(p.Key()))
			n.misbehave(p, 100, "blocktxn bad index")
			return
		}
		t := txs[i].Tx
		pc.txs[idx] = &t
	}
	for i, tx := range pc.txs {
		if tx == nil {
			log.Warn("blocktxn: still missing slots after reply", "peer", shortPeerKey(p.Key()), "first_missing", i)
			n.misbehave(p, 50, "blocktxn missing slots")
			return
		}
	}
	n.assembleAndAddBlock(p, pc.header, pc.txs)
}

func (n *Node) assembleAndAddBlock(p *Peer, header core.BlockHeader, slots []*txn.Transaction) {
	txns := make([]txn.Transaction, len(slots))
	for i, t := range slots {
		txns[i] = *t
	}
	b := core.Block{Header: header, Txns: txns}
	if got := b.ComputeMerkleRoot(); got != header.MerkleRoot {
		log.Warn("cmpctblock: merkle mismatch — short-id collision", "peer", shortPeerKey(p.Key()))
		p.Send(CmdGetData, EncodeInv([]InvItem{{Type: InvBlock, Hash: header.Hash()}}))
		return
	}
	bh := header.Hash()
	outcome, height, err := n.chain.AddBlock(n.ctx, b)
	if err != nil {
		log.Warn("AcceptBlock failed (cmpct)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "err", err)
		return
	}
	switch outcome {
	case core.OutcomeExtended:
		log.Info("received block (cmpct)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "height", height, "txs", len(b.Txns))
	case core.OutcomeReorg:
		log.Debug("received block (cmpct, reorg)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "height", height)
	case core.OutcomeSideChain:
		log.Debug("received block (cmpct, side-chain)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh), "block_height", height)
	case core.OutcomeOrphan:
		log.Debug("received orphan block (cmpct)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh))
	case core.OutcomeDuplicate:
		log.Debug("AlreadyHaveBlock (cmpct)", "peer", shortPeerKey(p.Key()), "hash", crypto.DisplayHex(bh))
	}
	n.BroadcastInv(InvItem{Type: InvBlock, Hash: bh}, p)
	extended := outcome == core.OutcomeExtended || outcome == core.OutcomeReorg
	behind := p.Height() > n.chain.Height() || len(n.chain.MissingOrphanParents()) > 0
	if extended && behind {
		loc := append([][32]byte{bh}, n.chain.Locator()...)
		p.MaybeRequestBlocks(EncodeGetBlocks(loc), GetBlocksMinGap)
	}
}

func (n *Node) gcCmpctPending() {
	now := time.Now()
	n.cmpctMu.Lock()
	defer n.cmpctMu.Unlock()
	for h, pc := range n.cmpctPending {
		if now.After(pc.deadline) {
			delete(n.cmpctPending, h)
		}
	}
}

// BroadcastInv relays an inv to all peers except `except` (may be nil).
func (n *Node) BroadcastInv(it InvItem, except *Peer) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	switch it.Type {
	case InvTx:
		for _, p := range n.peers {
			if p == except {
				continue
			}
			p.QueueTxInv(it.Hash)
		}
	default:
		payload := EncodeInv([]InvItem{it})
		for _, p := range n.peers {
			if p == except {
				continue
			}
			p.Send(CmdInv, payload)
		}
	}
}

// BroadcastBlock announces a block to all peers.
func (n *Node) BroadcastBlock(b core.Block) {
	h := b.Header.Hash()
	log.Debug("Relaying block", "hash", crypto.DisplayHex(h), "peers", n.PeerCount())
	n.BroadcastInv(InvItem{Type: InvBlock, Hash: h}, nil)
}

// BroadcastTx announces a tx to all peers.
func (n *Node) BroadcastTx(tx txn.Transaction) {
	h := tx.TxID()
	log.Debug("Relaying tx", "txid", crypto.DisplayHex(h), "peers", n.PeerCount())
	n.BroadcastInv(InvItem{Type: InvTx, Hash: h}, nil)
}

// --- peer persistence ---
//
// Bitcoin Core's peers.dat is an LRU keyed by CService (ip:port). We
// store one row per advertised endpoint: Key = 18-byte NetAddr wire
// form, Value = the same 18 bytes back (kept separate from key for
// forward compatibility — we can extend value with last-seen / scoring
// later without migrating).

func addrKey(a NetAddr) []byte {
	var k [18]byte
	encodeNetAddr(k[:], a)
	return k[:]
}

func encodePeerRecord(a NetAddr) []byte {
	out := make([]byte, 18+8)
	encodeNetAddr(out[0:18], a)
	binary.BigEndian.PutUint64(out[18:26], uint64(time.Now().Unix()))
	return out
}

func decodePeerRecord(b []byte) (NetAddr, error) {
	if len(b) < 18 {
		return NetAddr{}, errors.New("peer record: truncated")
	}
	return decodeNetAddr(b[:18]), nil
}

// persistPeer saves the peer's advertised listen endpoint for later
// redial. For inbound peers this is the self-reported addr_from (the
// raw RemoteAddr is an ephemeral outbound port, useless as a redial
// target). For outbound peers both sources are valid; we prefer the
// advertised one, falling back to the dialed key. Known-self
// endpoints are skipped so we don't persist our own address and then
// re-dial it on the next boot.
func (n *Node) persistPeer(p *Peer) {
	if n.db == nil {
		return
	}
	addr := p.AdvertisedAddr()
	if addr.IsZero() && p.Dir() == "outbound" {
		if na, ok := NetAddrFromHostPort(p.Key()); ok {
			addr = na
		}
	}
	if addr.IsZero() {
		return
	}
	if n.isKnownSelfAddr(addr.String()) {
		return
	}
	if err := n.db.Put([]byte(storage.BucketPeers), addrKey(addr), encodePeerRecord(addr)); err != nil {
		log.Warn("peer persist failed", "peer", shortPeerKey(p.Key()), "err", err)
	}
}

// forgetPersistedPeer removes any BucketPeers row whose NetAddr
// matches hp. Called when nonce-echo proves hp is actually ourselves
// so a prior-run persistence doesn't keep seeding self-dials on
// restart.
func (n *Node) forgetPersistedPeer(hp string) {
	if n.db == nil {
		return
	}
	na, ok := NetAddrFromHostPort(hp)
	if !ok {
		return
	}
	_ = n.db.Delete([]byte(storage.BucketPeers), addrKey(na))
}

// DialPersistedPeers attempts outbound connections to previously-saved
// peers, up to MaxOutbound total.
func (n *Node) DialPersistedPeers() {
	if n.db == nil {
		return
	}
	var targets []NetAddr
	_ = n.db.ForEach([]byte(storage.BucketPeers), func(k, v []byte) error {
		addr, err := decodePeerRecord(v)
		if err != nil || addr.IsZero() {
			return nil
		}
		targets = append(targets, addr)
		return nil
	})
	log.Debug("redialing persisted peers", "count", len(targets))
	for _, a := range targets {
		if n.outboundCount() >= MaxOutbound {
			return
		}
		dial := a.String()
		if n.isKnownSelfAddr(dial) {
			continue
		}
		n.mu.RLock()
		_, already := n.peers[dial]
		n.mu.RUnlock()
		if already {
			continue
		}
		s := dial
		n.spawn(func() {
			if err := n.Connect(s); err != nil {
				log.Debug("redial failed", "addr", s, "err", err)
			}
		})
	}
}

// PeerCount returns connected peer count.
func (n *Node) PeerCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return len(n.peers)
}

// PeerInfo is a lightweight snapshot of connected peers used by the
// RPC layer to shape getpeerinfo output.
type PeerInfo struct {
	Addr      string
	Height    uint32
	Inbound   bool
	Handshake bool
	LastSeen  time.Time
}

// Peers returns a snapshot of currently connected peers.
func (n *Node) Peers() []PeerInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]PeerInfo, 0, len(n.peers))
	for _, p := range n.peers {
		p.mu.Lock()
		last := p.LastSeen
		inbound := p.dir == "inbound"
		hs := p.versionRecv && p.verackRecv
		p.mu.Unlock()
		out = append(out, PeerInfo{
			Addr:      p.Key(),
			Height:    p.Height(),
			Inbound:   inbound,
			Handshake: hs,
			LastSeen:  last,
		})
	}
	return out
}
