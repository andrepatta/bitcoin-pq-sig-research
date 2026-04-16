package p2p

// DefaultBootnodes is the hardcoded list of host:port endpoints the
// node dials at startup when no override is supplied via --bootnodes.
//
// Entries are plain TCP dial strings (host can be IPv4, IPv6, or a
// DNS name; the :port suffix is mandatory). No peer identity suffix
// because we no longer authenticate the remote peer at the transport
// layer — anyone reachable at ip:port and speaking the qbitcoin wire
// protocol is considered a peer.
var DefaultBootnodes = []string{
	"72.61.186.233:8333",
}
