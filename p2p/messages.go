package p2p

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"

	"qbitcoin/core"
	"qbitcoin/crypto"
	"qbitcoin/txn"
)

// Magic is the 4-byte network identifier every qbitcoin wire message
// begins with — analogous to Bitcoin's pchMessageStart (0xD9B4BEF9 for
// mainnet). Picked distinct from every Bitcoin-family magic so a
// misconfigured Bitcoin node dialing us (or vice-versa) fails fast on
// the magic check instead of going down a cross-protocol parse path.
//
//	bytes: 0x51 0x42 0x43 0x54  ("QBCT")
const Magic uint32 = 0x51424354

// MessageHeaderSize is the fixed on-wire prefix every frame carries.
// Matches Bitcoin Core's CMessageHeader layout exactly.
const MessageHeaderSize = 24

// Application-level command names. Bitcoin Core ships these as
// null-padded 12-byte ASCII in the header; we preserve every name our
// set shares with Bitcoin (version, verack, getblocks, inv, getdata,
// block, tx, ping, pong, addr, reject) and reuse the BIP-152 names
// (cmpctblock, getblocktxn, blocktxn) verbatim. Any extension must fit
// in 12 bytes.
const (
	CmdVersion     = "version"
	CmdVerAck      = "verack"
	CmdGetBlocks   = "getblocks"
	CmdInv         = "inv"
	CmdGetData     = "getdata"
	CmdBlock       = "block"
	CmdTx          = "tx"
	CmdPing        = "ping"
	CmdPong        = "pong"
	CmdAddr        = "addr"
	CmdReject      = "reject"
	CmdCmpctBlock  = "cmpctblock"
	CmdGetBlockTxn = "getblocktxn"
	CmdBlockTxn    = "blocktxn"
)

// ShortIDLen is the truncated short-ID length in bytes (matches BIP-152).
const ShortIDLen = 6

// MaxInvItems caps a single MsgInv/MsgGetData payload. Same numeric
// value as Bitcoin Core's MAX_INV_SZ. Bounds the DecodeInv slice
// allocation before any item parsing.
const MaxInvItems = 50_000

// MaxLocatorHashes caps a getblocks locator. Bitcoin's historical
// MAX_LOCATOR_SZ = 500 (the BIP-37 era cap); tighter modern Core uses
// 101 but we give a little headroom for deep-reorg locators.
const MaxLocatorHashes = 500

// ComputeShortID returns the 6-byte BIP-152 short ID for `txid`. Key
// derivation: SHA256(headerBytes || nonce_le)[0:16] → (k0, k1) as two
// LE uint64s. Short ID = lower 48 bits (LE) of SipHash-2-4(k0, k1, txid).
// Per-block key prevents cross-block short-ID collision precomputation.
func ComputeShortID(headerBytes []byte, nonce uint64, txid [32]byte) [ShortIDLen]byte {
	k0, k1 := crypto.SipHashKeyFromBlock(headerBytes, nonce)
	h := crypto.SipHash24(k0, k1, txid[:])
	var out [ShortIDLen]byte
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], h)
	copy(out[:], buf[:ShortIDLen])
	return out
}

// Inv item types.
const (
	InvTx    = 0x01
	InvBlock = 0x02
)

// InvItem is a single inv/getdata entry.
type InvItem struct {
	Type uint8
	Hash [32]byte
}

// Message is a decoded wire message.
type Message struct {
	Command string
	Payload []byte
}

// MaxFramePayload caps a single message body. 32 MiB comfortably fits
// any block we'd propagate and matches the order of Bitcoin's
// MAX_PROTOCOL_MESSAGE_LENGTH.
const MaxFramePayload = 32 * 1024 * 1024

// writeCommand copies cmd into a 12-byte null-padded buffer. Commands
// longer than 12 bytes are a programmer error; we truncate and let the
// peer's magic+checksum check catch the garbage.
func writeCommand(dst []byte, cmd string) {
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, cmd)
}

// readCommand extracts a null-trimmed ASCII command from a 12-byte
// header field.
func readCommand(src []byte) string {
	end := 0
	for end < len(src) && src[end] != 0 {
		end++
	}
	return string(src[:end])
}

// WriteFrame writes one full Bitcoin-style message:
//
//	[4 B magic][12 B command][4 B LE length][4 B checksum][payload]
//
// Checksum = SHA256d(payload)[0:4]. Zero-length payload still gets a
// (deterministic) checksum computed over empty bytes — matches Core.
func WriteFrame(w io.Writer, cmd string, payload []byte) error {
	var hdr [MessageHeaderSize]byte
	binary.LittleEndian.PutUint32(hdr[0:4], Magic)
	writeCommand(hdr[4:16], cmd)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(payload)))
	sum := crypto.Hash256(payload)
	copy(hdr[20:24], sum[:4])
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ReadFrame reads one framed message from r. Validates magic and
// checksum; rejects oversize payloads. A magic mismatch is fatal to the
// stream — the remote isn't speaking our protocol.
func ReadFrame(r io.Reader) (Message, error) {
	var hdr [MessageHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Message{}, err
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != Magic {
		return Message{}, errors.New("p2p: bad magic")
	}
	cmd := readCommand(hdr[4:16])
	n := binary.LittleEndian.Uint32(hdr[16:20])
	if n > MaxFramePayload {
		return Message{}, errors.New("p2p: frame too big")
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Message{}, err
		}
	}
	sum := crypto.Hash256(payload)
	if !bytesEq(hdr[20:24], sum[:4]) {
		return Message{}, errors.New("p2p: bad checksum")
	}
	return Message{Command: cmd, Payload: payload}, nil
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- payload encoders/decoders ---

// NetAddr is a network-address entry used in version's addr_from field
// and in addr-gossip entries. 16-byte IPv6 (IPv4-mapped) + 2-byte BE
// port — mirrors Bitcoin's CService/CAddress layout (minus timestamp
// and services bitmap, which we don't expose).
type NetAddr struct {
	IP   [16]byte
	Port uint16
}

// encodeNetAddr emits the 18-byte wire form.
func encodeNetAddr(dst []byte, a NetAddr) {
	copy(dst[0:16], a.IP[:])
	binary.BigEndian.PutUint16(dst[16:18], a.Port)
}

// decodeNetAddr reads the 18-byte wire form.
func decodeNetAddr(src []byte) NetAddr {
	var a NetAddr
	copy(a.IP[:], src[0:16])
	a.Port = binary.BigEndian.Uint16(src[16:18])
	return a
}

// NetAddrFromHostPort canonicalizes a host:port string into a NetAddr.
// Returns ok=false if host cannot be resolved to an IP literal; we do
// not perform DNS lookups here (callers that hand us DNS names must
// resolve first).
func NetAddrFromHostPort(hp string) (NetAddr, bool) {
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return NetAddr{}, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return NetAddr{}, false
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return NetAddr{}, false
	}
	var out NetAddr
	ip16 := ip.To16()
	copy(out.IP[:], ip16)
	out.Port = uint16(p)
	return out, true
}

// String returns the canonical host:port form. IPv4-mapped addresses
// render as plain IPv4.
func (a NetAddr) String() string {
	ip := net.IP(a.IP[:])
	if v4 := ip.To4(); v4 != nil {
		return net.JoinHostPort(v4.String(), strconv.Itoa(int(a.Port)))
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(a.Port)))
}

// IPString returns just the IP portion (v4 normalized).
func (a NetAddr) IPString() string {
	ip := net.IP(a.IP[:])
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// IsZero reports an all-zero NetAddr, used as a "no addr_from" sentinel
// on the wire. Bitcoin uses an explicit 0-filled CService for the same
// purpose when a node has no listen address to advertise.
func (a NetAddr) IsZero() bool {
	for _, b := range a.IP {
		if b != 0 {
			return false
		}
	}
	return a.Port == 0
}

// EncodeVersion layout (subset of Bitcoin Core's `version`):
//
//	[4-byte version][4-byte height][18-byte addr_from][8-byte nonce][32-byte genesis]
//
// addr_from is the sender's self-reported listen address — inbound
// receivers have no other way to learn what host:port to dial the
// sender back on (the observed socket is the sender's ephemeral
// outbound port). A zero NetAddr means "no dialable listen addr".
//
// Nonce is a random u64 the sender picked for self-connection
// detection (Bitcoin Core's pchMessageStart-nonce trick). The receiver
// compares it against its own table of nonces sent in outbound
// versions; a match means we dialed ourselves and must disconnect.
//
// Genesis is the sender's block-0 hash. Two nodes with different
// genesis constants silently built incompatible chains; the receiver
// drops on mismatch so blocks don't orphan invisibly on the wire.
func EncodeVersion(version, height uint32, addrFrom NetAddr, nonce uint64, genesis [32]byte) []byte {
	b := make([]byte, 8+18+8+32)
	binary.BigEndian.PutUint32(b[0:4], version)
	binary.BigEndian.PutUint32(b[4:8], height)
	encodeNetAddr(b[8:26], addrFrom)
	binary.BigEndian.PutUint64(b[26:34], nonce)
	copy(b[34:66], genesis[:])
	return b
}

// DecodeVersion parses EncodeVersion output.
func DecodeVersion(b []byte) (version, height uint32, addrFrom NetAddr, nonce uint64, genesis [32]byte, err error) {
	if len(b) < 66 {
		return 0, 0, NetAddr{}, 0, [32]byte{}, errors.New("version: truncated")
	}
	version = binary.BigEndian.Uint32(b[0:4])
	height = binary.BigEndian.Uint32(b[4:8])
	addrFrom = decodeNetAddr(b[8:26])
	nonce = binary.BigEndian.Uint64(b[26:34])
	copy(genesis[:], b[34:66])
	return version, height, addrFrom, nonce, genesis, nil
}

// EncodeInv: [4-byte count] then count * (1-byte type || 32-byte hash)
func EncodeInv(items []InvItem) []byte {
	b := make([]byte, 4+33*len(items))
	binary.BigEndian.PutUint32(b[0:4], uint32(len(items)))
	off := 4
	for _, it := range items {
		b[off] = it.Type
		copy(b[off+1:off+33], it.Hash[:])
		off += 33
	}
	return b
}

// DecodeInv parses EncodeInv output. The size check uses uint64
// arithmetic so an attacker-controlled `n` cannot wrap uint32 and
// force an oversized allocation under the length gate.
func DecodeInv(b []byte) ([]InvItem, error) {
	if len(b) < 4 {
		return nil, errors.New("inv: truncated")
	}
	n := binary.BigEndian.Uint32(b[0:4])
	if n > MaxInvItems {
		return nil, errors.New("inv: count exceeds cap")
	}
	if uint64(len(b)) < 4+33*uint64(n) {
		return nil, errors.New("inv: truncated items")
	}
	out := make([]InvItem, n)
	off := 4
	for i := uint32(0); i < n; i++ {
		out[i].Type = b[off]
		copy(out[i].Hash[:], b[off+1:off+33])
		off += 33
	}
	return out, nil
}

// EncodeGetBlocks: [4-byte count] then count * 32-byte locator hashes.
func EncodeGetBlocks(locator [][32]byte) []byte {
	b := make([]byte, 4+32*len(locator))
	binary.BigEndian.PutUint32(b[0:4], uint32(len(locator)))
	off := 4
	for _, h := range locator {
		copy(b[off:off+32], h[:])
		off += 32
	}
	return b
}

// DecodeGetBlocks parses EncodeGetBlocks output. Size math uses
// uint64 to defeat uint32 overflow of `32*n`.
func DecodeGetBlocks(b []byte) ([][32]byte, error) {
	if len(b) < 4 {
		return nil, errors.New("getblocks: truncated")
	}
	n := binary.BigEndian.Uint32(b[0:4])
	if n > MaxLocatorHashes {
		return nil, errors.New("getblocks: count exceeds cap")
	}
	if uint64(len(b)) < 4+32*uint64(n) {
		return nil, errors.New("getblocks: truncated items")
	}
	out := make([][32]byte, n)
	off := 4
	for i := uint32(0); i < n; i++ {
		copy(out[i][:], b[off:off+32])
		off += 32
	}
	return out, nil
}

// AddrEntry is one peer (timestamp + network address) gossiped via
// MsgAddr. Timestamp is unix seconds; Bitcoin Core uses it to rank
// peer freshness inside AddrMan.
type AddrEntry struct {
	Timestamp int64 // unix seconds
	Addr      NetAddr
}

// MaxAddrEntries caps a single gossip message. Matches Bitcoin's
// MAX_ADDR_TO_SEND.
const MaxAddrEntries = 1000

// EncodeAddr: [4-byte count] then count * (8-byte LE timestamp + 18-byte netaddr).
func EncodeAddr(entries []AddrEntry) []byte {
	out := make([]byte, 4+26*len(entries))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(entries)))
	off := 4
	for _, e := range entries {
		binary.LittleEndian.PutUint64(out[off:off+8], uint64(e.Timestamp))
		off += 8
		encodeNetAddr(out[off:off+18], e.Addr)
		off += 18
	}
	return out
}

// DecodeAddr parses EncodeAddr output.
func DecodeAddr(b []byte) ([]AddrEntry, error) {
	if len(b) < 4 {
		return nil, errors.New("addr: truncated")
	}
	n := binary.BigEndian.Uint32(b[0:4])
	if n > MaxAddrEntries {
		return nil, errors.New("addr: count exceeds cap")
	}
	if uint64(len(b)) < 4+26*uint64(n) {
		return nil, errors.New("addr: truncated items")
	}
	out := make([]AddrEntry, n)
	off := 4
	for i := uint32(0); i < n; i++ {
		out[i].Timestamp = int64(binary.LittleEndian.Uint64(b[off : off+8]))
		off += 8
		out[i].Addr = decodeNetAddr(b[off : off+18])
		off += 18
	}
	return out, nil
}

// CmpctBlock is the BIP-152-style compact representation of a block.
type CmpctBlock struct {
	Header    core.BlockHeader
	Nonce     uint64
	ShortIDs  [][ShortIDLen]byte // one per non-prefilled tx, in block order
	Prefilled []PrefilledTx      // coinbase always prefilled at index 0
}

// PrefilledTx is a (block-position, full tx) pair shipped inside a
// CmpctBlock. Always includes the coinbase; senders may include more
// at their discretion (we just include the coinbase).
type PrefilledTx struct {
	Index uint32
	Tx    txn.Transaction
}

// EncodeCmpctBlock layout:
//
//	[88-byte header]
//	[8-byte nonce]
//	[4-byte short_id_count] + count * [6-byte short_id]
//	[4-byte prefilled_count] + count * ([4-byte index][4-byte tx_len][tx_bytes])
func EncodeCmpctBlock(c CmpctBlock) []byte {
	out := make([]byte, 0, core.HeaderSize+8+4+ShortIDLen*len(c.ShortIDs)+4+len(c.Prefilled)*256)
	out = append(out, c.Header.Serialize()...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], c.Nonce)
	out = append(out, b8[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(c.ShortIDs)))
	out = append(out, b4[:]...)
	for i := range c.ShortIDs {
		out = append(out, c.ShortIDs[i][:]...)
	}
	binary.BigEndian.PutUint32(b4[:], uint32(len(c.Prefilled)))
	out = append(out, b4[:]...)
	for _, p := range c.Prefilled {
		binary.BigEndian.PutUint32(b4[:], p.Index)
		out = append(out, b4[:]...)
		tb := p.Tx.Serialize()
		binary.BigEndian.PutUint32(b4[:], uint32(len(tb)))
		out = append(out, b4[:]...)
		out = append(out, tb...)
	}
	return out
}

// DecodeCmpctBlock parses EncodeCmpctBlock output.
func DecodeCmpctBlock(b []byte) (*CmpctBlock, error) {
	if len(b) < core.HeaderSize+8+4+4 {
		return nil, errors.New("cmpctblock: truncated")
	}
	h, err := core.DeserializeHeader(b[:core.HeaderSize])
	if err != nil {
		return nil, err
	}
	off := core.HeaderSize
	nonce := binary.BigEndian.Uint64(b[off : off+8])
	off += 8
	sn := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if sn > core.MaxBlockTxCount {
		return nil, errors.New("cmpctblock: short-id count exceeds cap")
	}
	if off+int(sn)*ShortIDLen > len(b) {
		return nil, errors.New("cmpctblock: short-id list truncated")
	}
	ids := make([][ShortIDLen]byte, sn)
	for i := uint32(0); i < sn; i++ {
		copy(ids[i][:], b[off:off+ShortIDLen])
		off += ShortIDLen
	}
	if off+4 > len(b) {
		return nil, errors.New("cmpctblock: prefilled count truncated")
	}
	pn := binary.BigEndian.Uint32(b[off : off+4])
	off += 4
	if pn > core.MaxBlockTxCount {
		return nil, errors.New("cmpctblock: prefilled count exceeds cap")
	}
	pre := make([]PrefilledTx, pn)
	for i := uint32(0); i < pn; i++ {
		if off+8 > len(b) {
			return nil, errors.New("cmpctblock: prefilled hdr truncated")
		}
		idx := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		tl := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if tl > core.MaxBlockSize || off+int(tl) > len(b) {
			return nil, errors.New("cmpctblock: prefilled tx truncated")
		}
		tx, _, err := txn.DeserializeTx(b[off : off+int(tl)])
		if err != nil {
			return nil, err
		}
		pre[i] = PrefilledTx{Index: idx, Tx: *tx}
		off += int(tl)
	}
	return &CmpctBlock{Header: h, Nonce: nonce, ShortIDs: ids, Prefilled: pre}, nil
}

// EncodeGetBlockTxn: [32-byte header_hash][4-byte count][4-byte index]*N
func EncodeGetBlockTxn(headerHash [32]byte, indices []uint32) []byte {
	out := make([]byte, 0, 32+4+4*len(indices))
	out = append(out, headerHash[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(indices)))
	out = append(out, b4[:]...)
	for _, i := range indices {
		binary.BigEndian.PutUint32(b4[:], i)
		out = append(out, b4[:]...)
	}
	return out
}

// DecodeGetBlockTxn parses EncodeGetBlockTxn output.
func DecodeGetBlockTxn(b []byte) (headerHash [32]byte, indices []uint32, err error) {
	if len(b) < 36 {
		return headerHash, nil, errors.New("getblocktxn: truncated")
	}
	copy(headerHash[:], b[:32])
	n := binary.BigEndian.Uint32(b[32:36])
	if n > core.MaxBlockTxCount {
		return headerHash, nil, errors.New("getblocktxn: count exceeds cap")
	}
	if len(b) < int(36+4*n) {
		return headerHash, nil, errors.New("getblocktxn: indices truncated")
	}
	indices = make([]uint32, n)
	off := 36
	for i := uint32(0); i < n; i++ {
		indices[i] = binary.BigEndian.Uint32(b[off : off+4])
		off += 4
	}
	return headerHash, indices, nil
}

// EncodeBlockTxn: [32-byte header_hash][4-byte count] + count *
// ([4-byte index][4-byte tx_len][tx_bytes])
func EncodeBlockTxn(headerHash [32]byte, txs []PrefilledTx) []byte {
	out := make([]byte, 0, 36+len(txs)*256)
	out = append(out, headerHash[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], uint32(len(txs)))
	out = append(out, b4[:]...)
	for _, p := range txs {
		binary.BigEndian.PutUint32(b4[:], p.Index)
		out = append(out, b4[:]...)
		tb := p.Tx.Serialize()
		binary.BigEndian.PutUint32(b4[:], uint32(len(tb)))
		out = append(out, b4[:]...)
		out = append(out, tb...)
	}
	return out
}

// DecodeBlockTxn parses EncodeBlockTxn output.
func DecodeBlockTxn(b []byte) (headerHash [32]byte, txs []PrefilledTx, err error) {
	if len(b) < 36 {
		return headerHash, nil, errors.New("blocktxn: truncated")
	}
	copy(headerHash[:], b[:32])
	n := binary.BigEndian.Uint32(b[32:36])
	if n > core.MaxBlockTxCount {
		return headerHash, nil, errors.New("blocktxn: count exceeds cap")
	}
	off := 36
	txs = make([]PrefilledTx, 0, n)
	for i := uint32(0); i < n; i++ {
		if off+8 > len(b) {
			return headerHash, nil, errors.New("blocktxn: entry hdr truncated")
		}
		idx := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		tl := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		if tl > core.MaxBlockSize || off+int(tl) > len(b) {
			return headerHash, nil, errors.New("blocktxn: tx truncated")
		}
		tx, _, e := txn.DeserializeTx(b[off : off+int(tl)])
		if e != nil {
			return headerHash, nil, e
		}
		txs = append(txs, PrefilledTx{Index: idx, Tx: *tx})
		off += int(tl)
	}
	return headerHash, txs, nil
}

// EncodePing: 8-byte nonce.
func EncodePing(nonce uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, nonce)
	return b
}

// DecodePing parses EncodePing output.
func DecodePing(b []byte) (uint64, error) {
	if len(b) < 8 {
		return 0, errors.New("ping: truncated")
	}
	return binary.BigEndian.Uint64(b[:8]), nil
}
