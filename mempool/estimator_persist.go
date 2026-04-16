package mempool

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

// estimatorMagic ("PQFE" = PQBC Fee Estimator) and version are written
// at the head of the persistence file so we can detect format drift.
// Bumps the version on any layout change.
const (
	estimatorMagic   = uint32(0x50514645) // "PQFE"
	estimatorVersion = uint32(1)
)

// Save writes the estimator state to w in a hand-rolled binary format.
// Counterpart to Load. Format:
//
//	[4 magic][4 version]
//	[4 bestSeenHeight][4 firstObserved]
//	[4 bucket_count] [bucket_count * 8 bytes float64] (shared bucket grid)
//	for each of {short, med, long} stats:
//	   [4 maxPeriods][4 scale][8 decay]
//	   confAvg/failAvg/txCtAvg/unconfTxs/oldUnconfTxs as below
//
// All multi-byte values big-endian.
func (e *BlockPolicyEstimator) Save(w io.Writer) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	wr := &errWriter{w: w}
	wr.u32(estimatorMagic)
	wr.u32(estimatorVersion)
	wr.u32(e.bestSeenHeight)
	wr.u32(e.firstObserved)
	wr.u32(uint32(len(e.buckets)))
	for _, b := range e.buckets {
		wr.f64(b)
	}
	for _, s := range []*txConfirmStats{e.shortStats, e.medStats, e.feeStats} {
		writeStats(wr, s)
	}
	return wr.err
}

// Load reads the estimator state previously written by Save. Returns
// an error on magic/version mismatch or truncation; on success,
// replaces the estimator's stats in place.
func (e *BlockPolicyEstimator) Load(r io.Reader) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	rd := &errReader{r: r}
	if m := rd.u32(); m != estimatorMagic {
		return errors.New("estimator: bad magic")
	}
	if v := rd.u32(); v != estimatorVersion {
		return errors.New("estimator: unsupported version")
	}
	e.bestSeenHeight = rd.u32()
	e.firstObserved = rd.u32()
	nb := int(rd.u32())
	if nb <= 0 || nb > 1024 {
		return errors.New("estimator: bad bucket count")
	}
	buckets := make([]float64, nb)
	for i := range buckets {
		buckets[i] = rd.f64()
	}
	if rd.err != nil {
		return rd.err
	}
	e.buckets = buckets
	e.bucketMap = append([]float64(nil), buckets...)

	short, err := readStats(rd, buckets)
	if err != nil {
		return err
	}
	med, err := readStats(rd, buckets)
	if err != nil {
		return err
	}
	long, err := readStats(rd, buckets)
	if err != nil {
		return err
	}
	e.shortStats = short
	e.medStats = med
	e.feeStats = long

	// trackedTxs is intentionally not persisted: those are mempool
	// entries which are themselves rebuilt at startup. The estimator
	// is rebuilt to match the live mempool after Load returns; until
	// then, ProcessBlock for un-tracked txs (the normal case for any
	// historical block we already saw) is silently skipped.
	e.trackedTxs = map[[32]byte]memPoolTrack{}

	// Clear live unconfirmed-tracking counters on load. They were
	// accurate at save time but refer to txs we no longer have in
	// trackedTxs (since that's not persisted). Leaving them populated
	// would over-count "extra fails" in queries. Historical
	// confAvg/failAvg/txCtAvg stay — they're the real decayed record.
	e.shortStats.clearLive()
	e.medStats.clearLive()
	e.feeStats.clearLive()
	return nil
}

func writeStats(w *errWriter, s *txConfirmStats) {
	w.u32(uint32(s.maxPeriods))
	w.u32(uint32(s.scale))
	w.f64(s.decay)
	w.u32(uint32(len(s.confAvg)))
	for i := range s.confAvg {
		w.u32(uint32(len(s.confAvg[i])))
		for _, v := range s.confAvg[i] {
			w.f64(v)
		}
	}
	w.u32(uint32(len(s.failAvg)))
	for i := range s.failAvg {
		w.u32(uint32(len(s.failAvg[i])))
		for _, v := range s.failAvg[i] {
			w.f64(v)
		}
	}
	w.u32(uint32(len(s.txCtAvg)))
	for _, v := range s.txCtAvg {
		w.f64(v)
	}
	w.u32(uint32(len(s.unconfTxs)))
	for i := range s.unconfTxs {
		w.u32(uint32(len(s.unconfTxs[i])))
		for _, v := range s.unconfTxs[i] {
			w.u32(uint32(v))
		}
	}
	w.u32(uint32(len(s.oldUnconfTxs)))
	for _, v := range s.oldUnconfTxs {
		w.u32(uint32(v))
	}
}

func readStats(r *errReader, buckets []float64) (*txConfirmStats, error) {
	maxPeriods := int(r.u32())
	scale := int(r.u32())
	decay := r.f64()
	if r.err != nil {
		return nil, r.err
	}
	if maxPeriods <= 0 || maxPeriods > 4096 || scale <= 0 || scale > 4096 {
		return nil, errors.New("estimator: bad stats geometry")
	}
	s := newTxConfirmStats(buckets, maxPeriods, decay, scale)

	if int(r.u32()) != len(s.confAvg) {
		return nil, errors.New("estimator: confAvg dim mismatch")
	}
	for i := range s.confAvg {
		if int(r.u32()) != len(s.confAvg[i]) {
			return nil, errors.New("estimator: confAvg row mismatch")
		}
		for j := range s.confAvg[i] {
			s.confAvg[i][j] = r.f64()
		}
	}
	if int(r.u32()) != len(s.failAvg) {
		return nil, errors.New("estimator: failAvg dim mismatch")
	}
	for i := range s.failAvg {
		if int(r.u32()) != len(s.failAvg[i]) {
			return nil, errors.New("estimator: failAvg row mismatch")
		}
		for j := range s.failAvg[i] {
			s.failAvg[i][j] = r.f64()
		}
	}
	if int(r.u32()) != len(s.txCtAvg) {
		return nil, errors.New("estimator: txCtAvg dim mismatch")
	}
	for j := range s.txCtAvg {
		s.txCtAvg[j] = r.f64()
	}
	if int(r.u32()) != len(s.unconfTxs) {
		return nil, errors.New("estimator: unconfTxs dim mismatch")
	}
	for i := range s.unconfTxs {
		if int(r.u32()) != len(s.unconfTxs[i]) {
			return nil, errors.New("estimator: unconfTxs row mismatch")
		}
		for j := range s.unconfTxs[i] {
			s.unconfTxs[i][j] = int(r.u32())
		}
	}
	if int(r.u32()) != len(s.oldUnconfTxs) {
		return nil, errors.New("estimator: oldUnconfTxs dim mismatch")
	}
	for j := range s.oldUnconfTxs {
		s.oldUnconfTxs[j] = int(r.u32())
	}
	return s, r.err
}

// errWriter / errReader keep the encode/decode functions terse by
// holding the first error and skipping subsequent operations.
type errWriter struct {
	w   io.Writer
	err error
}

func (w *errWriter) u32(v uint32) {
	if w.err != nil {
		return
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, w.err = w.w.Write(b[:])
}

func (w *errWriter) f64(v float64) {
	if w.err != nil {
		return
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], math.Float64bits(v))
	_, w.err = w.w.Write(b[:])
}

type errReader struct {
	r   io.Reader
	err error
}

func (r *errReader) u32() uint32 {
	if r.err != nil {
		return 0
	}
	var b [4]byte
	_, r.err = io.ReadFull(r.r, b[:])
	return binary.BigEndian.Uint32(b[:])
}

func (r *errReader) f64() float64 {
	if r.err != nil {
		return 0
	}
	var b [8]byte
	_, r.err = io.ReadFull(r.r, b[:])
	return math.Float64frombits(binary.BigEndian.Uint64(b[:]))
}
