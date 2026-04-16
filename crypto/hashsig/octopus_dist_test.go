package hashsig

import (
	"math/rand/v2"
	"sort"
	"testing"
)

// Sanity: for balanced t=2^20, K=8, Octopus should typically yield ~80 auth
// nodes (roughly K·(h - log2 K) = 8·17 with merges). Fewer than ~120 should
// be the rule; if our generalized Octopus is broken, sizes will balloon.
func TestOctopusSizeDistributionCompactParams(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	h := 20
	trials := 200
	var over105, over118, over200 int
	for range trials {
		seen := map[uint32]struct{}{}
		for len(seen) < 8 {
			seen[uint32(rand.Uint32()&((1<<20)-1))] = struct{}{}
		}
		idx := make([]uint32, 0, 8)
		for k := range seen {
			idx = append(idx, k)
		}
		sort.Slice(idx, func(i, j int) bool { return idx[i] < idx[j] })
		got := len(Octopus(idx, h))
		if got > 105 {
			over105++
		}
		if got > 118 {
			over118++
		}
		if got > 200 {
			over200++
		}
	}
	t.Logf("Octopus sizes over %d trials: >105=%d, >118=%d, >200=%d", trials, over105, over118, over200)
}
