package hashsig

import (
	"runtime"
	"sync"
)

// parallelFill runs `work(i)` for i in [0, n) across up to NumCPU
// goroutines, writing each result independently. Useful for the leaf
// generation loops in XMSS/hypertree and PORS+FP tree construction —
// every iteration depends only on its index. Falls through to a plain
// loop when n is tiny so the goroutine overhead never dominates.
//
// The Params, skSeed, and base ADRS used inside `work` are all read-only
// from the worker perspective (ADRS is value-typed; Params.PKSeed is not
// mutated; each hash call creates a fresh hasher), so no synchronization
// is required beyond what the caller's closure wraps.
func parallelFill(n int, work func(i int)) {
	if n <= 0 {
		return
	}
	workers := runtime.NumCPU()
	if workers < 2 || n < 64 {
		for i := 0; i < n; i++ {
			work(i)
		}
		return
	}
	if workers > n {
		workers = n
	}
	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * chunk
		end := start + chunk
		if end > n {
			end = n
		}
		if start >= end {
			break
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				work(i)
			}
		}(start, end)
	}
	wg.Wait()
}
