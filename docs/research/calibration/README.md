# `pqbc-cal` — difficulty calibration

A small standalone Go program that:

1. Benchmarks SHA-256d hashrate on the local host using the actual `core.BlockHeader.Hash()` path (so any micro-optimization in our serializer is reflected).
2. Computes the `Bits` value that would yield a chosen target mean block time at that hashrate.
3. Sanity-checks the proposed `Bits` by predicting block-time at the host's measured rate.

It's a separate Go module (`go.mod`) that imports `qbitcoin/core` from the parent repo. Run it from the repo root with `go run ./docs/research/calibration` (or `cd docs/research/calibration && go run .`), or copy it back to `/tmp` if you'd rather keep it out of the build path.

---

## Files

| File | What it does |
|---|---|
| `main.go` | Multi-threaded benchmark + `Bits` derivation. The active entrypoint. |
| `calc.go` | `//go:build ignore` — pure-formula sanity calculator at a hardcoded 10 MH/s. Run with `go run -tags whatever calc.go`. Useful when you want a `Bits` value without spinning up the host benchmark. |
| `check.go` | `//go:build ignore` — given a `Bits` value, prints the canonical-form `Bits` and predicted mean block time at three reference hashrates (10 / 40 / 87 MH/s). |
| `verify.go` | `//go:build ignore` — prints the genesis block's display hash, header fields, and PoW validity. Use after any change to genesis to verify the precomputed nonce still satisfies `CheckProof`. |

The `//go:build ignore` files are standalone scripts; `main.go` is the only one in the default build.

---

## Typical session

```sh
$ cd docs/research/calibration
$ go run .
threads:      16
hashes:       347823104 in 5s
hashrate:     69564620.80 H/s  (69.56 MH/s)
target block: 600s
target (hex): 000000000000003be...
bits:         0x180003be
predicted mean block time at these bits: 600.0s
```

If your host is slower than the current `core.GenesisBits`, the program clamps to `powLimit` and warns:

```
bits: 0x1e00ffff  (clamped to powLimit — your machine is slower than the current GenesisBits — keep GenesisBits as-is)
```

This is the right behavior for a research PoC: never lower difficulty below the constant in the source.

---

## Why this is a separate module

The benchmark exists to *change* `core.GenesisBits` when a new test network is being set up. Putting it in the main module would tie its build to the chain it's calibrating. The separate `go.mod` lets you point the import at any commit (including a working tree) without polluting the main module's dependency graph.
