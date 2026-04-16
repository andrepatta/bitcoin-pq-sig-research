package core

import (
	"math/big"
	"testing"
)

// TestDAA_Inherit: on non-retarget heights, bits pass through unchanged.
func TestDAA_Inherit(t *testing.T) {
	for _, nextH := range []uint64{1, 2, 100, RetargetInterval - 1, RetargetInterval + 1, 2*RetargetInterval - 1} {
		got := ComputeNextWorkRequired(nextH, GenesisBits, GenesisTimestamp+1000, 0)
		if got != GenesisBits {
			t.Errorf("nextHeight=%d: got bits=%08x, want inherited %08x", nextH, got, GenesisBits)
		}
	}
}

// TestDAA_OnSchedule: when the closing window ran exactly on schedule,
// new target ≈ old target * (2015/2016) — effectively unchanged after
// compact-bits quantization (round-trip through BigToBits).
func TestDAA_OnSchedule(t *testing.T) {
	// Ideal window spans 2015 intervals of 600s between pindexFirst and pindexLast.
	first := GenesisTimestamp
	last := first + uint64((RetargetInterval-1)*TargetBlockTimeSec)
	got := ComputeNextWorkRequired(RetargetInterval, GenesisBits, last, first)

	oldT := TargetToBig(BitsToTarget(GenesisBits))
	gotT := TargetToBig(BitsToTarget(got))

	// 2015/2016 ≈ 0.9995; tolerance 0.1% of old target.
	tol := new(big.Int).Div(oldT, big.NewInt(1000))
	diff := new(big.Int).Sub(oldT, gotT)
	diff.Abs(diff)
	if diff.Cmp(tol) > 0 {
		t.Errorf("on-schedule: got=%x want≈%x (diff=%x tol=%x)", gotT, oldT, diff, tol)
	}
}

// TestDAA_UpperClamp: window took more than 4× target; timespan is clamped,
// so new target = oldTarget * 4 (then clamped to powLimit if it exceeds).
func TestDAA_UpperClamp(t *testing.T) {
	first := uint64(1_000_000)
	// Pretend the window took 100× the ideal — clamp should cap the multiplier at 4.
	last := first + 100*uint64(TargetTimespanSec)

	// Use a tightened parent to avoid the powLimit clamp dominating.
	parentBits := uint32(0x1b00ffff) // Bitcoin mainnet-style pow limit shape
	got := ComputeNextWorkRequired(RetargetInterval, parentBits, last, first)

	oldT := TargetToBig(BitsToTarget(parentBits))
	want := new(big.Int).Mul(oldT, big.NewInt(4))
	powLimit := TargetToBig(BitsToTarget(GenesisBits))
	if want.Cmp(powLimit) > 0 {
		want = powLimit
	}
	gotT := TargetToBig(BitsToTarget(got))

	tol := new(big.Int).Div(want, big.NewInt(1000))
	diff := new(big.Int).Sub(gotT, want)
	diff.Abs(diff)
	if diff.Cmp(tol) > 0 {
		t.Errorf("upper clamp: got=%x want=%x (diff=%x tol=%x)", gotT, want, diff, tol)
	}
}

// TestDAA_LowerClamp: window closed in less than 1/4 target; timespan is
// clamped, so new target = oldTarget / 4.
func TestDAA_LowerClamp(t *testing.T) {
	first := uint64(1_000_000)
	last := first + 1 // absurdly fast

	parentBits := uint32(0x1b00ffff)
	got := ComputeNextWorkRequired(RetargetInterval, parentBits, last, first)

	oldT := TargetToBig(BitsToTarget(parentBits))
	want := new(big.Int).Rsh(oldT, 2) // /4
	gotT := TargetToBig(BitsToTarget(got))

	tol := new(big.Int).Div(want, big.NewInt(1000))
	diff := new(big.Int).Sub(gotT, want)
	diff.Abs(diff)
	if diff.Cmp(tol) > 0 {
		t.Errorf("lower clamp: got=%x want=%x (diff=%x tol=%x)", gotT, want, diff, tol)
	}
}

// TestDAA_PowLimitClamp: even if the math says the target should grow past
// the pow limit, the result is capped at GenesisBits' target.
func TestDAA_PowLimitClamp(t *testing.T) {
	first := uint64(1_000_000)
	last := first + 10*uint64(TargetTimespanSec)
	got := ComputeNextWorkRequired(RetargetInterval, GenesisBits, last, first)

	powLimit := TargetToBig(BitsToTarget(GenesisBits))
	gotT := TargetToBig(BitsToTarget(got))
	if gotT.Cmp(powLimit) > 0 {
		t.Errorf("pow limit clamp: target=%x exceeds powLimit=%x", gotT, powLimit)
	}
}
