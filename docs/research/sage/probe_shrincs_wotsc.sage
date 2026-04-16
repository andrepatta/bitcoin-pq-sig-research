#!/usr/bin/env sage
import os
os.chdir("/tmp/SPHINCS-Parameters")
load("/tmp/SPHINCS-Parameters/security.sage")
src = open("/tmp/SPHINCS-Parameters/costs.sage").read().replace(
    'load(os.path.join(_dir, "security.sage"))', 'pass'
)
exec(compile(src, "costs.sage", "exec"), globals())

# SHRINCS WOTS+C at (n=16, w=16, l=18, z=14): 18-chain WOTS+C with last 14 digits dropped.
# Find S such that 1/p_nu = 16^18 / nu is tolerable with a small counter.
# w=16, l=18 -> w^l = 16^18 = 2^72. With 32-bit counter, need nu >= 2^40.
# Sweep S from 0 to l*(w-1)=270.

l = 18
w = 16
wl = w**l  # 16^18

print(f"l={l} w={w} w^l=2^{float(log(wl,2)):.1f}")
print()
print(f"{'S':>4} {'nu':>20} {'log2(1/p_nu)':>14} {'counter_bits':>14}")
print("-"*60)

best = None
for S in range(0, l*(w-1)+1, 5):
    nu = compute_nu(l, S, w)
    if nu <= 0:
        continue
    log2_inv_p = float(log(wl,2)) - float(log(nu,2))
    marker = ""
    if best is None or abs(log2_inv_p - 32) < abs(best[1] - 32):
        best = (S, log2_inv_p, nu)
    print(f"{S:>4} {int(nu):>20} {log2_inv_p:>14.2f} {log2_inv_p:>14.2f}")

print()
print(f"Best S near 32-bit counter target: S={best[0]}, log2(1/p_nu)={best[1]:.2f}, nu={int(best[2])}")

# Fine sweep around best
print()
print("Fine sweep near best:")
for S in range(max(0, best[0]-10), min(l*(w-1), best[0]+10)+1):
    nu = compute_nu(l, S, w)
    if nu <= 0:
        continue
    log2_inv_p = float(log(wl,2)) - float(log(nu,2))
    print(f"  S={S:>3} nu={int(nu):>22} log2(1/p_nu)={log2_inv_p:.2f}")
