#!/usr/bin/env sage
import os, sys
os.chdir("/tmp/SPHINCS-Parameters")
load("/tmp/SPHINCS-Parameters/security.sage")
src = open("/tmp/SPHINCS-Parameters/costs.sage").read().replace(
    'load(os.path.join(_dir, "security.sage"))', 'pass'
)
exec(compile(src, "costs.sage", "exec"), globals())
# Paper's BOLD recommended q_s=2^40 W+C P+FP row: h=40, d=5, a=14, k=11, w=256, S=2040
compute_single("W+C_P+FP", 40, 40, 5, 14, 11, 256, 2040)
print("---")
# Alternate non-bold row from paper table: h=44, d=4, a=16, k=8
compute_single("W+C_P+FP", 40, 44, 4, 16, 8, 16, 240)
