#!/usr/bin/env sage
import os, sys
os.chdir("/tmp/SPHINCS-Parameters")
load("/tmp/SPHINCS-Parameters/security.sage")
src = open("/tmp/SPHINCS-Parameters/costs.sage").read().replace(
    'load(os.path.join(_dir, "security.sage"))', 'pass'
)
exec(compile(src, "costs.sage", "exec"), globals())
# Now call directly
compute_single("W+C_P+FP", 10, 12, 1, 17, 8, 16, 240)
