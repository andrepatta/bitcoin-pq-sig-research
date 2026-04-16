import os
os.chdir("/tmp/SPHINCS-Parameters")
load("/tmp/SPHINCS-Parameters/security.sage")
src = open("/tmp/SPHINCS-Parameters/costs.sage").read().replace(
    'load(os.path.join(_dir, "security.sage"))', 'pass'
)
exec(compile(src, "costs.sage", "exec"), globals())

# Compact: t=2^20, k=8, mmax=105
print("COMPACT (t=2^20, k=8, mmax=105):")
print(f"  log2(exp_work) = {log2_exp_work_from_mmax(1<<20, 8, 105):.2f}")
print(f"  exp_work = {exp_work_from_mmax(1<<20, 8, 105):.0f}")
# Fallback: t=11*2^14, k=11, mmax=118
print("FALLBACK (t=11*2^14=180224, k=11, mmax=118):")
print(f"  log2(exp_work) = {log2_exp_work_from_mmax(11*(1<<14), 11, 118):.2f}")
print(f"  exp_work = {exp_work_from_mmax(11*(1<<14), 11, 118):.0f}")
