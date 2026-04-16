#!/usr/bin/env sage
# Emits a JSON KAT fixture with paper-blessed sizes and security bits
# for the SPHINCS+ parameter sets pqbc uses (compact + fallback, both
# matching pqbc-params.md §4). The Go test loads this and cross-checks
# that our SigSize()/Validate() code agrees with the authors' oracle.

import os, json
os.chdir("/tmp/SPHINCS-Parameters")
load("/tmp/SPHINCS-Parameters/security.sage")
src = open("/tmp/SPHINCS-Parameters/costs.sage").read().replace(
    'load(os.path.join(_dir, "security.sage"))', 'pass'
)
exec(compile(src, "costs.sage", "exec"), globals())

def fixture(name, scheme, qs, h, d, a, k, w, swn):
    l = compute_wots_l(scheme, w)
    t = int(k * (1 << a))
    sec = compute_security(2**qs, h, k, a, "PORS+FP")
    sign = compute_signing_time(h, d, a, k, w, swn, scheme)
    size = compute_size(h, d, a, k, w, scheme, sign['mmax'])
    verify = compute_verification_time(h, d, a, k, w, swn, scheme, sign['mmax'])
    return {
        "name": str(name),
        "scheme": str(scheme),
        "q_s_log2": int(qs),
        "h": int(h), "d": int(d), "a": int(a), "k": int(k), "w": int(w), "swn": int(swn),
        "l": int(l),
        "t": int(t),
        "mmax": int(sign['mmax']),
        "sig_size_bytes": int(size),
        "security_bits": float(sec),
        "sign_compressions": int(sign['compressions']),
        "verify_compressions": int(verify['compressions']),
    }

fixtures = {
    "generated_by": "sage dump_katfixtures.sage (BlockstreamResearch/SPHINCS-Parameters)",
    "n_bytes": int(16),
    "parameter_sets": [
        fixture("shrimps_compact", "W+C_P+FP", 10, 12, 1, 17, 8, 16, 240),
        fixture("shrimps_fallback", "W+C_P+FP", 40, 40, 5, 14, 11, 256, 2040),
    ],
}
out = "/home/andrepatta/personal/poc-blockchain/crypto/hashsig/testdata/paper_kat.json"
with open(out, "w") as f:
    json.dump(fixtures, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"wrote {out}")
print(json.dumps(fixtures, indent=2, sort_keys=True))
