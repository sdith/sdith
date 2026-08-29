"""
Deterministic KAT generation for the SDitH round 3 Python reference.

The vectors are written into the repo-root kat_r3/ that the C reference also
uses (mini_kat and the C-vs-python differential read the same folder), so the
two references stay pinned to the same bytes.

Vectors follow the NIST PQCgenKAT_sign convention:
  * an outer AES-256-CTR DRBG seeded with entropy_input = bytes(range(48))
    produces, for each test i, a 48-byte per-test seed and a message of
    length mlen = 33*(i+1);
  * a per-test DRBG(seed) then supplies the key-generation entropy (2*lambda)
    followed by the signing entropy (2*lambda).
Output: <repo-root>/kat_r3/<DIR>/PQCsignKAT_<sk_bytes>.rsp (fields count/seed/
mlen/msg/pk/sk/smlen/sm), matching the layout test_kat.py reads.

Usage:
  python gen_kat.py [param_set] [num_vectors]
    param_set:   cat1-short (default), ..., cat5-fast, or 'all'
    num_vectors: how many vectors to emit (default: 3; pure-Python cat5 signing
                 is slow, so keep this small)
"""

import os
import sys
import time
from multiprocessing import Pool

from params import ALL_PARAMS
from nist_drbg import NistDRBG
from sdith import keygen, sign

# The KAT vectors live in the repo-root kat_r3/ shared with the C reference
# (python/round3 -> repo root is two levels up), not a python-local copy.
_HERE = os.path.dirname(os.path.abspath(__file__))
KAT_DIR = os.path.normpath(os.path.join(_HERE, '..', '..', 'kat_r3'))

# Per-set output subdir (the PQCsignKAT_<sk>.rsp file name uses sk_bytes).
KAT_SUBDIRS = {
    'cat1-short': 'SDITH_CAT1_SHORT', 'cat1-fast': 'SDITH_CAT1_FAST',
    'cat3-short': 'SDITH_CAT3_SHORT', 'cat3-fast': 'SDITH_CAT3_FAST',
    'cat5-short': 'SDITH_CAT5_SHORT', 'cat5-fast': 'SDITH_CAT5_FAST',
    'cat1-short-cipherpow': 'SDITH_CAT1_SHORT_CIPHERPOW',
    'cat1-fast-cipherpow': 'SDITH_CAT1_FAST_CIPHERPOW',
    'cat3-short-cipherpow': 'SDITH_CAT3_SHORT_CIPHERPOW',
    'cat3-fast-cipherpow': 'SDITH_CAT3_FAST_CIPHERPOW',
    'cat5-short-cipherpow': 'SDITH_CAT5_SHORT_CIPHERPOW',
    'cat5-fast-cipherpow': 'SDITH_CAT5_FAST_CIPHERPOW',
}

DEFAULT_VECTORS = 3


def _requests(num_vectors):
    """NIST outer-DRBG pass: (seed, msg) per test, from entropy 0..47."""
    outer = NistDRBG(bytes(range(48)))
    requests = []
    for i in range(num_vectors):
        seed = outer.randombytes(48)
        mlen = 33 * (i + 1)
        msg = outer.randombytes(mlen)
        requests.append((seed, mlen, msg))
    return requests


def generate(param_name, num_vectors=DEFAULT_VECTORS):
    """Generate and write the KAT file for one parameter set."""
    params = ALL_PARAMS[param_name]
    out_dir = os.path.join(KAT_DIR, KAT_SUBDIRS[param_name])
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f'PQCsignKAT_{params.sk_bytes}.rsp')

    start = time.time()
    lines = [f'# {param_name}', '']
    for count, (seed, mlen, msg) in enumerate(_requests(num_vectors)):
        rng = NistDRBG(seed)
        skey, pkey = keygen(params, rng.randombytes(2 * params.lambda_bytes))
        sig = sign(params, skey, msg,
                   rng.randombytes(2 * params.lambda_bytes))
        sm = msg + sig
        lines += [
            f'count = {count}',
            f'seed = {seed.hex().upper()}',
            f'mlen = {mlen}',
            f'msg = {msg.hex().upper()}',
            f'pk = {pkey.hex().upper()}',
            f'sk = {skey.hex().upper()}',
            f'smlen = {len(sm)}',
            f'sm = {sm.hex().upper()}',
            '',
        ]
    with open(out_path, 'w') as f:
        f.write('\n'.join(lines))
    elapsed = time.time() - start
    print(f'  [{param_name}] wrote {num_vectors} vectors -> '
          f'{out_path} ({elapsed:.0f}s)', flush=True)
    return param_name, out_path


def _worker(args):
    return generate(*args)


if __name__ == '__main__':
    param = sys.argv[1] if len(sys.argv) > 1 else 'cat1-short'
    num = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_VECTORS
    names = list(ALL_PARAMS.keys()) if param == 'all' else [param]

    if len(names) > 1:
        with Pool(len(names)) as pool:
            pool.map(_worker, [(n, num) for n in names])
    else:
        generate(names[0], num)
