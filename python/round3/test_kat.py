"""
KAT check for the SDitH round 3 Python reference.

The vectors live in the repo-root kat_r3/ shared with the C reference. The test
regenerates each one from its seed, checks pk/sk/sm byte-for-byte, and confirms
verify() accepts it. Run gen_kat.py first if kat_r3/ is missing, or after an
intentional byte-level change.

Usage:
  python test_kat.py [param_set] [max_tests]

  param_set: cat1-short (default), cat1-fast, cat3-short, cat3-fast,
             cat5-short, cat5-fast, or 'all'
  max_tests: number of test vectors to run (default: all present)

Examples:
  python test_kat.py                    # cat1-short, all vectors in kat_r3
  python test_kat.py cat3-short 3       # cat3-short, first 3 vectors
  python test_kat.py all 1              # all 6 param sets, 1 vector each
"""

import sys
import os
import time
from multiprocessing import Pool

from params import ALL_PARAMS
from nist_drbg import NistDRBG
from sdith import keygen, sign, verify

# Shared repo-root kat_r3/ (python/round3 -> repo root is two levels up).
_HERE = os.path.dirname(os.path.abspath(__file__))
KAT_DIR = os.path.normpath(os.path.join(_HERE, '..', '..', 'kat_r3'))

KAT_FILES = {
    'cat1-short': 'SDITH_CAT1_SHORT/PQCsignKAT_147.rsp',
    'cat1-fast': 'SDITH_CAT1_FAST/PQCsignKAT_147.rsp',
    'cat3-short': 'SDITH_CAT3_SHORT/PQCsignKAT_208.rsp',
    'cat3-fast': 'SDITH_CAT3_FAST/PQCsignKAT_208.rsp',
    'cat5-short': 'SDITH_CAT5_SHORT/PQCsignKAT_275.rsp',
    'cat5-fast': 'SDITH_CAT5_FAST/PQCsignKAT_275.rsp',
    'cat1-short-cipherpow': 'SDITH_CAT1_SHORT_CIPHERPOW/PQCsignKAT_147.rsp',
    'cat1-fast-cipherpow': 'SDITH_CAT1_FAST_CIPHERPOW/PQCsignKAT_147.rsp',
    'cat3-short-cipherpow': 'SDITH_CAT3_SHORT_CIPHERPOW/PQCsignKAT_208.rsp',
    'cat3-fast-cipherpow': 'SDITH_CAT3_FAST_CIPHERPOW/PQCsignKAT_208.rsp',
    'cat5-short-cipherpow': 'SDITH_CAT5_SHORT_CIPHERPOW/PQCsignKAT_275.rsp',
    'cat5-fast-cipherpow': 'SDITH_CAT5_FAST_CIPHERPOW/PQCsignKAT_275.rsp',
}


def parse_kat_file(path):
    """Parse a NIST KAT .rsp file into a list of test vectors."""
    tests = []
    current = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, val = line.split('=', 1)
            key, val = key.strip(), val.strip()
            if key == 'count':
                if current:
                    tests.append(current)
                current = {'count': int(val)}
            elif key in ('seed', 'pk', 'sk', 'sm', 'msg'):
                current[key] = bytes.fromhex(val)
            elif key in ('mlen', 'smlen'):
                current[key] = int(val)
        if current:
            tests.append(current)
    return tests


def run_kat_test(param_name, max_tests=None):
    """Run KAT tests for a single parameter set.

    Returns (param_name, passed, failed, elapsed).
    """
    params = ALL_PARAMS[param_name]
    kat_path = os.path.join(KAT_DIR, KAT_FILES[param_name])

    if not os.path.exists(kat_path):
        print(f"  [{param_name}] KAT file not found: "
              f"{kat_path}", flush=True)
        return (param_name, 0, 0, 0)

    tests = parse_kat_file(kat_path)
    if max_tests:
        tests = tests[:max_tests]

    passed = failed = 0
    start_time = time.time()

    for test in tests:
        rng = NistDRBG(test['seed'])
        entropy_keygen = rng.randombytes(2 * params.lambda_bytes)
        skey, pkey = keygen(params, entropy_keygen)

        if pkey != test['pk'] or skey != test['sk']:
            print(f"  [{param_name}] FAIL count="
                  f"{test['count']}: key mismatch",
                  flush=True)
            failed += 1
            continue

        entropy_sign = rng.randombytes(2 * params.lambda_bytes)
        sig = sign(params, skey, test['msg'], entropy_sign)
        signed_message = test['msg'] + sig

        if signed_message != test['sm']:
            first_diff = next(
                i for i in range(
                    min(len(signed_message), len(test['sm'])))
                if signed_message[i] != test['sm'][i])
            print(f"  [{param_name}] FAIL count="
                  f"{test['count']}: sm diff at byte "
                  f"{first_diff}", flush=True)
            failed += 1
            continue

        if not verify(params, pkey, test['msg'], sig):
            print(f"  [{param_name}] FAIL count="
                  f"{test['count']}: verify failed",
                  flush=True)
            failed += 1
            continue

        passed += 1
        elapsed = time.time() - start_time
        print(f"  [{param_name}] PASS count={test['count']}"
              f" (mlen={test['mlen']}, {elapsed:.0f}s)",
              flush=True)

    elapsed = time.time() - start_time
    return (param_name, passed, failed, elapsed)


def _worker(args):
    """Wrapper for multiprocessing Pool."""
    name, max_tests = args
    return run_kat_test(name, max_tests)


if __name__ == '__main__':
    param = sys.argv[1] if len(sys.argv) > 1 else 'cat1-short'
    max_tests = int(sys.argv[2]) if len(sys.argv) > 2 else None

    if param == 'all':
        names = list(ALL_PARAMS.keys())
    else:
        names = [param]

    wall_start = time.time()

    if len(names) > 1:
        with Pool(len(names)) as pool:
            results = pool.map(
                _worker,
                [(n, max_tests) for n in names])
    else:
        results = [run_kat_test(names[0], max_tests)]

    wall_time = time.time() - wall_start
    print(f"\n{'=' * 50}")
    all_ok = True
    for name, passed, failed, elapsed in results:
        total = passed + failed
        status = "PASS" if failed == 0 else "FAIL"
        print(f"  {name}: {passed}/{total} {status}"
              f" ({elapsed:.0f}s)")
        if failed:
            all_ok = False
    print(f"  wall time: {wall_time:.0f}s")
    sys.exit(0 if all_ok else 1)
