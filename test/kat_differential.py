#!/usr/bin/env python3
"""C-vs-python KAT differential for SDitH round 3.

For each parameter set, run the committed C NIST KAT generator
(kats_folder/SDITH_<SET>/PQCGenKat_<SET>) and compare its output record-by-record
against the python reference vectors committed under kat_r3/. The C generator emits
100 records; python ships only a few (pure-python cat5 signing is slow), so we stop
the C process once it has flushed the records python actually has, and compare only
those. Both sides share the same NIST AES-256-CTR DRBG seeded with entropy 0..47,
so the seed/mlen/msg fields validate the DRBG and pk/sk/sm validate the crypto.

Exit codes: 0 = every runnable set matched, 1 = mismatch, 77 = nothing to run
(C generators not built) so ctest records a SKIP.
"""

import argparse
import os
import subprocess
import sys
import time

SETS = ["CAT1_SHORT", "CAT1_FAST", "CAT3_SHORT", "CAT3_FAST", "CAT5_SHORT", "CAT5_FAST",
        "CAT1_SHORT_CIPHERPOW", "CAT1_FAST_CIPHERPOW",
        "CAT3_SHORT_CIPHERPOW", "CAT3_FAST_CIPHERPOW",
        "CAT5_SHORT_CIPHERPOW", "CAT5_FAST_CIPHERPOW"]
CMP_FIELDS = ("seed", "mlen", "msg", "pk", "sk", "smlen", "sm")


def parse_kat(path):
    """Parse a NIST .rsp into a list of {field: value} dicts (blank line = record end)."""
    records, cur = [], {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                if cur:
                    records.append(cur)
                    cur = {}
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                cur[k.strip()] = v.strip()
    if cur:
        records.append(cur)
    return records


def count_started(path):
    try:
        with open(path) as f:
            return sum(1 for line in f if line.startswith("count ="))
    except FileNotFoundError:
        return 0


def generate_c_records(binary, workdir, rsp_name, need, timeout):
    """Run the C generator, stop once `need` records are fully flushed, return the .rsp path."""
    stem = rsp_name[:-4]
    for ext in (".rsp", ".req"):
        p = os.path.join(workdir, stem + ext)
        if os.path.exists(p):
            os.remove(p)
    rsp = os.path.join(workdir, rsp_name)
    proc = subprocess.Popen([os.path.abspath(binary)], cwd=workdir, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    t0 = time.time()
    try:
        while True:
            if proc.poll() is not None:
                break  # generated all 100 records before we stopped it
            # `count = need` appears only once records 0..need-1 are fully written.
            if count_started(rsp) >= need + 1:
                break
            if time.time() - t0 > timeout:
                raise TimeoutError("C generator timed out for %s" % binary)
            time.sleep(0.05)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    return rsp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--c-bins", required=True, help="build kats_folder dir with SDITH_<SET>/PQCGenKat_<SET>")
    ap.add_argument("--golden", required=True, help="committed kat_r3 dir with SDITH_<SET>/PQCsignKAT_<sk>.rsp")
    ap.add_argument("--sets", nargs="*", default=SETS, help="subset of parameter sets to check")
    ap.add_argument("--timeout", type=float, default=180.0, help="per-set C generation timeout (s)")
    args = ap.parse_args()

    ran, failed = 0, 0
    for s in args.sets:
        binary = os.path.join(args.c_bins, "SDITH_%s" % s, "PQCGenKat_%s" % s)
        gdir = os.path.join(args.golden, "SDITH_%s" % s)
        golden_files = [f for f in os.listdir(gdir)] if os.path.isdir(gdir) else []
        golden_rsp = next((os.path.join(gdir, f) for f in golden_files if f.endswith(".rsp")), None)
        if not os.path.exists(binary) or golden_rsp is None:
            print("SKIP %s (binary or golden missing)" % s)
            continue

        expected = parse_kat(golden_rsp)
        need = len(expected)
        rsp_name = os.path.basename(golden_rsp)
        got_path = generate_c_records(binary, os.path.dirname(binary), rsp_name, need, args.timeout)
        got = parse_kat(got_path)[:need]
        ran += 1

        if len(got) < need:
            print("FAIL %s: C produced %d/%d records" % (s, len(got), need))
            failed += 1
            continue
        mism = []
        for i in range(need):
            for k in CMP_FIELDS:
                if got[i].get(k) != expected[i].get(k):
                    mism.append("record %d field %s" % (i, k))
        if mism:
            print("FAIL %s: %s" % (s, ", ".join(mism)))
            failed += 1
        else:
            print("OK   %s: %d record(s) byte-identical" % (s, need))

    if ran == 0:
        print("no C generators built -> skipping")
        return 77
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
