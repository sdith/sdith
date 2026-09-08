#!/usr/bin/env python3
"""Assemble the round-3 NIST submission package for SDitH (the VOLEitH variant).

The package has one self-contained folder per parameter set, twice:

    <out>/Reference_Implementation/<set>/    portable C only, -DONLY_REF_IMPLEMENTATION
    <out>/Optimized_Implementation/<set>/    same code plus the avx2/aes-ni backend
    <out>/KAT/sdith_<set>/PQCsignKAT_<sk>.{req,rsp}
    <out>/Supporting_Documentation/specifications.pdf

Each implementation folder is standalone: it carries its own CMakeLists.txt, a copy
of lib/aes and lib/sha3, the src/ tree, the bench_sdith C benchmark and the NIST KAT
generator with an api.h pinned to that parameter set.  Nothing C++ is copied, and no
C++ compiler is referenced by the generated CMake files.

Typical use, from the repository root:

    utils/make_nist_package.py --out /tmp/sdith_round3          # tree only
    utils/make_nist_package.py --out /tmp/sdith_round3 --check   # + compile all 24 folders
    utils/make_nist_package.py --out /tmp/sdith_round3 --kats generate   # + run the KATs

`--kats copy` reuses the goldens in kat_r3/ instead of recomputing them; it refuses to
run when those goldens disagree with the sizes the current source produces.
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# The 12 parameter sets, in the order the submission lists them.  Everything else
# about a set is derived from its token: CAT1_SHORT -> cat1_short, "SDiTH-CAT1-SHORT",
# CAT1_SHORT_PARAMETERS, kat_r3/SDITH_CAT1_SHORT, KAT/sdith_cat1_short.
CATEGORY_TOKENS = [
    "CAT1_SHORT",
    "CAT1_FAST",
    "CAT3_SHORT",
    "CAT3_FAST",
    "CAT5_SHORT",
    "CAT5_FAST",
    "CAT1_SHORT_CIPHERPOW",
    "CAT1_FAST_CIPHERPOW",
    "CAT3_SHORT_CIPHERPOW",
    "CAT3_FAST_CIPHERPOW",
    "CAT5_SHORT_CIPHERPOW",
    "CAT5_FAST_CIPHERPOW",
]

# Files carrying an avx2/aes-ni implementation, spotted by name.  This one rule covers
# src/*_avx2.c, lib/aes/*avx*.{c,h} and the whole lib/sha3/avx2/ directory.
AVX_RE = re.compile(r"avx", re.IGNORECASE)

REFERENCE = "Reference_Implementation"
OPTIMIZED = "Optimized_Implementation"
SPEC_PDF = "docs/sdith-v3.0.pdf"


class Category:
    def __init__(self, token):
        self.token = token
        self.dirname = token.lower()
        self.params = token + "_PARAMETERS"
        self.algname = "SDiTH-" + token.replace("_", "-")
        self.golden_dir = "SDITH_" + token  # this set's subdirectory of kat_r3/
        self.kat_dirname = "sdith_" + self.dirname
        self.kat_target = "PQCgenKAT_" + self.dirname
        # filled in by probe_sizes()
        self.secretkeybytes = None
        self.publickeybytes = None
        self.bytes = None

    def __str__(self):
        return self.token


def die(msg):
    sys.exit("make_nist_package: error: " + msg)


def note(msg):
    print("  " + msg, flush=True)


# --------------------------------------------------------------------------------------
# reading the source lists out of the repository CMake files
# --------------------------------------------------------------------------------------


def cmake_list(text, name):
    """Return the entries of a `set(<name> ...)` block in a CMakeLists.txt."""
    m = re.search(r"^[ \t]*set\([ \t]*" + re.escape(name) + r"\b([^)]*)\)", text, re.M)
    if not m:
        die("no set(%s ...) block found in the CMakeLists.txt" % name)
    return [tok for tok in m.group(1).split() if tok]


class Repo:
    """The source repository, and the file lists extracted from its CMake files."""

    def __init__(self, root):
        self.root = root
        for probe in ("CMakeLists.txt", "src/sdith_signature.h", "lib/aes/CMakeLists.txt"):
            if not (root / probe).exists():
                die("%s does not look like the SDitH repository (%s missing)" % (root, probe))
        top = (root / "CMakeLists.txt").read_text()
        aes = (root / "lib/aes/CMakeLists.txt").read_text()
        sha3 = (root / "lib/sha3/CMakeLists.txt").read_text()
        # src/: paths are already relative to the repository root.
        self.src_ref = cmake_list(top, "VOLE_SRCS")
        self.src_avx = cmake_list(top, "VOLE_SRCS_AVX2")
        # lib/: paths are relative to their own directory.
        self.aes_ref = cmake_list(aes, "AES_SRCS_GENERIC")
        self.aes_avx = cmake_list(aes, "AES_SRCS_AVX2")
        self.sha3_common = cmake_list(sha3, "SHA3_SRCS")
        self.sha3_avx = cmake_list(sha3, "SHA3_AVX2_SRCS")
        self.sha3_opt64 = cmake_list(sha3, "SHA3_OPT64_SRCS")
        self._sanity_check()

    def _sanity_check(self):
        """The avx/reference split must agree with the file names, both ways."""
        # src/ is copied wholesale, so a .c file missing from the CMake lists would ship
        # in the package but never be compiled.  (lib/ is exempt: aes_ansi_ref.c, the
        # original big-endian public reference, is deliberately shipped uncompiled.)
        listed = set(self.src_ref) | set(self.src_avx)
        orphans = sorted(
            "src/" + f.name for f in (self.root / "src").glob("*.c") if "src/" + f.name not in listed
        )
        if orphans:
            die(
                "these src/ files are in the tree but in neither VOLE_SRCS nor "
                "VOLE_SRCS_AVX2, so the package would ship them uncompiled: %s"
                % ", ".join(orphans)
            )
        for name, files, want_avx in (
            ("VOLE_SRCS", self.src_ref, False),
            ("VOLE_SRCS_AVX2", self.src_avx, True),
            ("AES_SRCS_GENERIC", self.aes_ref, False),
            ("AES_SRCS_AVX2", self.aes_avx, True),
            ("SHA3_SRCS", self.sha3_common, False),
            ("SHA3_AVX2_SRCS", self.sha3_avx, True),
            ("SHA3_OPT64_SRCS", self.sha3_opt64, False),
        ):
            for f in files:
                if bool(AVX_RE.search(f)) != want_avx:
                    die(
                        "%s lists %r, which the 'avx in the name' rule classifies the "
                        "other way round: the reference/optimized split would be wrong" % (name, f)
                    )

    def ref_compile_units(self):
        """(source file, include dirs) for a reference-only build, repo-relative."""
        srcs = [f for f in self.src_ref if f.endswith(".c")]
        srcs += ["lib/aes/" + f for f in self.aes_ref if f.endswith(".c")]
        srcs += ["lib/sha3/" + f for f in self.sha3_common + self.sha3_opt64 if f.endswith(".c")]
        incs = ["src", "lib/aes", "lib/sha3", "lib/sha3/opt64"]
        return srcs, incs


# --------------------------------------------------------------------------------------
# key/signature sizes
# --------------------------------------------------------------------------------------

PROBE_C = """\
/* generated by utils/make_nist_package.py: prints the api.h sizes of every set */
#include <stdio.h>
#include "sdith_signature.h"

#define PRINT_SET(TOKEN)                                                     \\
  printf("%s %llu %llu %llu\\n", #TOKEN,                                      \\
         (unsigned long long)sdith_secret_key_bytes(&TOKEN##_PARAMETERS),    \\
         (unsigned long long)sdith_public_key_bytes(&TOKEN##_PARAMETERS),    \\
         (unsigned long long)sdith_signature_bytes(&TOKEN##_PARAMETERS));

int main(void) {
@BODY@
  return 0;
}
"""


def probe_sizes(repo, categories, verbose):
    """Compile a tiny probe against the reference sources and read the real sizes.

    api.h has to state CRYPTO_{SECRETKEY,PUBLICKEY,}BYTES exactly; sign.c aborts at
    run time otherwise.  The library is the only trustworthy source for those three
    numbers, so ask it rather than trusting whatever the template api.h happens to say.
    """
    srcs, incs = repo.ref_compile_units()
    body = "\n".join("  PRINT_SET(%s)" % c.token for c in categories)
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory(prefix="sdith-probe-") as tmp:
        tmp = Path(tmp)
        (tmp / "probe.c").write_text(PROBE_C.replace("@BODY@", body))
        exe = tmp / "probe"
        cmd = [cc, "-O0", "-o", str(exe), str(tmp / "probe.c")]
        cmd += [str(repo.root / s) for s in srcs]
        cmd += ["-I" + str(repo.root / i) for i in incs]
        cmd += ["-DONLY_REF_IMPLEMENTATION", "-DNDEBUG", "-lm"]
        if verbose:
            note("probe: " + " ".join(cmd[:4]) + " ... (%d sources)" % len(srcs))
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            die("could not compile the size probe:\n" + r.stdout + r.stderr)
        r = subprocess.run([str(exe)], capture_output=True, text=True, check=True)
    seen = {}
    for line in r.stdout.split("\n"):
        if not line.strip():
            continue
        token, sk, pk, sig = line.split()
        seen[token] = (int(sk), int(pk), int(sig))
    for c in categories:
        if c.token not in seen:
            die("the size probe printed nothing for %s" % c.token)
        c.secretkeybytes, c.publickeybytes, c.bytes = seen[c.token]


def rsp_sizes(rsp_path):
    """(secretkeybytes, publickeybytes, bytes) as recorded in a NIST .rsp file."""
    pk = sk = mlen = smlen = None
    with rsp_path.open() as f:
        for line in f:
            if line.startswith("pk = "):
                pk = len(line.strip()[5:]) // 2
            elif line.startswith("sk = "):
                sk = len(line.strip()[5:]) // 2
            elif line.startswith("mlen = "):
                mlen = int(line.split("=")[1])
            elif line.startswith("smlen = "):
                smlen = int(line.split("=")[1])
                break
    if None in (pk, sk, mlen, smlen):
        die("%s is not a well-formed NIST .rsp file" % rsp_path)
    return sk, pk, smlen - mlen


def req_from_rsp(rsp_path, req_path):
    """Write the .req that produced a .rsp.

    PQCgenKAT_sign writes both files, and the request is just the first four lines of
    each response record followed by the four empty fields.  Reconstructing it here
    keeps the .req in step with whichever .rsp the package ships, byte for byte.
    """
    out = []
    records = 0
    with rsp_path.open() as f:
        for line in f:
            if line.startswith("count = "):
                records += 1
                out.append(line)
            elif line.startswith(("seed = ", "mlen = ", "msg = ")):
                out.append(line)
            elif line.startswith("smlen = "):
                out.append("pk =\nsk =\nsmlen =\nsm =\n\n")
    if records == 0:
        die("%s contains no KAT record" % rsp_path)
    req_path.write_text("".join(out))
    return records


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------------------
# generated CMake files
# --------------------------------------------------------------------------------------

TOP_CMAKE = """\
cmake_minimum_required(VERSION 3.10)
project(sdith_{dirname} C)

# Standalone build of the SDitH {flavour} implementation, parameter set {algname}.
# Generated from the reference repository by utils/make_nist_package.py.
#
#   mkdir build && cd build && cmake .. && make
#   ./bench_sdith                    -- keygen/sign/verify timings
#   ./generator/{kat_target}  -- writes PQCsignKAT_{sk}.req and .rsp

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Default build type: Release" FORCE)
endif ()

set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -Wall -Werror")
set(CMAKE_C_FLAGS_RELEASE "-O3 -g3 -Wall -Werror -DNDEBUG")
{asm}
set(BUILD_KATS ON CACHE BOOL "Build the NIST KAT generator (needs libcrypto)")
{arch}
add_subdirectory(lib/sha3)
add_subdirectory(lib/aes)

set(SDITH_SRCS
{srcs}
)
{avx_block}
add_library(sdith STATIC {lib_srcs})
target_include_directories(sdith PUBLIC src)
target_link_libraries(sdith sha3 aes m)

# The one C test shipped with the package: signs and verifies in a loop and prints a
# percentile histogram of the timings for this parameter set.
add_executable(bench_sdith test/bench_sdith.c)
target_link_libraries(bench_sdith sdith)
target_include_directories(bench_sdith PRIVATE test)

if (BUILD_KATS)
    add_subdirectory(generator)
endif (BUILD_KATS)
"""

ARCH_BLOCK = """
# The avx2/aes-ni backend is x86-64 only.  It is selected at run time through
# __builtin_cpu_supports, so one binary still runs on machines without it.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86_LINUX)|(amd64)|(AMD64)")
    set(X86_LINUX ON)
else ()
    set(X86_LINUX OFF)
endif ()
if (CMAKE_SYSTEM_NAME MATCHES "(Windows)|(MSYS)")
    set(X86_LINUX OFF)
endif ()
message(STATUS "--> X86_LINUX: ${X86_LINUX}")
"""

REF_BLOCK = """
# This package ships the portable C reference code only: the avx2/aes-ni sources are
# not part of it, so the run-time dispatch in vole_parameters.c is compiled out.
set(USE_REFERENCE_CODE_ONLY ON CACHE BOOL "Reference package: portable C only" FORCE)
add_definitions(-DONLY_REF_IMPLEMENTATION)
"""

AVX_BLOCK = """set(SDITH_SRCS_AVX2
{srcs_avx}
)
# -maes: sdith_prng_avx2.c fuses aes128 row generation with the gf128 reduction, so it
# needs the AES-NI intrinsics as well (same set as the lib/aes AVX2 sources).
set_source_files_properties(${{SDITH_SRCS_AVX2}} PROPERTIES COMPILE_FLAGS "-mpclmul -msse2 -mavx2 -maes")

if (NOT X86_LINUX)
    set(SDITH_SRCS_AVX2)
endif ()
"""

GENERATOR_CMAKE = """\
# NIST's KAT generator for {algname}.  rng.c is NIST's AES-256-CTR-DRBG, which calls
# into libcrypto; nothing else in the package needs it.
find_path(crypto_inc NAMES openssl/conf.h)
find_library(crypto NAMES crypto)
if (NOT (crypto_inc AND crypto))
    message(FATAL_ERROR "libcrypto not found (required by the NIST KAT generator): I=${{crypto_inc}} L=${{crypto}}")
endif ()
message(STATUS "Found libcrypto: I=${{crypto_inc}} L=${{crypto}}")

add_executable({kat_target} PQCgenKAT_sign.c rng.c rng.h sign.c api.h)
target_link_libraries({kat_target} sdith ${{crypto}})
target_include_directories({kat_target} PRIVATE ${{crypto_inc}})
set_source_files_properties(PQCgenKAT_sign.c PROPERTIES COMPILE_FLAGS "-Wno-unused-result")
set_source_files_properties(rng.c PROPERTIES COMPILE_FLAGS "-Wno-unused-but-set-variable")
"""

AES_REF_CMAKE = """\
# Reference package: the avx2/aes-ni sources of this library are not shipped.
# aes_ansi_ref.c is the original big-endian public reference implementation; it is
# kept for documentation and is deliberately not compiled.
set(AES_SRCS_GENERIC
{srcs}
)
add_library(aes STATIC ${AES_SRCS_GENERIC})
target_include_directories(aes PUBLIC .)
"""

SHA3_REF_CMAKE = """\
# Reference package: the avx2 sources of this library are not shipped, so the plain
# 64-bit C permutation is the only backend.
set(SHA3_SRCS
{srcs}
)
set(SHA3_OPT64_SRCS
{opt64}
)
add_library(sha3 STATIC ${SHA3_SRCS} ${SHA3_OPT64_SRCS})
target_include_directories(sha3 PUBLIC opt64)
target_include_directories(sha3 PUBLIC .)
"""

API_H_HEADER_END = "//   This is a sample 'api.h' for use 'sign.c'"

README = """\
SDitH -- round-3 NIST submission package
========================================

This package contains the {nsets} parameter sets of the VOLE-in-the-Head variant of
SDitH, each as two standalone folders:

  Reference_Implementation/<set>/   portable C only (built with -DONLY_REF_IMPLEMENTATION)
  Optimized_Implementation/<set>/   the same code plus an avx2/aes-ni backend for x86-64

The scheme is specified in Supporting_Documentation/specifications.pdf.

Both produce identical keys and signatures; the optimized folder simply picks the faster
backend at run time via __builtin_cpu_supports, so its binaries also run on machines
without avx2.

Building one folder
-------------------

  cd Optimized_Implementation/{example}
  mkdir build && cd build && cmake .. && make
  ./bench_sdith                        # keygen/sign/verify timings
  ./generator/PQCgenKAT_{example}      # writes PQCsignKAT_*.req and .rsp

CMake >= 3.10 and a C compiler are enough for the library and the benchmark.  The KAT
generator additionally needs libcrypto (OpenSSL) for NIST's AES-256-CTR-DRBG; configure
with -DBUILD_KATS=OFF to skip it.

Layout of an implementation folder
----------------------------------

  CMakeLists.txt   standalone build of the library, bench_sdith and the KAT generator
  src/             the signature scheme
  lib/aes/         AES-128 and Rijndael-256 block ciphers
  lib/sha3/        Keccak / SHAKE
  test/            bench_sdith.c, the C benchmark, and its cycle counter
  generator/       NIST's PQCgenKAT_sign.c, rng.c and sign.c, with api.h pinned to
                   this parameter set

Known answer tests
------------------

  KAT/sdith_<set>/PQCsignKAT_<CRYPTO_SECRETKEYBYTES>.req
  KAT/sdith_<set>/PQCsignKAT_<CRYPTO_SECRETKEYBYTES>.rsp

100 records per set, as produced by the generator in the matching implementation folder.

Parameter sets
--------------

{table}
"""


def indent(items, prefix="        "):
    return "\n".join(prefix + i for i in items)


# --------------------------------------------------------------------------------------
# emitting one implementation folder
# --------------------------------------------------------------------------------------


def copy_tree(src, dst, skip_avx, skip_names=()):
    """Copy a directory, optionally dropping every avx file and directory."""
    for path in sorted(src.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(src)
        if rel.name in skip_names:
            continue
        if skip_avx and any(AVX_RE.search(part) for part in rel.parts):
            continue
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, out)


def emit_bench(repo, dest, cat):
    """Copy bench_sdith.c with its parameter-set #if chain resolved to this set.

    The in-tree file picks a set from -DCAT1A.. -DCAT5B, which has no spelling for the
    CIPHERPOW sets and would be dead weight in a single-parameter-set folder anyway.
    """
    text = (repo.root / "test/bench_sdith.c").read_text()
    start = "#if defined(CAT5B)"
    end = "#error NO parameter defined\n#endif\n"
    i = text.find(start)
    j = text.find(end)
    if i < 0 or j < i:
        die("test/bench_sdith.c no longer has the parameter-set #if chain this script rewrites")
    text = text[:i] + "sig_params = %s;\n" % cat.params + text[j + len(end):]
    (dest / "test").mkdir(parents=True, exist_ok=True)
    (dest / "test/bench_sdith.c").write_text(text)
    shutil.copyfile(repo.root / "test/cpucycles.h", dest / "test/cpucycles.h")


def emit_api_h(repo, dest, cat):
    """Copy api.h with the sizes, algorithm name and parameter set of this category."""
    text = (repo.root / "kat" / "sdith_cat1_short" / "api.h").read_text()
    subs = {
        "CRYPTO_SECRETKEYBYTES": str(cat.secretkeybytes),
        "CRYPTO_PUBLICKEYBYTES": str(cat.publickeybytes),
        "CRYPTO_BYTES": str(cat.bytes),
        "CRYPTO_ALGNAME": '"%s"' % cat.algname,
        "SIGNATURE_PARAMS": cat.params,
    }
    for macro, value in subs.items():
        text, n = re.subn(
            r"^#define %s .*$" % macro, "#define %s %s" % (macro, value), text, flags=re.M
        )
        if n != 1:
            die("kat/sdith_cat1_short/api.h does not define %s exactly once" % macro)
    (dest / "generator" / "api.h").write_text(text)


def emit_generator(repo, dest, cat):
    src = repo.root / "kat" / "sdith_cat1_short"
    gen = dest / "generator"
    gen.mkdir(parents=True, exist_ok=True)
    for name in ("PQCgenKAT_sign.c", "rng.c", "rng.h", "sign.c"):
        shutil.copyfile(src / name, gen / name)
    emit_api_h(repo, dest, cat)
    (gen / "CMakeLists.txt").write_text(
        GENERATOR_CMAKE.format(algname=cat.algname, kat_target=cat.kat_target)
    )


def emit_supporting_documentation(repo, out):
    """Copy the specification into <out>/Supporting_Documentation/, under the name NIST
    expects.  The repository keeps it under docs/ with a version in the file name."""
    src = repo.root / SPEC_PDF
    if not src.exists():
        die("the specification is missing (%s)" % src)
    dest = out / "Supporting_Documentation"
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest / "specifications.pdf")
    return dest


def emit_implementation(repo, out, cat, flavour):
    """Write one <flavour>/<set>/ folder and return its path."""
    reference = flavour == REFERENCE
    dest = out / flavour / cat.dirname
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    # src/ and lib/: the reference folder drops every avx file.  lib/ is copied whole,
    # so the pieces the CMake source lists leave out (the original big-endian
    # aes_ansi_ref.c, the neon and plain32 Keccak backends) still ship as documentation.
    copy_tree(repo.root / "src", dest / "src", skip_avx=reference)
    copy_tree(repo.root / "lib/aes", dest / "lib/aes", skip_avx=reference)
    copy_tree(repo.root / "lib/sha3", dest / "lib/sha3", skip_avx=reference, skip_names=("Makefile",))

    if reference:
        (dest / "lib/aes/CMakeLists.txt").write_text(
            AES_REF_CMAKE.replace("{srcs}", indent(repo.aes_ref))
        )
        (dest / "lib/sha3/CMakeLists.txt").write_text(
            SHA3_REF_CMAKE.replace("{srcs}", indent(repo.sha3_common)).replace(
                "{opt64}", indent(repo.sha3_opt64)
            )
        )

    emit_bench(repo, dest, cat)
    emit_generator(repo, dest, cat)

    avx_block = "" if reference else AVX_BLOCK.format(srcs_avx=indent(repo.src_avx))
    (dest / "CMakeLists.txt").write_text(
        TOP_CMAKE.format(
            dirname=cat.dirname,
            algname=cat.algname,
            flavour="reference" if reference else "optimized",
            kat_target=cat.kat_target,
            sk=cat.secretkeybytes,
            asm="" if reference else "enable_language(ASM)\n",
            arch=REF_BLOCK if reference else ARCH_BLOCK,
            srcs=indent(repo.src_ref),
            avx_block=avx_block,
            lib_srcs="${SDITH_SRCS}" if reference else "${SDITH_SRCS} ${SDITH_SRCS_AVX2}",
        )
    )
    return dest


# --------------------------------------------------------------------------------------
# optional build / KAT stages
# --------------------------------------------------------------------------------------


def cmake_build(folder, jobs, targets=None, verbose=False):
    """Configure and build one implementation folder in place; return its build dir."""
    build = folder / "build"
    log = []
    for cmd in (
        ["cmake", "-B", str(build), "-S", str(folder), "-DCMAKE_BUILD_TYPE=Release"],
        ["cmake", "--build", str(build), "-j", str(jobs)]
        + ([] if targets is None else ["--target"] + list(targets)),
    ):
        r = subprocess.run(cmd, capture_output=True, text=True)
        log.append(r.stdout + r.stderr)
        if r.returncode != 0:
            raise RuntimeError("`%s` failed:\n%s" % (" ".join(cmd), "".join(log)))
    if verbose:
        note("".join(log).strip().splitlines()[-1])
    return build


def run_generator(build, cat, kat_dir):
    """Run the package's own KAT generator, writing straight into kat_dir."""
    exe = build / "generator" / cat.kat_target
    if not exe.exists():
        die("the KAT generator was not built: %s missing" % exe)
    kat_dir.mkdir(parents=True, exist_ok=True)
    for stale in kat_dir.glob("PQCsignKAT_*"):
        stale.unlink()
    r = subprocess.run([str(exe)], cwd=kat_dir, capture_output=True, text=True)
    if r.returncode != 0:
        die("%s exited with %d:\n%s" % (exe, r.returncode, r.stdout + r.stderr))
    rsp = kat_dir / ("PQCsignKAT_%d.rsp" % cat.secretkeybytes)
    req = kat_dir / ("PQCsignKAT_%d.req" % cat.secretkeybytes)
    for f in (rsp, req):
        if not f.exists():
            die("%s did not produce %s" % (exe, f.name))
    return req, rsp


# --------------------------------------------------------------------------------------


def main():
    p = argparse.ArgumentParser(
        description="Assemble the round-3 NIST submission package for SDitH.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Typical use" + __doc__.split("Typical use", 1)[1],
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="source repository (default: the one holding this script)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="package directory to create (default: <repo>/nist_round3_package)",
    )
    p.add_argument(
        "--kat-goldens",
        type=Path,
        default=None,
        help="committed KATs to copy or compare against (default: <repo>/kat_r3)",
    )
    p.add_argument(
        "--sets",
        default="all",
        help="comma-separated parameter sets to package (default: all %d)" % len(CATEGORY_TOKENS),
    )
    p.add_argument(
        "--kats",
        choices=("none", "copy", "generate"),
        default="none",
        help="how to fill KAT/: skip it, copy the goldens, or build and run each "
        "generator (default: none)",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="compile every generated folder (implied by --kats generate for the "
        "optimized ones)",
    )
    p.add_argument(
        "--keep-builds",
        action="store_true",
        help="leave the build/ directories inside the package (default: remove them)",
    )
    p.add_argument(
        "--verify-reference",
        action="store_true",
        help="with --kats generate, also run each Reference_Implementation generator "
        "and require it to produce the very same KAT as the optimized one (slow: the "
        "reference code is one to two orders of magnitude slower)",
    )
    p.add_argument("--zip", action="store_true", help="also write <out>.zip")
    p.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4)
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    repo_root = args.repo.resolve()
    out = (args.out or repo_root / "nist_round3_package").resolve()
    goldens = (args.kat_goldens or repo_root / "kat_r3").resolve()

    if args.sets == "all":
        tokens = CATEGORY_TOKENS
    else:
        tokens = [s.strip().upper() for s in args.sets.split(",") if s.strip()]
        unknown = [t for t in tokens if t not in CATEGORY_TOKENS]
        if unknown:
            die("unknown parameter set(s): %s" % ", ".join(unknown))
    categories = [Category(t) for t in tokens]

    # emit_implementation() rmtree's the folders it is about to write, so make sure the
    # package directory cannot swallow (part of) the repository it is generated from.
    if out.exists() and not out.is_dir():
        die("%s exists and is not a directory" % out)
    if out == repo_root or out in repo_root.parents:
        die("refusing to write the package over the repository (%s)" % out)
    if repo_root in out.parents and out.parent != repo_root:
        die("the package directory must not sit inside the repository tree (%s)" % out)

    repo = Repo(repo_root)

    print("source repository : %s" % repo_root)
    print("package directory : %s" % out)
    print("parameter sets    : %d" % len(categories))
    print()

    print("reading the key and signature sizes from the library ...")
    probe_sizes(repo, categories, args.verbose)
    for c in categories:
        note(
            "%-22s sk=%-4d pk=%-4d sig=%d"
            % (c.token, c.secretkeybytes, c.publickeybytes, c.bytes)
        )
    print()

    print("writing the implementation folders ...")
    folders = {}
    for c in categories:
        for flavour in (REFERENCE, OPTIMIZED):
            folders[(c.token, flavour)] = emit_implementation(repo, out, c, flavour)
        note("%s/{%s,%s}" % (c.dirname, "Reference", "Optimized"))
    emit_supporting_documentation(repo, out)
    note("Supporting_Documentation/specifications.pdf")
    print()

    # C++ never belongs in a NIST package: neither as a source file, nor as a language
    # the generated CMake files could switch on.
    strays = [
        f
        for f in out.rglob("*")
        if f.is_file() and f.suffix in (".cpp", ".cc", ".cxx", ".hpp", ".hh")
    ]
    if strays:
        die("C++ files ended up in the package: %s" % ", ".join(str(s) for s in strays[:5]))
    for cml in out.rglob("CMakeLists.txt"):
        text = cml.read_text()
        if re.search(r"\bCXX\b|CMAKE_CXX|\.cpp\b|gtest|benchmark", text):
            die("%s still mentions C++ or a C++ test dependency" % cml)

    failures = []  # the package is wrong and must not be shipped
    warnings = []  # worth knowing, but the package itself is self-consistent
    build_dirs = []

    if args.check or args.kats == "generate":
        print("building ...")
        for c in categories:
            for flavour in (REFERENCE, OPTIMIZED):
                # With --kats generate we must build the optimized folders anyway; the
                # reference ones are only built when --check asks for it.
                if not args.check and flavour == REFERENCE:
                    continue
                folder = folders[(c.token, flavour)]
                t0 = time.time()
                try:
                    build_dirs.append(cmake_build(folder, args.jobs, verbose=args.verbose))
                except RuntimeError as e:
                    failures.append("%s %s: %s" % (c.token, flavour, e))
                    note("FAIL %-22s %s" % (c.token, flavour))
                    continue
                note("ok   %-22s %-25s (%.0fs)" % (c.token, flavour, time.time() - t0))
        print()

    kat_report = []
    if args.kats != "none":
        print("filling KAT/ (%s) ..." % args.kats)
        for c in categories:
            kat_dir = out / "KAT" / c.kat_dirname
            golden = goldens / c.golden_dir / ("PQCsignKAT_%d.rsp" % c.secretkeybytes)
            if args.kats == "generate":
                folder = folders[(c.token, OPTIMIZED)]
                build = folder / "build"
                if not (build / "generator" / c.kat_target).exists():
                    note("skip %-22s (its build failed)" % c.token)
                    continue
                t0 = time.time()
                req, rsp = run_generator(build, c, kat_dir)
                status = "generated in %.0fs" % (time.time() - t0)
                # The two folders must be interchangeable: same keys, same signatures.
                # Running the reference generator over the same 100 records is the only
                # end-to-end proof of that, so it is worth the extra minutes.
                ref_build = folders[(c.token, REFERENCE)] / "build"
                if args.verify_reference and (ref_build / "generator" / c.kat_target).exists():
                    t0 = time.time()
                    with tempfile.TemporaryDirectory(prefix="sdith-ref-kat-") as tmp:
                        _, ref_rsp = run_generator(ref_build, c, Path(tmp))
                        same = sha256(ref_rsp) == sha256(rsp)
                    if same:
                        status += ", reference agrees (%.0fs)" % (time.time() - t0)
                    else:
                        status += ", REFERENCE DISAGREES"
                        failures.append(
                            "%s: Reference_Implementation and Optimized_Implementation "
                            "produce different KATs" % c.token
                        )
            else:
                if not golden.exists():
                    failures.append("%s: no golden KAT at %s" % (c.token, golden))
                    note("FAIL %-22s golden %s missing" % (c.token, golden.name))
                    continue
                g_sk, g_pk, g_sig = rsp_sizes(golden)
                if (g_sk, g_pk, g_sig) != (c.secretkeybytes, c.publickeybytes, c.bytes):
                    failures.append(
                        "%s: golden KAT is stale -- it has sk=%d pk=%d sig=%d, the "
                        "current source produces sk=%d pk=%d sig=%d"
                        % (c.token, g_sk, g_pk, g_sig, c.secretkeybytes, c.publickeybytes, c.bytes)
                    )
                    note("FAIL %-22s golden KAT is stale" % c.token)
                    continue
                kat_dir.mkdir(parents=True, exist_ok=True)
                rsp = kat_dir / golden.name
                req = kat_dir / (golden.stem + ".req")
                shutil.copyfile(golden, rsp)
                status = "copied from %s" % golden.parent.name
            records = req_from_rsp(rsp, req)
            digest = sha256(rsp)
            # A freshly generated KAT that disagrees with the committed golden does not
            # make the package wrong -- on a parameter-tuning branch the golden is simply
            # older than the source -- but it always deserves a line in the report.
            match = ""
            if golden.exists():
                same = sha256(golden) == digest
                match = " == %s" % goldens.name if same else " != %s (DIFFERS)" % goldens.name
                if not same:
                    warnings.append(
                        "%s: the generated KAT differs from the golden %s"
                        % (c.token, golden.relative_to(goldens.parent))
                    )
            kat_report.append((c, records, digest, status + match))
            note("%-22s %3d records  %s  %s" % (c.token, records, digest[:16], status + match))
        print()

    if not args.keep_builds:
        for b in build_dirs:
            shutil.rmtree(b, ignore_errors=True)

    table = "\n".join(
        "  %-22s  sk %4d B   pk %4d B   sig %6d B"
        % (c.algname, c.secretkeybytes, c.publickeybytes, c.bytes)
        for c in categories
    )
    (out / "README.txt").write_text(
        README.format(nsets=len(categories), example=categories[0].dirname, table=table)
    )

    if args.zip:
        archive = shutil.make_archive(str(out), "zip", root_dir=out.parent, base_dir=out.name)
        print("archive: %s (%.1f MiB)" % (archive, os.path.getsize(archive) / 1048576.0))

    nfiles = sum(1 for f in out.rglob("*") if f.is_file())
    print("package written: %d files under %s" % (nfiles, out))
    if warnings:
        print()
        print("%d warning(s):" % len(warnings))
        for w in warnings:
            print("  - " + w)
    if failures:
        print()
        print("%d problem(s):" % len(failures))
        for f in failures:
            print("  - " + f)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
