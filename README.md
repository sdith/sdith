# vole-sd

## prerequisites

```sh
apt install libgtest-dev libbenchmark-dev cmake build-essential
```

## build

```sh
cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```
 
(use Release instead of Debug for benchmarking of course)

# test

```sh
# unittests
./build/unittest

# benchmarks (better in Release mode)
./build/bench

# full suite via ctest (unittest + signature self-checks + stress smoke +
# constant-time timing + KAT differential + mini-KAT)
cd build && ctest --output-on-failure
```

## more tests

- **mini-KAT smoke** — the cheap per-commit KAT guard (round-3 VOLEitH). For each of the 12
  parameter sets it signs 3 fixed messages (empty, 256×`0x00`, 999-byte `0102…`) under a fixed
  DRBG seed and compares the SHAKE128-256 of each signature against
  `kat_r3/SDITH_<SET>/mini_kat.shake128`. Runs as the `mini_kat` ctest (part of the default
  `ctest`), ~5 s total. After an *intentional* KAT change, regenerate the goldens — the binary
  resolves `../kat_r3` relative to the cwd, so run it from the build directory:

  ```sh
  cmake --build build --target mini_kat
  cd build && ./mini_kat --regen     # rewrites the 12 kat_r3/SDITH_<SET>/mini_kat.shake128
  ```

  The same run also checks each `kat_r3/SDITH_<SET>/PQCsignKAT_<sk>.rsp` against the library's
  current key and signature sizes. It does not re-derive the 100 records — that is the full KAT
  below — but it is enough to fail the build when a parameter retune leaves a `.rsp` behind.

- **full KAT (manual)** — the thorough check, deliberately *not* in CI (too slow per commit):
  builds + runs the 12 full 100-record NIST generators, SHA-256s each `.rsp`, and compares
  against the committed `kat_r3/full_kat_hashes.txt`. Run on demand:

  ```sh
  cmake -B build -S . -DBUILD_KATS=ON        # -DOPENSSL_ROOT_DIR=... on macOS
  utils/check_full_kats build                # compare against committed hashes
  utils/check_full_kats build --update       # rewrite kat_r3/full_kat_hashes.txt after a change
  ```

  The 12 generator folders under `build/kats_folder/` are not in git: `-DBUILD_KATS=ON`
  materialises each of them from the `kat/sdith_cat1_short/` template, with an `api.h` written
  by `kat_api_gen` from the library's own parameter tables. `sign.c` aborts when `api.h`
  disagrees with the parameters it was built against, so generating it is what keeps the
  `CRYPTO_*BYTES` from going stale whenever the scheme is retuned.

  `full_kat_hashes.txt` and the `.rsp` files under `kat_r3/` both cover all 12 sets (the Python
  reference checks itself against the same files, see `python/round3/test_kat.py`). After an
  intentional KAT change, refresh all 12 and then update the hashes:

  ```sh
  for s in CAT1_SHORT CAT1_FAST CAT1_SHORT_CIPHERPOW CAT1_FAST_CIPHERPOW \
           CAT3_SHORT CAT3_FAST CAT3_SHORT_CIPHERPOW CAT3_FAST_CIPHERPOW \
           CAT5_SHORT CAT5_FAST CAT5_SHORT_CIPHERPOW CAT5_FAST_CIPHERPOW; do
    ( cd build/kats_folder/SDITH_$s && rm -f ./*.rsp ./*.req && ./PQCGenKat_$s >/dev/null )
    cp build/kats_folder/SDITH_$s/*.rsp kat_r3/SDITH_$s/
  done
  utils/check_full_kats build --update
  ```

- **stress soak** — `stress_<SET>` runs many keygen/sign/verify rounds. The ctest
  default is a quick smoke; bump for a real soak:

  ```sh
  cmake -B build -S . -DSTRESS_ITERS=10000
  ./build/stress_CAT5B 10000
  ```

- **constant-time** — `test_ct` has a portable timing mode (`ct_timing` ctest) and a
  valgrind/memcheck taint-tracking mode:

  ```sh
  cmake -B build -S . -DWITH_VALGRIND=ON
  cd build && ctest -R ct_valgrind --output-on-failure
  ```

  At the time of writing, only the code build in Release mode for an x86_64 target without `-DONLY_REF_IMPLEMENTATION` , and then executed over the AES-NI / AVX2 backend is constant-time. It shall be considered as a requirement for keygen and signing wherever timing attacks are in scope; 
  the reference implementation is for readability and KATs, not deployment.
  Signature verification is not subject to constant time constraints and can be run without limitation.
- **fuzzing** — libFuzzer harnesses (`fuzz_verify`, `fuzz_sign_mutate`), Clang only:

  ```sh
  CXX=clang++ cmake -B build-fuzz -S . -DBUILD_FUZZERS=ON
  cmake --build build-fuzz --target fuzz_verify fuzz_sign_mutate
  ./build-fuzz/fuzz_verify -max_total_time=60
  ```

## NIST submission package

`utils/make_nist_package.py` assembles the round-3 submission out of this repository: one
standalone `Reference_Implementation/<set>/` and `Optimized_Implementation/<set>/` folder per
parameter set, plus `KAT/sdith_<set>/PQCsignKAT_<sk>.{req,rsp}`. The reference folders carry
the portable C only (no avx2 sources, built with `-DONLY_REF_IMPLEMENTATION`); neither flavour
contains any C++, and the source lists are read out of the CMake files here so the two stay in
step.

```sh
utils/make_nist_package.py --out /tmp/sdith_round3                      # tree only
utils/make_nist_package.py --out /tmp/sdith_round3 --check              # + build all 24 folders
utils/make_nist_package.py --out /tmp/sdith_round3 --kats generate --verify-reference --zip
```

The last form is the release run: it builds everything, produces the KATs with each optimized
generator, re-runs each *reference* generator over the same records and requires the two to
agree byte for byte, and writes `<out>.zip`. Allow ~40 min — the reference code is one to two
orders of magnitude slower. `--kats copy` reuses `kat_r3/` instead and refuses to run when
those goldens no longer match the sizes the current source produces.



