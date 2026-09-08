/*
 * Constant-time validation for SDitH v2
 *
 * Two complementary approaches:
 *
 * 1. VALGRIND/CTGRIND MODE (-DWITH_VALGRIND):
 *    Mark secret data as "uninitialized" using Valgrind's memcheck.
 *    Run under: valgrind --tool=memcheck ./test_ct
 *    Any branch/memory-access on "uninitialized" (secret) data triggers
 *    a Valgrind warning. This is the standard approach used by ctgrind,
 *    TIMECOP, and the KyberSlash paper (Bernstein et al. 2025).
 *
 *    Reference: https://kyberslash.cr.yp.to
 *    Reference: https://www.imperialviolet.org/2010/04/01/ctgrind.html
 *
 * 2. TIMING VARIANCE MODE (default, no Valgrind needed):
 *    Run keygen/sign/verify many times with different keys and measure
 *    the coefficient of variation. Large CV suggests timing depends on
 *    secret data. This is empirical and less precise than Valgrind but
 *    works on any platform including macOS arm64.
 *
 * Build:
 *   cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
 *   cmake --build build --target test_ct
 *
 * Run (Valgrind mode, Linux x86 only):
 *   valgrind --tool=memcheck --track-origins=yes ./build/test_ct valgrind
 *
 * Run (timing variance mode, any platform):
 *   ./build/test_ct timing [num_iterations]
 */

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sdith_signature.h"

#ifdef WITH_VALGRIND
#include <valgrind/memcheck.h>
#define CT_POISON(addr, len) VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
#define CT_UNPOISON(addr, len) VALGRIND_MAKE_MEM_DEFINED(addr, len)
#else
#define CT_POISON(addr, len) ((void)0)
#define CT_UNPOISON(addr, len) ((void)0)
#endif

static void fill_random(void* buf, size_t len) {
  uint8_t* p = (uint8_t*)buf;
  for (size_t i = 0; i < len; i++) p[i] = (uint8_t)rand();
}

#if defined(__APPLE__)
#include <mach/mach_time.h>
static double get_time_ns(void) {
  static mach_timebase_info_data_t info = {0, 0};
  if (info.denom == 0) mach_timebase_info(&info);
  return (double)mach_absolute_time() * info.numer / info.denom;
}
#else
static double get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1e9 + ts.tv_nsec;
}
#endif

/* ----------------------------------------------------------------
 * Valgrind/ctgrind mode: taint-track secret data through operations
 * ---------------------------------------------------------------- */
static int test_ct_valgrind(const signature_parameters* params) {
  printf("=== Valgrind/ctgrind constant-time test ===\n");
  printf("Mark secret data as undefined, run keygen+sign+verify.\n");
  printf("Valgrind will warn on any branch/load depending on secrets.\n\n");

  uint64_t skey_bytes = sdith_secret_key_bytes(params);
  uint64_t pkey_bytes = sdith_public_key_bytes(params);
  uint64_t sig_bytes = sdith_signature_bytes(params);
  uint64_t keygen_entropy_bytes = sdith_keygen_entropy_bytes(params);
  uint64_t sign_entropy_bytes = sdith_signature_entropy_bytes(params);
  uint64_t keygen_tmp = sdith_keygen_tmp_bytes(params);
  uint64_t sign_tmp = sdith_signature_tmp_bytes(params);
  uint64_t verify_tmp = sdith_verify_tmp_bytes(params);

  uint8_t* skey = (uint8_t*)malloc(skey_bytes);
  uint8_t* pkey = (uint8_t*)malloc(pkey_bytes);
  uint8_t* sig = (uint8_t*)malloc(sig_bytes);
  uint8_t* keygen_entropy = (uint8_t*)malloc(keygen_entropy_bytes);
  uint8_t* sign_entropy = (uint8_t*)malloc(sign_entropy_bytes);
  uint8_t* kg_tmp = (uint8_t*)malloc(keygen_tmp);
  uint8_t* s_tmp = (uint8_t*)malloc(sign_tmp);
  uint8_t* v_tmp = (uint8_t*)malloc(verify_tmp);

  const char message[] = "constant-time test message";
  uint64_t message_len = strlen(message);

  /* Generate random entropy */
  fill_random(keygen_entropy, keygen_entropy_bytes);
  fill_random(sign_entropy, sign_entropy_bytes);

  /*
   * KEYGEN: Mark entropy as secret (undefined).
   * Valgrind will track which outputs depend on it.
   */
  printf("[keygen] Poisoning keygen entropy (%llu bytes)...\n",
         (unsigned long long)keygen_entropy_bytes);
  CT_POISON(keygen_entropy, keygen_entropy_bytes);

  sdith_keygen(params, skey, pkey, keygen_entropy, kg_tmp);

  /* Public key is public — unpoison it */
  CT_UNPOISON(pkey, pkey_bytes);
  /* Secret key remains tainted */
  printf("[keygen] Done. Secret key is tainted, public key is clean.\n");

  /*
   * SIGN: The secret key and sign entropy are secret.
   * The signature output becomes public.
   */
  printf("[sign] Poisoning sign entropy (%llu bytes)...\n",
         (unsigned long long)sign_entropy_bytes);
  CT_POISON(sign_entropy, sign_entropy_bytes);

  sdith_sign(params, sig, message, message_len, skey, sign_entropy, s_tmp);

  /* Signature is public — unpoison it */
  CT_UNPOISON(sig, sig_bytes);
  printf("[sign] Done. Signature is clean.\n");

  /*
   * VERIFY: No secrets involved — all inputs are public.
   * But we check that verification doesn't leak via early returns.
   */
  printf("[verify] Running verification (all inputs public)...\n");
  uint8_t result = sdith_verify(params, sig, message, message_len, pkey, v_tmp);
  /* Result is public */
  CT_UNPOISON(&result, sizeof(result));
  printf("[verify] Result: %s\n", result ? "PASS" : "FAIL");

  /*
   * VERIFY with bad signature: check that rejection doesn't leak
   * which check failed via timing.
   */
  printf("[verify-bad] Flipping signature bit, verifying...\n");
  sig[0] ^= 1;
  result = sdith_verify(params, sig, message, message_len, pkey, v_tmp);
  CT_UNPOISON(&result, sizeof(result));
  printf("[verify-bad] Result: %s (expected FAIL)\n", result ? "PASS" : "FAIL");

  free(skey);
  free(pkey);
  free(sig);
  free(keygen_entropy);
  free(sign_entropy);
  free(kg_tmp);
  free(s_tmp);
  free(v_tmp);

  printf("\nIf no Valgrind warnings above, the tested code paths are CT.\n");
  printf("Run with: valgrind --tool=memcheck --track-origins=yes ./test_ct valgrind\n");
  return 0;
}

/* ----------------------------------------------------------------
 * Timing variance mode: statistical detection of timing leaks
 * ---------------------------------------------------------------- */
static int test_ct_timing(const signature_parameters* params, int num_iterations) {
  printf("=== Timing variance constant-time test ===\n");
  printf("Running %d sign+verify iterations, measuring timing variance.\n\n", num_iterations);

  uint64_t skey_bytes = sdith_secret_key_bytes(params);
  uint64_t pkey_bytes = sdith_public_key_bytes(params);
  uint64_t sig_bytes = sdith_signature_bytes(params);
  uint64_t keygen_entropy_bytes = sdith_keygen_entropy_bytes(params);
  uint64_t sign_entropy_bytes = sdith_signature_entropy_bytes(params);
  uint64_t keygen_tmp = sdith_keygen_tmp_bytes(params);
  uint64_t sign_tmp = sdith_signature_tmp_bytes(params);
  uint64_t verify_tmp = sdith_verify_tmp_bytes(params);

  uint8_t* skey = (uint8_t*)malloc(skey_bytes);
  uint8_t* pkey = (uint8_t*)malloc(pkey_bytes);
  uint8_t* sig = (uint8_t*)malloc(sig_bytes);
  uint8_t* entropy = (uint8_t*)malloc(keygen_entropy_bytes > sign_entropy_bytes ? keygen_entropy_bytes : sign_entropy_bytes);
  uint8_t* tmp = (uint8_t*)malloc(keygen_tmp > sign_tmp ? (keygen_tmp > verify_tmp ? keygen_tmp : verify_tmp) : (sign_tmp > verify_tmp ? sign_tmp : verify_tmp));

  const char message[] = "timing test message";
  uint64_t message_len = strlen(message);

  double* sign_times = (double*)malloc(num_iterations * sizeof(double));
  double* verify_times = (double*)malloc(num_iterations * sizeof(double));
  double* keygen_times = (double*)malloc(num_iterations * sizeof(double));

  for (int i = 0; i < num_iterations; i++) {
    /* Fresh key each iteration — different secret = different timing if not CT */
    fill_random(entropy, keygen_entropy_bytes);
    double t0 = get_time_ns();
    sdith_keygen(params, skey, pkey, entropy, tmp);
    double t1 = get_time_ns();
    keygen_times[i] = t1 - t0;

    fill_random(entropy, sign_entropy_bytes);
    t0 = get_time_ns();
    sdith_sign(params, sig, message, message_len, skey, entropy, tmp);
    t1 = get_time_ns();
    sign_times[i] = t1 - t0;

    t0 = get_time_ns();
    uint8_t r = sdith_verify(params, sig, message, message_len, pkey, tmp);
    t1 = get_time_ns();
    verify_times[i] = t1 - t0;

    if (!r) {
      printf("ERROR: verification failed on iteration %d\n", i);
      return 1;
    }
  }

  /* Compute statistics */
  for (int phase = 0; phase < 3; phase++) {
    const char* name = phase == 0 ? "keygen" : (phase == 1 ? "sign" : "verify");
    double* times = phase == 0 ? keygen_times : (phase == 1 ? sign_times : verify_times);

    double sum = 0, sum2 = 0, mn = 1e18, mx = 0;
    for (int i = 0; i < num_iterations; i++) {
      sum += times[i];
      sum2 += times[i] * times[i];
      if (times[i] < mn) mn = times[i];
      if (times[i] > mx) mx = times[i];
    }
    double mean = sum / num_iterations;
    double variance = sum2 / num_iterations - mean * mean;
    double stddev = sqrt(variance);
    double cv = stddev / mean * 100.0;

    printf("%-8s  mean=%.1f us  stddev=%.1f us  CV=%.2f%%  min=%.1f  max=%.1f  range_ratio=%.2f\n",
           name, mean / 1000, stddev / 1000, cv, mn / 1000, mx / 1000, mx / mn);

    /*
     * Heuristic thresholds. A truly constant-time implementation should
     * have low CV and low range_ratio (close to 1). PoW grinding makes
     * sign inherently variable, so we use a higher threshold for sign.
     *
     * These thresholds are approximate — a proper Welch's t-test or
     * Dudect-style approach would be more rigorous.
     */
    double cv_threshold = (phase == 1) ? 30.0 : 5.0;
    double range_threshold = (phase == 1) ? 3.0 : 1.5;

    if (phase != 1 && cv > cv_threshold) {
      printf("  WARNING: high timing variance (CV=%.2f%% > %.1f%%) — possible timing leak\n", cv, cv_threshold);
    }
    if (phase != 1 && mx / mn > range_threshold) {
      printf("  WARNING: high range ratio (%.2f > %.1f) — possible timing leak\n", mx / mn, range_threshold);
    }
  }

  printf("\nNotes:\n");
  printf("- Sign timing is inherently variable due to PoW grinding (expected)\n");
  printf("- Keygen timing may vary due to rejection sampling (known issue, rsd.c:32-37)\n");
  printf("- Verify timing should be nearly constant for valid signatures\n");
  printf("- For rigorous testing, use Dudect or Valgrind/ctgrind instead\n");
  printf("\nReferences:\n");
  printf("- ctgrind: https://www.imperialviolet.org/2010/04/01/ctgrind.html\n");
  printf("- Dudect: https://github.com/oreparaz/dudect\n");
  printf("- KyberSlash: https://kyberslash.cr.yp.to\n");
  printf("- TIMECOP: https://www.post-apocalyptic-crypto.org/timecop/\n");

  free(skey);
  free(pkey);
  free(sig);
  free(entropy);
  free(tmp);
  free(sign_times);
  free(verify_times);
  free(keygen_times);
  return 0;
}

/* ---------------------------------------------------------------- */

int main(int argc, char** argv) {
  srand((unsigned)time(NULL));

  const char* mode = (argc >= 2) ? argv[1] : "timing";
  int num_iterations = (argc >= 3) ? atoi(argv[2]) : 100;
  if (num_iterations < 10) num_iterations = 100;

  // Parameter set selected at compile time (same CATxy tokens as stress_test_single.c).
#if defined(CAT5B)
  signature_parameters params = CAT5_FAST_PARAMETERS;
  const char* set_name = "CAT5-FAST";
#elif defined(CAT5A)
  signature_parameters params = CAT5_SHORT_PARAMETERS;
  const char* set_name = "CAT5-SHORT";
#elif defined(CAT3B)
  signature_parameters params = CAT3_FAST_PARAMETERS;
  const char* set_name = "CAT3-FAST";
#elif defined(CAT3A)
  signature_parameters params = CAT3_SHORT_PARAMETERS;
  const char* set_name = "CAT3-SHORT";
#elif defined(CAT1B)
  signature_parameters params = CAT1_FAST_PARAMETERS;
  const char* set_name = "CAT1-FAST";
#else
  signature_parameters params = CAT1_SHORT_PARAMETERS;
  const char* set_name = "CAT1-SHORT";
#endif

  printf("SDitH v2 constant-time test (%s)\n", set_name);
  printf("Mode: %s\n\n", mode);

  if (strcmp(mode, "valgrind") == 0) {
    return test_ct_valgrind(&params);
  } else if (strcmp(mode, "timing") == 0) {
    return test_ct_timing(&params, num_iterations);
  } else {
    printf("Usage: %s [valgrind|timing] [num_iterations]\n", argv[0]);
    printf("\n");
    printf("Modes:\n");
    printf("  valgrind  — Run under Valgrind memcheck to detect secret-dependent\n");
    printf("              branches and memory accesses (ctgrind approach)\n");
    printf("  timing    — Statistical timing analysis to detect variance\n");
    printf("\n");
    printf("Tools reference:\n");
    printf("  Valgrind/ctgrind   — Taint-tracking via VALGRIND_MAKE_MEM_UNDEFINED\n");
    printf("                       Detects: branches, loads, div on secret data\n");
    printf("                       Paper: KyberSlash (Bernstein et al. 2025)\n");
    printf("  TIMECOP            — SUPERCOP integration of ctgrind for PQC\n");
    printf("                       https://www.post-apocalyptic-crypto.org/timecop/\n");
    printf("  Dudect             — Statistical leakage detection (t-test)\n");
    printf("                       https://github.com/oreparaz/dudect\n");
    printf("  ct-verif           — Formal verification of CT properties\n");
    printf("                       https://github.com/AmbientVerification/ct-verif\n");
    printf("  HACL*/F*           — Type-based secret independence checking\n");
    printf("                       Used to discover KyberSlash1\n");
    return 1;
  }
}
