#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sdith_signature.h"

int main(int argc, char** argv) {
  const int NUM_ITERS = (argc > 1) ? atoi(argv[1]) : 10000;

#if defined(CAT5B)
  signature_parameters sig_params = CAT5_FAST_PARAMETERS;
  const char* name = "CAT5-FAST";
#elif defined(CAT5A)
  signature_parameters sig_params = CAT5_SHORT_PARAMETERS;
  const char* name = "CAT5-SHORT";
#elif defined(CAT3B)
  signature_parameters sig_params = CAT3_FAST_PARAMETERS;
  const char* name = "CAT3-FAST";
#elif defined(CAT3A)
  signature_parameters sig_params = CAT3_SHORT_PARAMETERS;
  const char* name = "CAT3-SHORT";
#elif defined(CAT1B)
  signature_parameters sig_params = CAT1_FAST_PARAMETERS;
  const char* name = "CAT1-FAST";
#else
  signature_parameters sig_params = CAT1_SHORT_PARAMETERS;
  const char* name = "CAT1-SHORT";
#endif

  const uint64_t sign_bytes = sdith_signature_bytes(&sig_params);
  const uint64_t skey_bytes = sdith_secret_key_bytes(&sig_params);
  const uint64_t pkey_bytes = sdith_public_key_bytes(&sig_params);
  const uint64_t keygen_entropy_bytes = sdith_keygen_entropy_bytes(&sig_params);
  const uint64_t sign_entropy_bytes = sdith_signature_entropy_bytes(&sig_params);
  const uint64_t keygen_tmp_bytes = sdith_keygen_tmp_bytes(&sig_params);
  const uint64_t sign_tmp_bytes = sdith_signature_tmp_bytes(&sig_params);
  const uint64_t verify_tmp_bytes = sdith_verify_tmp_bytes(&sig_params);

  uint8_t* sk = calloc(1, skey_bytes);
  uint8_t* pk = calloc(1, pkey_bytes);
  uint8_t* sig = calloc(1, sign_bytes + 256);
  uint8_t* keygen_entropy = calloc(1, keygen_entropy_bytes);
  uint8_t* sign_entropy = calloc(1, sign_entropy_bytes);
  uint8_t* keygen_tmp = calloc(1, keygen_tmp_bytes);
  uint8_t* sign_tmp = calloc(1, sign_tmp_bytes);
  uint8_t* verify_tmp = calloc(1, verify_tmp_bytes);

  if (!sk || !pk || !sig || !keygen_entropy || !sign_entropy ||
      !keygen_tmp || !sign_tmp || !verify_tmp) {
    fprintf(stderr, "allocation failed for %s\n", name);
    return 1;
  }

  unsigned int seed = (unsigned int)time(NULL);
  srand(seed);
  printf("stress_test %s: %d iterations, seed=%u\n", name, NUM_ITERS, seed);
  fflush(stdout);

  int failures = 0;
  double t0 = (double)clock() / CLOCKS_PER_SEC;

  for (int i = 0; i < NUM_ITERS; i++) {
    for (uint64_t j = 0; j < keygen_entropy_bytes; j++)
      keygen_entropy[j] = (uint8_t)rand();
    for (uint64_t j = 0; j < sign_entropy_bytes; j++)
      sign_entropy[j] = (uint8_t)rand();

    uint8_t msg[64];
    int msg_len = 1 + (rand() % 64);
    for (int j = 0; j < msg_len; j++) msg[j] = (uint8_t)rand();

    sdith_keygen(&sig_params, sk, pk, keygen_entropy, keygen_tmp);
    sdith_sign(&sig_params, sig, msg, msg_len, sk, sign_entropy, sign_tmp);
    int verify_ok =
        sdith_verify(&sig_params, sig, msg, msg_len, pk, verify_tmp);

    // sdith_verify returns 1 on success, 0 on failure.
    if (verify_ok == 0) {
      fprintf(stderr, "%s: VERIFY FAILED at iteration %d\n", name, i);
      failures++;
      if (failures >= 10) break;
    }

    if ((i + 1) % 1000 == 0) {
      double elapsed = (double)clock() / CLOCKS_PER_SEC - t0;
      printf("  %s: %d/%d (%.1fs)\n", name, i + 1, NUM_ITERS, elapsed);
      fflush(stdout);
    }
  }

  double elapsed = (double)clock() / CLOCKS_PER_SEC - t0;
  if (failures == 0)
    printf("[PASS] %s: %d/%d sign+verify OK (%.1fs)\n", name, NUM_ITERS,
           NUM_ITERS, elapsed);
  else
    printf("[FAIL] %s: %d failures in %d iterations\n", name, failures,
           NUM_ITERS);

  free(sk); free(pk); free(sig); free(keygen_entropy);
  free(sign_entropy); free(keygen_tmp); free(sign_tmp); free(verify_tmp);
  return failures > 0 ? 1 : 0;
}
