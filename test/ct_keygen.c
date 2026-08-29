/*
 * Keygen-only constant-time gate (ctgrind).
 *
 * Poisons ONLY the sk_seed half of the keygen entropy (pk_seed is public output
 * and may legitimately drive branches/addresses, e.g. H expansion), runs
 * sdith_keygen, and lets valgrind memcheck flag any secret-dependent branch or
 * memory access.
 *
 * The position sampler's rejection loop (rsd.c `while (pos >= npw_max)`) is an
 * accepted, secret-independent timing channel: its trip count depends only on
 * the raw rng stream, not on the accepted solution. It is whitelisted via
 * test/ct_keygen.supp. Any OTHER report is a real leak and fails the gate
 * (--error-exitcode=1).
 *
 * Meaningful only on the avx parameter table (the hardened ct helpers). The ref
 * table is the readable definition and the compiler may turn its masks back into
 * branches, so a ref build is expected to fail this gate.
 *
 * Build:  cmake -B build -DWITH_VALGRIND=ON && cmake --build build --target ct_keygen_CAT1_SHORT
 * Run:    valgrind --error-exitcode=1 --suppressions=test/ct_keygen.supp ./ct_keygen_CAT1_SHORT
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "sdith_signature.h"

#ifdef WITH_VALGRIND
#include <valgrind/memcheck.h>
#define CT_POISON(a, n) VALGRIND_MAKE_MEM_UNDEFINED(a, n)
#define CT_UNPOISON(a, n) VALGRIND_MAKE_MEM_DEFINED(a, n)
#else
#define CT_POISON(a, n) ((void)0)
#define CT_UNPOISON(a, n) ((void)0)
#endif

static void fill_random(void* buf, size_t len) {
  uint8_t* p = (uint8_t*)buf;
  for (size_t i = 0; i < len; i++) p[i] = (uint8_t)rand();
}

int main(void) {
#if defined(CAT5B)
  signature_parameters params = CAT5_FAST_PARAMETERS;
#elif defined(CAT5A)
  signature_parameters params = CAT5_SHORT_PARAMETERS;
#elif defined(CAT3B)
  signature_parameters params = CAT3_FAST_PARAMETERS;
#elif defined(CAT3A)
  signature_parameters params = CAT3_SHORT_PARAMETERS;
#elif defined(CAT1B)
  signature_parameters params = CAT1_FAST_PARAMETERS;
#else
  signature_parameters params = CAT1_SHORT_PARAMETERS;
#endif

  const uint64_t lambda_bytes = params.lambda / 8;
  const uint64_t skey_bytes = sdith_secret_key_bytes(&params);
  const uint64_t pkey_bytes = sdith_public_key_bytes(&params);
  const uint64_t entropy_bytes = sdith_keygen_entropy_bytes(&params);
  const uint64_t tmp_bytes = sdith_keygen_tmp_bytes(&params);

  uint8_t* skey = (uint8_t*)malloc(skey_bytes);
  uint8_t* pkey = (uint8_t*)malloc(pkey_bytes);
  uint8_t* entropy = (uint8_t*)malloc(entropy_bytes);
  uint8_t* tmp = (uint8_t*)malloc(tmp_bytes);

  fill_random(entropy, entropy_bytes);
  /* entropy = pk_seed (public) || sk_seed (secret): poison the sk_seed part only */
  CT_POISON(entropy + lambda_bytes, entropy_bytes - lambda_bytes);

  sdith_keygen(&params, skey, pkey, entropy, tmp);

  CT_UNPOISON(pkey, pkey_bytes);
  printf("keygen ct gate ran (any valgrind error above, other than the whitelisted rejection loop, is a leak)\n");

  free(skey);
  free(pkey);
  free(entropy);
  free(tmp);
  return 0;
}
