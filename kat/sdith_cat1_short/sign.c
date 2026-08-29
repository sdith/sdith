#include <stdlib.h>
#include <string.h>

#include "sdith_signature.h"
#include "api.h"
#include "rng.h"

// Zeroize secret scratch before free. The write goes through a volatile pointer
// so the compiler cannot drop it as a dead store ahead of free().
static void secure_zeroize(void* ptr, size_t len) {
  volatile unsigned char* p = (volatile unsigned char*)ptr;
  while (len--) *p++ = 0;
}

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk) {
  // safeguard
  if (CRYPTO_BYTES != sdith_signature_bytes(&SIGNATURE_PARAMS) ||
      CRYPTO_PUBLICKEYBYTES != sdith_public_key_bytes(&SIGNATURE_PARAMS) ||
      CRYPTO_SECRETKEYBYTES != sdith_secret_key_bytes(&SIGNATURE_PARAMS))
    abort();  // if it crashes here, it means that api.h is outdated

  uint64_t entropy_bytes = sdith_keygen_entropy_bytes(&SIGNATURE_PARAMS);
  uint64_t tmp_bytes = sdith_keygen_tmp_bytes(&SIGNATURE_PARAMS);
  uint8_t* entropy = malloc(entropy_bytes);
  uint8_t* tmp_space = malloc(tmp_bytes);
  randombytes(entropy, entropy_bytes);
  sdith_keygen(&SIGNATURE_PARAMS, sk, pk, entropy, tmp_space);
  // tmp_space holds the raw solution, entropy holds the sk_seed: wipe both.
  secure_zeroize(tmp_space, tmp_bytes);
  secure_zeroize(entropy, entropy_bytes);
  free(tmp_space);
  free(entropy);
  return 0;
}

int crypto_sign(unsigned char* sm, unsigned long long* smlen, const unsigned char* m, unsigned long long mlen,
                const unsigned char* sk) {
  uint64_t entropy_bytes = sdith_signature_entropy_bytes(&SIGNATURE_PARAMS);
  uint64_t tmp_bytes = sdith_signature_tmp_bytes(&SIGNATURE_PARAMS);
  uint8_t* entropy = malloc(entropy_bytes);
  uint8_t* tmp_space = malloc(tmp_bytes);
  randombytes(entropy, entropy_bytes);
  *smlen = CRYPTO_BYTES + mlen;
  memcpy(sm, m, mlen);
  sdith_sign(&SIGNATURE_PARAMS, sm + mlen, m, mlen, sk, entropy, tmp_space);
  // tmp_space and entropy hold secret signing state: wipe both.
  secure_zeroize(tmp_space, tmp_bytes);
  secure_zeroize(entropy, entropy_bytes);
  free(tmp_space);
  free(entropy);
  return 0;
}

int crypto_sign_open(unsigned char* m, unsigned long long* mlen, const unsigned char* sm, unsigned long long smlen,
                     const unsigned char* pk) {
  if (smlen < CRYPTO_BYTES) return -1;  // reject truncated input (avoid unsigned underflow -> OOB memcpy)
  uint64_t tmp_bytes = sdith_verify_tmp_bytes(&SIGNATURE_PARAMS);
  uint8_t* tmp_space = malloc(tmp_bytes);
  *mlen = smlen - CRYPTO_BYTES;
  memcpy(m, sm, *mlen);
  uint8_t res = sdith_verify(&SIGNATURE_PARAMS, sm + *mlen, m, *mlen, pk, tmp_space);
  free(tmp_space);  // verify touches only public data, nothing to wipe
  return !res;
}
