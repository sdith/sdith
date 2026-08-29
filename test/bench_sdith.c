#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "cpucycles.h"
#include "sdith_signature.h"
#include "vole_private.h"

double get_time() { return (double)clock() / (double)CLOCKS_PER_SEC; }

static int compare_double(const void* a, const void* b) { return *(double*)a > *(double*)b; }

static int compare_u64(const void* a, const void* b) {
  uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
  return (x > y) - (x < y);
}

int main(int argc, char** argv) {
  signature_parameters sig_params = {};
#if defined(CAT5B)
  sig_params = CAT5_FAST_PARAMETERS;
#elif defined(CAT5A)
  sig_params = CAT5_SHORT_PARAMETERS;
#elif defined(CAT3B)
  sig_params = CAT3_FAST_PARAMETERS;
#elif defined(CAT3A)
  sig_params = CAT3_SHORT_PARAMETERS;
#elif defined(CAT1B)
  sig_params = CAT1_FAST_PARAMETERS;
#elif defined(CAT1A)
  sig_params = CAT1_SHORT_PARAMETERS;
#else
#error NO parameter defined
#endif
  extended_parameters_t par;
  compute_extended_parameters(&par, &sig_params);

  printf("params...................: lambda=%" PRId64 "\n", par.lambda);
  printf("ggm......................: tau=%" PRId64 ",kappa=%" PRId64 "\n", par.tau, par.kappa);
  printf("proof-of-work:...........: topen=%" PRId64 ",proofow_w=%" PRId64 "\n", par.target_topen, par.proofow_w);
  printf("rsd......................: n=%" PRId64 ",w=%" PRId64 ",codim=%" PRId64 "\n",  //
         par.rsd_n, par.rsd_w, par.rsd_codim);
  printf("muxes....................: [%" PRId64 "", par.mux_arities[0]);
  {
    for (uint64_t i = 1; i < par.mux_depth; ++i) {
      printf(",%" PRId64 "", par.mux_arities[i]);
    }
  }
  printf("]\n");
  const uint64_t sign_bytes = sdith_signature_bytes(&sig_params);
  const uint64_t skey_bytes = sdith_secret_key_bytes(&sig_params);
  const uint64_t pkey_bytes = sdith_public_key_bytes(&sig_params);
  printf("sign_bytes ..............: %" PRId64 "\n", sign_bytes);
  printf("pkey_bytes ..............: %" PRId64 "\n", pkey_bytes);
  printf("skey_bytes ..............: %" PRId64 "\n", skey_bytes);

  const char message[] = "Hello World!";
  const uint64_t message_bytes = strlen(message);

  const uint64_t keygen_entropy_bytes = sdith_keygen_entropy_bytes(&sig_params);
  const uint64_t sign_entropy_bytes = sdith_signature_entropy_bytes(&sig_params);
  const uint64_t keygen_tmp_bytes = sdith_keygen_tmp_bytes(&sig_params);
  const uint64_t sign_tmp_bytes = sdith_signature_tmp_bytes(&sig_params);
  const uint64_t verify_tmp_bytes = sdith_verify_tmp_bytes(&sig_params);
  const uint64_t tmp_bytes = sign_tmp_bytes | verify_tmp_bytes | keygen_tmp_bytes;
  uint8_t* keygen_entropy = malloc(keygen_entropy_bytes);
  uint8_t* sign_entropy = malloc(sign_entropy_bytes);
  uint8_t* tmp_space = malloc(tmp_bytes);
  memset(sign_entropy, 0, sign_entropy_bytes);    // put some randomness
  memset(keygen_entropy, 0, sign_entropy_bytes);  // put some randomness
  uint8_t* signature = malloc(sign_bytes);

  uint8_t* secret_key = malloc(skey_bytes);
  uint8_t* public_key = malloc(pkey_bytes);

  sdith_keygen(&sig_params, secret_key, public_key, keygen_entropy, tmp_space);

  sdith_sign(&sig_params, signature, message, message_bytes, secret_key, sign_entropy, tmp_space);

  uint8_t verif_chk = sdith_verify(&sig_params, signature, message, message_bytes, public_key, tmp_space);

  CREQUIRE(verif_chk, "bug: verification failed!!");

  printf("Making an histogram...........:\n");
  uint64_t num_sigs = 201;
  double* tsig = malloc(num_sigs * sizeof(double));
  double* tver = malloc(num_sigs * sizeof(double));
  uint64_t* csig = malloc(num_sigs * sizeof(uint64_t));
  uint64_t* cver = malloc(num_sigs * sizeof(uint64_t));
  for (uint64_t i = 0; i < num_sigs; i++) {
    if (++sign_entropy[0] == 0) ++sign_entropy[1];
    double t1 = get_time();
    uint64_t k1 = cpucycles();
    sdith_sign(&sig_params, signature, message, message_bytes, secret_key, sign_entropy, tmp_space);
    uint64_t k2 = cpucycles();
    double t2 = get_time();
    verif_chk = sdith_verify(&sig_params, signature, message, message_bytes, public_key, tmp_space);
    uint64_t k3 = cpucycles();
    double t3 = get_time();
    CREQUIRE(verif_chk, "bug!!");
    tsig[i] = (t2 - t1);
    tver[i] = (t3 - t2);
    csig[i] = k2 - k1;
    cver[i] = k3 - k2;
  }
  qsort(tsig, num_sigs, 8, compare_double);
  qsort(tver, num_sigs, 8, compare_double);
  qsort(csig, num_sigs, sizeof(uint64_t), compare_u64);
  qsort(cver, num_sigs, sizeof(uint64_t), compare_u64);
  printf("percentile      sig_time     ver_time\n");
  for (uint64_t i = 0; i <= 100; i += 10) {
    printf("%3" PRId64 "%%            %.6lf     %.6lf\n", i, tsig[i * 2], tver[i * 2]);
  }
  printf("median %s: sign=%" PRIu64 "  verify=%" PRIu64 "\n", CPUCYCLES_UNIT, csig[num_sigs / 2],
         cver[num_sigs / 2]);

  free(tsig);
  free(tver);
  free(csig);
  free(cver);
  free(signature);
  free(secret_key);
  free(public_key);
  free(keygen_entropy);
  free(sign_entropy);
  free(tmp_space);
  return 0;
}
