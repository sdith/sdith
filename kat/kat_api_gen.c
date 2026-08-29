// Writes NIST's api.h for one parameter set, from the kat/sdith_cat1_short template.
//
//   kat_api_gen <template api.h> <SET token> <output api.h>
//
// Every line of the template is copied verbatim except the five defines that are
// specific to a parameter set.  The three CRYPTO_*BYTES sizes come from the library
// rather than from a committed file: sign.c abort()s at run time when api.h disagrees
// with the parameters it was built against, and those sizes move whenever the scheme
// is retuned.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sdith_signature.h"

typedef struct {
  const char* token;
  const signature_parameters* params;
} kat_set_t;

static const kat_set_t KAT_SETS[] = {
    {"CAT1_SHORT", &CAT1_SHORT_PARAMETERS},
    {"CAT1_FAST", &CAT1_FAST_PARAMETERS},
    {"CAT3_SHORT", &CAT3_SHORT_PARAMETERS},
    {"CAT3_FAST", &CAT3_FAST_PARAMETERS},
    {"CAT5_SHORT", &CAT5_SHORT_PARAMETERS},
    {"CAT5_FAST", &CAT5_FAST_PARAMETERS},
    {"CAT1_SHORT_CIPHERPOW", &CAT1_SHORT_CIPHERPOW_PARAMETERS},
    {"CAT1_FAST_CIPHERPOW", &CAT1_FAST_CIPHERPOW_PARAMETERS},
    {"CAT3_SHORT_CIPHERPOW", &CAT3_SHORT_CIPHERPOW_PARAMETERS},
    {"CAT3_FAST_CIPHERPOW", &CAT3_FAST_CIPHERPOW_PARAMETERS},
    {"CAT5_SHORT_CIPHERPOW", &CAT5_SHORT_CIPHERPOW_PARAMETERS},
    {"CAT5_FAST_CIPHERPOW", &CAT5_FAST_CIPHERPOW_PARAMETERS},
};
#define NSETS (sizeof(KAT_SETS) / sizeof(KAT_SETS[0]))

#define NDEFINES 5

// "#define <name> " at the start of the line, and nothing else on it.
static int is_define_of(const char* line, const char* name) {
  size_t n = strlen(name);
  return strncmp(line, "#define ", 8) == 0 && strncmp(line + 8, name, n) == 0 && line[8 + n] == ' ';
}

int main(int argc, char** argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <template api.h> <SET token> <output api.h>\n", argv[0]);
    return 2;
  }
  const char* tmpl_path = argv[1];
  const char* token = argv[2];
  const char* out_path = argv[3];

  const signature_parameters* p = NULL;
  for (size_t i = 0; i < NSETS; ++i) {
    if (strcmp(KAT_SETS[i].token, token) == 0) p = KAT_SETS[i].params;
  }
  if (p == NULL) {
    fprintf(stderr, "kat_api_gen: unknown parameter set '%s'\n", token);
    return 1;
  }

  // CRYPTO_ALGNAME is the name NIST's generator writes as the first line of the .rsp,
  // so it is part of the KAT: SDiTH-CAT1-SHORT, hyphens rather than underscores.
  char algname[64], params[64], sk[32], pk[32], sig[32];
  snprintf(algname, sizeof(algname), "\"SDiTH-%s\"", token);
  for (char* c = algname; *c != 0; ++c) {
    if (*c == '_') *c = '-';
  }
  snprintf(params, sizeof(params), "%s_PARAMETERS", token);
  snprintf(sk, sizeof(sk), "%llu", (unsigned long long)sdith_secret_key_bytes(p));
  snprintf(pk, sizeof(pk), "%llu", (unsigned long long)sdith_public_key_bytes(p));
  snprintf(sig, sizeof(sig), "%llu", (unsigned long long)sdith_signature_bytes(p));

  const char* names[NDEFINES] = {"CRYPTO_SECRETKEYBYTES", "CRYPTO_PUBLICKEYBYTES", "CRYPTO_BYTES",
                                 "CRYPTO_ALGNAME", "SIGNATURE_PARAMS"};
  const char* values[NDEFINES] = {sk, pk, sig, algname, params};
  int hits[NDEFINES] = {0};

  FILE* in = fopen(tmpl_path, "r");
  if (in == NULL) {
    fprintf(stderr, "kat_api_gen: cannot read the template %s\n", tmpl_path);
    return 1;
  }
  FILE* out = fopen(out_path, "w");
  if (out == NULL) {
    fprintf(stderr, "kat_api_gen: cannot write %s\n", out_path);
    fclose(in);
    return 1;
  }

  char line[4096];
  while (fgets(line, sizeof(line), in) != NULL) {
    int substituted = 0;
    for (int i = 0; i < NDEFINES; ++i) {
      if (is_define_of(line, names[i])) {
        fprintf(out, "#define %s %s\n", names[i], values[i]);
        hits[i]++;
        substituted = 1;
        break;
      }
    }
    if (!substituted) fputs(line, out);
  }
  fclose(in);
  if (fclose(out) != 0) {
    fprintf(stderr, "kat_api_gen: could not flush %s\n", out_path);
    return 1;
  }

  for (int i = 0; i < NDEFINES; ++i) {
    if (hits[i] != 1) {
      fprintf(stderr, "kat_api_gen: %s defines %s %d times, expected exactly once\n", tmpl_path, names[i],
              hits[i]);
      remove(out_path);
      return 1;
    }
  }
  return 0;
}
