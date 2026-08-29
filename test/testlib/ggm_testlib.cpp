#include <cstring>
#include <iostream>

#include "bit_matrix_layout.h"
#include "sdith_prng.h"
#include "vole_private.h"


GGM_COMMIT_RNG_F* default_ggm_commit_rng(uint64_t lambda) {
  // the trees now consume the extended leaf seed, so wire the ext commit cores.
  switch (lambda) {
    case 128:
      return ggm_commit_rng_ext_cat1_aes128_ref;
    case 192:
      return ggm_commit_rng_ext_cat3_rijndael256_ref;
    case 256:
      return ggm_commit_rng_ext_cat5_rijndael256_ref;
    default:
      REQUIRE_DRAMATICALLY(false, "unsupported lambda");
  }
}

EXTEND_LEAF_SEED_F* default_extend_leaf_seed(uint64_t lambda) {
  switch (lambda) {
    case 128:
      return extend_leaf_seed_cat1_aes128_ref;
    case 192:
      return extend_leaf_seed_cat3_rijndael256_ref;
    case 256:
      return extend_leaf_seed_cat5_rijndael256_ref;
    default:
      REQUIRE_DRAMATICALLY(false, "unsupported lambda");
  }
}

uint64_t default_extended_bytes(uint64_t lambda) {
  switch (lambda) {
    case 128:
      return extended_node_seed_bytes_cat1_aes128();
    case 192:
      return extended_node_seed_bytes_cat3_rijndael256();
    case 256:
      return extended_node_seed_bytes_cat5_rijndael256();
    default:
      REQUIRE_DRAMATICALLY(false, "unsupported lambda");
  }
}

bit_vector delta1_from_delta0(uint64_t kappa, uint64_t tau, uint64_t lambda, const bit_vector& delta0) {
  REQUIRE_DRAMATICALLY(lambda >= tau * kappa, "invalid lambda");
  bit_vector delta1(lambda);
  for (uint64_t i = 0; i < tau; ++i) {
    for (uint64_t k = 0; k < kappa - 1; ++k) {
      delta1.set(i * kappa + k, delta0.get(i * kappa + k) ^ delta0.get(i * kappa + k + 1));
    }
    delta1.set(i * kappa + kappa - 1, delta0.get(i * kappa + kappa - 1));
  }
  return delta1;
}
