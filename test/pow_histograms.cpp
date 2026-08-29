#include <cstdint>
#include <iostream>
#include <map>

#include <cinttypes>
#include "ggm.h"
#include "sdith_prng.h"
#include "testlib/vole_testlib.h"


int main(int argc, char** argv) {
  uint64_t kappa = 11;
  uint64_t tau = 11;
  if (argc == 3) {
    kappa = std::stoull(argv[1]);
    tau = std::stoull(argv[2]);
  }
  uint64_t num_trials = 1000000;
  uint64_t nbytes = (kappa * tau + 15) & UINT64_C(-16);
  std::vector<double> histogram(kappa * tau + 1, 0);
  std::vector<uint32_t> hidden_leaves_idx(tau);
  std::vector<uint8_t> tmp_space(estimate_topen_tmp_bytes(tau, kappa));
  bit_vector seed(8 * nbytes);  // nbytes is a multiple of 16 -> whole aes128 blocks
  // Statistical tool (not a KAT): any prng is fine. Draw each trial as one matrix
  // prng row; nbytes*8 is a multiple of lambda=128 so rows are unmasked blocks.
  uint8_t key[16] = {};  // fixed key; exact values are irrelevant here
  matrix_rng_t rng;
  matrix_rng_init_aes128_cat1_ref(&rng, key, nbytes * 8);

  for (uint64_t i = 0; i < num_trials; ++i) {
    matrix_rng_get_row_aes128_cat1_ref(&rng, seed.data(), i);
    hidden_leaves_indexes2(kappa, tau, hidden_leaves_idx.data(), seed.data());
    uint64_t topen = estimate_topen(tau, kappa, 1e9, hidden_leaves_idx.data(), tmp_space.data());
    REQUIRE_DRAMATICALLY(topen <= tau * kappa, "bug");
    histogram[topen] += 1;
  }
  //
  std::cout << "Topen proba estimation for kappa=" << kappa << " and tau=" << tau << "\n";
  double cumul = 0;
  for (uint64_t i = 0; i <= tau * kappa; ++i) {
    if (histogram[i] > 0) {
      cumul += histogram[i];
      const double proba = cumul / num_trials;
      printf("%" PRIu64 ",%lf\n", i, 1./proba);
    }
  }
}
