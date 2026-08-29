#include <gtest/gtest.h>

#include <cmath>
#include <cstring>
#include <vector>

#include "sdith_rsd.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/vole_testlib.h"
#include "vole_private.h"

// Distributional test for the RSD solution sampler (rsd.c:29-38). The sampler
// draws each of the `w` block positions uniformly in [0, npw) by reading a
// uniform uint32 and rejecting the biased tail (pos >= npw_max) before taking
// pos % npw. This is a chi-square goodness-of-fit test that the sampled
// positions are uniform over the npw bins -- it complements the existing bounds
// check (ASSERT_LT(solution[i], npw)) and the KAT/differential vectors with a
// statistical check that catches skew / off-by-one / PRG-wiring bugs.
//
// It is deterministic (a fixed sk_seed sequence) so it never flakes. Note that
// for realistic npw << 2^32 the rejection tail is astronomically rare, so this
// exercises the uniformity of `pos % npw`, not the rejection branch itself
// (which only matters for npw near 2^32, unreachable with real parameters).

static void assert_uniform_positions(uint64_t lambda, uint64_t npw, uint64_t rsd_w, uint64_t iters) {
  vole_parameters vole_params;
  vole_parameters_init_ref(&vole_params, lambda, 0, 0);
  const uint64_t rsd_codim = 16;  // small: the (unused-here) syndrome stays cheap
  const uint64_t rsd_n = rsd_w * npw;
  const uint64_t col_bytes = (rsd_codim + 7) / 8;
  ASSERT_GE(rsd_n, rsd_codim);

  std::vector<uint64_t> hist(npw, 0);
  bit_vector y(rsd_codim);
  std::vector<uint32_t> solution(rsd_w);
  const bit_vector pk_seed = bit_vector::zero(lambda);  // does not affect the solution
  std::vector<uint8_t> tmp(rsd_generate_random_instance_tmp_bytes(&vole_params, rsd_w, rsd_n, rsd_codim));

  for (uint64_t it = 0; it < iters; it++) {
    bit_vector sk_seed = bit_vector::zero(lambda);
    std::memcpy(sk_seed.data(), &it, sizeof(it));  // deterministic, distinct per iter
    rsd_generate_random_instance_ref(  //
        rsd_w, rsd_n, rsd_codim,       //
        &vole_params,                  //
        y.data(), col_bytes,           //
        solution.data(),               //
        sk_seed.data(), pk_seed.data(), tmp.data());
    for (uint64_t i = 0; i < rsd_w; i++) {
      ASSERT_LT(solution[i], npw);
      hist[solution[i]]++;
    }
  }

  const uint64_t total = iters * rsd_w;
  const double expected = (double)total / (double)npw;
  ASSERT_GE(expected, 10.0) << "too few samples per bin for a meaningful chi-square";
  double chi2 = 0.0;
  for (uint64_t b = 0; b < npw; b++) {
    const double d = (double)hist[b] - expected;
    chi2 += d * d / expected;
  }
  // Null is chi-square(df=npw-1): mean=df, sigma=sqrt(2*df). An ~8-sigma bound
  // is p < 1e-14 -- a correct uniform sampler never trips it, while any gross
  // skew blows far past it. Threshold scales with df so it works for every npw.
  const double df = (double)(npw - 1);
  const double threshold = df + 8.0 * std::sqrt(2.0 * df);
  EXPECT_LT(chi2, threshold) << "non-uniform rsd positions: chi2=" << chi2 << " df=" << df
                             << " threshold=" << threshold << " lambda=" << lambda << " npw=" << npw
                             << " samples=" << total;
}

TEST(rsd, solution_uniform_distribution) {
  // A couple of non-power-of-2 npw values across the three security levels
  // (distinct PRGs: cat1 AES-CTR, cat3/cat5 SHAKE256).
  assert_uniform_positions(/*lambda=*/128, /*npw=*/30, /*rsd_w=*/64, /*iters=*/1000);
  assert_uniform_positions(/*lambda=*/128, /*npw=*/45, /*rsd_w=*/64, /*iters=*/1200);
  assert_uniform_positions(/*lambda=*/192, /*npw=*/30, /*rsd_w=*/64, /*iters=*/1000);
  assert_uniform_positions(/*lambda=*/256, /*npw=*/31, /*rsd_w=*/64, /*iters=*/1000);
}
