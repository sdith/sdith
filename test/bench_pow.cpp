#include <benchmark/benchmark.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>

#include "ggm.h"
#include "sdith_prng.h"
#include "testlib/vole_testlib.h"
#include "vole_parameters.h"

static void BM_grind_aes(benchmark::State& state, uint64_t proofow_w) {
  const uint64_t lambda = 128;
  const uint64_t kappa = 11;
  const uint64_t tau = 11;
  vole_parameters params;
  vole_parameters_init_with_variant(&params, lambda, tau, kappa, PROOFOW_VARIANT_CIPHER);

  bit_vector delta0(lambda);
  bit_vector x = bit_vector::random(2 * lambda);
  uint64_t pow_ctx_v[1024] __attribute((aligned(32))); // TODO use the real size
  proofow_ctx_t* const pow_ctx = (proofow_ctx_t*)pow_ctx_v;
  uint64_t pow_ctr = 0;
  params.proofow_init(pow_ctx, lambda, kappa, tau, proofow_w, x.data());
  for (auto _ : state) {
    params.proofow_grind_w(pow_ctx, delta0.data(), &pow_ctr);
    ++pow_ctr;
  }
}
static void BM_grind_aes_9(benchmark::State& state) { BM_grind_aes(state, 9); }
static void BM_grind_aes_10(benchmark::State& state) { BM_grind_aes(state, 10); }
static void BM_grind_aes_11(benchmark::State& state) { BM_grind_aes(state, 11); }
static void BM_grind_aes_12(benchmark::State& state) { BM_grind_aes(state, 12); }


BENCHMARK(BM_grind_aes_9);
BENCHMARK(BM_grind_aes_10);
BENCHMARK(BM_grind_aes_11);
BENCHMARK(BM_grind_aes_12);

BENCHMARK_MAIN();
