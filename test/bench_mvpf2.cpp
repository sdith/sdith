#include <benchmark/benchmark.h>

#include <random>

#include "sdith_algebra.h"
#include "testlib/testlib.h"

static void BM_matrix_vector_product_f2_ref(benchmark::State& state) {
  uint64_t nrows = 260;
  uint64_t ncols = 4000;

  // Calculate sizes
  uint64_t a_bytes = (nrows * ncols) / 8;
  uint64_t b_bytes = ncols / 8;
  uint64_t res_bytes = (nrows + 7) / 8;

  // Allocate memory
  std::vector<uint8_t> a_v(a_bytes);
  bitmat_t* a = (bitmat_t*)a_v.data();
  randomize(a, a_bytes);
  std::vector<uint8_t> b_v(b_bytes);
  bitvec_t* b = (bitvec_t*)b_v.data();
  randomize(b, b_bytes);
  std::vector<uint8_t> res_ref_v(res_bytes);
  bitvec_t* res_ref = (bitvec_t*)res_ref_v.data();

  for (auto _ : state) {
    for (uint64_t i = 0; i < 500; ++i) {
      matrix_vector_product_f2_ref(nrows, ncols, res_ref, a, b);
    }
  }
}

#ifdef __x86_64__
static void BM_matrix_vector_product_f2_avx2(benchmark::State& state) {
  uint64_t nrows = 260;
  uint64_t ncols = 4000;

  // Calculate sizes
  uint64_t a_bytes = (nrows * ncols) / 8;
  uint64_t b_bytes = ncols / 8;
  uint64_t res_bytes = (nrows + 7) / 8;

  // Allocate memory
  std::vector<uint8_t> a_v(a_bytes);
  bitmat_t* a = (bitmat_t*)a_v.data();
  randomize(a, a_bytes);
  std::vector<uint8_t> b_v(b_bytes);
  bitvec_t* b = (bitvec_t*)b_v.data();
  randomize(b, b_bytes);
  std::vector<uint8_t> res_avx_v(res_bytes);
  bitvec_t* res_avx = (bitvec_t*)res_avx_v.data();

  for (auto _ : state) {
    for (uint64_t i = 0; i < 500; ++i) {
      matrix_vector_product_f2_avx2(nrows, ncols, res_avx, a, b);
    }
  }
}
#endif

static void BM_matrix_f2_times_vector_flambda_ref(benchmark::State& state, const uint64_t lambda_bits = 256) {
  // Realistic consistency-check sizes per category: nrows = cchk_nrows, ncols ~ L.
  //   CAT1 (128): kappa=11,tau=16 -> nrows=144, L=1144
  //   CAT3 (192): kappa=12,tau=16 -> nrows=208, L=1664
  //   CAT5 (256): kappa=12,tau=21 -> nrows=272, L=2184
  uint64_t nrows = (lambda_bits == 128) ? 144 : (lambda_bits == 192) ? 208 : 272;
  uint64_t ncols = (lambda_bits == 128) ? 1000 : (lambda_bits == 192) ? 1456 : 1912;
  int lambda = lambda_bits >> 3;

  // Calculate sizes
  uint64_t a_bytes = (nrows * ncols) / 8;
  uint64_t b_bytes = ncols * lambda;
  uint64_t res_bytes = nrows * lambda;

  // Allocate memory
  std::vector<uint8_t> a_v(a_bytes);
  bitmat_t* a = (bitmat_t*)a_v.data();
  randomize(a, a_bytes);
  std::vector<uint8_t> b_v(b_bytes);
  flambda_t* b = (flambda_t*)b_v.data();
  randomize(b, b_bytes);
  std::vector<uint8_t> res_avx_v(res_bytes);
  flambda_t* res_avx = (flambda_t*)res_avx_v.data();

  for (auto _ : state) {
    for (uint64_t i = 0; i < 500; ++i) {
      matrix_f2_times_vector_flambda_ref(lambda_bits, nrows, ncols, res_avx, a, b);
    }
  }
}

static void BM_matrix_f2_times_vector_flambda_ref_128(benchmark::State& state) {
  BM_matrix_f2_times_vector_flambda_ref(state, 128);
}

static void BM_matrix_f2_times_vector_flambda_ref_192(benchmark::State& state) {
  BM_matrix_f2_times_vector_flambda_ref(state, 192);
}

static void BM_matrix_f2_times_vector_flambda_ref_256(benchmark::State& state) {
  BM_matrix_f2_times_vector_flambda_ref(state, 256);
}

#ifdef __x86_64__
static void BM_matrix_f2_times_vector_flambda_avx2(benchmark::State& state, const uint64_t lambda_bits = 256) {
  // Realistic consistency-check sizes per category: nrows = cchk_nrows, ncols ~ L.
  //   CAT1 (128): kappa=11,tau=16 -> nrows=144, L=1144
  //   CAT3 (192): kappa=12,tau=16 -> nrows=208, L=1664
  //   CAT5 (256): kappa=12,tau=21 -> nrows=272, L=2184
  uint64_t nrows = (lambda_bits == 128) ? 144 : (lambda_bits == 192) ? 208 : 272;
  uint64_t ncols = (lambda_bits == 128) ? 1000 : (lambda_bits == 192) ? 1456 : 1912;
  int lambda = lambda_bits >> 3;

  // Calculate sizes
  uint64_t a_bytes = (nrows * ncols) / 8;
  uint64_t b_bytes = ncols * lambda;
  uint64_t res_bytes = nrows * lambda;

  // Allocate memory
  std::vector<uint8_t> a_v(a_bytes);
  bitmat_t* a = (bitmat_t*)a_v.data();
  randomize(a, a_bytes);
  std::vector<uint8_t> b_v(b_bytes);
  flambda_t* b = (flambda_t*)b_v.data();
  randomize(b, b_bytes);
  std::vector<uint8_t> res_avx_v(res_bytes);
  flambda_t* res_avx = (flambda_t*)res_avx_v.data();

  for (auto _ : state) {
    for (uint64_t i = 0; i < 500; ++i) {
      matrix_f2_times_vector_flambda_avx2(lambda_bits, nrows, ncols, res_avx, a, b);
    }
  }
}

static void BM_matrix_f2_times_vector_flambda_avx2_128(benchmark::State& state) {
  BM_matrix_f2_times_vector_flambda_avx2(state, 128);
}

static void BM_matrix_f2_times_vector_flambda_avx2_192(benchmark::State& state) {
  BM_matrix_f2_times_vector_flambda_avx2(state, 192);
}

static void BM_matrix_f2_times_vector_flambda_avx2_256(benchmark::State& state) {
  BM_matrix_f2_times_vector_flambda_avx2(state, 256);
}
#endif

BENCHMARK(BM_matrix_vector_product_f2_ref);
#ifdef __x86_64__
BENCHMARK(BM_matrix_vector_product_f2_avx2);
#endif

BENCHMARK(BM_matrix_f2_times_vector_flambda_ref_128);
BENCHMARK(BM_matrix_f2_times_vector_flambda_ref_192);
BENCHMARK(BM_matrix_f2_times_vector_flambda_ref_256);

#ifdef __x86_64__
BENCHMARK(BM_matrix_f2_times_vector_flambda_avx2_128);
BENCHMARK(BM_matrix_f2_times_vector_flambda_avx2_192);
BENCHMARK(BM_matrix_f2_times_vector_flambda_avx2_256);
#endif

BENCHMARK_MAIN();
