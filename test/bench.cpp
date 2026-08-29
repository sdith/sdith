#include <benchmark/benchmark.h>

#include <random>

#include "testlib/testlib.h"
#include "vole_private.h"

typedef typeof(gf128_product_ref) gf128_binop_f;
static void BM_gf128_binop(benchmark::State& state, gf128_binop_f gf128_binop) {
  __uint128_t a = uniform_u128();
  __uint128_t b = uniform_u128();
  __uint128_t c = uniform_u128();
  for (auto _ : state) {
    gf128_binop((gf128*)&c, (gf128*)&a, (gf128*)&b);
  }
}
static void BM_gf128_sum_naive(benchmark::State& state) { BM_gf128_binop(state, gf128_sum_ref); }
static void BM_gf128_product_naive(benchmark::State& state) { BM_gf128_binop(state, gf128_product_ref); }
#ifdef __x86_64__
static void BM_gf128_product_pclmul(benchmark::State& state) { BM_gf128_binop(state, gf128_product_pclmul); }
#endif
static void BM_gf128_product_f2_naive(benchmark::State& state) { BM_gf128_binop(state, gf128_product_f2_ref); }
#ifdef __x86_64__
static void BM_gf128_product_f2_pclmul(benchmark::State& state) { BM_gf128_binop(state, gf128_product_pclmul_f2); }
#endif
typedef typeof(gf128_inverse_ref) gf128_unop_f;
static void BM_gf128_unop(benchmark::State& state, gf128_unop_f gf128_unop) {
  __uint128_t a = uniform_u128();
  __uint128_t c = uniform_u128();
  for (auto _ : state) {
    gf128_unop((gf128*)&c, (gf128*)&a);
  }
}
static void BM_gf128_inverse_ref(benchmark::State& state) { BM_gf128_unop(state, gf128_inverse_ref); }
#ifdef __x86_64__
static void BM_gf128_inverse_pclmul(benchmark::State& state) { BM_gf128_unop(state, gf128_inverse_pclmul); }
#endif

typedef typeof(gf128_sum_pow2_naive) gf128_sum_pow2_f;
static void BM_gf128_sum_pow2(benchmark::State& state, gf128_sum_pow2_f gf128_sum_pow2) {
  __uint128_t a[128];
  __uint128_t c = uniform_u128();
  randomize_static_array(a);
  for (auto _ : state) {
    gf128_sum_pow2((gf128*)&c, (gf128*)&a);
  }
}
static void BM_gf128_sum_pow2_naive(benchmark::State& state) { BM_gf128_sum_pow2(state, gf128_sum_pow2_naive); }
static void BM_gf128_sum_pow2_ref(benchmark::State& state) { BM_gf128_sum_pow2(state, gf128_sum_pow2_ref); }

typedef typeof(transpose_128_128_naive) transpose_128_128_f;
static void BM_transpose_128_128(benchmark::State& state, transpose_128_128_f transpose_128_128) {
  __uint128_t out[128];
  __uint128_t in[128];
  randomize_static_array(out);
  randomize_static_array(in);
  for (auto _ : state) {
    transpose_128_128(out, in);
  }
}
static void BM_transpose_128_128_naive(benchmark::State& state) {
  BM_transpose_128_128(state, transpose_128_128_naive);
}

static void BM_transpose_128_128_ref(benchmark::State& state) {
  __uint128_t x[128];
  randomize_static_array(x);
  for (auto _ : state) {
    transpose_128_128_ref(x);
  }
}

static void BM_transpose_128_L_naive(benchmark::State& state) {
  __uint128_t x[1024], y[1024];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_128_L_naive(y, x, 1024, 1024/8);
  }
}

static void BM_transpose_128_L_ref_aligned(benchmark::State& state) {
  __uint128_t x[1024], y[1024];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_128_L_ref(y, x, 1024, 1024/8);
  }
}

static void BM_transpose_128_L_ref_unaligned(benchmark::State& state) {
  __uint128_t x[1024], y[1016];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_128_L_ref(y, x, 1016, 1024/8);
  }
}

static void BM_transpose_192_L_naive(benchmark::State& state) {
  static const uint64_t L = 1152;
  static const uint64_t Lbytes = L / 8;
  static const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  uint64_t x[3 * Lslice * 8], y[3 * L];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_192_L_naive(y, x, L, Lslice);
  }
}

static void BM_transpose_192_L_ref_aligned(benchmark::State& state) {
  static const uint64_t L = 1152;
  static const uint64_t Lbytes = L / 8;
  static const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  uint64_t x[3 * Lslice * 8], y[3 * L];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_192_L_ref(y, x, L, Lslice);
  }
}

static void BM_transpose_192_L_ref_unaligned(benchmark::State& state) {
  static const uint64_t L = 1144;
  static const uint64_t Lbytes = L / 8;
  static const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  uint64_t x[3 * Lslice * 8], y[3 * L];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_192_L_ref(y, x, L, Lslice);
  }
}

static void BM_transpose_256_L_naive(benchmark::State& state) {
  static const uint64_t L = 1024;
  static const uint64_t Lbytes = L / 8;
  static const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  __uint128_t x[2 * Lslice], y[2 * L];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_256_L_naive(y, x, L, Lslice);
  }
}

static void BM_transpose_256_L_ref_aligned(benchmark::State& state) {
  static const uint64_t L = 1024;
  static const uint64_t Lbytes = L / 8;
  static const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  __uint128_t x[2 * Lslice], y[2 * L];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_256_L_ref(y, x, L, Lslice);
  }
}

static void BM_transpose_256_L_ref_unaligned(benchmark::State& state) {
  static const uint64_t L = 1016;
  static const uint64_t Lbytes = L / 8;
  static const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  __uint128_t x[2 * Lslice], y[2 * L];
  randomize_static_array(x);
  randomize_static_array(y);
  for (auto _ : state) {
    transpose_256_L_ref(y, x, L, Lslice);
  }
}

/*
static void BM_ggm(benchmark::State& state) {
  const uint64_t lambda_bytes = 16;
  const uint64_t tree_depth = 15;
  const uint64_t tau = 11;
  const uint64_t kappa = 11;
  const uint64_t N = 1 << kappa;
  std::vector<uint8_t> ggm_tree_vec(bytes_of_ggm_tree(lambda_bytes, tree_depth));
  std::vector<uint8_t> root_seed_vec(lambda_bytes);
  std::vector<uint8_t> node_seed_vec(lambda_bytes);
  ggm_tree* tree = (ggm_tree*)ggm_tree_vec.data();
  uint8_t* root_seed = root_seed_vec.data();
  uint8_t* node_seed = node_seed_vec.data();
  randomize(root_seed, lambda_bytes);
  for (auto _ : state) {
    ggm_tree_init(tree, lambda_bytes, tree_depth, 1, root_seed);
    for (uint64_t i = 0; i < tau * N; ++i) {
      ggm_tree_get_node_seed(tree, tree_depth, i, node_seed);
    }
  }
}
*/

static void BM_hidden_leaves_indexes(benchmark::State& state) {
  const uint64_t kappa = 11;
  const uint64_t tau = 11;
  const uint64_t num_hidden_leaves = 1 << kappa;
  std::vector<uint32_t> hidden_leaves(num_hidden_leaves);
  std::vector<uint32_t> delta_vec(tau);
  uint32_t* hidden_leaves_ptr = hidden_leaves.data();
  uint32_t* delta = delta_vec.data();
  randomize(delta, tau);
  for (auto _ : state) {
    hidden_leaves_indexes(kappa, tau, hidden_leaves_ptr, delta);
  }
}

BENCHMARK(BM_hidden_leaves_indexes);

BENCHMARK(BM_gf128_sum_naive);
BENCHMARK(BM_gf128_product_naive);
#ifdef __x86_64__
BENCHMARK(BM_gf128_product_pclmul);
#endif
BENCHMARK(BM_gf128_product_f2_naive);
#ifdef __x86_64__
BENCHMARK(BM_gf128_product_f2_pclmul);
#endif
BENCHMARK(BM_gf128_inverse_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf128_inverse_pclmul);
#endif
BENCHMARK(BM_gf128_sum_pow2_naive);
BENCHMARK(BM_gf128_sum_pow2_ref);
BENCHMARK(BM_transpose_128_128_naive);
BENCHMARK(BM_transpose_128_128_ref);
BENCHMARK(BM_transpose_128_L_naive);
BENCHMARK(BM_transpose_128_L_ref_aligned);
BENCHMARK(BM_transpose_128_L_ref_unaligned);
BENCHMARK(BM_transpose_192_L_naive);
BENCHMARK(BM_transpose_192_L_ref_aligned);
BENCHMARK(BM_transpose_192_L_ref_unaligned);
BENCHMARK(BM_transpose_256_L_naive);
BENCHMARK(BM_transpose_256_L_ref_aligned);
BENCHMARK(BM_transpose_256_L_ref_unaligned);

BENCHMARK_MAIN();
