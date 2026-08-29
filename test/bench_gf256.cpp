#include <benchmark/benchmark.h>

#include "testlib/testlib.h"
#include "vole_private.h"

typedef typeof(gf256_product_ref) gf256_binop_f;
static void BM_gf256_binop(benchmark::State& state, gf256_binop_f gf256_binop) {
  gf256 a, b, c;
  randomize_primitive_var(a);
  randomize_primitive_var(b);
  randomize_primitive_var(c);
  for (auto _ : state) {
    gf256_binop(&c, &a, &b);
  }
}
static void BM_gf256_sum_ref(benchmark::State& state) { BM_gf256_binop(state, gf256_sum_ref); }
static void BM_gf256_product_ref(benchmark::State& state) { BM_gf256_binop(state, gf256_product_ref); }
static void BM_gf256_product_f2_ref(benchmark::State& state) { BM_gf256_binop(state, gf256_product_f2_ref); }

#ifdef __x86_64__
static void BM_gf256_sum_avx2(benchmark::State& state) { BM_gf256_binop(state, gf256_sum_avx2); }
static void BM_gf256_product_pclmul(benchmark::State& state) { BM_gf256_binop(state, gf256_product_pclmul); }
static void BM_gf256_product_pclmul_f2(benchmark::State& state) { BM_gf256_binop(state, gf256_product_pclmul_f2); }
#endif

typedef typeof(gf256_inverse_ref) gf256_unop_f;
static void BM_gf256_unop(benchmark::State& state, gf256_unop_f gf256_unop) {
  gf256 a, c;
  randomize_primitive_var(a);
  randomize_primitive_var(c);
  for (auto _ : state) {
    gf256_unop(&c, &a);
  }
}
static void BM_gf256_inverse_ref(benchmark::State& state) { BM_gf256_unop(state, gf256_inverse_ref); }
#ifdef __x86_64__
static void BM_gf256_inverse_pclmul(benchmark::State& state) { BM_gf256_unop(state, gf256_inverse_pclmul); }
#endif

typedef typeof(gf256_sum_pow2_naive) gf256_sum_pow2_f;
static void BM_gf256_sum_pow2(benchmark::State& state, gf256_sum_pow2_f gf256_sum_pow2) {
  gf256 a[256];
  gf256 c;
  randomize_static_array(a);
  randomize_primitive_var(c);
  for (auto _ : state) {
    gf256_sum_pow2(&c, a);
  }
}
static void BM_gf256_sum_pow2_naive(benchmark::State& state) { BM_gf256_sum_pow2(state, gf256_sum_pow2_naive); }
static void BM_gf256_sum_pow2_ref(benchmark::State& state) { BM_gf256_sum_pow2(state, gf256_sum_pow2_ref); }

BENCHMARK(BM_gf256_sum_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf256_sum_avx2);
#endif
BENCHMARK(BM_gf256_product_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf256_product_pclmul);
#endif
BENCHMARK(BM_gf256_inverse_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf256_inverse_pclmul);
#endif
BENCHMARK(BM_gf256_sum_pow2_naive);
BENCHMARK(BM_gf256_sum_pow2_ref);
BENCHMARK(BM_gf256_product_f2_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf256_product_pclmul_f2);
#endif
BENCHMARK_MAIN();
