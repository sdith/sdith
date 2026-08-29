#include <benchmark/benchmark.h>

#include "testlib/testlib.h"
#include "vole_private.h"

typedef typeof(gf192_product_ref) gf192_binop_f;
static void BM_gf192_binop(benchmark::State& state, gf192_binop_f gf192_binop) {
  gf192 a, b, c;
  randomize_primitive_var(a);
  randomize_primitive_var(b);
  randomize_primitive_var(c);
  for (auto _ : state) {
    gf192_binop(&c, &a, &b);
  }
}
static void BM_gf192_sum_ref(benchmark::State& state) { BM_gf192_binop(state, gf192_sum_ref); }
static void BM_gf192_product_ref(benchmark::State& state) { BM_gf192_binop(state, gf192_product_ref); }

#ifdef __x86_64__
static void BM_gf192_product_pclmul(benchmark::State& state) { BM_gf192_binop(state, gf192_product_pclmul); }
#endif
static void BM_gf192_product_f2_ref(benchmark::State& state) { BM_gf192_binop(state, gf192_product_f2_ref); }

typedef typeof(gf192_inverse_ref) gf192_unop_f;
static void BM_gf192_unop(benchmark::State& state, gf192_unop_f gf192_unop) {
  gf192 a, c;
  randomize_primitive_var(a);
  randomize_primitive_var(c);
  for (auto _ : state) {
    gf192_unop(&c, &a);
  }
}
static void BM_gf192_inverse_ref(benchmark::State& state) { BM_gf192_unop(state, gf192_inverse_ref); }
#ifdef __x86_64__
static void BM_gf192_inverse_pclmul(benchmark::State& state) { BM_gf192_unop(state, gf192_inverse_pclmul); }
#endif

typedef typeof(gf192_sum_pow2_naive) gf192_sum_pow2_f;
static void BM_gf192_sum_pow2(benchmark::State& state, gf192_sum_pow2_f gf192_sum_pow2) {
  gf192 a[192];
  gf192 c;
  randomize_static_array(a);
  randomize_primitive_var(c);
  for (auto _ : state) {
    gf192_sum_pow2(&c, a);
  }
}
static void BM_gf192_sum_pow2_naive(benchmark::State& state) { BM_gf192_sum_pow2(state, gf192_sum_pow2_naive); }
static void BM_gf192_sum_pow2_ref(benchmark::State& state) { BM_gf192_sum_pow2(state, gf192_sum_pow2_ref); }

BENCHMARK(BM_gf192_sum_ref);
BENCHMARK(BM_gf192_product_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf192_product_pclmul);
#endif
BENCHMARK(BM_gf192_product_f2_ref);
BENCHMARK(BM_gf192_inverse_ref);
#ifdef __x86_64__
BENCHMARK(BM_gf192_inverse_pclmul);
#endif
BENCHMARK(BM_gf192_sum_pow2_naive);
BENCHMARK(BM_gf192_sum_pow2_ref);

BENCHMARK_MAIN();
