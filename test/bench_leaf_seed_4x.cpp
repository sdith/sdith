// Microbenchmarks for the 4x leaf-seed expansion: batched extend_leaf_seed_*_4x
// vs calling the 1x function four times, ref + avx2, all three cats. Numbers are
// per seed (SetItemsProcessed = iters * 4), so the 4x is directly comparable to
// the 1x baseline and shows whether the batching brings a speed-up.

#include <benchmark/benchmark.h>

#include <cstdint>
#include <cstring>

#include "sdith_prng.h"
#include "testlib/testlib.h"

// ---------------------------------------------------------------------------
// ref: 1x-called-4-times baseline vs 4x
// ---------------------------------------------------------------------------
static void BM_leaf_cat1_1x4_ref(benchmark::State& s) {
  uint8_t seeds[4 * 16], out[4 * 16 * 11];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    for (int i = 0; i < 4; ++i) extend_leaf_seed_cat1_aes128_ref(out + i * 16 * 11, seeds + i * 16);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat1_4x_ref(benchmark::State& s) {
  uint8_t seeds[4 * 16], out[4 * 16 * 11];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    extend_leaf_seed_cat1_aes128_4x_ref(out, seeds);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat3_1x4_ref(benchmark::State& s) {
  uint8_t seeds[4 * 24], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    for (int i = 0; i < 4; ++i) extend_leaf_seed_cat3_rijndael256_ref(out + i * 480, seeds + i * 24);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat3_4x_ref(benchmark::State& s) {
  uint8_t seeds[4 * 24], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    extend_leaf_seed_cat3_rijndael256_4x_ref(out, seeds);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat5_1x4_ref(benchmark::State& s) {
  uint8_t seeds[4 * 32], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    for (int i = 0; i < 4; ++i) extend_leaf_seed_cat5_rijndael256_ref(out + i * 480, seeds + i * 32);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat5_4x_ref(benchmark::State& s) {
  uint8_t seeds[4 * 32], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    extend_leaf_seed_cat5_rijndael256_4x_ref(out, seeds);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
BENCHMARK(BM_leaf_cat1_1x4_ref);
BENCHMARK(BM_leaf_cat1_4x_ref);
BENCHMARK(BM_leaf_cat3_1x4_ref);
BENCHMARK(BM_leaf_cat3_4x_ref);
BENCHMARK(BM_leaf_cat5_1x4_ref);
BENCHMARK(BM_leaf_cat5_4x_ref);

// ---------------------------------------------------------------------------
// avx2 (x86 only): this is where the batched key schedule is expected to win.
// ---------------------------------------------------------------------------
#ifdef __x86_64__
static void BM_leaf_cat1_1x4_avx2(benchmark::State& s) {
  uint8_t seeds[4 * 16], out[4 * 16 * 11];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    for (int i = 0; i < 4; ++i) extend_leaf_seed_cat1_aes128_avx2(out + i * 16 * 11, seeds + i * 16);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat1_4x_avx2(benchmark::State& s) {
  uint8_t seeds[4 * 16], out[4 * 16 * 11];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    extend_leaf_seed_cat1_aes128_4x_avx2(out, seeds);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat3_1x4_avx2(benchmark::State& s) {
  uint8_t seeds[4 * 24], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    for (int i = 0; i < 4; ++i) extend_leaf_seed_cat3_rijndael256_avx2(out + i * 480, seeds + i * 24);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat3_4x_avx2(benchmark::State& s) {
  uint8_t seeds[4 * 24], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    extend_leaf_seed_cat3_rijndael256_4x_avx2(out, seeds);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat5_1x4_avx2(benchmark::State& s) {
  uint8_t seeds[4 * 32], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    for (int i = 0; i < 4; ++i) extend_leaf_seed_cat5_rijndael256_avx2(out + i * 480, seeds + i * 32);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_leaf_cat5_4x_avx2(benchmark::State& s) {
  uint8_t seeds[4 * 32], out[4 * 480];
  randomize(seeds, sizeof(seeds));
  for (auto _ : s) {
    extend_leaf_seed_cat5_rijndael256_4x_avx2(out, seeds);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
BENCHMARK(BM_leaf_cat1_1x4_avx2);
BENCHMARK(BM_leaf_cat1_4x_avx2);
BENCHMARK(BM_leaf_cat3_1x4_avx2);
BENCHMARK(BM_leaf_cat3_4x_avx2);
BENCHMARK(BM_leaf_cat5_1x4_avx2);
BENCHMARK(BM_leaf_cat5_4x_avx2);
#endif  // __x86_64__

BENCHMARK_MAIN();
