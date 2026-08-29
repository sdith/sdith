// Microbenchmarks for the low-level lib/aes primitives:
//   * batched key schedules (aes128 x1..x4, rijndael256 x1..x2)
//   * no-carry CTR encryption (aes128 1..4 block, rijndael256 1..2 block, nblocks)
// Numbers are reported per key / per block (SetItemsProcessed), so x2/x3/x4 are
// directly comparable to x1, and used to decide whether the optional rijndael
// x3/x4 and 3/4-block variants "bring a speed-up".
//
// ref vs avx2 comparison is added with the avx2 implementation (x86 only).

#include <benchmark/benchmark.h>

#include <cstdint>
#include <cstring>

#include "aes128_ctrle.h"
#include "rijndael256_ctrle.h"
#include "testlib/testlib.h"

// ---------------------------------------------------------------------------
// aes128 key schedule (per key)
// ---------------------------------------------------------------------------
static void BM_aes128_set_key_ref(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11];
  randomize(key, sizeof(key));
  for (auto _ : s) {
    aes128_key_schedule_x1_ref(rk, key);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations());
}
static void BM_aes128_key_schedule_x1_ref(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11];
  randomize(key, sizeof(key));
  for (auto _ : s) {
    aes128_key_schedule_x1_ref(rk, key);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations());
}
static void BM_aes128_key_schedule_x4_ref(benchmark::State& s) {
  uint8_t k[4][16], rk[4][16 * 11];
  randomize(k, sizeof(k));
  for (auto _ : s) {
    aes128_key_schedule_x4_ref(rk[0], rk[1], rk[2], rk[3], k[0], k[1], k[2], k[3]);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
BENCHMARK(BM_aes128_set_key_ref);
BENCHMARK(BM_aes128_key_schedule_x1_ref);
BENCHMARK(BM_aes128_key_schedule_x4_ref);

// ---------------------------------------------------------------------------
// aes128 no-carry CTR (per block)
// ---------------------------------------------------------------------------
static void BM_aes128_nocarry_1block_ref(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11], ctr[16], out[16];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  aes128_key_schedule_x1_ref(rk, key);
  for (auto _ : s) {
    aes128_ctrle_nocarry_1block_ref(out, rk, ctr);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations());
}
static void BM_aes128_nocarry_4blocks_ref(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11], ctr[16], out[16 * 4];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  aes128_key_schedule_x1_ref(rk, key);
  for (auto _ : s) {
    aes128_ctrle_nocarry_4blocks_ref(out, rk, ctr);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void BM_aes128_nocarry_nblocks_ref(benchmark::State& s) {
  const uint64_t n = 64;
  uint8_t key[16], rk[16 * 11], ctr[16];
  uint8_t out[16 * 64];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  aes128_key_schedule_x1_ref(rk, key);
  for (auto _ : s) {
    aes128_ctrle_nocarry_nblocks_ref(out, rk, ctr, n);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * n);
}
BENCHMARK(BM_aes128_nocarry_1block_ref);
BENCHMARK(BM_aes128_nocarry_4blocks_ref);
BENCHMARK(BM_aes128_nocarry_nblocks_ref);

// ---------------------------------------------------------------------------
// rijndael256 key schedule (per key)
// ---------------------------------------------------------------------------
static void BM_rijndael256_set_key_ref(benchmark::State& s) {
  uint8_t key[32], rk[RIJNDAEL256_RK_BYTES];
  randomize(key, sizeof(key));
  for (auto _ : s) {
    rijndael256_key_schedule_x1_ref(rk, key);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations());
}
static void BM_rijndael256_key_schedule_x2_ref(benchmark::State& s) {
  uint8_t k[2][32], rk[2][RIJNDAEL256_RK_BYTES];
  randomize(k, sizeof(k));
  for (auto _ : s) {
    rijndael256_key_schedule_x2_ref(rk[0], rk[1], k[0], k[1]);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations() * 2);
}
BENCHMARK(BM_rijndael256_set_key_ref);
BENCHMARK(BM_rijndael256_key_schedule_x2_ref);

// ---------------------------------------------------------------------------
// rijndael256 no-carry CTR (per block)
// ---------------------------------------------------------------------------
static void BM_rijndael256_nocarry_1block_ref(benchmark::State& s) {
  uint8_t key[32], rk[RIJNDAEL256_RK_BYTES], ctr[32], out[32];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  rijndael256_key_schedule_x1_ref(rk, key);
  for (auto _ : s) {
    rijndael256_ctrle_nocarry_1block_ref(out, rk, ctr);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations());
}
static void BM_rijndael256_nocarry_2block_ref(benchmark::State& s) {
  uint8_t key[32], rk[RIJNDAEL256_RK_BYTES], ctr[32], out[32 * 2];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  rijndael256_key_schedule_x1_ref(rk, key);
  for (auto _ : s) {
    rijndael256_ctrle_nocarry_2block_ref(out, rk, ctr);
    benchmark::DoNotOptimize(out);
  }
  s.SetItemsProcessed(s.iterations() * 2);
}
BENCHMARK(BM_rijndael256_nocarry_1block_ref);
BENCHMARK(BM_rijndael256_nocarry_2block_ref);

// ---------------------------------------------------------------------------
// avx2 (x86 only). Sizes match the real usage: exactly 2 blocks, or 1k-2k bytes
// (aes128: 64/128 blocks; rijndael256: 32/64 blocks) — always whole blocks.
// ---------------------------------------------------------------------------
#ifdef __x86_64__
static void BM_aes128_key_schedule_x1_avx2(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11];
  randomize(key, sizeof(key));
  for (auto _ : s) { aes128_key_schedule_x1_avx2(rk, key); benchmark::DoNotOptimize(rk); }
  s.SetItemsProcessed(s.iterations());
}
static void BM_aes128_key_schedule_x4_avx2(benchmark::State& s) {
  uint8_t k[4][16], rk[4][16 * 11];
  randomize(k, sizeof(k));
  for (auto _ : s) {
    aes128_key_schedule_x4_avx2(rk[0], rk[1], rk[2], rk[3], k[0], k[1], k[2], k[3]);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void aes128_nocarry_avx2_bench(benchmark::State& s, uint64_t n) {
  uint8_t key[16], rk[16 * 11], ctr[16];
  std::vector<uint8_t> out(16 * n);
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  aes128_key_schedule_x1_avx2(rk, key);
  for (auto _ : s) { aes128_ctrle_nocarry_nblocks_avx2(out.data(), rk, ctr, n); benchmark::DoNotOptimize(out.data()); }
  s.SetItemsProcessed(s.iterations() * n);
}
static void BM_aes128_nocarry_1block_avx2(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11], ctr[16], out[16];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  aes128_key_schedule_x1_avx2(rk, key);
  for (auto _ : s) { aes128_ctrle_nocarry_1block_avx2(out, rk, ctr); benchmark::DoNotOptimize(out); }
  s.SetItemsProcessed(s.iterations() * 2);
}
static void BM_aes128_nocarry_2block_avx2(benchmark::State& s) {
  uint8_t key[16], rk[16 * 11], ctr[16], out[32];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  aes128_key_schedule_x1_avx2(rk, key);
  for (auto _ : s) { aes128_ctrle_nocarry_2block_avx2(out, rk, ctr); benchmark::DoNotOptimize(out); }
  s.SetItemsProcessed(s.iterations() * 2);
}
static void BM_aes128_nocarry_64blocks_avx2(benchmark::State& s) { aes128_nocarry_avx2_bench(s, 64); }
static void BM_aes128_nocarry_128blocks_avx2(benchmark::State& s) { aes128_nocarry_avx2_bench(s, 128); }
BENCHMARK(BM_aes128_key_schedule_x1_avx2);
BENCHMARK(BM_aes128_key_schedule_x4_avx2);
BENCHMARK(BM_aes128_nocarry_1block_avx2);
BENCHMARK(BM_aes128_nocarry_2block_avx2);
BENCHMARK(BM_aes128_nocarry_64blocks_avx2);
BENCHMARK(BM_aes128_nocarry_128blocks_avx2);

static void BM_rijndael256_set_key_avx2(benchmark::State& s) {
  uint8_t key[32], rk[RIJNDAEL256_RK_BYTES];
  randomize(key, sizeof(key));
  for (auto _ : s) { rijndael256_key_schedule_x1_avx2(rk, key); benchmark::DoNotOptimize(rk); }
  s.SetItemsProcessed(s.iterations());
}
static void BM_rijndael256_key_schedule_x2_avx2(benchmark::State& s) {
  uint8_t k[2][32], rk[2][RIJNDAEL256_RK_BYTES];
  randomize(k, sizeof(k));
  for (auto _ : s) { rijndael256_key_schedule_x2_avx2(rk[0], rk[1], k[0], k[1]); benchmark::DoNotOptimize(rk); }
  s.SetItemsProcessed(s.iterations() * 2);
}
static void BM_rijndael256_key_schedule_x4_avx2(benchmark::State& s) {
  uint8_t k[4][32], rk[4][RIJNDAEL256_RK_BYTES];
  randomize(k, sizeof(k));
  for (auto _ : s) {
    rijndael256_key_schedule_x4_avx2(rk[0], rk[1], rk[2], rk[3], k[0], k[1], k[2], k[3]);
    benchmark::DoNotOptimize(rk);
  }
  s.SetItemsProcessed(s.iterations() * 4);
}
static void rij256_nocarry_avx2_bench(benchmark::State& s, uint64_t n) {
  uint8_t key[32], rk[RIJNDAEL256_RK_BYTES], ctr[32];
  std::vector<uint8_t> out(32 * n);
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  rijndael256_key_schedule_x1_avx2(rk, key);
  for (auto _ : s) { rijndael256_ctrle_nocarry_nblocks_avx2(out.data(), rk, ctr, n); benchmark::DoNotOptimize(out.data()); }
  s.SetItemsProcessed(s.iterations() * n);
}
static void BM_rijndael256_nocarry_2block_avx2(benchmark::State& s) {
  uint8_t key[32], rk[RIJNDAEL256_RK_BYTES], ctr[32], out[64];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  rijndael256_key_schedule_x1_avx2(rk, key);
  for (auto _ : s) { rijndael256_ctrle_nocarry_2block_avx2(out, rk, ctr); benchmark::DoNotOptimize(out); }
  s.SetItemsProcessed(s.iterations() * 2);
}
static void BM_rijndael256_nocarry_32blocks_avx2(benchmark::State& s) { rij256_nocarry_avx2_bench(s, 32); }
static void BM_rijndael256_nocarry_64blocks_avx2(benchmark::State& s) { rij256_nocarry_avx2_bench(s, 64); }
BENCHMARK(BM_rijndael256_set_key_avx2);
BENCHMARK(BM_rijndael256_key_schedule_x2_avx2);
BENCHMARK(BM_rijndael256_key_schedule_x4_avx2);
BENCHMARK(BM_rijndael256_nocarry_2block_avx2);
BENCHMARK(BM_rijndael256_nocarry_32blocks_avx2);
BENCHMARK(BM_rijndael256_nocarry_64blocks_avx2);
#endif  // __x86_64__

BENCHMARK_MAIN();
