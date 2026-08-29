// 4x leaf-seed expansion: the batched extend_leaf_seed_*_4x must be byte-identical
// to calling the 1x extend_leaf_seed_* four times. That equality is the
// KAT-preservation guarantee: when the BFS traversal swaps 1x -> 4x, the extended
// seeds (hence the signatures) are unchanged.
//
// NOTE: the expanded round-key blob layout differs between ref and avx2 (see
// aes_lowlevel_test.cpp), so we never cross-compare ref vs avx round keys. The
// gate is intra-impl: 4x_ref == 4x1x_ref, and 4x_avx2 == 4x1x_avx2. Each is what
// matters, since production builds use one impl consistently for both paths.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "sdith_prng.h"
#include "testlib/testlib.h"

namespace {

// EXTEND_LEAF_SEED_F and EXTEND_LEAF_SEED_4X_F share this signature.
using extend_fn = void (*)(void*, const void*);

// 4x(out, seeds) must equal 1x applied to each of the four seeds, and must not
// write past its four output slots. seed_sz / ext_sz are the natural strides.
void expect_4x_matches_1x(const char* tag, size_t seed_sz, size_t ext_sz, extend_fn fn1x, extend_fn fn4x) {
  const size_t guard = 32;
  for (int trial = 0; trial < 256; ++trial) {
    std::vector<uint8_t> seeds(4 * seed_sz);
    randomize(seeds.data(), seeds.size());

    std::vector<uint8_t> out4(4 * ext_sz + guard, 0xAA);  // trailing guard catches overruns
    fn4x(out4.data(), seeds.data());

    std::vector<uint8_t> want(4 * ext_sz);
    for (int i = 0; i < 4; ++i) fn1x(want.data() + i * ext_sz, seeds.data() + i * seed_sz);

    ASSERT_EQ(0, memcmp(out4.data(), want.data(), 4 * ext_sz)) << tag << ": 4x != 4x1x (trial " << trial << ")";
    for (size_t i = 0; i < guard; ++i)
      ASSERT_EQ(0xAA, out4[4 * ext_sz + i]) << tag << ": overran output at +" << i << " (trial " << trial << ")";
  }
}

}  // namespace

TEST(leaf_seed_4x, ref_matches_1x) {
  expect_4x_matches_1x("cat1 ref", 16, 16 * 11, extend_leaf_seed_cat1_aes128_ref, extend_leaf_seed_cat1_aes128_4x_ref);
  expect_4x_matches_1x("cat3 ref", 24, 480, extend_leaf_seed_cat3_rijndael256_ref,
                       extend_leaf_seed_cat3_rijndael256_4x_ref);
  expect_4x_matches_1x("cat5 ref", 32, 480, extend_leaf_seed_cat5_rijndael256_ref,
                       extend_leaf_seed_cat5_rijndael256_4x_ref);
}

// cat3 packs a 24-byte seed padded to 32 (k || 0^64); confirm the 4x path applies
// the same padding by feeding seeds whose bytes 24..31 would matter if read.
TEST(leaf_seed_4x, cat3_ref_ignores_bytes_past_24) {
  uint8_t seeds[4 * 24];
  randomize(seeds, sizeof(seeds));
  uint8_t out[4 * 480];
  extend_leaf_seed_cat3_rijndael256_4x_ref(out, seeds);
  uint8_t want[4 * 480];
  for (int i = 0; i < 4; ++i) extend_leaf_seed_cat3_rijndael256_ref(want + i * 480, seeds + i * 24);
  EXPECT_EQ(0, memcmp(out, want, sizeof(out)));
}

#ifdef __x86_64__
TEST(leaf_seed_4x, avx_matches_1x) {
  expect_4x_matches_1x("cat1 avx", 16, 16 * 11, extend_leaf_seed_cat1_aes128_avx2,
                       extend_leaf_seed_cat1_aes128_4x_avx2);
  expect_4x_matches_1x("cat3 avx", 24, 480, extend_leaf_seed_cat3_rijndael256_avx2,
                       extend_leaf_seed_cat3_rijndael256_4x_avx2);
  expect_4x_matches_1x("cat5 avx", 32, 480, extend_leaf_seed_cat5_rijndael256_avx2,
                       extend_leaf_seed_cat5_rijndael256_4x_avx2);
}
#endif  // __x86_64__
