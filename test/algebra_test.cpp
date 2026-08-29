// Unit coverage for previously-untested algebra helpers:
//   * bitvec_xor / bitvec_xor_to / bitvec_cascade_xor_to (F2 vector adds)
//   * gf*_set_ref (field-element copy)
//   * gf*_sum_pow2 (combine lambda bit-VOLEs into one field VOLE)
//
// Reference paths are checked against an independent oracle and run everywhere;
// the avx2/pclmul paths are checked against the reference and are x86-only.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "sdith_algebra.h"
#include "sdith_arithmetic.h"
#include "testlib/testlib.h"

namespace {

const uint64_t kByteLens[] = {1, 7, 8, 15, 16, 31, 32, 33, 64, 100};

std::vector<uint8_t> random_bytes(uint64_t n) {
  std::vector<uint8_t> v(n);
  randomize(v.data(), n);
  return v;
}

}  // namespace

TEST(algebra_bitvec, xor_to_ref) {
  for (uint64_t n : kByteLens) {
    std::vector<uint8_t> res = random_bytes(n), b = random_bytes(n), res0 = res;
    bitvec_xor_to_ref(n, (bitvec_t*)res.data(), (const bitvec_t*)b.data());
    for (uint64_t i = 0; i < n; ++i) EXPECT_EQ(res[i], (uint8_t)(res0[i] ^ b[i])) << "n=" << n << " i=" << i;
  }
}

TEST(algebra_bitvec, xor_ref) {
  for (uint64_t n : kByteLens) {
    std::vector<uint8_t> a = random_bytes(n), b = random_bytes(n), res(n, 0xAA);
    bitvec_xor_ref(n, (bitvec_t*)res.data(), (const bitvec_t*)a.data(), (const bitvec_t*)b.data());
    for (uint64_t i = 0; i < n; ++i) EXPECT_EQ(res[i], (uint8_t)(a[i] ^ b[i])) << "n=" << n << " i=" << i;
  }
}

TEST(algebra_bitvec, cascade_xor_to_ref) {
  // Semantics (from matrix_vector_products_f2.c): b ^= a; c ^= b.
  for (uint64_t n : kByteLens) {
    std::vector<uint8_t> a = random_bytes(n), b = random_bytes(n), c = random_bytes(n);
    std::vector<uint8_t> b0 = b, c0 = c;
    bitvec_cascade_xor_to_ref(n, (bitvec_t*)c.data(), (bitvec_t*)b.data(), (const bitvec_t*)a.data());
    for (uint64_t i = 0; i < n; ++i) {
      const uint8_t expect_b = b0[i] ^ a[i];
      EXPECT_EQ(b[i], expect_b) << "b n=" << n << " i=" << i;
      EXPECT_EQ(c[i], (uint8_t)(c0[i] ^ expect_b)) << "c n=" << n << " i=" << i;
    }
  }
}

#ifdef __x86_64__
TEST(algebra_bitvec, xor_avx2_matches_ref) {
  for (uint64_t n : kByteLens) {
    std::vector<uint8_t> a = random_bytes(n), b = random_bytes(n), base = random_bytes(n);

    std::vector<uint8_t> to_ref = base, to_avx = base;
    bitvec_xor_to_ref(n, (bitvec_t*)to_ref.data(), (const bitvec_t*)b.data());
    bitvec_xor_to_avx2(n, (bitvec_t*)to_avx.data(), (const bitvec_t*)b.data());
    EXPECT_EQ(to_ref, to_avx) << "xor_to n=" << n;

    std::vector<uint8_t> r_ref(n), r_avx(n);
    bitvec_xor_ref(n, (bitvec_t*)r_ref.data(), (const bitvec_t*)a.data(), (const bitvec_t*)b.data());
    bitvec_xor_avx2(n, (bitvec_t*)r_avx.data(), (const bitvec_t*)a.data(), (const bitvec_t*)b.data());
    EXPECT_EQ(r_ref, r_avx) << "xor n=" << n;

    std::vector<uint8_t> c_ref = base, b_ref = b, c_avx = base, b_avx = b;
    bitvec_cascade_xor_to_ref(n, (bitvec_t*)c_ref.data(), (bitvec_t*)b_ref.data(), (const bitvec_t*)a.data());
    bitvec_cascade_xor_to_avx2(n, (bitvec_t*)c_avx.data(), (bitvec_t*)b_avx.data(), (const bitvec_t*)a.data());
    EXPECT_EQ(b_ref, b_avx) << "cascade b n=" << n;
    EXPECT_EQ(c_ref, c_avx) << "cascade c n=" << n;
  }
}
#endif  // __x86_64__

TEST(algebra_gf, set_ref_copies) {
  {
    alignas(16) uint8_t a[16], r[16];
    randomize_static_array(a);
    gf128_set_ref((gf128*)r, (const gf128*)a);
    EXPECT_EQ(0, memcmp(r, a, sizeof(a)));
  }
  {
    alignas(8) uint8_t a[24], r[24];
    randomize_static_array(a);
    gf192_set_ref((gf192*)r, (const gf192*)a);
    EXPECT_EQ(0, memcmp(r, a, sizeof(a)));
  }
  {
    alignas(32) uint8_t a[32], r[32];
    randomize_static_array(a);
    gf256_set_ref((gf256*)r, (const gf256*)a);
    EXPECT_EQ(0, memcmp(r, a, sizeof(a)));
  }
}

// No avx2 cross-check here: gf128/gf256 sum_pow2 have no avx2 implementation
// (header decl only), and gf192_sum_pow2_avx2 just forwards to the ref.
TEST(algebra_gf, sum_pow2_ref_matches_naive) {
  {  // gf128: x is 128 elements of 16 bytes
    aligned_vector_u8 x(32, 128 * 16);
    randomize(x.data(), x.size());
    alignas(16) uint8_t r_ref[16], r_naive[16];
    gf128_sum_pow2_ref((gf128*)r_ref, (const gf128*)x.data());
    gf128_sum_pow2_naive((gf128*)r_naive, (const gf128*)x.data());
    EXPECT_EQ(0, memcmp(r_ref, r_naive, 16));
  }
  {  // gf192: x is 192 elements of 24 bytes
    aligned_vector_u8 x(32, 192 * 24);
    randomize(x.data(), x.size());
    alignas(8) uint8_t r_ref[24], r_naive[24];
    gf192_sum_pow2_ref((gf192*)r_ref, (const gf192*)x.data());
    gf192_sum_pow2_naive((gf192*)r_naive, (const gf192*)x.data());
    EXPECT_EQ(0, memcmp(r_ref, r_naive, 24));
  }
  {  // gf256: x is 256 elements of 32 bytes
    aligned_vector_u8 x(32, 256 * 32);
    randomize(x.data(), x.size());
    alignas(32) uint8_t r_ref[32], r_naive[32];
    gf256_sum_pow2_ref((gf256*)r_ref, (const gf256*)x.data());
    gf256_sum_pow2_naive((gf256*)r_naive, (const gf256*)x.data());
    EXPECT_EQ(0, memcmp(r_ref, r_naive, 32));
  }
}
