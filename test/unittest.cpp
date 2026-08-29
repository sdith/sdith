#include <random>

#include "ggm.h"
#include "gtest/gtest.h"
#include "rijndael256.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/testlib.h"
#include "vole_private.h"

#ifdef __x86_64__
#include "rijndael256_avx.h"
#endif

#ifdef __x86_64__
TEST(gf128, gf128_product_pclmul) {
  for (uint64_t i = 0; i < 1000; ++i) {
    __uint128_t a = uniform_u128();
    __uint128_t b = uniform_u128();
    __uint128_t expect;
    __uint128_t actual;
    gf128_product_pclmul((gf128*)&actual, (gf128*)&a, (gf128*)&b);
    gf128_product_ref((gf128*)&expect, (gf128*)&a, (gf128*)&b);
    ASSERT_EQ(actual, expect);
  }
}

TEST(gf128, gf128_product_pclmul_f2) {
  for (uint64_t i = 0; i < 1000; ++i) {
    __uint128_t a = uniform_u128();
    __uint128_t b = uniform_u128() % 2;
    __uint128_t expect;
    __uint128_t actual;
    gf128_product_pclmul((gf128*)&actual, (gf128*)&a, (gf128*)&b);
    gf128_product_pclmul_f2((gf128*)&expect, (gf128*)&a, (gf128*)&b);
    ASSERT_EQ(actual, expect);
  }
}

#endif

TEST(gf128, gf128_product_f2_ref) {
  for (uint64_t i = 0; i < 1000; ++i) {
    __uint128_t a = uniform_u128();
    __uint128_t b_f2 = uniform_u128() % 2;
    __uint128_t expect;
    __uint128_t actual;
    gf128_product_ref((gf128*)&actual, (gf128*)&a, (gf128*)&b_f2);
    gf128_product_f2_ref((gf128*)&expect, (gf128*)&a, (gf128*)&b_f2);
    ASSERT_EQ(actual, expect);
  }
}

#ifdef __x86_64__
TEST(gf192, gf192_product_pclmul) {
  for (uint64_t i = 0; i < 1000; ++i) {
    uint64_t a[3], b[3], expect[3], actual[3];
    for (uint64_t j = 0; j < 3; j++) {
      a[j] = uniform_u128();
      b[j] = uniform_u128();
    }
    gf192_product_pclmul((gf192*)&actual, (gf192*)&a, (gf192*)&b);
    gf192_product_ref((gf192*)&expect, (gf192*)&a, (gf192*)&b);
    for (uint64_t j = 0; j < 3; j++) {
      ASSERT_EQ(actual[j], expect[j]);
    }
  }
}
#endif  // __x86_64__

TEST(gf192, gf192_product_f2_ref) {
  for (uint64_t i = 0; i < 1000; ++i) {
    uint64_t a[3], b_f2[3], expect[3], actual[3];
    for (uint64_t j = 0; j < 3; j++) {
      a[j] = uniform_u128();
      if (j == 0)
        b_f2[j] = uniform_u128() % 2;
      else
        b_f2[j] = 0;
    }
    gf192_product_ref((gf192*)&actual, (gf192*)&a, (gf192*)&b_f2);
    gf192_product_f2_ref((gf192*)&expect, (gf192*)&a, (gf192*)&b_f2);
    for (uint64_t j = 0; j < 3; j++) {
      ASSERT_EQ(actual[j], expect[j]);
    }
  }
}

#ifdef __x86_64__
TEST(gf192, gf192_sum_pow2_avx2) {
  for (uint64_t i = 0; i < 10; ++i) {
    uint64_t a[192 * 3];
    uint64_t expect[3], actual[3];
    randomize_static_array(a);
    gf192_sum_pow2_ref((gf192*)&expect, (gf192*)a);
    gf192_sum_pow2_avx2((gf192*)&actual, (gf192*)a);
    fflush(stdout);
    for (int j = 0; j < 3; j++) {
      ASSERT_EQ(actual[j], expect[j]);
    }
  }
}
#endif

TEST(gf128, gf128_inverse_ref) {
  for (uint64_t i = 0; i < 1000; ++i) {
    __uint128_t a = uniform_u128();
    __uint128_t ainv;
    __uint128_t expect = 1;
    __uint128_t actual = 1;
    gf128_inverse_ref((gf128*)&ainv, (gf128*)&a);
    gf128_product_ref((gf128*)&actual, (gf128*)&a, (gf128*)&ainv);
    ASSERT_EQ(actual, expect);
  }
}

#ifdef __x86_64__
TEST(gf128, gf128_inverse_pclmul) {
  for (uint64_t i = 0; i < 1000; ++i) {
    __uint128_t a = uniform_u128();
    __uint128_t expect = 1;
    __uint128_t actual = 1;
    gf128_inverse_ref((gf128*)&expect, (gf128*)&a);
    gf128_inverse_pclmul((gf128*)&actual, (gf128*)&a);
    ASSERT_EQ(actual, expect);
  }
}
#endif  // __x86_64__

TEST(gf128, gf128_sum_pow2_ref) {
  for (uint64_t i = 0; i < 10; ++i) {
    __uint128_t a[128];
    __uint128_t expect;
    __uint128_t actual;
    randomize_static_array(a);
    gf128_sum_pow2_naive((gf128*)&expect, (gf128*)a);
    gf128_sum_pow2_ref((gf128*)&actual, (gf128*)a);
    ASSERT_EQ(actual, expect);
  }
}

typedef typeof(gf128_echelon_pow2_naive) gf128_echelon_pow2_f;

static void test_gf128_echelon_pow2(gf128_echelon_pow2_f gf128_echelon_pow2) {
  for (uint64_t k : {1, 3, 8}) {
    for (uint64_t x_size : {0, 1, 2, 63, 128}) {
      if (k * x_size > 128) continue;
      for (uint64_t xbs : {1, 2, 3}) {
        std::vector<uint8_t> x(x_size * xbs * sizeof(gf128));
        randomize(x.data(), x.size());
        gf128 expect;
        gf128 actual;
        gf128_echelon_pow2_naive(k, &expect, (gf128*)x.data(), x_size, xbs * sizeof(gf128));
        gf128_echelon_pow2(k, &actual, (gf128*)x.data(), x_size, xbs * sizeof(gf128));
        ASSERT_TRUE(gf128v_equals(actual, expect));
      }
    }
  }
}

TEST(gf128, gf128_echelon_pow2_ref) { test_gf128_echelon_pow2(gf128_echelon_pow2_ref); }
#ifdef __x86_64__
TEST(gf128, gf128_echelon_pow2_avx) { test_gf128_echelon_pow2(gf128_echelon_pow2_avx); }
#endif

TEST(transpose, transpose_128_128_naive) {
  uint8_t x[128 * 128 / 8], y[128 * 128 / 8];
  for (uint64_t rep = 0; rep < 10; rep++) {
    randomize_static_array(x);
    transpose_128_128_naive(y, x);
    for (uint64_t i = 0; i < 128; i++) {
      for (uint64_t j = 0; j < 128; j++) {
        ASSERT_EQ(((x[(128 * i + j) / 8] >> (j % 8)) & 1), ((y[(128 * j + i) / 8] >> (i % 8)) & 1));
      }
    }
  }
}

TEST(transpose, transpose_128_128_ref) {
  uint8_t x[128 * 128 / 8], y[128 * 128 / 8];
  for (uint64_t rep = 0; rep < 10; rep++) {
    randomize_static_array(x);
    transpose_128_128_naive(y, x);
    transpose_128_128_ref(x);
    for (uint64_t i = 0; i < 128 * 128 / 8; i++) {
      ASSERT_EQ(x[i], y[i]);
    }
  }
}


static void check_transposition_function(
 MATRIX_LAMBDA_TRANSPOSE_F transposition_function,
 const uint64_t in_rows) {
  for (uint64_t L : {120, 128, 240, 608}) {
    REQUIRE_DRAMATICALLY(L % 8 == 0, "L must be a multiple of 8");
    uint64_t Lbytes = L / 8;
    uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
    bit_matrix in = bit_matrix::random(in_rows, Lslice * 8);
    bit_matrix out = bit_matrix::random(L, in_rows);
    transposition_function(out.data(), in.data(), L, Lslice);
    for (uint64_t i = 0; i < L; i++) {
      for (uint64_t j = 0; j < in_rows; j++) {
        ASSERT_EQ(in.get(j,i), out.get(i,j));
      }
    }
  }
}

TEST(transpose, transpose_128_L_naive) {
  check_transposition_function(transpose_128_L_naive, 128);
}

TEST(transpose, transpose_128_L_ref) {
  check_transposition_function(transpose_128_L_ref, 128);
}

TEST(transpose, transpose_192_192_naive) {
  uint8_t x[192 * 192 / 8], y[192 * 192 / 8];
  for (uint64_t rep = 0; rep < 10; rep++) {
    randomize_static_array(x);
    transpose_192_192_naive(y, x);
    for (uint64_t i = 0; i < 192; i++) {
      for (uint64_t j = 0; j < 192; j++) {
        ASSERT_EQ(((x[(192 * i + j) / 8] >> (j % 8)) & 1), ((y[(192 * j + i) / 8] >> (i % 8)) & 1));
      }
    }
  }
}

TEST(transpose, transpose_192_192_ref) {
  uint8_t x[192 * 192 / 8], y[192 * 192 / 8];
  for (uint64_t rep = 0; rep < 10; rep++) {
    randomize_static_array(x);
    transpose_192_192_naive(y, x);
    transpose_192_192_ref(x);
    for (uint64_t i = 0; i < 192 * 192 / 8; i++) {
      ASSERT_EQ(x[i], y[i]);
    }
  }
}

TEST(transpose, transpose_192_L_naive) {
  check_transposition_function(transpose_192_L_naive, 192);
}

TEST(transpose, transpose_192_L_ref) {
  check_transposition_function(transpose_192_L_ref, 192);
}

TEST(transpose, transpose_256_256_naive) {
  uint8_t x[256 * 256 / 8], y[256 * 256 / 8];
  for (uint64_t rep = 0; rep < 10; rep++) {
    randomize_static_array(x);
    transpose_256_256_naive(y, x);
    for (uint64_t i = 0; i < 256; i++) {
      for (uint64_t j = 0; j < 256; j++) {
        ASSERT_EQ(((x[(256 * i + j) / 8] >> (j % 8)) & 1), ((y[(256 * j + i) / 8] >> (i % 8)) & 1));
      }
    }
  }
}

TEST(transpose, transpose_256_256_ref) {
  uint8_t x[256 * 256 / 8], y[256 * 256 / 8];
  for (uint64_t rep = 0; rep < 10; rep++) {
    randomize_static_array(x);
    transpose_256_256_naive(y, x);
    transpose_256_256_ref(x);
    for (uint64_t i = 0; i < 256 * 256 / 8; i++) {
      ASSERT_EQ(x[i], y[i]);
    }
  }
}

TEST(transpose, transpose_256_L_naive) {
  check_transposition_function(transpose_256_L_naive, 256);
}

TEST(transpose, transpose_256_L_ref) {
  check_transposition_function(transpose_256_L_ref, 256);
}


TEST(rijndael256, rijndael256_encrypt_1block_ref)
{
  const uint8_t expected[32]  = {0xC6, 0x22, 0x7E, 0x77, 0x40, 0xB7, 0xE5, 0x3B, 0x5C, 0xB7, 0x78, 0x65, 0x27, 0x8E, 0xAB, 0x07, 0x26, 0xF6, 0x23, 0x66, 0xD9, 0xAA, 0xBA, 0xD9, 0x08, 0x93, 0x61, 0x23, 0xA1, 0xFC, 0x8A, 0xF3};
  const uint8_t expected2[32] = {0x98, 0x43, 0xE8, 0x07, 0x31, 0x9C, 0x32, 0xAD, 0x1E, 0xA3, 0x93, 0x5E, 0xF5, 0x6A, 0x2B, 0xA9, 0x6E, 0x4B, 0xF1, 0x9C, 0x30, 0xE4, 0x7D, 0x88, 0xA2, 0xB9, 0x7C, 0xBB, 0xF2, 0xE1, 0x59, 0xE7};
  uint8_t res[64], res2[64], key[32] = {0}, ctr[32] = {0};
  rijndael256_rk_t roundkeys;
  rijndael256_key_schedule_ref(&roundkeys, key);
  rijndael256_encrypt_1block_ref(res, ctr, &roundkeys);
  rijndael256_encrypt_1block_ref(res2, res, &roundkeys);
  for (size_t i = 0; i < 32; i++)
  {
    ASSERT_EQ(res[i], expected[i]);
    ASSERT_EQ(res2[i], expected2[i]);
  }
}

#ifdef __x86_64__
TEST(rijndael256, rijndael256_key_schedule_avx)
{
  uint8_t key[32];
  rijndael256_rk_t kref;
  rijndael256_avx_rk_t kavx;
  for (int i = 0; i < 100; i++)
  {
    randomize_static_array(key);
    rijndael256_key_schedule_ref(&kref, key);
    rijndael256_key_schedule_avx(&kavx, key);
    for (size_t j = 0; j < 15; j++)
    {
      for (size_t k = 0; k < 32; k++)
      {
        ASSERT_EQ(kref.rk[j][k], kavx.rk[j].b[k]);
      }
    }
  }
}

// NOTE: the avx ECB / CTR encryption cores were removed (superseded by the
// register-based rijndael256_ctrle_nocarry_* path); their correctness vs the ref is
// now covered by aes_lowlevel.rijndael256_avx_ctr_matches_oracle.
#endif
