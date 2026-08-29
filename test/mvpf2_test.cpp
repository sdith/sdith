#include "ggm.h"
#include "gtest/gtest.h"
#include "sdith_algebra.h"
#include "testlib/testlib.h"

#ifdef __x86_64__
TEST(matrix_vector_product, matrix_vector_product_f2_avx2) {
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
  std::vector<uint8_t> res_avx_v(res_bytes);
  bitvec_t* res_avx = (bitvec_t*)res_avx_v.data();

  matrix_vector_product_f2_ref(nrows, ncols, res_ref, a, b);
  matrix_vector_product_f2_avx2(nrows, ncols, res_avx, a, b);

  ASSERT_TRUE(memcmp(res_ref, res_avx, res_bytes) == 0);
}
#endif  // __x86_64__

#ifdef __x86_64__
static void test_matrix_f2_times_vector_flambda_avx2(const uint64_t lambda_bits = 256, uint64_t nrows = 260,
                                                     uint64_t ncols = 256) {
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
  std::vector<uint8_t> res_ref_v(res_bytes);
  flambda_t* res_ref = (flambda_t*)res_ref_v.data();
  std::vector<uint8_t> res_avx_v(res_bytes);
  flambda_t* res_avx = (flambda_t*)res_avx_v.data();

  matrix_f2_times_vector_flambda_ref(lambda_bits, nrows, ncols, res_ref, a, b);
  matrix_f2_times_vector_flambda_avx2(lambda_bits, nrows, ncols, res_avx, a, b);

  ASSERT_TRUE(memcmp(res_ref, res_avx, res_bytes) == 0);
}
#endif  // __x86_64__

#ifdef __x86_64__
TEST(matrix_vector_product, matrix_f2_times_vector_flambda_avx2_128) { test_matrix_f2_times_vector_flambda_avx2(128); }

// Realistic consistency-check sizes with a row count that is not a multiple of the
// kernel's row-block, exercising the row-tail path.
TEST(matrix_vector_product, matrix_f2_times_vector_flambda_avx2_128_tail) {
  test_matrix_f2_times_vector_flambda_avx2(128, 146, 1000);
}

TEST(matrix_vector_product, matrix_f2_times_vector_flambda_avx2_192) { test_matrix_f2_times_vector_flambda_avx2(192); }

// Realistic CAT3 sizes with a row count that is not a multiple of the kernel's
// row-block, exercising the row-tail path.
TEST(matrix_vector_product, matrix_f2_times_vector_flambda_avx2_192_tail) {
  test_matrix_f2_times_vector_flambda_avx2(192, 210, 1456);
}

TEST(matrix_vector_product, matrix_f2_times_vector_flambda_avx2_256) { test_matrix_f2_times_vector_flambda_avx2(256); }

// Realistic CAT5 sizes with a row count that is not a multiple of the kernel's
// row-block, exercising the row-tail path.
TEST(matrix_vector_product, matrix_f2_times_vector_flambda_avx2_256_tail) {
  test_matrix_f2_times_vector_flambda_avx2(256, 274, 1912);
}
#endif  // __x86_64__
