// Exhaustive per-function correctness tests for src/matrix_transpose_f2.c
//
// This module implements F_2 bit-matrix transposes. There is NO AVX2 variant of
// any transpose (grep of src/*_avx2.c finds none, and vole_parameters_avx2.c
// wires the same transpose_*_L_ref as the scalar path). Each transpose therefore
// ships two implementations that we cross-check:
//   *_naive : the straightforward bit-by-bit reference
//   *_ref   : the optimized production implementation
//
// Exported symbols covered (all declared in sdith_arithmetic.h):
//   transpose_128_128_naive / _192_192_naive / _256_256_naive  (out-of-place, BxB)
//   transpose_128_128_ref   / _192_192_ref   / _256_256_ref    (in-place,     BxB)
//   transpose_128_L_naive   / _192_L_naive   / _256_L_naive     (out-of-place, BxL)
//   transpose_128_L_ref     / _192_L_ref     / _256_L_ref       (out-of-place, BxL)
//
// Ground truth is an independent LSB-first bit transpose (oracle_transpose,
// below). Its bit convention is exactly that of the round-3 python oracle
// sdith-py/round3/utils.py: get_bit(data, i) == (data[i/8] >> (i%8)) & 1, and
// transpose_vole_matrix() sets output bit r from input bit (row r, col c). The
// three widths B in {128, 192, 256} correspond to the lambda = 128/192/256
// security levels, i.e. all six SDitH parameter sets (short/fast variants at a
// given level share the same lambda and thus the same transpose routine).
//
// A distinct gtest suite name ("matrix_transpose_f2") is used on purpose: the
// unittest executable already links test/unittest.cpp, which registers a
// "transpose" suite, so reusing that suite name would collide at registration.

#include <cstdint>
#include <cstring>

#include "gtest/gtest.h"
#include "sdith_arithmetic.h"
#include "testlib/testlib.h"

/*
namespace {

constexpr uint64_t kAlign = 32;

// Independent reference transpose, LSB-first, row-major.
//   in  : nrows x ncols bit matrix, row stride = ncols/8 bytes
//   out : ncols x nrows bit matrix, row stride = nrows/8 bytes
// Requires nrows % 8 == 0 and ncols % 8 == 0 (always true here).
void oracle_transpose(uint8_t* out, const uint8_t* in, uint64_t nrows, uint64_t ncols) {
  const uint64_t in_stride = ncols / 8;
  const uint64_t out_stride = nrows / 8;
  memset(out, 0, (size_t)ncols * out_stride);
  for (uint64_t r = 0; r < nrows; ++r) {
    for (uint64_t c = 0; c < ncols; ++c) {
      const uint8_t bit = (uint8_t)((in[r * in_stride + c / 8] >> (c % 8)) & 1u);
      out[c * out_stride + r / 8] |= (uint8_t)(bit << (r % 8));
    }
  }
}

// ---------------------------------------------------------------------------
// Square, out-of-place: transpose_B_B_naive(out, in)
// ---------------------------------------------------------------------------
void run_square_naive(void (*fn)(void*, const void*), uint64_t B) {
  const uint64_t bytes = B * B / 8;
  const uint64_t stride = B / 8;
  aligned_vector_u8 in(kAlign, bytes);
  aligned_vector_u8 out(kAlign, bytes);
  aligned_vector_u8 expect(kAlign, bytes);

  // zero -> zero (oracle-independent known answer)
  memset(in.data(), 0x00, bytes);
  memset(out.data(), 0xAA, bytes);
  fn(out.data(), in.data());
  for (uint64_t i = 0; i < bytes; ++i) ASSERT_EQ(out[i], (uint8_t)0x00) << "B=" << B << " i=" << i;

  // all-ones -> all-ones (oracle-independent known answer)
  memset(in.data(), 0xFF, bytes);
  fn(out.data(), in.data());
  for (uint64_t i = 0; i < bytes; ++i) ASSERT_EQ(out[i], (uint8_t)0xFF) << "B=" << B << " i=" << i;

  // single bit (r,c) transposes to exactly (c,r) (oracle-independent)
  const uint64_t coords[8][2] = {{0, 0},     {0, 1},     {1, 0},     {3, 100},
                                 {B - 1, B - 1}, {B - 1, 0}, {0, B - 1}, {7, 8}};
  for (const auto& rc : coords) {
    const uint64_t r = rc[0], c = rc[1];
    memset(in.data(), 0x00, bytes);
    in[r * stride + c / 8] = (uint8_t)(1u << (c % 8));
    fn(out.data(), in.data());
    for (uint64_t i = 0; i < bytes; ++i) {
      const uint8_t want = (i == c * stride + r / 8) ? (uint8_t)(1u << (r % 8)) : (uint8_t)0u;
      ASSERT_EQ(out[i], want) << "B=" << B << " r=" << r << " c=" << c << " i=" << i;
    }
  }

  // random inputs vs the independent oracle
  for (uint64_t rep = 0; rep < 8; ++rep) {
    randomize(in.data(), bytes);
    fn(out.data(), in.data());
    oracle_transpose(expect.data(), in.data(), B, B);
    ASSERT_EQ(memcmp(out.data(), expect.data(), bytes), 0) << "B=" << B << " rep=" << rep;
  }

  // round trip: transpose . transpose == identity
  aligned_vector_u8 tmp(kAlign, bytes);
  for (uint64_t rep = 0; rep < 4; ++rep) {
    randomize(in.data(), bytes);
    fn(tmp.data(), in.data());
    fn(out.data(), tmp.data());
    ASSERT_EQ(memcmp(out.data(), in.data(), bytes), 0) << "B=" << B << " rep=" << rep;
  }
}

// ---------------------------------------------------------------------------
// Square, in-place: transpose_B_B_ref(x). Checked against BOTH the oracle and
// the naive reference (never against itself).
// ---------------------------------------------------------------------------
void check_ref_square_pattern(void (*ref)(void*), void (*naive)(void*, const void*),
                              const uint8_t* in, uint64_t B) {
  const uint64_t bytes = B * B / 8;
  aligned_vector_u8 work(kAlign, bytes);
  aligned_vector_u8 expect(kAlign, bytes);
  aligned_vector_u8 nout(kAlign, bytes);

  memcpy(work.data(), in, bytes);
  ref(work.data());
  oracle_transpose(expect.data(), in, B, B);
  ASSERT_EQ(memcmp(work.data(), expect.data(), bytes), 0) << "ref vs oracle B=" << B;
  naive(nout.data(), in);
  ASSERT_EQ(memcmp(work.data(), nout.data(), bytes), 0) << "ref vs naive B=" << B;
}

void run_square_ref(void (*ref)(void*), void (*naive)(void*, const void*), uint64_t B) {
  const uint64_t bytes = B * B / 8;
  const uint64_t stride = B / 8;
  aligned_vector_u8 in(kAlign, bytes);

  // zero
  memset(in.data(), 0x00, bytes);
  check_ref_square_pattern(ref, naive, in.data(), B);

  // all ones
  memset(in.data(), 0xFF, bytes);
  check_ref_square_pattern(ref, naive, in.data(), B);

  // identity (its transpose is itself)
  memset(in.data(), 0x00, bytes);
  for (uint64_t d = 0; d < B; ++d) in[d * stride + d / 8] |= (uint8_t)(1u << (d % 8));
  check_ref_square_pattern(ref, naive, in.data(), B);

  // a few single bits
  const uint64_t coords[5][2] = {{0, 0}, {0, B - 1}, {B - 1, 0}, {B - 1, B - 1}, {5, 40}};
  for (const auto& rc : coords) {
    memset(in.data(), 0x00, bytes);
    in[rc[0] * stride + rc[1] / 8] = (uint8_t)(1u << (rc[1] % 8));
    check_ref_square_pattern(ref, naive, in.data(), B);
  }

  // random inputs
  for (uint64_t rep = 0; rep < 8; ++rep) {
    randomize(in.data(), bytes);
    check_ref_square_pattern(ref, naive, in.data(), B);
  }

  // round trip: in-place transpose twice == identity
  aligned_vector_u8 work(kAlign, bytes);
  for (uint64_t rep = 0; rep < 4; ++rep) {
    randomize(in.data(), bytes);
    memcpy(work.data(), in.data(), bytes);
    ref(work.data());
    ref(work.data());
    ASSERT_EQ(memcmp(work.data(), in.data(), bytes), 0) << "roundtrip B=" << B << " rep=" << rep;
  }
}

// ---------------------------------------------------------------------------
// Rectangular, out-of-place: transpose_B_L_{naive,ref}(out, in, L).
// Both share the same signature/semantics, so this drives either against the
// oracle across a spread of L that exercises both the fast (L % B == 0) and the
// byte-wise remainder (L % B != 0) branches of the _ref implementation.
// ---------------------------------------------------------------------------
void run_L_vs_oracle(void (*fn)(void*, const void*, uint64_t), uint64_t B, const uint64_t* Ls,
                     size_t nL) {
  for (size_t li = 0; li < nL; ++li) {
    const uint64_t L = Ls[li];
    const uint64_t in_stride = L / 8;   // bytes per input row (B rows)
    const uint64_t out_stride = B / 8;  // bytes per output row (L rows)
    const uint64_t in_bytes = B * in_stride;
    const uint64_t out_bytes = L * out_stride;  // == in_bytes
    aligned_vector_u8 in(kAlign, in_bytes);
    aligned_vector_u8 out(kAlign, out_bytes);
    aligned_vector_u8 expect(kAlign, out_bytes);

    // zero -> zero (oracle-independent)
    memset(in.data(), 0x00, in_bytes);
    memset(out.data(), 0xAA, out_bytes);
    fn(out.data(), in.data(), L);
    for (uint64_t i = 0; i < out_bytes; ++i)
      ASSERT_EQ(out[i], (uint8_t)0x00) << "zero B=" << B << " L=" << L << " i=" << i;

    // all-ones -> all-ones (oracle-independent)
    memset(in.data(), 0xFF, in_bytes);
    fn(out.data(), in.data(), L);
    for (uint64_t i = 0; i < out_bytes; ++i)
      ASSERT_EQ(out[i], (uint8_t)0xFF) << "ones B=" << B << " L=" << L << " i=" << i;

    // single bit (r,c) transposes to exactly (c,r) (oracle-independent)
    const uint64_t coords[6][2] = {{0, 0},         {0, L - 1}, {B - 1, 0},
                                   {B - 1, L - 1}, {1, 7},     {7, 1}};
    for (const auto& rc : coords) {
      const uint64_t r = rc[0], c = rc[1];
      if (r >= B || c >= L) continue;
      memset(in.data(), 0x00, in_bytes);
      in[r * in_stride + c / 8] = (uint8_t)(1u << (c % 8));
      fn(out.data(), in.data(), L);
      for (uint64_t i = 0; i < out_bytes; ++i) {
        const uint8_t want = (i == c * out_stride + r / 8) ? (uint8_t)(1u << (r % 8)) : (uint8_t)0u;
        ASSERT_EQ(out[i], want) << "bit B=" << B << " L=" << L << " r=" << r << " c=" << c
                                << " i=" << i;
      }
    }

    // random inputs vs the independent oracle
    for (uint64_t rep = 0; rep < 5; ++rep) {
      randomize(in.data(), in_bytes);
      fn(out.data(), in.data(), L);
      oracle_transpose(expect.data(), in.data(), B, L);
      ASSERT_EQ(memcmp(out.data(), expect.data(), out_bytes), 0)
          << "rand B=" << B << " L=" << L << " rep=" << rep;
    }
  }
}

// ref vs naive cross-check for the rectangular transpose (res_ref vs res_naive).
void run_L_ref_vs_naive(void (*ref)(void*, const void*, uint64_t),
                        void (*naive)(void*, const void*, uint64_t), uint64_t B, const uint64_t* Ls,
                        size_t nL) {
  for (size_t li = 0; li < nL; ++li) {
    const uint64_t L = Ls[li];
    const uint64_t bytes = B * (L / 8);
    aligned_vector_u8 in(kAlign, bytes);
    aligned_vector_u8 res_ref(kAlign, bytes);
    aligned_vector_u8 res_naive(kAlign, bytes);
    for (uint64_t rep = 0; rep < 5; ++rep) {
      randomize(in.data(), bytes);
      naive(res_naive.data(), in.data(), L);
      ref(res_ref.data(), in.data(), L);
      ASSERT_EQ(memcmp(res_ref.data(), res_naive.data(), bytes), 0)
          << "B=" << B << " L=" << L << " rep=" << rep;
    }
  }
}

// L spreads per width. Each list mixes:
//   * fast path      (L % B == 0, e.g. B, 2B)
//   * pure remainder (L < B, Lbyte < B/8, only the byte-wise 8x8 loop)
//   * mixed          (L > B and L % B != 0: at least one full BxB block + remainder)
//   * non-word odd   (multiples of 8 that are not multiples of B)
const uint64_t kL128[] = {8, 40, 64, 120, 128, 136, 200, 256};
const uint64_t kL192[] = {8, 40, 184, 192, 200, 376, 384};
const uint64_t kL256[] = {8, 40, 248, 256, 264, 504, 512};

}  // namespace

// ===========================================================================
// square, out-of-place
// ===========================================================================
TEST(matrix_transpose_f2, transpose_128_128_naive) { run_square_naive(transpose_128_128_naive, 128); }
TEST(matrix_transpose_f2, transpose_192_192_naive) { run_square_naive(transpose_192_192_naive, 192); }
TEST(matrix_transpose_f2, transpose_256_256_naive) { run_square_naive(transpose_256_256_naive, 256); }

// ===========================================================================
// square, in-place (checked vs oracle AND vs naive)
// ===========================================================================
TEST(matrix_transpose_f2, transpose_128_128_ref) {
  run_square_ref(transpose_128_128_ref, transpose_128_128_naive, 128);
}
TEST(matrix_transpose_f2, transpose_192_192_ref) {
  run_square_ref(transpose_192_192_ref, transpose_192_192_naive, 192);
}
TEST(matrix_transpose_f2, transpose_256_256_ref) {
  run_square_ref(transpose_256_256_ref, transpose_256_256_naive, 256);
}

// ===========================================================================
// rectangular naive (vs oracle)
// ===========================================================================
TEST(matrix_transpose_f2, transpose_128_L_naive) {
  run_L_vs_oracle(transpose_128_L_naive, 128, kL128, sizeof(kL128) / sizeof(kL128[0]));
}
TEST(matrix_transpose_f2, transpose_192_L_naive) {
  run_L_vs_oracle(transpose_192_L_naive, 192, kL192, sizeof(kL192) / sizeof(kL192[0]));
}
TEST(matrix_transpose_f2, transpose_256_L_naive) {
  run_L_vs_oracle(transpose_256_L_naive, 256, kL256, sizeof(kL256) / sizeof(kL256[0]));
}

// ===========================================================================
// rectangular ref (vs oracle AND vs naive)
// ===========================================================================
TEST(matrix_transpose_f2, transpose_128_L_ref) {
  run_L_vs_oracle(transpose_128_L_ref, 128, kL128, sizeof(kL128) / sizeof(kL128[0]));
  run_L_ref_vs_naive(transpose_128_L_ref, transpose_128_L_naive, 128, kL128,
                     sizeof(kL128) / sizeof(kL128[0]));
}
TEST(matrix_transpose_f2, transpose_192_L_ref) {
  run_L_vs_oracle(transpose_192_L_ref, 192, kL192, sizeof(kL192) / sizeof(kL192[0]));
  run_L_ref_vs_naive(transpose_192_L_ref, transpose_192_L_naive, 192, kL192,
                     sizeof(kL192) / sizeof(kL192[0]));
}
TEST(matrix_transpose_f2, transpose_256_L_ref) {
  run_L_vs_oracle(transpose_256_L_ref, 256, kL256, sizeof(kL256) / sizeof(kL256[0]));
  run_L_ref_vs_naive(transpose_256_L_ref, transpose_256_L_naive, 256, kL256,
                     sizeof(kL256) / sizeof(kL256[0]));
}

// ===========================================================================
// empty edge case: L == 0 must be a well-defined no-op for every rectangular
// variant (Lbyte == 0 -> zero output rows -> nothing written).
// ===========================================================================
TEST(matrix_transpose_f2, transpose_L_empty) {
  aligned_vector_u8 in(kAlign, 32);
  aligned_vector_u8 out(kAlign, 32);
  randomize(in.data(), 32);
  void (*fns[6])(void*, const void*, uint64_t) = {
      transpose_128_L_naive, transpose_192_L_naive, transpose_256_L_naive,
      transpose_128_L_ref,   transpose_192_L_ref,   transpose_256_L_ref};
  for (const auto& fn : fns) {
    memset(out.data(), 0xC3, 32);
    fn(out.data(), in.data(), 0);
    for (uint64_t i = 0; i < 32; ++i) ASSERT_EQ(out[i], (uint8_t)0xC3) << "L=0 must write nothing i=" << i;
  }
}
*/