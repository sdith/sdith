// Exhaustive per-function correctness tests for the round-3 "commons" module
// (src/commons.c). Every exported (non-static) function of that translation
// unit is covered:
//
//   * binval_of / binval_of_compat  (2-adic valuation / count-trailing-zeros)
//   * grey_of / inv_grey_of         (binary<->Gray code)
//   * bit_of                        (little-endian bit extraction)
//   * flambda_power                 (field exponentiation, all 6 param sets)
//   * flambda_is_zero_nonct         (field-element zero test, all 6 param sets)
//   * bitvec_is_zero_nonct          (packed bit-vector zero test)
//
// Oracles: hand-computed known-answer tables, independent re-implementations
// that do NOT restate the C code, round-trip / algebraic properties, and the
// Python reference (sdith-py/round3/utils.py) for the bit helpers
// (bitvec_is_zero, lowest_set_bit, get_bit).
//
// Follows the gtest conventions of the exemplar test/gf192_test.cpp (include
// list style, randomize* helpers, TEST() naming). The commons module has no
// avx2 implementation, so there are no ref-vs-avx2 / x86-only tests here.
//
// NOTE ON LINKAGE: binval_of/grey_of/inv_grey_of are declared in
// vole_private.h WITHOUT `extern "C"`, but commons.c is compiled as C, so those
// header declarations mangle and fail to link from C++. bit_of/binval_of_compat
// are not declared in any header at all. We therefore include only
// vole_parameters.h (for the vole_parameters struct + init) and declare every
// commons.c symbol ourselves with correct C linkage below.

#include "gtest/gtest.h"

#include <cstdint>
#include <cstring>
#include <vector>

#include "commons.h"
#include "testlib/testlib.h"
#include "vole_parameters.h"

extern "C" {
uint16_t binval_of(uint16_t i);
uint16_t binval_of_compat(uint16_t i);
uint16_t grey_of(uint16_t x);
uint16_t inv_grey_of(uint16_t x);
uint8_t bit_of(uint16_t x, uint16_t pos);
void flambda_power(const vole_parameters* vole_params, flambda_t* res, const flambda_t* x, uint64_t p);
uint8_t flambda_is_zero_nonct(const vole_parameters* vole_params, const flambda_t* x);
uint8_t bitvec_is_zero_nonct(const uint8_t* x, uint64_t num_bits);
}

namespace {

// ---------------------------------------------------------------------------
// Independent oracles (do not reuse the C implementations under test)
// ---------------------------------------------------------------------------

// Position of the lowest set bit, computed by a plain scan (NOT __builtin_ctz).
// Mirrors utils.py lowest_set_bit() for n != 0.
uint16_t trailing_zeros_ref(uint16_t i) {
  uint16_t c = 0;
  while (((i >> c) & 1u) == 0) ++c;
  return c;
}

uint16_t popcount16(uint16_t x) { return (uint16_t)__builtin_popcount((unsigned)x); }

// Mirror of utils.py bitvec_is_zero(data, num_bits).
bool bitvec_is_zero_oracle(const uint8_t* x, uint64_t num_bits) {
  const uint64_t full = num_bits / 8;
  for (uint64_t i = 0; i < full; ++i) {
    if (x[i]) return false;
  }
  const uint64_t rem = num_bits % 8;
  if (rem && (x[full] & (uint8_t)((1u << rem) - 1u))) return false;
  return true;
}

// The six SDitH round-3 parameter sets (values from
// src/sdith_signature_parameters.c). flambda arithmetic depends only on lambda,
// but we exercise all six sets so the parameter plumbing is covered.
struct param_set_t {
  const char* name;
  uint64_t lambda;
  uint64_t tau;
  uint64_t kappa;
};
const param_set_t kParamSets[] = {
    {"cat1_short", 128, 11, 11}, {"cat3_short", 192, 16, 12}, {"cat5_short", 256, 21, 12},
    {"cat1_fast", 128, 16, 8},   {"cat3_fast", 192, 24, 8},   {"cat5_fast", 256, 32, 8},
};

// Naive field exponentiation: identity multiplied by x, p times. Independent of
// the square-and-multiply loop in flambda_power (same product, different ladder).
void flambda_power_naive(const vole_parameters* vp, uint8_t* res, const uint8_t* x, uint64_t p) {
  const uint64_t lb = vp->lambda_bytes;
  alignas(32) uint8_t acc[32];
  alignas(32) uint8_t base[32];
  memset(acc, 0, sizeof(acc));
  acc[0] = 1;  // multiplicative identity
  memset(base, 0, sizeof(base));
  memcpy(base, x, lb);
  for (uint64_t i = 0; i < p; ++i) {
    vp->flambda_product(acc, acc, base);
  }
  memcpy(res, acc, lb);
}

}  // namespace

// ===========================================================================
// binval_of  (return __builtin_ctz(i); i != 0)
// ===========================================================================

TEST(commons, binval_of_kat) {
  // Hand-computed known answers.
  EXPECT_EQ(binval_of(1), 0u);
  EXPECT_EQ(binval_of(2), 1u);
  EXPECT_EQ(binval_of(3), 0u);
  EXPECT_EQ(binval_of(4), 2u);
  EXPECT_EQ(binval_of(6), 1u);
  EXPECT_EQ(binval_of(8), 3u);
  EXPECT_EQ(binval_of(12), 2u);
  EXPECT_EQ(binval_of(16), 4u);
  EXPECT_EQ(binval_of(0x00FF), 0u);
  EXPECT_EQ(binval_of(0x0100), 8u);
  EXPECT_EQ(binval_of(0x4000), 14u);
  EXPECT_EQ(binval_of(0x8000), 15u);
  EXPECT_EQ(binval_of(0x8001), 0u);
  EXPECT_EQ(binval_of(0xFFFF), 0u);
}

TEST(commons, binval_of_exhaustive_vs_ref) {
  // binval_of(0) is documented as undefined (CASSERT), so start at 1.
  for (uint32_t i = 1; i <= 0xFFFF; ++i) {
    EXPECT_EQ(binval_of((uint16_t)i), trailing_zeros_ref((uint16_t)i)) << "i=" << i;
  }
}

// ===========================================================================
// binval_of_compat  (branch-free popcount variant of binval_of)
// ===========================================================================

TEST(commons, binval_of_compat_kat) {
  EXPECT_EQ(binval_of_compat(1), 0u);
  EXPECT_EQ(binval_of_compat(2), 1u);
  EXPECT_EQ(binval_of_compat(4), 2u);
  EXPECT_EQ(binval_of_compat(6), 1u);
  EXPECT_EQ(binval_of_compat(0x0100), 8u);
  EXPECT_EQ(binval_of_compat(0x8000), 15u);
  EXPECT_EQ(binval_of_compat(0xFFFF), 0u);
}

TEST(commons, binval_of_compat_exhaustive_matches_binval_of) {
  // Two distinct implementations of the same function must agree everywhere.
  for (uint32_t i = 1; i <= 0xFFFF; ++i) {
    EXPECT_EQ(binval_of_compat((uint16_t)i), trailing_zeros_ref((uint16_t)i)) << "i=" << i;
    EXPECT_EQ(binval_of_compat((uint16_t)i), binval_of((uint16_t)i)) << "i=" << i;
  }
}

// ===========================================================================
// grey_of  (x ^ (x >> 1))
// ===========================================================================

TEST(commons, grey_of_kat) {
  // Hand-computed standard reflected binary Gray code.
  const uint16_t expect[16] = {0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8};
  for (uint16_t x = 0; x < 16; ++x) {
    EXPECT_EQ(grey_of(x), expect[x]) << "x=" << x;
  }
}

TEST(commons, grey_of_adjacent_differ_by_one_bit) {
  // Defining property of a Gray code: successive codes differ in exactly one bit.
  for (uint32_t x = 0; x < 0xFFFF; ++x) {
    const uint16_t d = (uint16_t)(grey_of((uint16_t)x) ^ grey_of((uint16_t)(x + 1)));
    EXPECT_EQ(popcount16(d), 1u) << "x=" << x;
  }
}

// ===========================================================================
// inv_grey_of  (Gray -> binary decode)
// ===========================================================================

TEST(commons, inv_grey_of_kat) {
  // Inverse of the grey_of KAT table above.
  const uint16_t gray[16] = {0, 1, 3, 2, 6, 7, 5, 4, 12, 13, 15, 14, 10, 11, 9, 8};
  for (uint16_t x = 0; x < 16; ++x) {
    EXPECT_EQ(inv_grey_of(gray[x]), x) << "x=" << x;
  }
}

TEST(commons, grey_roundtrip_exhaustive) {
  // grey_of and inv_grey_of are mutual inverses over the whole 16-bit domain.
  for (uint32_t x = 0; x <= 0xFFFF; ++x) {
    const uint16_t xx = (uint16_t)x;
    EXPECT_EQ(inv_grey_of(grey_of(xx)), xx) << "fwd x=" << x;
    EXPECT_EQ(grey_of(inv_grey_of(xx)), xx) << "bwd x=" << x;
  }
}

// ===========================================================================
// bit_of  ((x >> pos) & 1, little-endian)
// ===========================================================================

TEST(commons, bit_of_kat) {
  // 0x000A = 0b1010
  EXPECT_EQ(bit_of(0x000A, 0), 0u);
  EXPECT_EQ(bit_of(0x000A, 1), 1u);
  EXPECT_EQ(bit_of(0x000A, 2), 0u);
  EXPECT_EQ(bit_of(0x000A, 3), 1u);
  // extremes
  EXPECT_EQ(bit_of(0x0001, 0), 1u);
  EXPECT_EQ(bit_of(0x8000, 15), 1u);
  for (uint16_t p = 0; p < 16; ++p) {
    EXPECT_EQ(bit_of(0x0000, p), 0u) << "zero p=" << p;
    EXPECT_EQ(bit_of(0xFFFF, p), 1u) << "ones p=" << p;
  }
  // bit above the top set bit reads as 0 (x promoted to int, shift < 32 is defined)
  EXPECT_EQ(bit_of(0x0001, 1), 0u);
  EXPECT_EQ(bit_of(0x8000, 14), 0u);
}

TEST(commons, bit_of_reconstructs_value) {
  // Summing bit_of(x, i) << i over i in [0,16) must rebuild x, for every x.
  for (uint32_t x = 0; x <= 0xFFFF; ++x) {
    uint16_t acc = 0;
    for (uint16_t p = 0; p < 16; ++p) {
      acc = (uint16_t)(acc | ((uint16_t)bit_of((uint16_t)x, p) << p));
    }
    EXPECT_EQ(acc, (uint16_t)x) << "x=" << x;
  }
}

// ===========================================================================
// flambda_power  (parameterized over all 6 sets)
// ===========================================================================

TEST(commons, flambda_power_matches_naive_all_param_sets) {
  const uint64_t exps[] = {0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 255, 256, 1000};
  for (const auto& ps : kParamSets) {
    vole_parameters vp;
    vole_parameters_init_ref(&vp, ps.lambda, ps.tau, ps.kappa);
    const uint64_t lb = vp.lambda_bytes;
    ASSERT_EQ(lb, ps.lambda / 8);

    for (int trial = 0; trial < 8; ++trial) {
      alignas(32) uint8_t x[32] = {0};
      randomize(x, lb);
      for (uint64_t p : exps) {
        alignas(32) uint8_t got[32] = {0};
        alignas(32) uint8_t want[32] = {0};
        flambda_power(&vp, got, x, p);
        flambda_power_naive(&vp, want, x, p);
        EXPECT_EQ(0, memcmp(got, want, lb)) << ps.name << " p=" << p << " trial=" << trial;
      }
    }
  }
}

TEST(commons, flambda_power_edge_values) {
  for (const auto& ps : kParamSets) {
    vole_parameters vp;
    vole_parameters_init_ref(&vp, ps.lambda, ps.tau, ps.kappa);
    const uint64_t lb = vp.lambda_bytes;

    alignas(32) uint8_t one[32] = {0};
    one[0] = 1;
    alignas(32) uint8_t zero[32] = {0};
    alignas(32) uint8_t got[32] = {0};

    // x^0 == 1 for any x (identity), including x == 0.
    alignas(32) uint8_t x[32] = {0};
    randomize(x, lb);
    flambda_power(&vp, got, x, 0);
    EXPECT_EQ(0, memcmp(got, one, lb)) << ps.name << " x^0";
    flambda_power(&vp, got, zero, 0);
    EXPECT_EQ(0, memcmp(got, one, lb)) << ps.name << " 0^0";

    // x^1 == x.
    flambda_power(&vp, got, x, 1);
    EXPECT_EQ(0, memcmp(got, x, lb)) << ps.name << " x^1";

    // x^2 == x*x.
    alignas(32) uint8_t sq[32] = {0};
    vp.flambda_product(sq, x, x);
    flambda_power(&vp, got, x, 2);
    EXPECT_EQ(0, memcmp(got, sq, lb)) << ps.name << " x^2";

    // 0^p == 0 for p >= 1.
    for (uint64_t p : {(uint64_t)1, (uint64_t)2, (uint64_t)5}) {
      flambda_power(&vp, got, zero, p);
      EXPECT_EQ(0, memcmp(got, zero, lb)) << ps.name << " 0^" << p;
    }

    // 1^p == 1 for all p.
    for (uint64_t p : {(uint64_t)0, (uint64_t)1, (uint64_t)2, (uint64_t)7, (uint64_t)255}) {
      flambda_power(&vp, got, one, p);
      EXPECT_EQ(0, memcmp(got, one, lb)) << ps.name << " 1^" << p;
    }
  }
}

TEST(commons, flambda_power_exponent_laws) {
  for (const auto& ps : kParamSets) {
    vole_parameters vp;
    vole_parameters_init_ref(&vp, ps.lambda, ps.tau, ps.kappa);
    const uint64_t lb = vp.lambda_bytes;

    for (int trial = 0; trial < 8; ++trial) {
      alignas(32) uint8_t x[32] = {0};
      randomize(x, lb);
      const uint64_t a = 3 + (uint64_t)trial;
      const uint64_t b = 5 + 2 * (uint64_t)trial;

      // x^a * x^b == x^(a+b)
      alignas(32) uint8_t xa[32] = {0}, xb[32] = {0}, prod[32] = {0}, xab[32] = {0};
      flambda_power(&vp, xa, x, a);
      flambda_power(&vp, xb, x, b);
      vp.flambda_product(prod, xa, xb);
      flambda_power(&vp, xab, x, a + b);
      EXPECT_EQ(0, memcmp(prod, xab, lb)) << ps.name << " add law trial=" << trial;

      // (x^a)^b == x^(a*b)
      alignas(32) uint8_t xa_b[32] = {0}, xamulb[32] = {0};
      flambda_power(&vp, xa_b, xa, b);
      flambda_power(&vp, xamulb, x, a * b);
      EXPECT_EQ(0, memcmp(xa_b, xamulb, lb)) << ps.name << " mul law trial=" << trial;
    }
  }
}

// ===========================================================================
// flambda_is_zero_nonct  (parameterized over all 6 sets)
// ===========================================================================

TEST(commons, flambda_is_zero_nonct_all_param_sets) {
  for (const auto& ps : kParamSets) {
    vole_parameters vp;
    vole_parameters_init_ref(&vp, ps.lambda, ps.tau, ps.kappa);
    const uint64_t lb = vp.lambda_bytes;

    alignas(32) uint8_t buf[32];

    // all-zero -> 1
    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(flambda_is_zero_nonct(&vp, buf), 1u) << ps.name << " zero";

    // all-ones (within lambda_bytes) -> 0
    memset(buf, 0, sizeof(buf));
    memset(buf, 0xFF, lb);
    EXPECT_EQ(flambda_is_zero_nonct(&vp, buf), 0u) << ps.name << " ones";

    // a single nonzero byte at each position in range -> 0
    for (uint64_t i = 0; i < lb; ++i) {
      memset(buf, 0, sizeof(buf));
      buf[i] = 0x01;
      EXPECT_EQ(flambda_is_zero_nonct(&vp, buf), 0u) << ps.name << " byte=" << i << " lsb";
      buf[i] = 0x80;
      EXPECT_EQ(flambda_is_zero_nonct(&vp, buf), 0u) << ps.name << " byte=" << i << " msb";
    }
  }
}

// ===========================================================================
// bitvec_is_zero_nonct  (standalone, packed little-endian bits)
// ===========================================================================

TEST(commons, bitvec_is_zero_nonct_kat) {
  // num_bits == 0 -> always zero/true, even with garbage data.
  const uint8_t garbage[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  EXPECT_EQ(bitvec_is_zero_nonct(garbage, 0), 1u);

  // all-zero buffer over assorted lengths -> 1
  const uint8_t zeros[16] = {0};
  for (uint64_t nb : {(uint64_t)1, (uint64_t)7, (uint64_t)8, (uint64_t)9, (uint64_t)16, (uint64_t)17, (uint64_t)64,
                      (uint64_t)100}) {
    EXPECT_EQ(bitvec_is_zero_nonct(zeros, nb), 1u) << "zeros nb=" << nb;
  }

  // Byte boundary: {0x00, 0x01}
  {
    const uint8_t d[2] = {0x00, 0x01};
    EXPECT_EQ(bitvec_is_zero_nonct(d, 8), 1u);   // only byte 0 checked
    EXPECT_EQ(bitvec_is_zero_nonct(d, 9), 0u);   // bit 8 (lsb of byte 1) is set
    EXPECT_EQ(bitvec_is_zero_nonct(d, 16), 0u);  // whole byte 1 checked
  }

  // Masking: a bit past num_bits must be ignored.
  {
    const uint8_t d[2] = {0x00, 0x80};  // bit 15 set
    EXPECT_EQ(bitvec_is_zero_nonct(d, 9), 1u);   // bit 15 outside first 9 bits
    EXPECT_EQ(bitvec_is_zero_nonct(d, 15), 1u);  // bit 15 outside first 15 bits (0..14)
    EXPECT_EQ(bitvec_is_zero_nonct(d, 16), 0u);  // bit 15 now inside
  }

  // Masking within the first byte.
  {
    const uint8_t d[1] = {0x20};  // bit 5 set
    EXPECT_EQ(bitvec_is_zero_nonct(d, 5), 1u);  // checks bits 0..4 only
    EXPECT_EQ(bitvec_is_zero_nonct(d, 6), 0u);  // bit 5 now inside
  }
}

TEST(commons, bitvec_is_zero_nonct_single_bit_sweep) {
  // For a lone set bit at global position p, the first q bits are zero iff p >= q.
  const uint64_t nbytes = 8;
  for (uint64_t p = 0; p < nbytes * 8; ++p) {
    uint8_t buf[8];
    memset(buf, 0, sizeof(buf));
    buf[p / 8] = (uint8_t)(1u << (p % 8));
    for (uint64_t q = 0; q <= nbytes * 8; ++q) {
      const uint8_t expect = (p >= q) ? 1u : 0u;
      EXPECT_EQ(bitvec_is_zero_nonct(buf, q), expect) << "p=" << p << " q=" << q;
    }
  }
}

TEST(commons, bitvec_is_zero_nonct_random_vs_oracle) {
  for (int trial = 0; trial < 2000; ++trial) {
    uint8_t buf[24];
    randomize(buf, sizeof(buf));
    // occasionally sparse so the "all zero" path is also exercised
    if ((trial & 3) == 0) memset(buf, 0, sizeof(buf));
    for (uint64_t nb : {(uint64_t)0, (uint64_t)1, (uint64_t)3, (uint64_t)8, (uint64_t)13, (uint64_t)16, (uint64_t)23,
                        (uint64_t)24, (uint64_t)33, (uint64_t)64, (uint64_t)100, (uint64_t)8 * 24}) {
      const uint8_t got = bitvec_is_zero_nonct(buf, nb);
      const uint8_t want = bitvec_is_zero_oracle(buf, nb) ? 1u : 0u;
      EXPECT_EQ(got, want) << "trial=" << trial << " nb=" << nb;
    }
  }
}
