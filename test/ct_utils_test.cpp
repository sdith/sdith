#include <gtest/gtest.h>

#include <vector>

#include "sdith_ct_utils.h"
#include "testlib/vole_testlib.h"
#include "vole_private.h"

// The _ref helpers are the definition and the _avx ones are the hardened
// rewrite, so the only thing to check is that they compute the same function.
// The _ref side is checked against plain C on top of that.

namespace {

struct ct_variant {
  const char* name;
  const ct_utils* fns;
};

const std::vector<ct_variant> kCtVariants = {
    {"ref", &ct_utils_ref},
#ifdef __x86_64__
    {"avx", &ct_utils_avx},
#endif
};

// values around every interesting boundary: 0, 1, small, word edges, max
const std::vector<uint64_t> kProbes = {
    0, 1, 2, 3, 7, 8, 63, 64, 65, 127, 128, 255, 256, 4095,
    UINT64_C(0x7FFFFFFF), UINT64_C(0x80000000), UINT64_C(0xFFFFFFFF),
    UINT64_C(0x100000000), UINT64_C(0x7FFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFFFFFFFFFF),
};

}  // namespace

TEST(ct_utils, mask_lt_and_eq) {
  for (const ct_variant& v : kCtVariants) {
    SCOPED_TRACE(v.name);
    for (uint64_t a : kProbes) {
      for (uint64_t b : kProbes) {
        ASSERT_EQ(v.fns->mask_lt(a, b), a < b ? UINT64_C(-1) : 0) << a << " < " << b;
        ASSERT_EQ(v.fns->mask_eq(a, b), a == b ? UINT64_C(-1) : 0) << a << " == " << b;
      }
    }
  }
}

TEST(ct_utils, div_rem_u32) {
  for (const ct_variant& v : kCtVariants) {
    SCOPED_TRACE(v.name);
    // every divisor that matters (the mux arities and the rsd_npw in use), plus
    // the extremes where the 33-bit remainder accumulator is exercised
    const std::vector<uint32_t> divisors = {1,   2,   3,     4,          5,          185,
                                            191, 252, 65535, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
    for (uint32_t d : divisors) {
      for (uint64_t n64 : kProbes) {
        const uint32_t n = (uint32_t)n64;
        uint32_t q = 0xDEADBEEF, r = 0xDEADBEEF;
        v.fns->div_rem_u32(&q, &r, n, d);
        ASSERT_EQ(q, n / d) << n << " / " << d;
        ASSERT_EQ(r, n % d) << n << " % " << d;
      }
      for (int i = 0; i < 200; ++i) {
        const uint32_t n = (uint32_t)uniform_u128();
        uint32_t q = 0, r = 0;
        v.fns->div_rem_u32(&q, &r, n, d);
        ASSERT_EQ(q, n / d) << n << " / " << d;
        ASSERT_EQ(r, n % d) << n << " % " << d;
      }
    }
  }
}

TEST(ct_utils, bitvec_xor_to_masked) {
  for (const ct_variant& v : kCtVariants) {
    SCOPED_TRACE(v.name);
    // cross the 32-byte vector step in both directions, and stop on it exactly
    for (uint64_t bytelen : {1, 7, 31, 32, 33, 63, 64, 65, 100, 137}) {
      for (uint64_t mask : {UINT64_C(0), UINT64_C(-1)}) {
        std::vector<uint8_t> res(bytelen), b(bytelen), expect(bytelen);
        randomize(res.data(), bytelen);
        randomize(b.data(), bytelen);
        for (uint64_t i = 0; i < bytelen; ++i) expect[i] = res[i] ^ (b[i] & (uint8_t)mask);
        v.fns->bitvec_xor_to_masked(res.data(), bytelen, b.data(), mask);
        ASSERT_EQ(res, expect) << "bytelen=" << bytelen << " mask=" << mask;
      }
    }
  }
}

TEST(ct_utils, bitvec_xoru32) {
  for (const ct_variant& v : kCtVariants) {
    SCOPED_TRACE(v.name);
    const uint64_t bytelen = 24;
    // every width from 1 to 32, at every offset that still fits: the field must
    // stay inside the vector with no slack, and must not disturb its neighbours
    for (uint64_t nbits : {1, 2, 3, 4, 7, 8, 9, 16, 31, 32}) {
      for (uint64_t bitpos = 0; bitpos + nbits <= bytelen * 8; ++bitpos) {
        for (uint32_t value : {UINT32_C(0), UINT32_C(1), UINT32_C(0x80000000), UINT32_C(0xDEADBEEF)}) {
          std::vector<uint8_t> res(bytelen), expect(bytelen);
          randomize(res.data(), bytelen);
          expect = res;
          for (uint64_t k = 0; k < nbits; ++k) {
            if ((value >> k) & 1) expect[(bitpos + k) >> 3] ^= (uint8_t)1 << ((bitpos + k) & 7);
          }
          v.fns->bitvec_xoru32(res.data(), bytelen, bitpos, nbits, value);
          ASSERT_EQ(res, expect) << "bitpos=" << bitpos << " nbits=" << nbits << " value=" << value;
        }
      }
    }
  }
}

TEST(ct_utils, bitvec_xorbit) {
  for (const ct_variant& v : kCtVariants) {
    SCOPED_TRACE(v.name);
    for (uint64_t bytelen : {1, 7, 32, 100}) {
      for (uint64_t bitpos = 0; bitpos < bytelen * 8; ++bitpos) {
        for (uint64_t mask : {UINT64_C(0), UINT64_C(-1)}) {
          std::vector<uint8_t> res(bytelen), expect(bytelen);
          randomize(res.data(), bytelen);
          expect = res;
          if (mask) expect[bitpos >> 3] ^= (uint8_t)1 << (bitpos & 7);
          v.fns->bitvec_xorbit(res.data(), bytelen, bitpos, mask);
          ASSERT_EQ(res, expect) << "bytelen=" << bytelen << " bitpos=" << bitpos << " mask=" << mask;
        }
      }
    }
  }
}
