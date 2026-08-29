#include "gtest/gtest.h"
#include "testlib/testlib.h"
#include "vole_private.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// gf128 has no v64[] member (only v[16] and v128), so we build/compare through
// the native __uint128_t value.
static gf128 mk128(uint64_t hi, uint64_t lo) {
  gf128 r;
  r.v128 = ((__uint128_t)hi << 64) | (__uint128_t)lo;
  return r;
}

// Bounds-checked bit accessor: gf128v_bitof aborts (CREQUIRE) for pos >= 128,
// so wrap it for the shift tests that probe out-of-range positions.
static bool gf128v_xbitof(const gf128& a, int64_t pos) {
  if (pos < 0 || pos >= 128) return false;
  return gf128v_bitof(a, pos);
}

// ---------------------------------------------------------------------------
// Known-answer vectors (ground truth: sdith-py/round3 gf.py GF128, poly 0x87)
// ---------------------------------------------------------------------------
struct gf128_mul_kat {
  uint64_t ah, al, bh, bl, rh, rl;
};

// a * b == r  in GF(2^128)
static const gf128_mul_kat MUL_KATS[] = {
    // 0 * 0 = 0
    {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
     0x0000000000000000},
    // 1 * 0 = 0
    {0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
     0x0000000000000000},
    // 0 * 12345 = 0
    {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000003039, 0x0000000000000000,
     0x0000000000000000},
    // 1 * X = X (identity)
    {0x0000000000000000, 0x0000000000000001, 0x0123456789abcdef, 0xfedcba9876543210, 0x0123456789abcdef,
     0xfedcba9876543210},
    // 2 * 2^127 = 0x87 (reduction wrap)
    {0x0000000000000000, 0x0000000000000002, 0x8000000000000000, 0x0000000000000000, 0x0000000000000000,
     0x0000000000000087},
    // generic
    {0x0123456789abcdef, 0xfedcba9876543210, 0x1111111111111111, 0x2222222222222222, 0x18f902e72ccd36d4,
     0xa7649358cf0cfb37},
    // all-ones * all-ones
    {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x5555555555555555,
     0x555555555555402f},
    // all-ones * 1 = all-ones
    {0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000001, 0xffffffffffffffff,
     0xffffffffffffffff},
    // 3 * 3 = 5 (x+1)^2 = x^2+1
    {0x0000000000000000, 0x0000000000000003, 0x0000000000000000, 0x0000000000000003, 0x0000000000000000,
     0x0000000000000005},
    // generic 2
    {0xdeadbeefcafebabe, 0x0011223344556677, 0x8899aabbccddeeff, 0x0f1e2d3c4b5a6978, 0x75cbfc228c4ee206,
     0x428b27febb4c3e67},
};

struct gf128_inv_kat {
  uint64_t ah, al, rh, rl;
};

// inv(a) == r ; verified a * r == 1 in the generator
static const gf128_inv_kat INV_KATS[] = {
    {0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000001},
    {0x0000000000000000, 0x0000000000000002, 0x8000000000000000, 0x0000000000000043},
    {0x0000000000000000, 0x0000000000000003, 0xffffffffffffffff, 0xffffffffffffff82},
    {0x0123456789abcdef, 0xfedcba9876543210, 0xac20a8a9f088c918, 0xe7a4a93e6b40984a},
    {0xffffffffffffffff, 0xffffffffffffffff, 0xfe08629e8e4b766a, 0xfc10c53d1c96eca8},
    {0xdeadbeefcafebabe, 0x0011223344556677, 0x317ab1e99002148c, 0x433566de1c6e5e8e},
};

// ---------------------------------------------------------------------------
// gf128_set_ref : res = a
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_set_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    randomize_primitive_var(x);
    gf128_set_ref(&y, &x);
    ASSERT_TRUE(gf128v_equals(y, x));
  }
  // edge cases
  gf128 z;
  gf128_set_ref(&z, &GF128_ZERO);
  ASSERT_TRUE(gf128v_equals(z, GF128_ZERO));
  gf128_set_ref(&z, &GF128_ONE);
  ASSERT_TRUE(gf128v_equals(z, GF128_ONE));
}

// ---------------------------------------------------------------------------
// gf128_sum_ref / gf128v_sum / gf128p_sum : res = a ^ b
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_sum_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    gf128 sx;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf128_sum_ref(&sx, &x, &y);
    ASSERT_TRUE(gf128v_equals(sx, mk128((uint64_t)(x.v128 >> 64) ^ (uint64_t)(y.v128 >> 64),
                                        (uint64_t)x.v128 ^ (uint64_t)y.v128)));
  }
  // edge cases: a ^ 0 == a, a ^ a == 0, all-ones ^ all-ones == 0
  gf128 a = mk128(0x0123456789abcdef, 0xfedcba9876543210);
  gf128 r;
  gf128_sum_ref(&r, &a, &GF128_ZERO);
  ASSERT_TRUE(gf128v_equals(r, a));
  gf128_sum_ref(&r, &a, &a);
  ASSERT_TRUE(gf128v_equals(r, GF128_ZERO));
  gf128 ones = mk128(0xffffffffffffffff, 0xffffffffffffffff);
  gf128_sum_ref(&r, &ones, &ones);
  ASSERT_TRUE(gf128v_equals(r, GF128_ZERO));
}

TEST(gf128_ext, gf128v_sum) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf128 sv = gf128v_sum(x, y);
    gf128 sp;
    gf128_sum_ref(&sp, &x, &y);
    ASSERT_TRUE(gf128v_equals(sv, sp));
  }
}

TEST(gf128_ext, gf128p_sum) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    gf128 sp;
    gf128 sr;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf128p_sum(&sp, &x, &y);
    gf128_sum_ref(&sr, &x, &y);
    ASSERT_TRUE(gf128v_equals(sp, sr));
  }
}

// ---------------------------------------------------------------------------
// gf128v_bitof : extract bit at position
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_bitof) {
  // lo=0x81 sets bits 0 and 7; hi=0x8000000000000001 sets bits 64 and 127.
  gf128 a = mk128(0x8000000000000001, 0x0000000000000081);
  ASSERT_EQ(gf128v_bitof(a, 0), 1);
  ASSERT_EQ(gf128v_bitof(a, 7), 1);
  ASSERT_EQ(gf128v_bitof(a, 64), 1);
  ASSERT_EQ(gf128v_bitof(a, 127), 1);
  ASSERT_EQ(gf128v_bitof(a, 1), 0);
  ASSERT_EQ(gf128v_bitof(a, 8), 0);
  ASSERT_EQ(gf128v_bitof(a, 63), 0);
  ASSERT_EQ(gf128v_bitof(a, 126), 0);
  ASSERT_EQ(gf128v_bitof(GF128_ZERO, 0), 0);
  ASSERT_EQ(gf128v_bitof(GF128_ONE, 0), 1);
  ASSERT_EQ(gf128v_bitof(GF128_ONE, 1), 0);
  // consistency against a fully random value
  for (uint64_t i = 0; i < 20; ++i) {
    gf128 x;
    randomize_primitive_var(x);
    for (uint64_t k = 0; k < 128; ++k) {
      ASSERT_EQ(gf128v_bitof(x, k), (uint8_t)((x.v128 >> k) & 1));
    }
  }
}

// ---------------------------------------------------------------------------
// gf128v_lsh / gf128p_lsh : left shift
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_lsh) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 sx1;
    gf128 sx2;
    randomize_primitive_var(x);
    for (uint64_t j = 0; j < 128; ++j) {
      sx1 = gf128v_lsh(x, j);
      for (uint64_t k = 0; k < 128; ++k) {
        ASSERT_EQ(gf128v_bitof(sx1, k), gf128v_xbitof(x, k - j));
      }
      // test inplace by-pointer version
      sx2 = x;
      gf128p_lsh(&sx2, &sx2, j);
      ASSERT_TRUE(gf128v_equals(sx1, sx2));
    }
  }
}

// ---------------------------------------------------------------------------
// gf128v_rsh / gf128p_rsh : right shift
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_rsh) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 sx1;
    gf128 sx2;
    randomize_primitive_var(x);
    for (uint64_t j = 0; j < 128; ++j) {
      sx1 = gf128v_rsh(x, j);
      for (uint64_t k = 0; k < 128; ++k) {
        ASSERT_EQ(gf128v_bitof(sx1, k), gf128v_xbitof(x, k + j));
      }
      // test inplace by-pointer version
      sx2 = x;
      gf128p_rsh(&sx2, &sx2, j);
      ASSERT_TRUE(gf128v_equals(sx1, sx2));
    }
  }
}

// ---------------------------------------------------------------------------
// gf128_product_ref : field multiply (KAT vs python oracle)
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_product_ref_kat) {
  for (const gf128_mul_kat& kat : MUL_KATS) {
    gf128 a = mk128(kat.ah, kat.al);
    gf128 b = mk128(kat.bh, kat.bl);
    gf128 r;
    gf128_product_ref(&r, &a, &b);
    ASSERT_TRUE(gf128v_equals(r, mk128(kat.rh, kat.rl)));
    // commutativity on the same vector
    gf128_product_ref(&r, &b, &a);
    ASSERT_TRUE(gf128v_equals(r, mk128(kat.rh, kat.rl)));
  }
}

// ---------------------------------------------------------------------------
// gf128_product_ref : algebraic property sweep
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_product_group) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    gf128 z;
    gf128 p1;
    gf128 p2;
    gf128 p3;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    randomize_primitive_var(z);
    // zero: x*0 == 0*x == 0
    gf128_product_ref(&p1, &x, &GF128_ZERO);
    gf128_product_ref(&p2, &GF128_ZERO, &x);
    ASSERT_TRUE(gf128v_equals(p1, GF128_ZERO));
    ASSERT_TRUE(gf128v_equals(p2, GF128_ZERO));
    // neutral: x*1 == 1*x == x
    gf128_product_ref(&p1, &x, &GF128_ONE);
    gf128_product_ref(&p2, &GF128_ONE, &x);
    ASSERT_TRUE(gf128v_equals(p1, x));
    ASSERT_TRUE(gf128v_equals(p2, x));
    // commutativity
    gf128_product_ref(&p1, &x, &y);
    gf128_product_ref(&p2, &y, &x);
    ASSERT_TRUE(gf128v_equals(p1, p2));
    // associativity
    gf128_product_ref(&p1, &x, &y);
    gf128_product_ref(&p1, &p1, &z);
    gf128_product_ref(&p2, &y, &z);
    gf128_product_ref(&p2, &x, &p2);
    ASSERT_TRUE(gf128v_equals(p1, p2));
    // distributivity: z*(x+y) == z*x + z*y
    gf128_sum_ref(&p1, &x, &y);
    gf128_product_ref(&p1, &z, &p1);
    gf128_product_ref(&p3, &z, &x);
    gf128_product_ref(&p2, &z, &y);
    gf128_sum_ref(&p2, &p2, &p3);
    ASSERT_TRUE(gf128v_equals(p1, p2));
  }
}

TEST(gf128_ext, gf128v_mul) {
  // by-value variant must match by-pointer ref, and the KATs
  for (const gf128_mul_kat& kat : MUL_KATS) {
    gf128 a = mk128(kat.ah, kat.al);
    gf128 b = mk128(kat.bh, kat.bl);
    gf128 r = gf128v_mul(a, b);
    ASSERT_TRUE(gf128v_equals(r, mk128(kat.rh, kat.rl)));
  }
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf128 rv = gf128v_mul(x, y);
    gf128 rp;
    gf128_product_ref(&rp, &x, &y);
    ASSERT_TRUE(gf128v_equals(rv, rp));
  }
}

TEST(gf128_ext, gf128p_mul) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    gf128 rp;
    gf128 rr;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf128p_mul(&rp, &x, &y);
    gf128_product_ref(&rr, &x, &y);
    ASSERT_TRUE(gf128v_equals(rp, rr));
  }
}

// ---------------------------------------------------------------------------
// gf128_product_f2_ref : multiply by an F2 scalar (b in {0,1})
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_product_f2_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    randomize_primitive_var(x);
    gf128 r;
    // b == 0  ->  0
    gf128_product_f2_ref(&r, &x, &GF128_ZERO);
    ASSERT_TRUE(gf128v_equals(r, GF128_ZERO));
    // b == 1  ->  x
    gf128_product_f2_ref(&r, &x, &GF128_ONE);
    ASSERT_TRUE(gf128v_equals(r, x));
  }
  // explicit edge values
  gf128 ones = mk128(0xffffffffffffffff, 0xffffffffffffffff);
  gf128 r;
  gf128_product_f2_ref(&r, &ones, &GF128_ONE);
  ASSERT_TRUE(gf128v_equals(r, ones));
  gf128_product_f2_ref(&r, &ones, &GF128_ZERO);
  ASSERT_TRUE(gf128v_equals(r, GF128_ZERO));
}

// ---------------------------------------------------------------------------
// gf128_inverse_ref : multiplicative inverse
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_inverse_ref_kat) {
  for (const gf128_inv_kat& kat : INV_KATS) {
    gf128 a = mk128(kat.ah, kat.al);
    gf128 invx;
    gf128_inverse_ref(&invx, &a);
    ASSERT_TRUE(gf128v_equals(invx, mk128(kat.rh, kat.rl)));
    // x * inv(x) == 1
    gf128 prod;
    gf128_product_ref(&prod, &a, &invx);
    ASSERT_TRUE(gf128v_equals(prod, GF128_ONE));
  }
}

TEST(gf128_ext, gf128_inverse_ref) {
  // inv(1) == 1
  gf128 inv1;
  gf128_inverse_ref(&inv1, &GF128_ONE);
  ASSERT_TRUE(gf128v_equals(inv1, GF128_ONE));
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 invx;
    gf128 actual;
    // generate a non-zero element
    do {
      randomize_primitive_var(x);
    } while (gf128v_equals(x, GF128_ZERO));
    gf128_inverse_ref(&invx, &x);
    gf128_product_ref(&actual, &x, &invx);
    ASSERT_TRUE(gf128v_equals(actual, GF128_ONE));
  }
}

// ---------------------------------------------------------------------------
// gf128_sum_pow2_naive / gf128_sum_pow2_ref : sum_i 2^i . x_i  (128 elements)
// ---------------------------------------------------------------------------
TEST(gf128_ext, gf128_sum_pow2_kat) {
  // sparse input: x[0]=A, x[1]=B, x[64]=C, x[127]=D, rest zero.
  gf128 x[128] = {};
  x[0] = mk128(0x0123456789abcdef, 0xfedcba9876543210);
  x[1] = mk128(0xdeadbeefcafebabe, 0x0011223344556677);
  x[64] = mk128(0x8899aabbccddeeff, 0x0f1e2d3c4b5a6978);
  x[127] = mk128(0x1111111111111111, 0xffffffffffffffff);
  gf128 expect = mk128(0x4c99ea7ba8f32e69, 0x09e7f63bf6180b65);
  gf128 rn;
  gf128 rr;
  gf128_sum_pow2_naive(&rn, x);
  gf128_sum_pow2_ref(&rr, x);
  ASSERT_TRUE(gf128v_equals(rn, expect));
  ASSERT_TRUE(gf128v_equals(rr, expect));
}

TEST(gf128_ext, gf128_sum_pow2_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x[128];
    gf128 expect;
    gf128 actual;
    randomize_static_array(x);
    gf128_sum_pow2_naive(&expect, x);
    gf128_sum_pow2_ref(&actual, x);
    ASSERT_TRUE(gf128v_equals(actual, expect));
  }
}

// ---------------------------------------------------------------------------
// gf128_echelon_pow2_{naive,ref} : sum_i x_i . 2^(k.i)
// ---------------------------------------------------------------------------
struct gf128_echelon_kat {
  uint64_t k;
  uint64_t n;
  gf128 e[4];
  gf128 r;
};

TEST(gf128_ext, gf128_echelon_pow2_kat) {
  const gf128 A = mk128(0x0123456789abcdef, 0xfedcba9876543210);
  const gf128 B = mk128(0xdeadbeefcafebabe, 0x0011223344556677);
  const gf128 C = mk128(0x8899aabbccddeeff, 0x0f1e2d3c4b5a6978);
  const gf128 D = mk128(0x1111111111111111, 0xffffffffffffffff);
  const gf128_echelon_kat kats[] = {
      {1, 3, {A, B, C, {}}, mk128(0x9e1e92572f21036f, 0xc2864a0fd3975a97)},
      {3, 4, {A, B, C, D}, mk128(0xf0063ec8cb078423, 0xc6211bef7d9aa2ba)},
      {8, 4, {A, B, C, D}, mk128(0x173777618811830e, 0x3d3d3d79bdf220b2)},
      {64, 2, {A, B, {}, {}}, mk128(0x01326754cdfeabf5, 0xb143f5f27df0482a)},
      {2, 1, {A, {}, {}, {}}, mk128(0x0123456789abcdef, 0xfedcba9876543210)},
  };
  for (const gf128_echelon_kat& kat : kats) {
    gf128 buf[4];
    for (uint64_t i = 0; i < kat.n; ++i) buf[i] = kat.e[i];
    gf128 rn;
    gf128 rr;
    gf128_echelon_pow2_naive(kat.k, &rn, buf, kat.n, sizeof(gf128));
    gf128_echelon_pow2_ref(kat.k, &rr, buf, kat.n, sizeof(gf128));
    ASSERT_TRUE(gf128v_equals(rn, kat.r));
    ASSERT_TRUE(gf128v_equals(rr, kat.r));
  }
}

typedef typeof(gf128_echelon_pow2_naive) gf128_echelon_pow2_f;

static void test_gf128_echelon_pow2(gf128_echelon_pow2_f gf128_echelon_pow2) {
  for (uint64_t k : {1, 3, 8}) {
    for (uint64_t x_size : {0, 1, 2, 63, 128}) {
      if (k * x_size > 128) continue;
      for (uint64_t xbs : {1, 2, 3}) {
        // gf128 is 16-byte aligned; give the buffer matching alignment.
        aligned_vector_u8 x(16, x_size * xbs * sizeof(gf128));
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

TEST(gf128_ext, gf128_echelon_pow2_ref) { test_gf128_echelon_pow2(gf128_echelon_pow2_ref); }

TEST(gf128_ext, gf128_dot_product_ref) {
  for (uint64_t size = 0; size < 33; ++size) {
    std::vector<uint8_t> xb((size + 1) * sizeof(gf128) + 16);
    std::vector<uint8_t> yb((size + 1) * sizeof(gf128) + 16);
    gf128* x = (gf128*)(((uintptr_t)xb.data() + 15) & ~(uintptr_t)15);
    gf128* y = (gf128*)(((uintptr_t)yb.data() + 15) & ~(uintptr_t)15);
    randomize(x, size * sizeof(gf128));
    randomize(y, size * sizeof(gf128));
    // reference: naive sum of pairwise products
    gf128 expect = GF128_ZERO;
    for (uint64_t i = 0; i < size; ++i) {
      gf128 t;
      gf128_product_ref(&t, &x[i], &y[i]);
      gf128_sum_ref(&expect, &expect, &t);
    }
    gf128 actual;
    gf128_dot_product_ref(&actual, x, y, size);
    ASSERT_TRUE(gf128v_equals(actual, expect)) << "size=" << size;
  }
}

// ---------------------------------------------------------------------------
// AVX2 / PCLMUL variants (x86-64 only) : always compared against the ref path.
// ---------------------------------------------------------------------------
#ifdef __x86_64__
TEST(gf128_ext, gf128_sum_avx2) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 y;
    gf128 res_avx;
    gf128 res_ref;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf128_sum_avx2(&res_avx, &x, &y);
    gf128_sum_ref(&res_ref, &x, &y);
    ASSERT_TRUE(gf128v_equals(res_avx, res_ref));
  }
}

TEST(gf128_ext, gf128_product_pclmul) {
  // KATs first
  for (const gf128_mul_kat& kat : MUL_KATS) {
    gf128 a = mk128(kat.ah, kat.al);
    gf128 b = mk128(kat.bh, kat.bl);
    gf128 r;
    gf128_product_pclmul(&r, &a, &b);
    ASSERT_TRUE(gf128v_equals(r, mk128(kat.rh, kat.rl)));
  }
  // random ref-vs-avx2
  for (uint64_t i = 0; i < 1000; ++i) {
    gf128 a;
    gf128 b;
    gf128 res_avx;
    gf128 res_ref;
    randomize_primitive_var(a);
    randomize_primitive_var(b);
    gf128_product_pclmul(&res_avx, &a, &b);
    gf128_product_ref(&res_ref, &a, &b);
    ASSERT_TRUE(gf128v_equals(res_avx, res_ref));
  }
}

TEST(gf128_ext, gf128_product_pclmul_f2) {
  for (uint64_t i = 0; i < 1000; ++i) {
    gf128 a;
    randomize_primitive_var(a);
    // b restricted to F2 ({0,1}); both impls only agree in that domain.
    gf128 b = (uniform_u128() % 2) ? GF128_ONE : GF128_ZERO;
    gf128 res_avx;
    gf128 res_ref;
    gf128_product_pclmul_f2(&res_avx, &a, &b);
    gf128_product_f2_ref(&res_ref, &a, &b);
    ASSERT_TRUE(gf128v_equals(res_avx, res_ref));
  }
}

TEST(gf128_ext, gf128_inverse_pclmul) {
  // KATs
  for (const gf128_inv_kat& kat : INV_KATS) {
    gf128 a = mk128(kat.ah, kat.al);
    gf128 actual;
    gf128_inverse_pclmul(&actual, &a);
    ASSERT_TRUE(gf128v_equals(actual, mk128(kat.rh, kat.rl)));
  }
  // random ref-vs-avx2
  for (uint64_t i = 0; i < 50; ++i) {
    gf128 x;
    gf128 expect;
    gf128 actual;
    do {
      randomize_primitive_var(x);
    } while (gf128v_equals(x, GF128_ZERO));
    gf128_inverse_ref(&expect, &x);
    gf128_inverse_pclmul(&actual, &x);
    ASSERT_TRUE(gf128v_equals(actual, expect));
  }
}

TEST(gf128_ext, gf128_echelon_pow2_avx) { test_gf128_echelon_pow2(gf128_echelon_pow2_avx); }

TEST(gf128_ext, gf128_dot_product_pclmul) {
  for (uint64_t size = 0; size < 33; ++size) {
    std::vector<uint8_t> xb((size + 1) * sizeof(gf128) + 16);
    std::vector<uint8_t> yb((size + 1) * sizeof(gf128) + 16);
    gf128* x = (gf128*)(((uintptr_t)xb.data() + 15) & ~(uintptr_t)15);
    gf128* y = (gf128*)(((uintptr_t)yb.data() + 15) & ~(uintptr_t)15);
    randomize(x, size * sizeof(gf128));
    randomize(y, size * sizeof(gf128));
    gf128 expect;
    gf128 actual;
    gf128_dot_product_ref(&expect, x, y, size);
    gf128_dot_product_pclmul(&actual, x, y, size);
    ASSERT_TRUE(gf128v_equals(actual, expect)) << "size=" << size;
  }
}
#endif  // __x86_64__

// ---------------------------------------------------------------------------
// strided accumulating dot products (used by the qary-mux gate)
// ---------------------------------------------------------------------------
namespace {
// naive reference: res += sum_i x[i . x_byte_slice] * y[i], y[i] optionally reduced to a bit
void gf128_dot_product_acc_naive(gf128* res, const gf128* x, uint64_t x_byte_slice, const gf128* y, uint64_t size,
                                bool y_is_f2) {
  for (uint64_t i = 0; i < size; ++i) {
    const gf128* xi = (const gf128*)((const uint8_t*)x + i * x_byte_slice);
    gf128 t;
    if (y_is_f2) {
      gf128_product_f2_ref(&t, xi, &y[i]);
    } else {
      gf128_product_ref(&t, xi, &y[i]);
    }
    gf128_sum_ref(res, res, &t);
  }
}

// x holds `size` elements spaced `slice` elements apart (garbage in between), y holds `size` elements
struct gf128_strided_inputs {
  std::vector<uint8_t> xb, yb;
  gf128* x;
  gf128* y;
  gf128_strided_inputs(uint64_t size, uint64_t slice, bool y_is_f2)
      : xb((size * slice + 1) * sizeof(gf128) + 16), yb((size + 1) * sizeof(gf128) + 16) {
    x = (gf128*)(((uintptr_t)xb.data() + 16 - 1) & ~(uintptr_t)(16 - 1));
    y = (gf128*)(((uintptr_t)yb.data() + 16 - 1) & ~(uintptr_t)(16 - 1));
    randomize(x, size * slice * sizeof(gf128));
    memset(y, 0, size * sizeof(gf128));
    if (y_is_f2) {
      for (uint64_t i = 0; i < size; ++i) y[i].v[0] = (uint8_t)(rand() & 1);
    } else {
      randomize(y, size * sizeof(gf128));
    }
  }
};
}  // namespace

TEST(gf128_ext, gf128_dot_product_acc_ref) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf128_strided_inputs in(size, slice, false);
      gf128 expect, actual;
      randomize(&expect, sizeof(gf128));  // the accumulator starts from an arbitrary value
      actual = expect;
      gf128_dot_product_acc_naive(&expect, in.x, slice * sizeof(gf128), in.y, size, false);
      gf128_dot_product_acc_ref(&actual, in.x, slice * sizeof(gf128), in.y, size);
      ASSERT_TRUE(gf128v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

TEST(gf128_ext, gf128_dot_product_f2_acc_ref) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf128_strided_inputs in(size, slice, true);
      gf128 expect, actual;
      randomize(&expect, sizeof(gf128));
      actual = expect;
      gf128_dot_product_acc_naive(&expect, in.x, slice * sizeof(gf128), in.y, size, true);
      gf128_dot_product_f2_acc_ref(&actual, in.x, slice * sizeof(gf128), in.y, size);
      ASSERT_TRUE(gf128v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

#ifdef __x86_64__
TEST(gf128_ext, gf128_dot_product_acc_pclmul) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf128_strided_inputs in(size, slice, false);
      gf128 expect, actual;
      randomize(&expect, sizeof(gf128));
      actual = expect;
      gf128_dot_product_acc_ref(&expect, in.x, slice * sizeof(gf128), in.y, size);
      gf128_dot_product_acc_pclmul(&actual, in.x, slice * sizeof(gf128), in.y, size);
      ASSERT_TRUE(gf128v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

TEST(gf128_ext, gf128_dot_product_f2_acc_avx2) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf128_strided_inputs in(size, slice, true);
      gf128 expect, actual;
      randomize(&expect, sizeof(gf128));
      actual = expect;
      gf128_dot_product_f2_acc_ref(&expect, in.x, slice * sizeof(gf128), in.y, size);
      gf128_dot_product_f2_acc_avx2(&actual, in.x, slice * sizeof(gf128), in.y, size);
      ASSERT_TRUE(gf128v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}
#endif  // __x86_64__
