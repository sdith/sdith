#include "gtest/gtest.h"
#include "testlib/testlib.h"
#include "vole_private.h"

bool gf192v_xbitof(const gf192& a, int64_t pos) {
  if (pos < 0 || pos >= 192) return false;
  return gf192v_bitof(a, pos);
}

TEST(gf192, gf192_lsh) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x;
    gf192 sx1;
    gf192 sx2;
    randomize_primitive_var(x);
    for (uint64_t j = 0; j < 192; ++j) {
      sx1 = gf192v_lsh(x, j);
      for (uint64_t k = 0; k < 192; ++k) {
        ASSERT_EQ(gf192v_bitof(sx1, k), gf192v_xbitof(x, k - j));
      }
      // test inplace version
      sx2 = x;
      gf192p_lsh(&sx2, &sx2, j);
      ASSERT_TRUE(gf192v_equals(sx1, sx2));
    }
  }
}

TEST(gf192, gf192_rsh) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x;
    gf192 sx1;
    gf192 sx2;
    randomize_primitive_var(x);
    for (uint64_t j = 0; j < 192; ++j) {
      sx1 = gf192v_rsh(x, j);
      for (uint64_t k = 0; k < 192; ++k) {
        ASSERT_EQ(gf192v_bitof(sx1, k), gf192v_xbitof(x, k + j));
      }
      // test inplace version
      sx2 = x;
      gf192p_rsh(&sx2, &sx2, j);
      ASSERT_TRUE(gf192v_equals(sx1, sx2));
    }
  }
}

TEST(gf192, gf192_sum_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x;
    gf192 y;
    gf192 sx;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf192_sum_ref(&sx, &x, &y);
    for (uint64_t k = 0; k < 3; ++k) {
      ASSERT_EQ(sx.v64[k], x.v64[k] ^ y.v64[k]);
    }
  }
}

TEST(gf192, gf192_product_group) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x;
    gf192 y;
    gf192 z;
    gf192 p1;
    gf192 p2;
    gf192 p3;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    randomize_primitive_var(z);
    // zero
    gf192_product_ref(&p1, &x, &GF192_ZERO);
    gf192_product_ref(&p2, &GF192_ZERO, &x);
    ASSERT_TRUE(gf192v_equals(p1, GF192_ZERO));
    ASSERT_TRUE(gf192v_equals(p2, GF192_ZERO));
    // neutral
    gf192_product_ref(&p1, &x, &GF192_ONE);
    gf192_product_ref(&p2, &GF192_ONE, &x);
    ASSERT_TRUE(gf192v_equals(p1, x));
    ASSERT_TRUE(gf192v_equals(p2, x));
    // commutativity
    gf192_product_ref(&p1, &x, &y);
    gf192_product_ref(&p2, &y, &x);
    ASSERT_TRUE(gf192v_equals(p1, p2));
    // associativity
    gf192_product_ref(&p1, &x, &y);
    gf192_product_ref(&p1, &p1, &z);
    gf192_product_ref(&p2, &y, &z);
    gf192_product_ref(&p2, &x, &p2);
    ASSERT_TRUE(gf192v_equals(p1, p2));
    // distributivity
    gf192_sum_ref(&p1, &x, &y);
    gf192_product_ref(&p1, &z, &p1);
    gf192_product_ref(&p3, &z, &x);
    gf192_product_ref(&p2, &z, &y);
    gf192_sum_ref(&p2, &p2, &p3);
    ASSERT_TRUE(gf192v_equals(p1, p2));
  }
}

TEST(gf192, gf192_inverse_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x;
    gf192 invx;
    gf192 actual;
    // generate a non-zero
    do {
      randomize_primitive_var(x);
    } while (gf192v_equals(x, GF192_ZERO));
    // inverse
    gf192_inverse_ref(&invx, &x);
    // check product
    gf192_product_ref(&actual, &x, &invx);
    ASSERT_TRUE(gf192v_equals(actual, GF192_ONE));
  }
}

#ifdef __x86_64__
TEST(gf192, gf192_inverse_pclmul) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x;
    gf192 expect;
    gf192 actual;
    // generate a non-zero
    do {
      randomize_primitive_var(x);
    } while (gf192v_equals(x, GF192_ZERO));
    // inverse
    gf192_inverse_ref(&expect, &x);
    gf192_inverse_pclmul(&actual, &x);
    ASSERT_TRUE(gf192v_equals(actual, expect));
  }
}
#endif  // __x86_64__

TEST(gf192, gf192_sum_pow2_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf192 x[192];
    gf192 expect;
    gf192 actual;
    randomize_static_array(x);
    gf192_sum_pow2_naive(&expect, x);
    gf192_sum_pow2_ref(&actual, x);
    // check product
    ASSERT_TRUE(gf192v_equals(actual, expect));
  }
}

typedef typeof(gf192_echelon_pow2_naive) gf192_echelon_pow2_f;

static void test_gf192_echelon_pow2(gf192_echelon_pow2_f gf192_echelon_pow2) {
  for (uint64_t k : {1, 3, 8}) {
    for (uint64_t x_size : {0, 1, 2, 63, 192}) {
      if (k * x_size > 192) continue;
      for (uint64_t xbs : {1, 2, 3}) {
        std::vector<uint8_t> x(x_size * xbs * sizeof(gf192));
        randomize(x.data(), x.size());
        gf192 expect;
        gf192 actual;
        gf192_echelon_pow2_naive(k, &expect, (gf192*)x.data(), x_size, xbs * sizeof(gf192));
        gf192_echelon_pow2(k, &actual, (gf192*)x.data(), x_size, xbs * sizeof(gf192));
        ASSERT_TRUE(gf192v_equals(actual, expect));
      }
    }
  }
}

TEST(gf192, gf192_echelon_pow2_ref) { test_gf192_echelon_pow2(gf192_echelon_pow2_ref); }
#ifdef __x86_64__
TEST(gf192, gf192_echelon_pow2_avx) { test_gf192_echelon_pow2(gf192_echelon_pow2_avx); }
#endif

TEST(gf192, gf192_dot_product_ref) {
  for (uint64_t size = 0; size < 33; ++size) {
    std::vector<uint8_t> xb((size + 1) * sizeof(gf192));
    std::vector<uint8_t> yb((size + 1) * sizeof(gf192));
    randomize(xb.data(), size * sizeof(gf192));
    randomize(yb.data(), size * sizeof(gf192));
    const gf192* x = (const gf192*)xb.data();
    const gf192* y = (const gf192*)yb.data();
    gf192 expect = GF192_ZERO;
    for (uint64_t i = 0; i < size; ++i) {
      gf192 t;
      gf192_product_ref(&t, &x[i], &y[i]);
      gf192_sum_ref(&expect, &expect, &t);
    }
    gf192 actual;
    gf192_dot_product_ref(&actual, x, y, size);
    ASSERT_TRUE(gf192v_equals(actual, expect)) << "size=" << size;
  }
}

#ifdef __x86_64__
TEST(gf192, gf192_dot_product_pclmul) {
  for (uint64_t size = 0; size < 33; ++size) {
    std::vector<uint8_t> xb((size + 1) * sizeof(gf192));
    std::vector<uint8_t> yb((size + 1) * sizeof(gf192));
    randomize(xb.data(), size * sizeof(gf192));
    randomize(yb.data(), size * sizeof(gf192));
    const gf192* x = (const gf192*)xb.data();
    const gf192* y = (const gf192*)yb.data();
    gf192 expect;
    gf192 actual;
    gf192_dot_product_ref(&expect, x, y, size);
    gf192_dot_product_pclmul(&actual, x, y, size);
    ASSERT_TRUE(gf192v_equals(actual, expect)) << "size=" << size;
  }
}
#endif

// ---------------------------------------------------------------------------
// strided accumulating dot products (used by the qary-mux gate)
// ---------------------------------------------------------------------------
namespace {
// naive reference: res += sum_i x[i . x_byte_slice] * y[i], y[i] optionally reduced to a bit
void gf192_dot_product_acc_naive(gf192* res, const gf192* x, uint64_t x_byte_slice, const gf192* y, uint64_t size,
                                bool y_is_f2) {
  for (uint64_t i = 0; i < size; ++i) {
    const gf192* xi = (const gf192*)((const uint8_t*)x + i * x_byte_slice);
    gf192 t;
    if (y_is_f2) {
      gf192_product_f2_ref(&t, xi, &y[i]);
    } else {
      gf192_product_ref(&t, xi, &y[i]);
    }
    gf192_sum_ref(res, res, &t);
  }
}

// x holds `size` elements spaced `slice` elements apart (garbage in between), y holds `size` elements
struct gf192_strided_inputs {
  std::vector<uint8_t> xb, yb;
  gf192* x;
  gf192* y;
  gf192_strided_inputs(uint64_t size, uint64_t slice, bool y_is_f2)
      : xb((size * slice + 1) * sizeof(gf192) + 8), yb((size + 1) * sizeof(gf192) + 8) {
    x = (gf192*)(((uintptr_t)xb.data() + 8 - 1) & ~(uintptr_t)(8 - 1));
    y = (gf192*)(((uintptr_t)yb.data() + 8 - 1) & ~(uintptr_t)(8 - 1));
    randomize(x, size * slice * sizeof(gf192));
    memset(y, 0, size * sizeof(gf192));
    if (y_is_f2) {
      for (uint64_t i = 0; i < size; ++i) y[i].v[0] = (uint8_t)(rand() & 1);
    } else {
      randomize(y, size * sizeof(gf192));
    }
  }
};
}  // namespace

TEST(gf192, gf192_dot_product_acc_ref) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf192_strided_inputs in(size, slice, false);
      gf192 expect, actual;
      randomize(&expect, sizeof(gf192));  // the accumulator starts from an arbitrary value
      actual = expect;
      gf192_dot_product_acc_naive(&expect, in.x, slice * sizeof(gf192), in.y, size, false);
      gf192_dot_product_acc_ref(&actual, in.x, slice * sizeof(gf192), in.y, size);
      ASSERT_TRUE(gf192v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

TEST(gf192, gf192_dot_product_f2_acc_ref) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf192_strided_inputs in(size, slice, true);
      gf192 expect, actual;
      randomize(&expect, sizeof(gf192));
      actual = expect;
      gf192_dot_product_acc_naive(&expect, in.x, slice * sizeof(gf192), in.y, size, true);
      gf192_dot_product_f2_acc_ref(&actual, in.x, slice * sizeof(gf192), in.y, size);
      ASSERT_TRUE(gf192v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

#ifdef __x86_64__
TEST(gf192, gf192_dot_product_acc_pclmul) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf192_strided_inputs in(size, slice, false);
      gf192 expect, actual;
      randomize(&expect, sizeof(gf192));
      actual = expect;
      gf192_dot_product_acc_ref(&expect, in.x, slice * sizeof(gf192), in.y, size);
      gf192_dot_product_acc_pclmul(&actual, in.x, slice * sizeof(gf192), in.y, size);
      ASSERT_TRUE(gf192v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

TEST(gf192, gf192_dot_product_f2_acc_avx2) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf192_strided_inputs in(size, slice, true);
      gf192 expect, actual;
      randomize(&expect, sizeof(gf192));
      actual = expect;
      gf192_dot_product_f2_acc_ref(&expect, in.x, slice * sizeof(gf192), in.y, size);
      gf192_dot_product_f2_acc_avx2(&actual, in.x, slice * sizeof(gf192), in.y, size);
      ASSERT_TRUE(gf192v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}
#endif  // __x86_64__
