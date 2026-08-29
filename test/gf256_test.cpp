#include "gtest/gtest.h"
#include "testlib/testlib.h"
#include "vole_private.h"

#ifdef __x86_64__
TEST(gf256, gf256_product_pclmul) {
  for (uint64_t i = 0; i < 1000; ++i) {
    gf256 a, b, expect, actual;
    randomize_primitive_var(a);
    randomize_primitive_var(b);
    gf256_product_pclmul((gf256*)&actual, (gf256*)&a, (gf256*)&b);
    gf256_product_ref((gf256*)&expect, (gf256*)&a, (gf256*)&b);
    for (uint64_t j = 0; j < 4; j++) {
      ASSERT_EQ(actual.v64[j], expect.v64[j]);
    }
  }
}

TEST(gf256, gf256_product_pclmul_f2) {
  for (uint64_t i = 0; i < 1000; ++i) {
    gf256 a, b_f2, expect, actual;
    randomize_primitive_var(a);
    for (uint64_t j = 0; j < 4; j++) {
      if (j == 0)
        b_f2.v64[j] = uniform_u128() % 2;
      else
        b_f2.v64[j] = 0;
    }
    gf256_product_pclmul((gf256*)&actual, (gf256*)&a, (gf256*)&b_f2);
    gf256_product_pclmul_f2((gf256*)&expect, (gf256*)&a, (gf256*)&b_f2);
    for (uint64_t j = 0; j < 4; j++) {
      ASSERT_EQ(actual.v64[j], expect.v64[j]);
    }
  }
}
#endif

bool gf256v_xbitof(const gf256& a, int64_t pos) {
  if (pos < 0 || pos >= 256) return false;
  return gf256v_bitof(a, pos);
}

TEST(gf256, gf256_lsh) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 sx1;
    gf256 sx2;
    randomize_primitive_var(x);
    for (uint64_t j = 0; j < 256; ++j) {
      sx1 = gf256v_lsh(x, j);
      for (uint64_t k = 0; k < 256; ++k) {
        ASSERT_EQ(gf256v_bitof(sx1, k), gf256v_xbitof(x, k - j));
      }
      // test inplace version
      sx2 = x;
      gf256p_lsh(&sx2, &sx2, j);
      ASSERT_TRUE(gf256v_equals(sx1, sx2));
    }
  }
}

TEST(gf256, gf256_rsh) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 sx1;
    gf256 sx2;
    randomize_primitive_var(x);
    for (uint64_t j = 0; j < 256; ++j) {
      sx1 = gf256v_rsh(x, j);
      for (uint64_t k = 0; k < 256; ++k) {
        ASSERT_EQ(gf256v_bitof(sx1, k), gf256v_xbitof(x, k + j));
      }
      // test inplace version
      sx2 = x;
      gf256p_rsh(&sx2, &sx2, j);
      ASSERT_TRUE(gf256v_equals(sx1, sx2));
    }
  }
}

TEST(gf256, gf256_sum_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 y;
    gf256 sx;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf256_sum_ref(&sx, &x, &y);
    for (uint64_t k = 0; k < 4; ++k) {
      ASSERT_EQ(sx.v64[k], x.v64[k] ^ y.v64[k]);
    }
  }
}

#ifdef __x86_64__
TEST(gf256, gf256_sum_avx2) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 y;
    gf256 sx;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    gf256_sum_avx2(&sx, &x, &y);
    for (uint64_t k = 0; k < 4; ++k) {
      ASSERT_EQ(sx.v64[k], x.v64[k] ^ y.v64[k]);
    }
  }
}
#endif

TEST(gf256, gf256_product_group) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 y;
    gf256 z;
    gf256 p1;
    gf256 p2;
    gf256 p3;
    randomize_primitive_var(x);
    randomize_primitive_var(y);
    randomize_primitive_var(z);
    // zero
    gf256_product_ref(&p1, &x, &GF256_ZERO);
    gf256_product_ref(&p2, &GF256_ZERO, &x);
    ASSERT_TRUE(gf256v_equals(p1, GF256_ZERO));
    ASSERT_TRUE(gf256v_equals(p2, GF256_ZERO));
    // neutral
    gf256_product_ref(&p1, &x, &GF256_ONE);
    gf256_product_ref(&p2, &GF256_ONE, &x);
    ASSERT_TRUE(gf256v_equals(p1, x));
    ASSERT_TRUE(gf256v_equals(p2, x));
    // commutativity
    gf256_product_ref(&p1, &x, &y);
    gf256_product_ref(&p2, &y, &x);
    ASSERT_TRUE(gf256v_equals(p1, p2));
    // associativity
    gf256_product_ref(&p1, &x, &y);
    gf256_product_ref(&p1, &p1, &z);
    gf256_product_ref(&p2, &y, &z);
    gf256_product_ref(&p2, &x, &p2);
    ASSERT_TRUE(gf256v_equals(p1, p2));
    // distributivity
    gf256_sum_ref(&p1, &x, &y);
    gf256_product_ref(&p1, &z, &p1);
    gf256_product_ref(&p3, &z, &x);
    gf256_product_ref(&p2, &z, &y);
    gf256_sum_ref(&p2, &p2, &p3);
    ASSERT_TRUE(gf256v_equals(p1, p2));
  }
}

TEST(gf256, gf256_inverse_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 invx;
    gf256 actual;
    // generate a non-zero
    do {
      randomize_primitive_var(x);
    } while (gf256v_equals(x, GF256_ZERO));
    // inverse
    gf256_inverse_ref(&invx, &x);
    // check product
    gf256_product_ref(&actual, &x, &invx);
    ASSERT_TRUE(gf256v_equals(actual, GF256_ONE));
  }
}

#ifdef __x86_64__
TEST(gf256, gf256_inverse_pclmul) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x;
    gf256 expect;
    gf256 actual;
    // generate a non-zero
    do {
      randomize_primitive_var(x);
    } while (gf256v_equals(x, GF256_ZERO));
    // inverse
    gf256_inverse_ref(&expect, &x);
    gf256_inverse_pclmul(&actual, &x);
    ASSERT_TRUE(gf256v_equals(actual, expect));
  }
}
#endif  // __x86_64__

TEST(gf256, gf256_sum_pow2_ref) {
  for (uint64_t i = 0; i < 50; ++i) {
    gf256 x[256];
    gf256 expect;
    gf256 actual;
    randomize_static_array(x);
    gf256_sum_pow2_naive(&expect, x);
    gf256_sum_pow2_ref(&actual, x);
    // check product
    ASSERT_TRUE(gf256v_equals(actual, expect));
  }
}

typedef typeof(gf256_echelon_pow2_naive) gf256_echelon_pow2_f;

static void test_gf256_echelon_pow2(gf256_echelon_pow2_f gf256_echelon_pow2) {
  for (uint64_t k : {1, 3, 8}) {
    for (uint64_t x_size : {0, 1, 2, 63, 256}) {
      if (k * x_size > 256) continue;
      for (uint64_t xbs : {1, 2, 3}) {
        aligned_vector_u8 x(32, x_size * xbs * sizeof(gf256));
        randomize(x.data(), x.size());
        gf256 expect;
        gf256 actual;
        gf256_echelon_pow2_naive(k, &expect, (gf256*)x.data(), x_size, xbs * sizeof(gf256));
        gf256_echelon_pow2(k, &actual, (gf256*)x.data(), x_size, xbs * sizeof(gf256));
        ASSERT_TRUE(gf256v_equals(actual, expect));
      }
    }
  }
}

TEST(gf256, gf256_echelon_pow2_ref) { test_gf256_echelon_pow2(gf256_echelon_pow2_ref); }
#ifdef __x86_64__
TEST(gf256, gf256_echelon_pow2_avx) { test_gf256_echelon_pow2(gf256_echelon_pow2_avx); }
#endif

TEST(gf256, gf256_dot_product_ref) {
  for (uint64_t size = 0; size < 33; ++size) {
    std::vector<uint8_t> xb((size + 1) * sizeof(gf256) + 32);
    std::vector<uint8_t> yb((size + 1) * sizeof(gf256) + 32);
    gf256* x = (gf256*)(((uintptr_t)xb.data() + 31) & ~(uintptr_t)31);
    gf256* y = (gf256*)(((uintptr_t)yb.data() + 31) & ~(uintptr_t)31);
    randomize(x, size * sizeof(gf256));
    randomize(y, size * sizeof(gf256));
    gf256 expect = GF256_ZERO;
    for (uint64_t i = 0; i < size; ++i) {
      gf256 t;
      gf256_product_ref(&t, &x[i], &y[i]);
      gf256_sum_ref(&expect, &expect, &t);
    }
    gf256 actual;
    gf256_dot_product_ref(&actual, x, y, size);
    ASSERT_TRUE(gf256v_equals(actual, expect)) << "size=" << size;
  }
}

#ifdef __x86_64__
TEST(gf256, gf256_dot_product_pclmul) {
  for (uint64_t size = 0; size < 33; ++size) {
    std::vector<uint8_t> xb((size + 1) * sizeof(gf256) + 32);
    std::vector<uint8_t> yb((size + 1) * sizeof(gf256) + 32);
    gf256* x = (gf256*)(((uintptr_t)xb.data() + 31) & ~(uintptr_t)31);
    gf256* y = (gf256*)(((uintptr_t)yb.data() + 31) & ~(uintptr_t)31);
    randomize(x, size * sizeof(gf256));
    randomize(y, size * sizeof(gf256));
    gf256 expect;
    gf256 actual;
    gf256_dot_product_ref(&expect, x, y, size);
    gf256_dot_product_pclmul(&actual, x, y, size);
    ASSERT_TRUE(gf256v_equals(actual, expect)) << "size=" << size;
  }
}
#endif

// ---------------------------------------------------------------------------
// strided accumulating dot products (used by the qary-mux gate)
// ---------------------------------------------------------------------------
namespace {
// naive reference: res += sum_i x[i . x_byte_slice] * y[i], y[i] optionally reduced to a bit
void gf256_dot_product_acc_naive(gf256* res, const gf256* x, uint64_t x_byte_slice, const gf256* y, uint64_t size,
                                bool y_is_f2) {
  for (uint64_t i = 0; i < size; ++i) {
    const gf256* xi = (const gf256*)((const uint8_t*)x + i * x_byte_slice);
    gf256 t;
    if (y_is_f2) {
      gf256_product_f2_ref(&t, xi, &y[i]);
    } else {
      gf256_product_ref(&t, xi, &y[i]);
    }
    gf256_sum_ref(res, res, &t);
  }
}

// x holds `size` elements spaced `slice` elements apart (garbage in between), y holds `size` elements
struct gf256_strided_inputs {
  std::vector<uint8_t> xb, yb;
  gf256* x;
  gf256* y;
  gf256_strided_inputs(uint64_t size, uint64_t slice, bool y_is_f2)
      : xb((size * slice + 1) * sizeof(gf256) + 32), yb((size + 1) * sizeof(gf256) + 32) {
    x = (gf256*)(((uintptr_t)xb.data() + 32 - 1) & ~(uintptr_t)(32 - 1));
    y = (gf256*)(((uintptr_t)yb.data() + 32 - 1) & ~(uintptr_t)(32 - 1));
    randomize(x, size * slice * sizeof(gf256));
    memset(y, 0, size * sizeof(gf256));
    if (y_is_f2) {
      for (uint64_t i = 0; i < size; ++i) y[i].v[0] = (uint8_t)(rand() & 1);
    } else {
      randomize(y, size * sizeof(gf256));
    }
  }
};
}  // namespace

TEST(gf256, gf256_dot_product_acc_ref) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf256_strided_inputs in(size, slice, false);
      gf256 expect, actual;
      randomize(&expect, sizeof(gf256));  // the accumulator starts from an arbitrary value
      actual = expect;
      gf256_dot_product_acc_naive(&expect, in.x, slice * sizeof(gf256), in.y, size, false);
      gf256_dot_product_acc_ref(&actual, in.x, slice * sizeof(gf256), in.y, size);
      ASSERT_TRUE(gf256v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

TEST(gf256, gf256_dot_product_f2_acc_ref) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf256_strided_inputs in(size, slice, true);
      gf256 expect, actual;
      randomize(&expect, sizeof(gf256));
      actual = expect;
      gf256_dot_product_acc_naive(&expect, in.x, slice * sizeof(gf256), in.y, size, true);
      gf256_dot_product_f2_acc_ref(&actual, in.x, slice * sizeof(gf256), in.y, size);
      ASSERT_TRUE(gf256v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

#ifdef __x86_64__
TEST(gf256, gf256_dot_product_acc_pclmul) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf256_strided_inputs in(size, slice, false);
      gf256 expect, actual;
      randomize(&expect, sizeof(gf256));
      actual = expect;
      gf256_dot_product_acc_ref(&expect, in.x, slice * sizeof(gf256), in.y, size);
      gf256_dot_product_acc_pclmul(&actual, in.x, slice * sizeof(gf256), in.y, size);
      ASSERT_TRUE(gf256v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}

TEST(gf256, gf256_dot_product_f2_acc_avx2) {
  for (uint64_t slice = 1; slice <= 3; ++slice) {
    for (uint64_t size = 0; size < 17; ++size) {
      gf256_strided_inputs in(size, slice, true);
      gf256 expect, actual;
      randomize(&expect, sizeof(gf256));
      actual = expect;
      gf256_dot_product_f2_acc_ref(&expect, in.x, slice * sizeof(gf256), in.y, size);
      gf256_dot_product_f2_acc_avx2(&actual, in.x, slice * sizeof(gf256), in.y, size);
      ASSERT_TRUE(gf256v_equals(actual, expect)) << "size=" << size << " slice=" << slice;
    }
  }
}
#endif  // __x86_64__
