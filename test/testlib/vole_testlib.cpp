#include "vole_testlib.h"
#include "vole_private.h"

#include <cstring>
#include <iostream>

void vole_flambda_mul(uint64_t lambda, flambda_t* res, const flambda_t* a, const flambda_t* b) {
  switch (lambda) {
    case 128:
      return gf128_product_ref((gf128*)res, (gf128*)a, (gf128*)b);
    case 192:
      return gf192_product_ref((gf192*)res, (gf192*)a, (gf192*)b);
    case 256:
      return gf256_product_ref((gf256*)res, (gf256*)a, (gf256*)b);
    default:
      REQUIRE_DRAMATICALLY(false, "NOT IMPLEMENTED");
  }
}

void vole_flambda_xor(uint64_t lambda, flambda_t* res, const flambda_t* a, const flambda_t* b) {
  switch (lambda) {
    case 128:
      return gf128_sum_ref((gf128*)res, (gf128*)a, (gf128*)b);
    case 192:
      return gf192_sum_ref((gf192*)res, (gf192*)a, (gf192*)b);
    case 256:
      return gf256_sum_ref((gf256*)res, (gf256*)a, (gf256*)b);
    default:
      REQUIRE_DRAMATICALLY(false, "NOT IMPLEMENTED");
  }
}

void vole_flambda_inv(uint64_t lambda, flambda_t* res, const flambda_t* a) {
  switch (lambda) {
    case 128:
      return gf128_inverse_ref((gf128*)res, (gf128*)a);
    case 192:
      return gf192_inverse_ref((gf192*)res, (gf192*)a);
    case 256:
      return gf256_inverse_ref((gf256*)res, (gf256*)a);
    default:
      REQUIRE_DRAMATICALLY(false, "NOT IMPLEMENTED");
  }
}

void vole_flambda_set(uint64_t lambda, flambda_t* res, const flambda_t* a) { memcpy(res, a, (lambda + 7) / 8); }
bool vole_flambda_eq(uint64_t lambda, const flambda_t* a, const flambda_t* b) {
  return memcmp(a, b, (lambda + 7) / 8) == 0;
}

flam_elem::flam_elem() {}
flam_elem::flam_elem(uint64_t lambda, bool f2_value) : v(lambda) { v.set(0, f2_value); }
flam_elem::flam_elem(uint64_t lambda, const flambda_t* val) : v(lambda) { memcpy(v.data(), val, (lambda + 7) / 8); }
uint64_t flam_elem::bit_size() const { return v.bit_size(); }
const flambda_t* flam_elem::data() const { return v.data(); }
flambda_t* flam_elem::data() { return v.data(); }
flam_elem flam_elem::zero(uint64_t lambda) { return flam_elem(lambda, false); }
flam_elem flam_elem::one(uint64_t lambda) { return flam_elem(lambda, true); }
flam_elem flam_elem::random(uint64_t lambda) {
  flam_elem ret(flam_elem(lambda, false));
  ret.v.randomize();
  return ret;
}
flam_elem flam_elem::random_non_zero(uint64_t lambda) {
  flam_elem zero(flam_elem(lambda, false));
  flam_elem ret(flam_elem(lambda, false));
  do {
    ret.v.randomize();
  } while (ret == zero);
  return ret;
}

flam_vector::flam_vector() {}
flam_vector::flam_vector(uint64_t lambda, uint64_t size) : v(size, lambda) {}
uint64_t flam_vector::bit_size() const { return v.num_cols(); }
uint64_t flam_vector::size() const { return v.num_rows(); }
const flambda_t* flam_vector::data() const { return v.data(); }
flambda_t* flam_vector::data() { return v.data(); }
flam_elem flam_vector::get(uint64_t i) const {
  REQUIRE_DRAMATICALLY(i < size(), "index overflow " << i << " / " << size());
  return flam_elem(bit_size(), v.row_ptr(i));
}
void flam_vector::set(uint64_t i, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(i < size(), "index overflow " << i << " / " << size());
  REQUIRE_DRAMATICALLY(value.bit_size() == bit_size(),
                       "incompatible lambda: " << value.bit_size() << " vs. " << bit_size());
  vole_flambda_set(bit_size(), v.row_ptr(i), value.data());
}
void flam_vector::randomize() { v.randomize(); }
flam_vector flam_vector::zero(uint64_t lambda, uint64_t size) { return flam_vector(lambda, size); }
flam_vector flam_vector::random(uint64_t lambda, uint64_t size) {
  flam_vector ret(lambda, size);
  ret.randomize();
  return ret;
}
bool operator==(const flam_vector& a, const flam_vector& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(lambda == b.bit_size(), "lambda mismatch: " << lambda << " vs. " << b.bit_size());
  uint64_t da = a.size();
  REQUIRE_DRAMATICALLY(da == b.size(), "declared degrees mismatch: " << da << " vs. " << b.size());
  return a.v == b.v;
}

flam_poly::flam_poly() {}
flam_poly::flam_poly(uint64_t lambda, uint64_t declared_degree) : v(lambda, declared_degree + 1) {}
uint64_t flam_poly::bit_size() const { return v.bit_size(); }
uint64_t flam_poly::declared_degree() const { return v.size() - 1; }
const flambda_t* flam_poly::data() const { return v.data(); }
flambda_t* flam_poly::data() { return v.data(); }
flam_elem flam_poly::get(uint64_t i) const { return v.get(i); }
void flam_poly::set(uint64_t i, const flam_elem& value) { v.set(i, value); }
flam_poly flam_poly::zero(uint64_t lambda, uint64_t degree) { return flam_poly(lambda, degree); }
flam_poly flam_poly::random(uint64_t lambda, uint64_t declared_degree) {
  flam_poly ret(lambda, declared_degree);
  ret.v.randomize();
  return ret;
}
flam_poly flam_poly::deg0(const flam_elem& value) {
  flam_poly res(value.bit_size(), 0);
  res.set(0, value);
  return res;
}
flam_poly operator+(const flam_poly& a, const flam_poly& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(lambda == b.bit_size(), "lambda mismatch: " << lambda << " vs. " << b.bit_size());
  uint64_t da = a.declared_degree();
  uint64_t db = b.declared_degree();
  uint64_t d = std::max(da, db);
  flam_poly res = flam_poly::zero(lambda, d);
  if (da < db) {
    for (uint64_t i = 0; i <= da; i++) {
      res.set(i, a.get(i) + b.get(i));
    }
    for (uint64_t i = da + 1; i <= db; i++) {
      res.set(i, b.get(i));
    }
  } else {
    for (uint64_t i = 0; i <= db; i++) {
      res.set(i, a.get(i) + b.get(i));
    }
    for (uint64_t i = db + 1; i <= da; i++) {
      res.set(i, a.get(i));
    }
  }
  return res;
}
flam_poly operator*(const flam_poly& a, const flam_poly& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(lambda == b.bit_size(), "lambda mismatch: " << lambda << " vs. " << b.bit_size());
  uint64_t da = a.declared_degree();
  uint64_t db = b.declared_degree();
  uint64_t d = da + db;
  flam_poly res = flam_poly::zero(lambda, d);
  for (uint64_t i = 0; i <= da; i++) {
    flam_elem ai = a.get(i);
    for (uint64_t j = 0; j <= db; j++) {
      flam_elem bj = b.get(j);
      res.set(i + j, res.get(i + j) + ai * bj);
    }
  }
  return res;
}
flam_poly operator*(const flam_elem& a, const flam_poly& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(lambda == b.bit_size(), "lambda mismatch: " << lambda << " vs. " << b.bit_size());
  uint64_t db = b.declared_degree();
  flam_poly res = flam_poly::zero(lambda, db);
  for (uint64_t i = 0; i <= db; i++) {
    res.set(i, a * b.get(i));
  }
  return res;
}
flam_poly& operator+=(flam_poly& a, const flam_poly& b) {
  a = a + b;
  return a;
}
bool operator==(const flam_poly& a, const flam_poly& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(lambda == b.bit_size(), "lambda mismatch: " << lambda << " vs. " << b.bit_size());
  uint64_t da = a.declared_degree();
  REQUIRE_DRAMATICALLY(da == b.declared_degree(),
                       "declared degrees mismatch: " << da << " vs. " << b.declared_degree());
  return a.v == b.v;
}

flam_elem operator+(const flam_elem& a, const flam_elem& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(b.bit_size() == lambda, "bit size mismatch");
  flam_elem res(lambda, false);
  vole_flambda_xor(lambda, res.data(), a.data(), b.data());
  return res;
}

flam_elem& operator+=(flam_elem& a, const flam_elem& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(b.bit_size() == lambda, "bit size mismatch");
  vole_flambda_xor(lambda, a.data(), a.data(), b.data());
  return a;
}

flam_elem operator*(const flam_elem& a, const flam_elem& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(b.bit_size() == lambda, "bit size mismatch");
  flam_elem res(lambda, false);
  vole_flambda_mul(lambda, res.data(), a.data(), b.data());
  return res;
}
flam_elem operator*(bool a, const flam_elem& b) {
  if (a) {
    return b;
  } else {
    return flam_elem(b.bit_size(), false);
  }
}

flam_elem& operator*=(flam_elem& a, const flam_elem& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(b.bit_size() == lambda, "bit size mismatch");
  vole_flambda_mul(lambda, a.data(), a.data(), b.data());
  return a;
}

bool operator==(const flam_elem& a, const flam_elem& b) {
  uint64_t lambda = a.bit_size();
  REQUIRE_DRAMATICALLY(b.bit_size() == lambda, "bit size mismatch");
  return vole_flambda_eq(lambda, a.data(), b.data());
}

flam_elem inv(const flam_elem& x) {
  uint64_t lambda = x.bit_size();
  flam_elem r = flam_elem::zero(lambda);
  vole_flambda_inv(lambda, r.data(), x.data());
  return r;
}

flam_elem pow(const flam_elem& x, int64_t y) {
  REQUIRE_DRAMATICALLY(y >= -1000 && y < 1000, "something is weird here (given the use-case)");
  uint64_t lambda = x.bit_size();
  flam_elem r = flam_elem::one(lambda);
  if (y == 0) return r;
  flam_elem t = x;
  if (y < 0) {
    vole_flambda_inv(lambda, t.data(), x.data());
    y = -y;
  }
  // invariant: r.t^y
  while (y > 0) {
    if (y & 1) {
      r *= t;
    }
    t *= t;
    y >>= 1;
  }
  REQUIRE_DRAMATICALLY(y == 0, "bug");
  return r;
}

bool vole_std_f2_deg1_uvq::get_u(uint64_t i) const { return u.get(i); }
void vole_std_f2_deg1_uvq::set_u(uint64_t i, bool value) { u.set(i, value); }
flam_elem vole_std_f2_deg1_uvq::get_v(uint64_t i) const { return flam_elem(lambda, v.row_ptr(i)); }
void vole_std_f2_deg1_uvq::set_v(uint64_t i, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(value.bit_size() == lambda, "lambda mismatch");
  vole_flambda_set(lambda, v.row_ptr(i), value.data());
}
flam_elem vole_std_f2_deg1_uvq::get_q(uint64_t i) const { return flam_elem(lambda, q.row_ptr(i)); }
void vole_std_f2_deg1_uvq::set_q(uint64_t i, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(value.bit_size() == lambda, "lambda mismatch");
  vole_flambda_set(lambda, q.row_ptr(i), value.data());
}

vole_std_f2_deg1_uvq::vole_std_f2_deg1_uvq(uint64_t lambda, uint64_t L) : lambda(lambda), L(L) {
  u = bit_vector::zero(L);
  v = bit_matrix::zero(L, lambda);
  q = bit_matrix::zero(L, lambda);
}

void vole_std_f2_deg1_uvq::randomize(const flambda_t* delta1) {
  u.randomize();
  v.randomize();
  const flam_elem delta(lambda, delta1);
  for (uint64_t i = 0; i < L; i++) {
    set_q(i, get_v(i) + get_u(i) * delta);
  }
}

void vole_std_f2_deg1_uvq::assert_correct(const flambda_t* delta1) {
  const flam_elem delta(lambda, delta1);
  for (uint64_t i = 0; i < L; i++) {
    REQUIRE_DRAMATICALLY(get_q(i) == get_v(i) + (get_u(i) * delta), "incorrect vole pair");
  }
}

vole_cst_f2_deg1_uvq::vole_cst_f2_deg1_uvq(uint64_t lambda, uint64_t L)
    : lambda(lambda), L(L), u(L), v(L, lambda), q(L, lambda) {}

bool vole_cst_f2_deg1_uvq::get_u(uint64_t i) const { return u.get(i); }
void vole_cst_f2_deg1_uvq::set_u(uint64_t i, bool value) { u.set(i, value); }
flam_elem vole_cst_f2_deg1_uvq::get_v(uint64_t i) const { return flam_elem(lambda, v.row_ptr(i)); }
void vole_cst_f2_deg1_uvq::set_v(uint64_t i, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(value.bit_size() == lambda, "lambda mismatch");
  vole_flambda_set(lambda, v.row_ptr(i), value.data());
}
flam_elem vole_cst_f2_deg1_uvq::get_q(uint64_t i) const { return flam_elem(lambda, q.row_ptr(i)); }
void vole_cst_f2_deg1_uvq::set_q(uint64_t i, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(value.bit_size() == lambda, "lambda mismatch");
  vole_flambda_set(lambda, q.row_ptr(i), value.data());
}

void vole_cst_f2_deg1_uvq::randomize(const flambda_t* delta2) {
  u.randomize();
  v.randomize();
  const flam_elem delta(lambda, delta2);
  for (uint64_t i = 0; i < L; i++) {
    set_q(i, flam_elem(lambda, get_u(i)) + get_v(i) * delta);
  }
}

void vole_cst_f2_deg1_uvq::assert_correct(const flambda_t* delta2) const {
  const flam_elem delta(lambda, delta2);
  for (uint64_t i = 0; i < L; i++) {
    REQUIRE_DRAMATICALLY(get_q(i) == flam_elem(lambda, get_u(i)) + get_v(i) * delta, "incorrect vole pair");
  }
}

vole_flambda_poly::vole_flambda_poly(uint64_t lambda, uint64_t degree, uint64_t L)
    : lambda(lambda), degree(degree), L(L), f(L * (degree + 1), lambda), q(L * (degree + 1), lambda) {
  f.randomize();  // will catch assumptions that output is zero
  q.randomize();  // will catch assumptions that output is zero
}

void vole_flambda_poly::randomize(const flambda_t* delta) {
  f.randomize();
  const flam_elem delt = flam_elem(lambda, delta);
  for (uint64_t i = 0; i < L; i++) {
    flam_elem tmp = get_f(i, degree);
    for (int64_t j = degree - 1; j >= 0; j--) {
      tmp = delt * tmp + get_f(i, j);
    }
    set_q(i, tmp);
  }
}

void vole_flambda_poly::randomize_f2(const flambda_t* delta) {
  f.randomize();
  for (uint64_t i = 0; i < L; i++) {
    if (*(uint8_t*)f.row_ptr(i * (degree + 1)) % 2 == 0)
      vole_flambda_set(lambda, f.row_ptr(i * (degree + 1)), flam_elem::zero(lambda).data());
    else
      vole_flambda_set(lambda, f.row_ptr(i * (degree + 1)), flam_elem::one(lambda).data());
  }
  const flam_elem delt = flam_elem(lambda, delta);
  for (uint64_t i = 0; i < L; i++) {
    flam_elem tmp = get_f(i, degree);
    for (int64_t j = degree - 1; j >= 0; j--) {
      tmp = delt * tmp + get_f(i, j);
    }
    set_q(i, tmp);
  }
}

void vole_flambda_poly::assert_correct(const flambda_t* delta) const {
  const flam_elem delt = flam_elem(lambda, delta);
  for (uint64_t i = 0; i < L; i++) {
    flam_elem tmp = get_f(i, degree);
    for (int64_t j = degree - 1; j >= 0; j--) {
      tmp = delt * tmp + get_f(i, j);
    }
    REQUIRE_DRAMATICALLY(get_q(i) == tmp, "incorrect vole pair");
  }
}

flam_elem vole_flambda_poly::get_f(uint64_t i, uint64_t j) const {
  REQUIRE_DRAMATICALLY(i < L, "index overflow " << i << " / " << L);
  REQUIRE_DRAMATICALLY(j <= degree, "degree overflow " << j << " / " << degree);
  return flam_elem(lambda, f.row_ptr(i * (degree + 1) + j));
}
void vole_flambda_poly::set_f(uint64_t i, uint64_t j, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(i < L, "index overflow " << i << " / " << L);
  REQUIRE_DRAMATICALLY(j <= degree, "degree overflow " << j << " / " << degree);
  vole_flambda_set(lambda, f.row_ptr(i * (degree + 1) + j), value.data());
}
flam_poly vole_flambda_poly::get_f(uint64_t i) const {
  REQUIRE_DRAMATICALLY(i < L, "index overflow " << i << " / " << L);
  flam_poly res(lambda, degree);
  for (uint64_t j = 0; j <= degree; j++) {
    res.set(j, get_f(i, j));
  }
  return res;
}
void vole_flambda_poly::set_f(uint64_t i, const flam_poly& value) {
  REQUIRE_DRAMATICALLY(i < L, "index overflow " << i << " / " << L);
  REQUIRE_DRAMATICALLY(value.declared_degree() == degree, "invalid declared degree:" << value.declared_degree());
  for (uint64_t j = 0; j <= degree; j++) {
    set_f(i, j, value.get(j));
  }
}
flam_elem vole_flambda_poly::get_q(uint64_t i) const {
  REQUIRE_DRAMATICALLY(i < L, "index overflow " << i << " / " << L);
  return flam_elem(lambda, q.row_ptr(i));
}
void vole_flambda_poly::set_q(uint64_t i, const flam_elem& value) {
  REQUIRE_DRAMATICALLY(i < L, "index overflow " << i << " / " << L);
  vole_flambda_set(lambda, q.row_ptr(i), value.data());
}

flam_poly echelon_pow2(uint64_t k, const std::vector<flam_poly>& polys) {
  const uint64_t arity = polys.size();
  REQUIRE_DRAMATICALLY(arity > 0, "arity must be > 0");
  const uint64_t lambda = polys[0].bit_size();
  const uint64_t degree = polys[0].declared_degree();
  flam_poly res = flam_poly::zero(lambda, degree);
  for (uint64_t i = 0; i < arity; i++) {
    REQUIRE_DRAMATICALLY(polys[i].declared_degree() == degree, "incompatible degree");
    REQUIRE_DRAMATICALLY(polys[i].bit_size() == lambda, "incompatible lambda");
    flam_elem ci = flam_elem::zero(lambda);
    *((uint64_t*)ci.data()) = UINT64_C(1) << (i * k);
    res += ci * polys[i];
  }
  return res;
}

flam_poly check_unitary(const flam_elem& coeff, const std::vector<flam_poly>& polys) {
  const uint64_t arity = polys.size();
  REQUIRE_DRAMATICALLY(arity > 1, "arity must be > 1");
  const std::vector<flam_poly> polys_m1(polys.begin(), polys.end() - 1);
  flam_poly p1 = echelon_pow2(1, polys);
  flam_poly p2 = echelon_pow2(arity, polys_m1);
  flam_poly p3 = echelon_pow2(arity + 1, polys_m1);
  return coeff * (p1 * p2 + p3);
}
flam_poly qary_mux(const std::vector<flam_poly>& c, const std::vector<flam_poly>& a) {
  const uint64_t arity = a.size();
  REQUIRE_DRAMATICALLY(arity > 0, "arity must be > 0");
  REQUIRE_DRAMATICALLY(c.size() >= arity - 1, "mux has not enough control bits");
  const uint64_t lambda = a[0].bit_size();
  const uint64_t degree = a[0].declared_degree();
  flam_poly res = flam_poly::zero(lambda, degree + 1);
  res += a[0];
  for (uint64_t i = 1; i < arity; i++) {
    REQUIRE_DRAMATICALLY(a[i].declared_degree() == degree, "incompatible degree");
    REQUIRE_DRAMATICALLY(a[i].bit_size() == lambda, "incompatible lambda");
    REQUIRE_DRAMATICALLY(c[i - 1].declared_degree() == 1, "mux ctrl degree must be = 1");
    REQUIRE_DRAMATICALLY(c[i - 1].bit_size() == lambda, "incompatible lambda");
    res += c[i - 1] * (a[i] + a[0]);
  }
  return res;
}

flam_poly qary_mux_circuit(                             //
    const std::vector<uint64_t>& arities,               // declared arities
    const std::vector<flam_poly>& c,                    // mux control bits (sum (arities-1))
    const std::vector<flam_elem>& a,                    // input coeffs (<= prod arities)
    const flam_elem& check_unitary_coeff)  // check_unitary challenge coeff
{
  const uint64_t depth = arities.size();
  const uint64_t a_size = a.size();
  REQUIRE_DRAMATICALLY(a_size > 0, "a_size must > 0");
  const uint64_t lambda = a[0].bit_size();
  uint64_t mux_size = 1;
  uint64_t mux_ctrl_bits = 0;
  uint64_t unitary_challenge_powers = 0;
  for (uint64_t i = 0; i < depth; i++) {
    REQUIRE_DRAMATICALLY(arities[i] >= 2, "arities must be >= 2");
    mux_size *= arities[i];
    mux_ctrl_bits += arities[i] - 1;
    if (arities[i] > 2) {
      unitary_challenge_powers += 32;
    }
  }
  REQUIRE_DRAMATICALLY(unitary_challenge_powers <= lambda, "invalid challenge powers");
  REQUIRE_DRAMATICALLY(a_size <= mux_size, "mux tree cannot select among that many inputs");
  REQUIRE_DRAMATICALLY(c.size() == mux_ctrl_bits, "wrong number of ctrl bits");
  for (uint64_t i = 0; i < c.size(); i++) {
    REQUIRE_DRAMATICALLY(c[i].bit_size() == lambda, "incompatible lambda");
    REQUIRE_DRAMATICALLY(c[i].declared_degree() == 1, "incompatible degree");
  };
  // cast the inputs a as degree-0 polynomials
  std::vector<flam_poly> a_in(a_size);
  for (uint64_t i = 0; i < a_size; i++) {
    REQUIRE_DRAMATICALLY(a[i].bit_size() == lambda, "incompatible lambda");
    a_in[i] = flam_poly::deg0(a[i]);
  };

  flam_poly check_unitary_sum = flam_poly::zero(lambda, 2);
  flam_elem current_check_unitary_coeff = check_unitary_coeff;
  static const flambda_max_t FLAMBDA_2P32 = {UINT64_C(1) << 32, 0, 0, 0};
  uint64_t c_pos = 0;
  for (uint64_t d = 0; d < depth; d++) {
    const uint64_t arity = arities[d];
    std::vector<flam_poly> c_in(arity - 1);
    // extract the arity - 1 ctrl bits for this depth
    for (uint64_t i = 0; i < arity - 1; i++) {
      c_in[i] = c[c_pos + i];
    }
    c_pos += arity - 1;
    // add the check unitary component
    if (arity > 2) {
      check_unitary_sum += check_unitary(current_check_unitary_coeff, c_in);
      current_check_unitary_coeff *= flam_elem(lambda, FLAMBDA_2P32);
    }
    // apply the muxes
    const uint64_t num_out = std::ceil(double(a_in.size()) / double(arity));
    std::vector<flam_poly> a_out(num_out);
    // the first num_out-1 are full
    uint64_t a_pos = 0;
    for (uint64_t j = 0; j < num_out - 1; j++) {
      std::vector<flam_poly> a_mux_in(arity);
      for (uint64_t i = 0; i < arity; i++) {
        a_mux_in[i] = a_in[a_pos + i];
      }
      a_pos += arity;
      a_out[j] = qary_mux(c_in, a_mux_in);
    }
    // the last mux can be incomplete
    {
      uint64_t j = num_out - 1;
      uint64_t last_arity = a_in.size() - a_pos;
      REQUIRE_DRAMATICALLY(last_arity <= arity && last_arity >= 1, "bug!!");
      std::vector<flam_poly> a_mux_in(last_arity);
      for (uint64_t i = 0; i < last_arity; i++) {
        a_mux_in[i] = a_in[a_pos + i];
      }
      a_pos += last_arity;
      a_out[j] = qary_mux(c_in, a_mux_in);
    }
    REQUIRE_DRAMATICALLY(a_pos == a_in.size(), "bug!!");
    // and start over again
    a_in = a_out;
  }
  REQUIRE_DRAMATICALLY(c_pos == mux_ctrl_bits, "bug!!");
  REQUIRE_DRAMATICALLY(a_in.size() == 1, "bug!!");
  REQUIRE_DRAMATICALLY(a_in[0].declared_degree() == depth, "bug!!");
  return check_unitary_sum + a_in[0];
}
