#ifndef VOLE_TESTLIB_H
#define VOLE_TESTLIB_H
#include <cstdint>

#include "commons.h"
#include "bit_matrix_layout.h"

/** (test function) field multiplication */
void vole_flambda_mul(uint64_t lambda, flambda_t* res, const flambda_t* a, const flambda_t* b);
/** (test function) field addition */
void vole_flambda_xor(uint64_t lambda, flambda_t* res, const flambda_t* a, const flambda_t* b);
/** (test function) field copy */
void vole_flambda_set(uint64_t lambda, flambda_t* res, const flambda_t* a);
/** (test function) field inverse */
void vole_flambda_inv(uint64_t lambda, flambda_t* res, const flambda_t* a);
/** (test function) field equality test */
bool vole_flambda_eq(uint64_t lambda, const flambda_t* a, const flambda_t* b);
/** (test function) field inverse */
void vole_flambda_inv(uint64_t lambda, flambda_t* res, const flambda_t* a);

/** (test class) represents one large field element */
struct flam_elem {
 private:
  bit_vector v;

 public:
  flam_elem();
  flam_elem(uint64_t lambda, bool f2_value);
  flam_elem(uint64_t lambda, const flambda_t* val);
  [[nodiscard]] uint64_t bit_size() const;
  [[nodiscard]] const flambda_t* data() const;
  [[nodiscard]] flambda_t* data();
  static flam_elem zero(uint64_t lambda);
  static flam_elem one(uint64_t lambda);
  static flam_elem random(uint64_t lambda);
  static flam_elem random_non_zero(uint64_t lambda);
};

/** (test class) represents one vector of large field element */
class flam_vector {
  bit_matrix v;

 public:
  flam_vector();
  flam_vector(uint64_t lambda, uint64_t size);
  uint64_t bit_size() const;
  uint64_t size() const;
  const flambda_t* data() const;
  flambda_t* data();
  flam_elem get(uint64_t i) const;
  void set(uint64_t i, const flam_elem& value);
  void randomize();
  static flam_vector zero(uint64_t lambda, uint64_t size);
  static flam_vector random(uint64_t lambda, uint64_t size);
  friend bool operator==(const flam_vector& a, const flam_vector& b);
};

bool operator==(const flam_vector& a, const flam_vector& b);

/** (test class) represents a polynomial of degree <= declared degree */
class flam_poly {
  flam_vector v;

 public:
  flam_poly();
  flam_poly(uint64_t lambda, uint64_t declared_degree);
  [[nodiscard]] uint64_t bit_size() const;
  [[nodiscard]] uint64_t declared_degree() const;
  [[nodiscard]] const flambda_t* data() const;
  [[nodiscard]] flambda_t* data();
  [[nodiscard]] flam_elem get(uint64_t i) const;
  void set(uint64_t i, const flam_elem& value);
  static flam_poly zero(uint64_t lambda, uint64_t declared_degree);
  static flam_poly random(uint64_t lambda, uint64_t declared_degree);
  static flam_poly deg0(const flam_elem& value);
  friend bool operator==(const flam_poly& a, const flam_poly& b);
};

// operators will operate according to the declared degree
flam_poly operator+(const flam_poly& a, const flam_poly& b);
flam_poly operator*(const flam_poly& a, const flam_poly& b);
flam_poly operator*(const flam_elem& a, const flam_poly& b);
flam_poly& operator+=(flam_poly& a, const flam_poly& b);
bool operator==(const flam_poly& a, const flam_poly& b);

/** field addition */
flam_elem operator+(const flam_elem& a, const flam_elem& b);
/** field addition */
flam_elem& operator+=(flam_elem& a, const flam_elem& b);
/** field multiplication */
flam_elem operator*(const flam_elem& a, const flam_elem& b);
/** field multiplication by f2 */
flam_elem operator*(bool a, const flam_elem& b);
// flam_elem operator*(const flam_elem &a, bool b);
/** field multiplication */
flam_elem& operator*=(flam_elem& a, const flam_elem& b);
/** field equality test */
bool operator==(const flam_elem& a, const flam_elem& b);
/** field inverse */
flam_elem inv(const flam_elem& x);
/** field exponentiation */
flam_elem pow(const flam_elem& x, int64_t y);

/** layout of packed deg.1 std vole-pairs over F2 */
struct vole_std_f2_deg1_uvq {
  const uint64_t lambda;
  const uint64_t L;

  bit_vector u;
  bit_matrix v;
  bit_matrix q;

  bool get_u(uint64_t i) const;
  void set_u(uint64_t i, bool value);
  flam_elem get_v(uint64_t i) const;
  void set_v(uint64_t i, const flam_elem& value);
  flam_elem get_q(uint64_t i) const;
  void set_q(uint64_t i, const flam_elem& value);

  vole_std_f2_deg1_uvq(uint64_t lambda, uint64_t L);
  /** @brief random s.t q = u.delta1 + v */
  void randomize(const flambda_t* delta1);
  /** @brief verify that q = u.delta1 + v */
  void assert_correct(const flambda_t* delta1);
};

/** layout of packed deg.1 cst vole-pairs over F2 */
struct vole_cst_f2_deg1_uvq {
  const uint64_t lambda;
  const uint64_t L;

  bit_vector u;
  bit_matrix v;
  bit_matrix q;

  vole_cst_f2_deg1_uvq(uint64_t lambda, uint64_t L);
  /** @brief random s.t q = u + v.delta2 */
  void randomize(const flambda_t* delta2);
  /** @brief verify that q = u + v.delta2 */
  void assert_correct(const flambda_t* delta2) const;

  bool get_u(uint64_t i) const;
  void set_u(uint64_t i, bool value);
  flam_elem get_v(uint64_t i) const;
  void set_v(uint64_t i, const flam_elem& value);
  flam_elem get_q(uint64_t i) const;
  void set_q(uint64_t i, const flam_elem& value);
};

/** layout of deg.d cst or std vole-pairs over F2 */
struct vole_flambda_poly {
  const uint64_t lambda;
  const uint64_t degree;
  const uint64_t L;

  bit_matrix f;
  bit_matrix q;

  vole_flambda_poly(uint64_t lambda, uint64_t degree, uint64_t L);
  /** @brief random s.t q = f(delta) */
  void randomize(const flambda_t* delta);
  void randomize_f2(const flambda_t* delta);
  /** @brief verify that q = f(delta) */
  void assert_correct(const flambda_t* delta1) const;

  flam_elem get_f(uint64_t i, uint64_t j) const;
  void set_f(uint64_t i, uint64_t j, const flam_elem& value);
  flam_poly get_f(uint64_t i) const;
  void set_f(uint64_t i, const flam_poly& value);
  flam_elem get_q(uint64_t i) const;
  void set_q(uint64_t i, const flam_elem& value);
};

flam_poly echelon_pow2(uint64_t k, const std::vector<flam_poly>& polys);
flam_poly check_unitary(const flam_elem& coeff, const std::vector<flam_poly>& polys);
flam_poly qary_mux(const std::vector<flam_poly>& c, const std::vector<flam_poly>& a);
flam_poly qary_mux_circuit(                              //
    const std::vector<uint64_t>& arities,                // declared arities
    const std::vector<flam_poly>& c,                     // mux control bits (sum (arities-1))
    const std::vector<flam_elem>& a,                     // input coeffs (<= prod arities)
    const flam_elem& check_unitary_coeff);  // check_unitary challenge coeffs (depth)

bit_vector delta1_from_delta0(uint64_t kappa, uint64_t tau, uint64_t lambda, const bit_vector& delta0);

#endif  // VOLE_TESTLIB_H
