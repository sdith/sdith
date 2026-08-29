// Exhaustive per-function correctness tests for the piop_circuit module
// (src/piop_circuit.c).
//
// Ground truth for the expected input/output relations is the round-3 Python
// oracle (sdith-py/round3/piop.py + tests/test_piop_metamorphic.py). The C++
// testlib helpers echelon_pow2 / check_unitary / qary_mux / qary_mux_circuit
// are an independent re-implementation of that oracle and are used here as the
// known-answer reference. Prover/verifier "duality" (metamorphic) is checked via
// vole_flambda_poly::assert_correct, which asserts q == f(delta2) exactly as the
// Python duality invariant eval(prover_gate(polys), delta2) == verifier_gate(...).
//
// Conventions (includes, TEST naming, randomize()/testlib helpers) mirror
// test/vole_circuits_test.cpp.
//
// The gate functions depend only on lambda; the tau/kappa parameters are
// irrelevant ("circuits don't care"), so the 6 named parameter sets
// (cat{1,3,5}-{short,fast}) collapse to the 3 distinct field sizes
// lambda in {128, 192, 256}, all exercised below.
//
// NOTE: there is no verifier-side F2-optimized mux gate. The product_f2 fast
// path only applies prover-side (control bits are plaintext over F2 there); the
// verifier uses full q-products, so verifier_cst_vole_qary_mux_gate_ref is the
// only verifier implementation.

#include <gtest/gtest.h>
#include <vole_private.h>

#include <cstring>
#include <vector>

#include "testlib/vole_testlib.h"

namespace {

constexpr uint64_t FAKE_KAPPA = 0;  // circuits don't care
constexpr uint64_t FAKE_TAU = 0;    // circuits don't care

}  // namespace

// ---------------------------------------------------------------------------
// prover_cst_vole_packed_secret_input_ct_ref / verifier_cst_vole_packed_secret_input_ref
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_packed_secret_input / verifier_packed_secret_input):
//   pub      = (in_value ^ rvp_u) with the trailing partial byte masked
//   out_f[i] = [ bit_i(in_value) , rvp_v[i] ]     (degree-1 poly, cst over F2)
//   verifier: q[i] = rvp_q[i] ^ bit_i(pub)
TEST(piop_circuit, packed_secret_input) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    // include odd/unaligned lengths, exact-byte lengths, single element
    for (uint64_t num_inputs : {1, 2, 7, 8, 9, 16, 42, 64}) {
      // three secret-value flavours: random, all-zero, all-ones
      for (int flavour = 0; flavour < 3; ++flavour) {
        vole_cst_f2_deg1_uvq rvp(lambda, num_inputs);
        bit_vector in_value = bit_vector::zero(num_inputs);
        bit_vector pub(num_inputs);
        vole_flambda_poly out(lambda, 1, num_inputs);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        rvp.randomize(delta2.data());
        if (flavour == 0) {
          in_value.randomize();
        } else if (flavour == 2) {
          for (uint64_t i = 0; i < num_inputs; ++i) in_value.set(i, true);
        }  // flavour == 1 -> stays all zero

        prover_cst_vole_packed_secret_input_ct_ref(  //
            &vole_params, num_inputs, pub.data(), out.f.data(), in_value.data(), rvp.u.data(), rvp.v.data());
        verifier_cst_vole_packed_secret_input_ref(  //
            &vole_params, num_inputs, out.q.data(), pub.data(), rvp.q.data(), delta2.data());

        // publication == (in_value xor rvp_u), trailing bits masked out
        bit_vector expected = in_value ^ rvp.u;
        uint64_t leftover_bits = num_inputs & 7;
        if (leftover_bits) {
          uint8_t* expected_u8 = (uint8_t*)expected.data();
          uint64_t idx = ((num_inputs + 7) >> 3) - 1;
          uint64_t and_mask = (1 << leftover_bits) - 1;
          expected_u8[idx] &= and_mask;
        }
        ASSERT_EQ(pub, expected);

        // output polynomial coefficients
        for (uint64_t i = 0; i < num_inputs; ++i) {
          ASSERT_EQ(out.get_f(i, 0), flam_elem(lambda, in_value.get(i)));
          ASSERT_EQ(out.get_f(i, 1), rvp.get_v(i));
        }

        // prover/verifier duality
        out.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_vole_check_zero_gate_ct_ref / verifier_cst_vole_check_zero_gate_ref
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_check_zero_gate / verifier_check_zero_gate):
//   pub[i]      = rvp[i] ^ result[i+1]     for i in 0..degree-1
//   verifier deduces out_value = result[0] (the constant term) and returns
//   1 iff out_value == 0.
TEST(piop_circuit, check_zero_gate) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t degree : {1, 2, 4, 7}) {
      // --- generic (constant term almost surely non-zero) ---
      {
        vole_flambda_poly in(lambda, degree, 1);
        vole_flambda_poly rvp(lambda, degree - 1, 1);
        flam_poly pub(lambda, degree - 1);
        flam_elem out_value = flam_elem::zero(lambda);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in.randomize(delta2.data());
        rvp.randomize(delta2.data());

        prover_cst_vole_check_zero_gate_ct_ref(  //
            &vole_params, degree, pub.data(), in.f.data(), rvp.f.data());
        uint8_t res = verifier_cst_vole_check_zero_gate_ref(  //
            &vole_params, degree, out_value.data(), pub.data(), in.q.data(), rvp.q.data(), delta2.data());

        for (uint64_t i = 0; i <= degree - 1; ++i) {
          ASSERT_EQ(pub.get(i), in.get_f(0, i + 1) + rvp.get_f(0, i));
        }
        ASSERT_EQ(out_value, in.get_f(0, 0));
        ASSERT_EQ(res, (uint8_t)(out_value == flam_elem::zero(lambda) ? 1 : 0));
      }

      // --- forced zero constant term: verifier must return 1 ---
      {
        vole_flambda_poly in(lambda, degree, 1);
        vole_flambda_poly rvp(lambda, degree - 1, 1);
        flam_poly pub(lambda, degree - 1);
        flam_elem out_value = flam_elem::random(lambda);  // must be overwritten to zero
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in.randomize(delta2.data());
        rvp.randomize(delta2.data());

        // set constant term to 0 and rebuild the vole evaluation q(delta2)
        in.set_f(0, 0, flam_elem::zero(lambda));
        flam_elem acc = in.get_f(0, degree);
        for (int64_t j = (int64_t)degree - 1; j >= 0; --j) {
          acc = delta2 * acc + in.get_f(0, j);
        }
        in.set_q(0, acc);

        prover_cst_vole_check_zero_gate_ct_ref(  //
            &vole_params, degree, pub.data(), in.f.data(), rvp.f.data());
        uint8_t res = verifier_cst_vole_check_zero_gate_ref(  //
            &vole_params, degree, out_value.data(), pub.data(), in.q.data(), rvp.q.data(), delta2.data());

        ASSERT_EQ(out_value, flam_elem::zero(lambda));
        ASSERT_EQ(res, (uint8_t)1);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_vole_xor_gate_ct_ref / verifier_cst_vole_xor_gate_ref
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_xor_gate / verifier_xor_gate):
//   prover: coefficient-wise add of the two polynomials
//   verifier: res_q = a_q + b_q
TEST(piop_circuit, xor_gate) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t degree_a : {0, 1, 2, 4, 7}) {
      for (uint64_t degree_b : {0, 1, 3, 5, 10}) {
        uint64_t degree_res = std::max<uint64_t>(degree_a, degree_b);
        vole_flambda_poly in_a(lambda, degree_a, 1);
        vole_flambda_poly in_b(lambda, degree_b, 1);
        vole_flambda_poly out(lambda, degree_res, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_b.randomize(delta2.data());

        prover_cst_vole_xor_gate_ct_ref(  //
            &vole_params, out.f.data(), in_a.f.data(), degree_a, in_b.f.data(), degree_b);
        verifier_cst_vole_xor_gate_ref(  //
            &vole_params, out.q.data(), in_a.q.data(), degree_a, in_b.q.data(), degree_b, delta2.data());

        // KAT: full polynomial equals a + b
        ASSERT_EQ(out.get_f(0), in_a.get_f(0) + in_b.get_f(0));
        // KAT: verifier evaluation equals a(delta2) + b(delta2)
        ASSERT_EQ(out.get_q(0), in_a.get_q(0) + in_b.get_q(0));
        // duality
        out.assert_correct(delta2.data());
      }
    }
  }
}

TEST(piop_circuit, xor_gate_in_place) {
  // xor gate must also work with out == a
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t degree_a : {0, 1, 4, 7}) {
      for (uint64_t degree_b : {0, 1, 5, 10}) {
        uint64_t degree_res = std::max<uint64_t>(degree_a, degree_b);
        vole_flambda_poly in_a(lambda, degree_a, 1);
        vole_flambda_poly in_b(lambda, degree_b, 1);
        vole_flambda_poly out(lambda, degree_res, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_b.randomize(delta2.data());

        for (uint64_t j = 0; j <= degree_a; ++j) out.set_f(0, j, in_a.get_f(0, j));
        out.set_q(0, in_a.get_q(0));

        prover_cst_vole_xor_gate_ct_ref(  //
            &vole_params, out.f.data(), out.f.data(), degree_a, in_b.f.data(), degree_b);
        verifier_cst_vole_xor_gate_ref(  //
            &vole_params, out.q.data(), out.q.data(), degree_a, in_b.q.data(), degree_b, delta2.data());

        ASSERT_EQ(out.get_f(0), in_a.get_f(0) + in_b.get_f(0));
        out.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_vole_mul_gate_ct_ref / verifier_cst_vole_mul_gate_ref
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_mul_gate / verifier_mul_gate):
//   prover: schoolbook polynomial product
//   verifier: res_q = a_q * b_q
TEST(piop_circuit, mul_gate) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t degree_a : {0, 1, 2, 4, 7}) {
      for (uint64_t degree_b : {0, 1, 3, 5, 10}) {
        uint64_t degree_res = degree_a + degree_b;
        vole_flambda_poly in_a(lambda, degree_a, 1);
        vole_flambda_poly in_b(lambda, degree_b, 1);
        vole_flambda_poly out(lambda, degree_res, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_b.randomize(delta2.data());

        prover_cst_vole_mul_gate_ct_ref(  //
            &vole_params, out.f.data(), in_a.f.data(), degree_a, in_b.f.data(), degree_b);
        verifier_cst_vole_mul_gate_ref(  //
            &vole_params, out.q.data(), in_a.q.data(), degree_a, in_b.q.data(), degree_b, delta2.data());

        // KAT: full polynomial equals a * b
        ASSERT_EQ(out.get_f(0), in_a.get_f(0) * in_b.get_f(0));
        // KAT: verifier evaluation equals a(delta2) * b(delta2)
        ASSERT_EQ(out.get_q(0), in_a.get_q(0) * in_b.get_q(0));
        // duality
        out.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_vole_echelon_pow2_ct_ref / verifier_cst_vole_echelon_pow2_ref
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_echelon_pow2_gate):
//   res = sum_i 2^{k*i} * a[i]   (applied to constant and linear coeffs)
TEST(piop_circuit, echelon_pow2) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t arity : {1, 2, 3, 4, 5}) {
      for (uint64_t k : {1, 3, 6, 15}) {
        // (arity-1)*k stays < 64 so the testlib echelon_pow2 shift is well defined
        vole_flambda_poly in(lambda, 1, arity);
        vole_flambda_poly out(lambda, 1, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in.randomize(delta2.data());

        prover_cst_vole_echelon_pow2_ct_ref(  //
            &vole_params, arity, k, out.f.data(), in.f.data());
        verifier_cst_vole_echelon_pow2_ref(  //
            &vole_params, arity, k, out.q.data(), in.q.data(), delta2.data());

        // KAT vs oracle: expected = sum 2^{ki} a[i]
        std::vector<flam_poly> in_polys;
        for (uint64_t i = 0; i < arity; ++i) in_polys.push_back(in.get_f(i));
        flam_poly expect = echelon_pow2(k, in_polys);
        ASSERT_EQ(out.get_f(0), expect);

        // duality
        out.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_check_unitary_gate_ct_ref / verifier_cst_check_unitary_gate_ref
// (and their *_tmp_bytes)
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_check_unitary_gate / verifier_check_unitary_gate):
//   res = coeff * ( echelon(1,c) * echelon(m,c[:m-1]) + echelon(m+1,c[:m-1]) )
//   where m = arity here matches the C "arity" (= number of control polys).
TEST(piop_circuit, check_unitary_gate) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t arity : {2, 3, 4, 5}) {
      vole_flambda_poly in(lambda, 1, arity);
      vole_flambda_poly out(lambda, 2, 1);
      flam_elem delta2 = flam_elem::random_non_zero(lambda);
      flam_elem coeff = flam_elem::random_non_zero(lambda);

      in.randomize(delta2.data());

      {
        std::vector<uint8_t> tmp(prover_cst_check_unitary_gate_ct_ref_tmp_bytes(&vole_params));
        prover_cst_check_unitary_gate_ct_ref(&vole_params, arity, out.f.data(), in.f.data(), coeff.data(), tmp.data());
      }
      {
        std::vector<uint8_t> tmp(verifier_cst_check_unitary_gate_ref_tmp_bytes(&vole_params));
        verifier_cst_check_unitary_gate_ref(&vole_params, arity, out.q.data(), in.q.data(), coeff.data(), delta2.data(),
                                            tmp.data());
      }

      // KAT vs oracle
      std::vector<flam_poly> in_f;
      for (uint64_t i = 0; i < arity; ++i) in_f.push_back(in.get_f(i));
      flam_poly expect = check_unitary(coeff, in_f);
      ASSERT_EQ(out.get_f(0), expect);

      // duality
      out.assert_correct(delta2.data());
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_vole_qary_mux_gate_ct_naive / verifier_cst_vole_qary_mux_gate_ref
// (and their *_tmp_bytes)
// ---------------------------------------------------------------------------
// Oracle (piop.py::prover_qary_mux_gate / verifier_qary_mux_gate):
//   res = a[0] + sum_{i>=1} c[i-1] * (a[i] - a[0])
TEST(piop_circuit, qary_mux_gate) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t in_degree : {0, 1, 3, 7}) {
      for (uint64_t arity : {1, 2, 3, 5}) {
        const uint64_t out_degree = in_degree + 1;
        vole_flambda_poly in_a(lambda, in_degree, arity);
        vole_flambda_poly in_c(lambda, 1, arity - 1);
        vole_flambda_poly out(lambda, out_degree, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_c.randomize(delta2.data());

        {
          std::vector<uint8_t> tmp(prover_cst_vole_qary_mux_gate_ct_ref_tmp_bytes(&vole_params, arity, in_degree));
          prover_cst_vole_qary_mux_gate_ct_naive(  //
              &vole_params, arity, in_degree, out.f.data(), in_c.f.data(), in_a.f.data(), tmp.data());
        }
        {
          std::vector<uint8_t> tmp(verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, in_degree));
          verifier_cst_vole_qary_mux_gate_ref(  //
              &vole_params, arity, in_degree, out.q.data(), in_c.q.data(), in_a.q.data(), delta2.data(), tmp.data());
        }

        // KAT vs oracle
        std::vector<flam_poly> cv;
        for (uint64_t i = 0; i < arity - 1; ++i) cv.push_back(in_c.get_f(i));
        std::vector<flam_poly> av;
        for (uint64_t i = 0; i < arity; ++i) av.push_back(in_a.get_f(i));
        flam_poly expect = qary_mux(cv, av);
        ASSERT_EQ(out.get_f(0), expect);

        // duality
        out.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_vole_qary_mux_gate_ct_f2_ref  (FOCUS)
// ---------------------------------------------------------------------------
// Specialised prover MUX that uses product_f2 for the control constant term.
// It must produce EXACTLY the same polynomial as the generic
// prover_cst_vole_qary_mux_gate_ct_naive (and the oracle qary_mux) WHEN the
// control constant terms are genuine bits (built via randomize_f2). The
// generic verifier is then used to confirm prover/verifier duality.
TEST(piop_circuit, qary_mux_gate_ct_f2) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    for (uint64_t in_degree : {0, 1, 3, 7}) {
      for (uint64_t arity : {1, 2, 3, 5}) {
        const uint64_t out_degree = in_degree + 1;
        vole_flambda_poly in_a(lambda, in_degree, arity);
        vole_flambda_poly in_c(lambda, 1, arity - 1);
        vole_flambda_poly out_actual(lambda, out_degree, 1);
        vole_flambda_poly out_expected(lambda, out_degree, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_c.randomize_f2(delta2.data());  // control constant terms are bits

        // the f2 specialisation (function under test)
        {
          std::vector<uint8_t> tmp(prover_cst_vole_qary_mux_gate_ct_f2_ref_tmp_bytes(&vole_params, arity));
          prover_cst_vole_qary_mux_gate_ct_f2_ref(  //
              &vole_params, arity, in_degree, out_actual.f.data(), in_c.f.data(), in_a.f.data(), tmp.data());
        }

        // the generic prover, as an independent reference
        {
          std::vector<uint8_t> tmp(prover_cst_vole_qary_mux_gate_ct_ref_tmp_bytes(&vole_params, arity, in_degree));
          prover_cst_vole_qary_mux_gate_ct_naive(  //
              &vole_params, arity, in_degree, out_expected.f.data(), in_c.f.data(), in_a.f.data(), tmp.data());
        }

        // f2 prover output == generic prover output, coefficient by coefficient
        // (both polys are constructed with out_degree, so compare coefficients, not the degree field)
        for (uint64_t j = 0; j <= out_degree; ++j) {
          ASSERT_EQ(out_actual.get_f(0, j), out_expected.get_f(0, j));
        }

        // f2 prover output == oracle qary_mux
        std::vector<flam_poly> cv;
        for (uint64_t i = 0; i < arity - 1; ++i) cv.push_back(in_c.get_f(i));
        std::vector<flam_poly> av;
        for (uint64_t i = 0; i < arity; ++i) av.push_back(in_a.get_f(i));
        ASSERT_EQ(out_actual.get_f(0), qary_mux(cv, av));

        // prover(f2)/verifier duality
        {
          std::vector<uint8_t> tmp(verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, in_degree));
          verifier_cst_vole_qary_mux_gate_ref(  //
              &vole_params, arity, in_degree, out_actual.q.data(), in_c.q.data(), in_a.q.data(), delta2.data(),
              tmp.data());
        }
        out_actual.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover/verifier qary-mux duality (mirrors tests/test_piop_metamorphic.py
// test_qary_mux_gate_duality): degree-1 inputs, F2 control bits.
// ---------------------------------------------------------------------------
TEST(piop_circuit, qary_mux_gate_duality) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

    const uint64_t in_degree = 1;
    const uint64_t out_degree = in_degree + 1;
    for (uint64_t arity : {2, 3, 4, 5}) {
      for (int rep = 0; rep < 8; ++rep) {
        vole_flambda_poly in_a(lambda, in_degree, arity);
        vole_flambda_poly in_c(lambda, 1, arity - 1);
        vole_flambda_poly out(lambda, out_degree, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_c.randomize_f2(delta2.data());

        {
          std::vector<uint8_t> tmp(prover_cst_vole_qary_mux_gate_ct_f2_ref_tmp_bytes(&vole_params, arity));
          prover_cst_vole_qary_mux_gate_ct_f2_ref(  //
              &vole_params, arity, in_degree, out.f.data(), in_c.f.data(), in_a.f.data(), tmp.data());
        }
        {
          std::vector<uint8_t> tmp(verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, in_degree));
          verifier_cst_vole_qary_mux_gate_ref(  //
              &vole_params, arity, in_degree, out.q.data(), in_c.q.data(), in_a.q.data(), delta2.data(), tmp.data());
        }
        // eval(prover_poly, delta2) == verifier_result
        out.assert_correct(delta2.data());
      }
    }
  }
}

// ---------------------------------------------------------------------------
// prover_cst_mux_circuit_ct_ref / verifier_cst_mux_circuit_ref (and *_tmp_bytes)
// ---------------------------------------------------------------------------
// Oracle: piop.py::prover_mux_circuit / verifier_mux_circuit, mirrored by the
// testlib qary_mux_circuit helper. Covers non-binary arities (with the unitary
// challenge ladder) and a binary-only tree, plus a truncated last group.
namespace {
void run_mux_circuit(uint64_t lambda, const std::vector<uint64_t>& arities, uint64_t n) {
  vole_parameters vole_params = {};
  vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);

  const uint64_t depth = arities.size();
  uint64_t num_ctrl_bits = 0;
  uint64_t check_unitary_power = 0;
  for (uint64_t a : arities) {
    num_ctrl_bits += a - 1;
    if (a > 2) check_unitary_power += 32;
  }
  REQUIRE_DRAMATICALLY(check_unitary_power < lambda, "too many non-binary arities");

  flam_vector a = flam_vector::random(lambda, n);
  flam_elem chall_unitary_coeff = flam_elem::random(lambda);
  vole_flambda_poly in_c(lambda, 1, num_ctrl_bits);
  vole_flambda_poly out(lambda, depth, 1);
  flam_elem delta2 = flam_elem::random_non_zero(lambda);

  in_c.randomize_f2(delta2.data());

  {
    std::vector<uint8_t> tmp(prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, depth, arities.data(), n));
    prover_cst_mux_circuit_ct_ref(  //
        &vole_params, depth, arities.data(), n, out.f.data(), in_c.f.data(), a.data(), chall_unitary_coeff.data(),
        tmp.data());
  }
  {
    std::vector<uint8_t> tmp(verifier_cst_mux_circuit_ref_tmp_bytes(&vole_params, depth, arities.data(), n));
    verifier_cst_mux_circuit_ref(  //
        &vole_params, depth, arities.data(), n, out.q.data(), in_c.q.data(), a.data(), chall_unitary_coeff.data(),
        delta2.data(), tmp.data());
  }

  // KAT vs oracle
  std::vector<flam_poly> in_c_f;
  for (uint64_t i = 0; i < num_ctrl_bits; ++i) in_c_f.push_back(in_c.get_f(i));
  std::vector<flam_elem> av;
  for (uint64_t i = 0; i < n; ++i) av.push_back(a.get(i));
  flam_poly expect = qary_mux_circuit(arities, in_c_f, av, chall_unitary_coeff);
  ASSERT_EQ(out.get_f(0), expect);

  // duality
  out.assert_correct(delta2.data());
}
}  // namespace

TEST(piop_circuit, mux_circuit) {
  for (uint64_t lambda : {128, 192, 256}) {
    // non-binary tree with a full and a truncated last group
    run_mux_circuit(lambda, {5, 4, 3, 2}, 95);
    run_mux_circuit(lambda, {5, 4, 3, 2}, 120);
    // binary-only tree (arity==2 path: no unitary challenge), truncated group
    run_mux_circuit(lambda, {2, 2, 2, 2}, 13);
    run_mux_circuit(lambda, {2, 2, 2, 2}, 16);
    // mixed depth-2 tree
    run_mux_circuit(lambda, {3, 2}, 5);
  }
}

// ---------------------------------------------------------------------------
// *_tmp_bytes scratch-size helpers: deterministic and sufficiently large.
// ---------------------------------------------------------------------------
TEST(piop_circuit, tmp_bytes_sizes) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, FAKE_TAU, FAKE_KAPPA);
    const uint64_t lambda_bytes = vole_params.lambda_bytes;

    // check_unitary prover: two aligned temporaries of 3 and 2 lambda_bytes
    uint64_t pu = prover_cst_check_unitary_gate_ct_ref_tmp_bytes(&vole_params);
    EXPECT_EQ(pu, prover_cst_check_unitary_gate_ct_ref_tmp_bytes(&vole_params));  // deterministic
    EXPECT_GE(pu, 5 * lambda_bytes);

    // check_unitary verifier: two aligned temporaries of 1 lambda_bytes each
    uint64_t vu = verifier_cst_check_unitary_gate_ref_tmp_bytes(&vole_params);
    EXPECT_EQ(vu, verifier_cst_check_unitary_gate_ref_tmp_bytes(&vole_params));
    EXPECT_GE(vu, 2 * lambda_bytes);

    for (uint64_t arity : {1, 2, 3, 5}) {
      // The f2 prover gate and the verifier gate only hold the prepared control (sized by arity,
      // not by the degree). The old one-shot gates sized scratch from the degree, so lock the new
      // degree-independence: the value at in_degree 0 must hold for every degree.
      const uint64_t pf2_ref = prover_cst_vole_qary_mux_gate_ct_f2_ref_tmp_bytes(&vole_params, arity);
      const uint64_t vm_ref = verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, /*in_degree=*/0);
      EXPECT_GE(pf2_ref, prover_cst_vole_qary_mux_ctrl_bytes(&vole_params, arity));
      EXPECT_GE(vm_ref, verifier_cst_vole_qary_mux_ctrl_bytes(&vole_params, arity));

      for (uint64_t in_degree : {0, 1, 3, 7}) {
        // the non-f2 prover gate keeps a degree-sized scratch (it grows with the degree)
        uint64_t pm = prover_cst_vole_qary_mux_gate_ct_ref_tmp_bytes(&vole_params, arity, in_degree);
        EXPECT_GE(pm, 2 * (in_degree + 2) * lambda_bytes);

        // f2 prover and verifier scratch do not depend on the degree
        EXPECT_EQ(prover_cst_vole_qary_mux_gate_ct_f2_ref_tmp_bytes(&vole_params, arity), pf2_ref);
        EXPECT_EQ(verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, in_degree), vm_ref);
      }
    }

    // full mux-circuit scratch: deterministic and non-zero
    std::vector<uint64_t> arities = {5, 4, 3, 2};
    const uint64_t n = 120;
    uint64_t pc = prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, arities.size(), arities.data(), n);
    EXPECT_EQ(pc, prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, arities.size(), arities.data(), n));
    EXPECT_GT(pc, 0u);
    uint64_t vc = verifier_cst_mux_circuit_ref_tmp_bytes(&vole_params, arities.size(), arities.data(), n);
    EXPECT_EQ(vc, verifier_cst_mux_circuit_ref_tmp_bytes(&vole_params, arities.size(), arities.data(), n));
    EXPECT_GT(vc, 0u);
  }
}

// ---------------------------------------------------------------------------
// mux_circuit_check_shape (the shape guard added with the dot-product rewrite)
// must reject malformed circuits. It is static, so it is reached through the
// *_tmp_bytes entry points; CREQUIRE calls abort(), so these are death tests.
// ---------------------------------------------------------------------------
TEST(piop_circuitDeathTest, mux_circuit_check_shape_rejects_bad_shape) {
  vole_parameters vole_params = {};
  vole_parameters_init_ref(&vole_params, 128, FAKE_TAU, FAKE_KAPPA);

  const std::vector<uint64_t> ok = {5, 4, 3, 2};  // 95 -> 19 -> 5 -> 2 -> 1: a valid chain

  // depth 0
  EXPECT_DEATH(prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, 0, ok.data(), 95), "depth must be");
  // no input
  EXPECT_DEATH(prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, ok.size(), ok.data(), 0), "at least one input");
  // a zero arity
  const std::vector<uint64_t> zero_arity = {5, 0, 3, 2};
  EXPECT_DEATH(prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, zero_arity.size(), zero_arity.data(), 95),
               "arity must be");
  // arities too small to collapse to a single output (the ceil-chain never reaches 1)
  const std::vector<uint64_t> too_small = {2};
  EXPECT_DEATH(prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, too_small.size(), too_small.data(), 5),
               "too small");
  // the verifier entry point runs the same guard
  EXPECT_DEATH(verifier_cst_mux_circuit_ref_tmp_bytes(&vole_params, 0, ok.data(), 95), "depth must be");
}
