#include <gtest/gtest.h>
#include <vole_private.h>

#include "testlib/vole_testlib.h"

TEST(vole_circuits, check_zero_gate) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

    for (uint64_t degree : {1, 2, 4, 7}) {
      vole_flambda_poly in(lambda, degree, 1);
      vole_flambda_poly rvp(lambda, degree - 1, 1);
      flam_poly pub(lambda, degree - 1);
      flam_elem out_value = flam_elem::zero(lambda);
      flam_elem delta2 = flam_elem::random_non_zero(lambda);

      in.randomize(delta2.data());
      rvp.randomize(delta2.data());

      prover_cst_vole_check_zero_gate_ct_ref(  //
          &vole_params, degree, pub.data(), in.f.data(), rvp.f.data());
      bool res = verifier_cst_vole_check_zero_gate_ref(  //
          &vole_params, degree,                          //
          out_value.data(), pub.data(), in.q.data(), rvp.q.data(), delta2.data());

      // verify the publication coeffs
      for (uint64_t i = 0; i <= degree - 1; ++i) {
        ASSERT_EQ(pub.get(i), in.get_f(0, i + 1) + rvp.get_f(0, i));
      }

      // verify the output value
      ASSERT_EQ(out_value, in.get_f(0, 0));

      // verify the zero test
      ASSERT_EQ(res, out_value == flam_elem::zero(lambda));
    }
  }
}

TEST(vole_circuits, mul_gate) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
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
            &vole_params, out.f.data(),   //
            in_a.f.data(), degree_a,      //
            in_b.f.data(), degree_b);
        verifier_cst_vole_mul_gate_ref(  //
            &vole_params, out.q.data(),  //
            in_a.q.data(), degree_a,     //
            in_b.q.data(), degree_b, delta2.data());

        // verify the output value
        ASSERT_EQ(out.get_f(0), in_a.get_f(0) * in_b.get_f(0));

        // verify q
        out.assert_correct(delta2.data());
      }
    }
  }
}

TEST(vole_circuits, xor_gate) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
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
            &vole_params, out.f.data(),   //
            in_a.f.data(), degree_a,      //
            in_b.f.data(), degree_b);
        verifier_cst_vole_xor_gate_ref(  //
            &vole_params, out.q.data(),  //
            in_a.q.data(), degree_a,     //
            in_b.q.data(), degree_b, delta2.data());

        // verify the output value
        ASSERT_EQ(out.get_f(0), in_a.get_f(0) + in_b.get_f(0));

        // verify q
        out.assert_correct(delta2.data());
      }
    }
  }
}

TEST(vole_circuits, xor_gate_in_place) {
  // the xor gate shall also work when in_a and out are at the same address
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
    for (uint64_t degree_a : {0, 1, 2, 4, 7}) {
      for (uint64_t degree_b : {0, 1, 3, 5, 10}) {
        uint64_t degree_res = std::max<uint64_t>(degree_a, degree_b);
        vole_flambda_poly in_a(lambda, degree_a, 1);
        vole_flambda_poly in_b(lambda, degree_b, 1);
        vole_flambda_poly out(lambda, degree_res, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_b.randomize(delta2.data());

        // copy the relevant terms from in_a to out
        for (uint64_t j = 0; j <= degree_a; ++j) {
          out.set_f(0, j, in_a.get_f(0, j));
        }
        out.set_q(0, in_a.get_q(0));

        prover_cst_vole_xor_gate_ct_ref(  //
            &vole_params, out.f.data(),   //
            out.f.data(), degree_a,       //
            in_b.f.data(), degree_b);
        verifier_cst_vole_xor_gate_ref(  //
            &vole_params, out.q.data(),  //
            out.q.data(), degree_a,      //
            in_b.q.data(), degree_b, delta2.data());

        // verify the output value
        ASSERT_EQ(out.get_f(0), in_a.get_f(0) + in_b.get_f(0));

        // verify q
        out.assert_correct(delta2.data());
      }
    }
  }
}

TEST(vole_circuits, packed_secret_input) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
    for (uint64_t num_inputs : {1, 2, 7, 8, 42}) {
      vole_cst_f2_deg1_uvq rvp(lambda, num_inputs);
      bit_vector in_value(num_inputs);
      bit_vector pub(num_inputs);
      vole_flambda_poly out(lambda, 1, num_inputs);
      flam_elem delta2 = flam_elem::random_non_zero(lambda);

      rvp.randomize(delta2.data());
      in_value.randomize();

      prover_cst_vole_packed_secret_input_ct_ref(  //
          &vole_params, num_inputs, pub.data(), out.f.data(), in_value.data(), rvp.u.data(), rvp.v.data());
      verifier_cst_vole_packed_secret_input_ref(  //
          &vole_params, num_inputs,               //
          out.q.data(), pub.data(), rvp.q.data(), delta2.data());

      bit_vector expected = in_value ^ rvp.u;
      uint64_t leftover_bits = num_inputs & 7;
      if (leftover_bits) {
        uint8_t* expected_u8 = (uint8_t*)expected.data();
        uint64_t idx = ((num_inputs + 7) >> 3) - 1;
        uint64_t and_mask = (1 << leftover_bits) - 1;
        expected_u8[idx] &= and_mask;
      }

      // verify the publication coeffs
      ASSERT_EQ(pub, expected);

      // verify the output value
      for (uint64_t i = 0; i < num_inputs; ++i) {
        ASSERT_EQ(out.get_f(i, 0), flam_elem(lambda, in_value.get(i)));
        ASSERT_EQ(out.get_f(i, 1), rvp.get_v(i));
      }

      out.assert_correct(delta2.data());
    }
  }
}

TEST(vole_circuits, echelon_pow2) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
    const uint64_t lambda_bytes = lambda >> 3;

    for (uint64_t arity : {1, 2, 3, 4, 5}) {
      for (uint64_t k : {1, 3, 6, 15}) {
        vole_flambda_poly in(lambda, 1, arity);
        vole_flambda_poly out(lambda, 1, 1);
        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        // note we don't specialize it to inputs over f2 here. if we specalize the implem, we may need to update this
        // line
        in.randomize(delta2.data());

        prover_cst_vole_echelon_pow2_ct_ref(  //
            &vole_params, arity, k, out.f.data(), in.f.data());
        verifier_cst_vole_echelon_pow2_ref(  //
            &vole_params, arity, k, out.q.data(), in.q.data(), delta2.data());

        // verify the output value
        flam_poly expect(lambda, 1);
        vole_params.flambda_echelon_pow2(k, expect.data(), in.f.data(), arity, 2 * lambda_bytes);
        vole_params.flambda_echelon_pow2(k, ((uint8_t*)expect.data()) + lambda_bytes,
                                         ((uint8_t*)in.f.data()) + lambda_bytes, arity, 2 * lambda_bytes);
        ASSERT_TRUE(memcmp(out.f.data(), expect.data(), 2 * lambda_bytes) == 0);

        out.assert_correct(delta2.data());
      }
    }
  }
}

TEST(vole_circuits, check_unitary_gate) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

    for (uint64_t arity : {2, 3, 4, 5}) {
      vole_flambda_poly in(lambda, 1, arity);
      vole_flambda_poly out(lambda, 2, 1);
      flam_elem delta2 = flam_elem::random_non_zero(lambda);
      flam_elem coeff = flam_elem::random_non_zero(lambda);

      in.randomize(delta2.data());

      {
        std::vector<uint8_t> tmp_space(prover_cst_check_unitary_gate_ct_ref_tmp_bytes(&vole_params));
        prover_cst_check_unitary_gate_ct_ref(&vole_params, arity,  //
                                             out.f.data(), in.f.data(), coeff.data(), tmp_space.data());
      }
      {
        std::vector<uint8_t> tmp_space(verifier_cst_check_unitary_gate_ref_tmp_bytes(&vole_params));
        verifier_cst_check_unitary_gate_ref(&vole_params, arity,  //
                                            out.q.data(), in.q.data(), coeff.data(), delta2.data(), tmp_space.data());
      }

      // check that the output f is correct
      std::vector<flam_poly> in_f;
      for (uint64_t i = 0; i < arity; ++i) {
        in_f.push_back(in.get_f(i));
      }
      flam_poly expect = check_unitary(coeff, in_f);
      ASSERT_EQ(out.get_f(0), expect);

      // check consistency
      out.assert_correct(delta2.data());
    }
  }
}

TEST(vole_circuits, qary_mux_gate) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

    for (uint64_t in_degree : {0, 1, 3, 7}) {
      for (uint64_t arity : {1, 2, 3, 5}) {
        // const uint64_t out_degree = (arity==1)?in_degree:(in_degree+1);
        const uint64_t out_degree = in_degree + 1;
        vole_flambda_poly in_a(lambda, in_degree, arity);
        vole_flambda_poly in_c(lambda, 1, arity - 1);
        vole_flambda_poly out(lambda, out_degree, 1);

        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_c.randomize(delta2.data());

        {
          std::vector<uint8_t> tmp_space(
              prover_cst_vole_qary_mux_gate_ct_ref_tmp_bytes(&vole_params, arity, in_degree));
          prover_cst_vole_qary_mux_gate_ct_naive(              //
              &vole_params, arity, in_degree, out.f.data(),  //
              in_c.f.data(), in_a.f.data(), tmp_space.data());
        }
        {
          std::vector<uint8_t> tmp_space(verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, in_degree));
          verifier_cst_vole_qary_mux_gate_ref(               //
              &vole_params, arity, in_degree, out.q.data(),  //
              in_c.q.data(), in_a.q.data(), delta2.data(), tmp_space.data());
        }

        // check that the output f is correct
        std::vector<flam_poly> cv;
        for (uint64_t i = 0; i < arity - 1; ++i) {
          cv.push_back(in_c.get_f(i));
        }
        std::vector<flam_poly> av;
        for (uint64_t i = 0; i < arity; ++i) {
          av.push_back(in_a.get_f(i));
        }
        flam_poly expect = qary_mux(cv, av);
        ASSERT_EQ(out.get_f(0), expect);

        // check consistency
        out.assert_correct(delta2.data());
      }
    }
  }
}

TEST(vole_circuits, qary_mux_gate_f2) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

    for (uint64_t in_degree : {0, 1, 3, 7}) {
      for (uint64_t arity : {1, 2, 3, 5}) {
        // const uint64_t out_degree = (arity==1)?in_degree:(in_degree+1);
        const uint64_t out_degree = in_degree + 1;
        vole_flambda_poly in_a(lambda, in_degree, arity);
        vole_flambda_poly in_c(lambda, 1, arity - 1);
        vole_flambda_poly out_expected(lambda, out_degree, 1);
        vole_flambda_poly out_actual(lambda, out_degree, 1);

        flam_elem delta2 = flam_elem::random_non_zero(lambda);

        in_a.randomize(delta2.data());
        in_c.randomize_f2(delta2.data());

        {
          std::vector<uint8_t> tmp_space(prover_cst_vole_qary_mux_gate_ct_f2_ref_tmp_bytes(&vole_params, arity));
          prover_cst_vole_qary_mux_gate_ct_f2_ref(                  //
              &vole_params, arity, in_degree, out_actual.f.data(),  //
              in_c.f.data(), in_a.f.data(), tmp_space.data());
        }
        {
          std::vector<uint8_t> tmp_space(
              prover_cst_vole_qary_mux_gate_ct_ref_tmp_bytes(&vole_params, arity, in_degree));
          prover_cst_vole_qary_mux_gate_ct_naive(                       //
              &vole_params, arity, in_degree, out_expected.f.data(),  //
              in_c.f.data(), in_a.f.data(), tmp_space.data());
        }
        ASSERT_EQ(out_expected.lambda, out_actual.lambda);
        ASSERT_EQ(out_expected.degree, out_actual.degree);
        ASSERT_EQ(out_expected.L, out_actual.L);
        for (uint64_t i = 0; i < out_expected.L; ++i) {
          ASSERT_EQ(out_expected.get_f(i), out_actual.get_f(i));
        }

        {
          std::vector<uint8_t> tmp_space(verifier_cst_vole_qary_mux_gate_ref_tmp_bytes(&vole_params, arity, in_degree));
          verifier_cst_vole_qary_mux_gate_ref(                      //
              &vole_params, arity, in_degree, out_actual.q.data(),  //
              in_c.q.data(), in_a.q.data(), delta2.data(), tmp_space.data());
        }

        // check that the output f is correct
        std::vector<flam_poly> cv;
        for (uint64_t i = 0; i < arity - 1; ++i) {
          cv.push_back(in_c.get_f(i));
        }
        std::vector<flam_poly> av;
        for (uint64_t i = 0; i < arity; ++i) {
          av.push_back(in_a.get_f(i));
        }
        flam_poly expect = qary_mux(cv, av);
        ASSERT_EQ(out_actual.get_f(0), expect);

        // check consistency
        out_actual.assert_correct(delta2.data());
      }
    }
  }
}

TEST(vole_circuits, qary_mux_circuit) {
  uint64_t fake_kappa = 0;  // circuits don't care
  uint64_t fake_tau = 0;    // circuits don't care

  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

    std::vector<uint64_t> arities = {5, 4, 3, 2};
    uint64_t depth = arities.size();
    uint64_t num_ctrl_bits = 0;
    uint64_t check_unitary_power = 0;
    for (uint64_t a : arities) {
      num_ctrl_bits += a - 1;
      if (a > 2) check_unitary_power += 32;
    }
    REQUIRE_DRAMATICALLY(check_unitary_power < lambda, "Too many non-binary arities");
    for (uint64_t n : {95, 120}) {
      flam_vector a = flam_vector::random(lambda, n);
      flam_elem chall_unitary_coeff = flam_elem::random(lambda);
      vole_flambda_poly in_c(lambda, 1, num_ctrl_bits);
      vole_flambda_poly out(lambda, depth, 1);
      flam_elem delta2 = flam_elem::random_non_zero(lambda);

      in_c.randomize_f2(delta2.data());

      {
        std::vector<uint8_t> tmp_space(prover_cst_mux_circuit_ct_ref_tmp_bytes(&vole_params, depth, arities.data(), n));
        prover_cst_mux_circuit_ct_ref(               //
            &vole_params, depth, arities.data(), n,  //
            out.f.data(), in_c.f.data(), a.data(), chall_unitary_coeff.data(), tmp_space.data());
      }
      {
        std::vector<uint8_t> tmp_space(verifier_cst_mux_circuit_ref_tmp_bytes(&vole_params, depth, arities.data(), n));
        verifier_cst_mux_circuit_ref(                //
            &vole_params, depth, arities.data(), n,  //
            out.q.data(), in_c.q.data(), a.data(), chall_unitary_coeff.data(), delta2.data(), tmp_space.data());
      }

      // check f
      std::vector<flam_poly> in_c_f;
      for (uint64_t i = 0; i < num_ctrl_bits; ++i) {
        in_c_f.push_back(in_c.get_f(i));
      }
      std::vector<flam_elem> av;
      for (uint64_t i = 0; i < n; ++i) {
        av.push_back(a.get(i));
      }
      flam_poly expect = qary_mux_circuit(arities, in_c_f, av, chall_unitary_coeff);
      ASSERT_EQ(out.get_f(0), expect);

      // check q
      out.assert_correct(delta2.data());
    }
  }
}
