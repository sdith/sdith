#include <gtest/gtest.h>

#include "sdith_vole_to_piop.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/vole_testlib.h"
#include "vole_generation.h"
#include "vole_private.h"

// concatenation test

TEST(vole_conversions, prover_midsize_to_fullsize_std_vole) {
  for (const uint64_t lambda : {128, 192, 256}) {
    for (const uint64_t kappa : {11, 12}) {
      const uint64_t tau = lambda / kappa;
      vole_parameters vole_params = {};
      vole_parameters_init_ref(&vole_params, lambda, tau, kappa);
      const uint64_t L = 1400;
      const uint64_t Lbytes = (L + 7) / 8;
      const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);

      bit_matrix in_u = bit_matrix::random(tau, Lslice * 8);
      bit_matrix in_v = bit_matrix::random(lambda, Lslice * 8);
      bit_vector out_u(Lslice * 8);
      bit_matrix out_corr(tau - 1, Lslice * 8);
      bit_matrix out_v(L, lambda);

      prover_midsize_to_fullsize_std_vole_ct_ref(&vole_params, L, out_u.data(), out_corr.data(), out_v.data(),
                                                 in_u.data(), in_v.data());

      // check u and corr
      for (uint64_t j = 0; j < L; ++j) {
        ASSERT_EQ(out_u.get(j), in_u.get(0, j));
      }
      for (uint64_t i = 1; i < tau - 1; ++i) {
        for (uint64_t j = 0; j < L; ++j) {
          ASSERT_EQ(out_corr.get(i - 1, j), in_u.get(i, j) ^ in_u.get(0, j));
        }
      }
      // check v
      for (uint64_t i = 0; i < lambda; ++i) {
        for (uint64_t j = 0; j < L; ++j) {
          ASSERT_EQ(out_v.get(j, i), in_v.get(i, j));
        }
      }
    }
  }
}

TEST(vole_conversions, verifier_midsize_to_fullsize_std_vole) {
  for (const uint64_t lambda : {128, 192, 256}) {
    for (const uint64_t kappa : {11, 12}) {
      const uint64_t tau = lambda / kappa;
      vole_parameters vole_params = {};
      vole_parameters_init_ref(&vole_params, lambda, tau, kappa);
      const uint64_t L = 1400;
      const uint64_t Lbytes = (L + 7) / 8;
      const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);

      bit_matrix in_q = bit_matrix::random(lambda, Lslice * 8);
      bit_matrix out_q(L, lambda);

      verifier_midsize_to_fullsize_std_vole_ref(&vole_params, L, out_q.data(), in_q.data());

      // check q
      for (uint64_t i = 0; i < lambda; ++i) {
        for (uint64_t j = 0; j < L; ++j) {
          ASSERT_EQ(out_q.get(j, i), in_q.get(i, j));
        }
      }
    }
  }
}

// consistency check test

TEST(vole_conversions, consistency_cchk) {
  for (const uint64_t lambda : {128, 192, 256}) {
    for (const uint64_t kappa : {11, 12}) {
      const uint64_t tau = lambda / kappa;
      vole_parameters vole_params = {};
      vole_parameters_init_ref(&vole_params, lambda, tau, kappa);
      const uint64_t seed1_bytes = 17;
      const uint64_t L = 1400;
      const uint64_t cchk_nrows = vole_consistency_check_matrix_nrows(&vole_params);
      const uint64_t cchk_ncols = vole_consistency_check_matrix_ncols(&vole_params, L);

      vole_std_f2_deg1_uvq in(lambda, L);
      bit_matrix chk_matrix(cchk_nrows, cchk_ncols);
      bit_vector chk_u(cchk_nrows);
      flam_vector chk_v(lambda, cchk_nrows);
      flam_vector chk_v2(lambda, cchk_nrows);
      bit_vector chk_seed1 = bit_vector::random(seed1_bytes * 8);
      flam_elem delta1 = flam_elem::random_non_zero(lambda);

      both_vole_consistency_check_matrix(&vole_params, L, chk_matrix.data(), chk_seed1.data(), seed1_bytes);
      prover_vole_consistency_check(&vole_params, L, chk_u.data(), chk_v.data(), in.u.data(), in.v.data(),
                                    chk_matrix.data());
      verifier_vole_consistency_check(&vole_params, L, chk_v2.data(), chk_u.data(), in.q.data(), chk_matrix.data(),
                                      delta1.data());

      ASSERT_EQ(chk_v, chk_v2);
    }
  }
}

// F2 to Flambda: degree 1

TEST(vole_conversions, consistency_self_vole_std_f2_deg1_uvq) {
  for (uint64_t lambda : {128, 192, 256}) {
    const uint64_t num_pairs = 53;

    bit_vector delta1 = bit_vector::random(lambda);
    vole_std_f2_deg1_uvq in(lambda, num_pairs);

    in.randomize(delta1.data());
    in.assert_correct(delta1.data());
  }
}

TEST(vole_conversions, consistency_self_vole_cst_f2_deg1_uvq) {
  for (uint64_t lambda : {128, 192, 256}) {
    const uint64_t num_pairs = 53;

    bit_vector delta2 = bit_vector::random(lambda);
    vole_cst_f2_deg1_uvq in(lambda, num_pairs);

    in.randomize(delta2.data());
    in.assert_correct(delta2.data());
  }
}

TEST(vole_conversions, consistency_self_vole_flambda_poly) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t degree : {1, 2, 7}) {
      const uint64_t num_pairs = 53;

      bit_vector delta = bit_vector::random(lambda);
      vole_flambda_poly in(lambda, degree, num_pairs);

      in.randomize(delta.data());
      in.assert_correct(delta.data());
    }
  }
}

TEST(vole_conversions, prover_f2_to_flambda_deg1_std_vole_ct_ref) {
  const uint64_t lambda = 128;
  const uint64_t num_pairs = 53;
  const uint64_t fake_tau = 0;
  const uint64_t fake_kappa = 0;

  vole_parameters vole_params = {};
  vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
  bit_matrix out_f(2 * num_pairs, lambda);
  bit_vector in_u(lambda * num_pairs);
  bit_matrix in_v(lambda * num_pairs, lambda);

  prover_f2_to_flambda_deg1_std_vole_ct_ref(&vole_params, num_pairs,  //
                                            out_f.data(), in_u.data(), in_v.data());

  for (uint64_t i = 0; i < num_pairs; i++) {
    // verify f0
    for (uint64_t j = 0; j < lambda; j++) {
      ASSERT_EQ(out_f.get(2 * i, j), in_u.get(i * lambda + j));
    }
    // verify f1
    bit_vector expect(lambda);
    vole_params.flambda_sum_pow2(expect.data(), in_v.row_ptr(i * lambda));
    ASSERT_EQ(out_f.row(2 * i + 1), expect);
  }
}

TEST(vole_conversions, verifier_f2_to_flambda_deg1_std_vole_ref) {
  const uint64_t lambda = 128;
  const uint64_t num_pairs = 53;
  const uint64_t fake_tau = 0;
  const uint64_t fake_kappa = 0;

  vole_parameters vole_params = {};
  vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
  bit_matrix out_q(num_pairs, lambda);
  bit_matrix in_q(lambda * num_pairs, lambda);

  verifier_f2_to_flambda_deg1_std_vole_ref(&vole_params, num_pairs,  //
                                           out_q.data(), in_q.data());

  for (uint64_t i = 0; i < num_pairs; i++) {
    // verify f1
    bit_vector expect(lambda);
    vole_params.flambda_sum_pow2(expect.data(), in_q.row_ptr(i * lambda));
    ASSERT_EQ(out_q.row(i), expect);
  }
}

TEST(vole_conversions, consistency_f2_to_flambda_deg1_std_vole_ref) {
  const uint64_t lambda = 128;
  const uint64_t num_pairs = 53;
  const uint64_t fake_tau = 0;
  const uint64_t fake_kappa = 0;

  vole_parameters vole_params = {};
  vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

  bit_vector delta1 = bit_vector::random(lambda);
  vole_std_f2_deg1_uvq in(lambda, num_pairs * lambda);
  vole_flambda_poly out(lambda, 1, num_pairs);

  in.randomize(delta1.data());

  prover_f2_to_flambda_deg1_std_vole_ct_ref(&vole_params, num_pairs,  //
                                            out.f.data(), in.u.data(), in.v.data());
  verifier_f2_to_flambda_deg1_std_vole_ref(&vole_params, num_pairs,  //
                                           out.q.data(), in.q.data());

  out.assert_correct(delta1.data());
}

TEST(vole_conversions, consistency_flambda_deg1_to_degd_vole_ref) {
  const uint64_t fake_kappa = 0;
  const uint64_t fake_tau = 0;
  for (const uint64_t lambda : {128, 192, 256}) {
    for (const uint64_t out_degree : {1, 2, 5, 11}) {
      vole_parameters vole_params = {};
      vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

      flam_elem delta1 = flam_elem::random_non_zero(lambda);

      vole_flambda_poly in(lambda, 1, out_degree);
      vole_flambda_poly out(lambda, out_degree, 1);

      in.randomize(delta1.data());

      prover_flambda_deg1_to_degd_vole_ref(&vole_params, out_degree,  //
                                           out.f.data(), in.f.data());
      verifier_flambda_deg1_to_degd_vole_ref(&vole_params, out_degree,  //
                                             out.q.data(), in.q.data(), delta1.data());

      // check also the coeffs of f (paranoia mode)
      ASSERT_EQ(out.get_f(0, 0), in.get_f(0, 0));
      for (uint64_t j = 1; j < out_degree; j++) {
        ASSERT_EQ(out.get_f(0, j), in.get_f(j - 1, 1) + in.get_f(j, 0));
      }
      ASSERT_EQ(out.get_f(0, out_degree), in.get_f(out_degree - 1, 1));

      // consistency check
      out.assert_correct(delta1.data());
    }
  }
}

TEST(vole_conversions, consistency_flambda_deg1_to_degd_vole_in_place_ref) {
  const uint64_t fake_kappa = 0;
  const uint64_t fake_tau = 0;
  for (const uint64_t lambda : {128, 192, 256}) {
    for (const uint64_t out_degree : {1, 2, 5, 11}) {
      vole_parameters vole_params = {};
      vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

      flam_elem delta1 = flam_elem::random_non_zero(lambda);

      vole_flambda_poly in(lambda, 1, out_degree);
      vole_flambda_poly out(lambda, out_degree, 1);

      in.randomize(delta1.data());

      bit_matrix in_out_f = in.f;
      bit_matrix in_out_q = in.q;

      prover_flambda_deg1_to_degd_vole_ref(&vole_params, out_degree,  //
                                           in_out_f.data(), in_out_f.data());
      verifier_flambda_deg1_to_degd_vole_ref(&vole_params, out_degree,  //
                                             in_out_q.data(), in_out_q.data(), delta1.data());

      // copy the relevant coeffs to out
      for (uint64_t j = 0; j <= out_degree; j++) {
        out.set_f(0, j, flam_elem(lambda, in_out_f.row_ptr(j)));
      }
      out.set_q(0, flam_elem(lambda, in_out_q.row_ptr(0)));

      // check also the coeffs of f (paranoia mode)
      ASSERT_EQ(out.get_f(0, 0), in.get_f(0, 0));
      for (uint64_t j = 1; j < out_degree; j++) {
        ASSERT_EQ(out.get_f(0, j), in.get_f(j - 1, 1) + in.get_f(j, 0));
      }
      ASSERT_EQ(out.get_f(0, out_degree), in.get_f(out_degree - 1, 1));

      // consistency check
      out.assert_correct(delta1.data());
    }
  }
}

TEST(vole_conversions, consistency_f2_deg1_std_to_cst_vole_ref) {
  const uint64_t fake_kappa = 0;
  const uint64_t fake_tau = 0;
  for (const uint64_t lambda : {128, 192, 256}) {
    for (const uint64_t num_pairs : {11, 16}) {
      vole_parameters vole_params = {};
      vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);
      switch (lambda) {
        case 128:
          vole_params.flambda_sum = (FLAMBDA_SUM_F*)gf128_sum_ref;
          vole_params.flambda_product = (FLAMBDA_PRODUCT_F*)gf128_product_ref;
          break;
        case 192:
          vole_params.flambda_sum = (FLAMBDA_SUM_F*)gf192_sum_ref;
          vole_params.flambda_product = (FLAMBDA_PRODUCT_F*)gf192_product_ref;
          break;
        case 256:
          vole_params.flambda_sum = (FLAMBDA_SUM_F*)gf256_sum_ref;
          vole_params.flambda_product = (FLAMBDA_PRODUCT_F*)gf256_product_ref;
          break;
        default:
          REQUIRE_DRAMATICALLY(false, "lambda not supported" << lambda);
      }

      bit_vector delta1 = bit_vector::random(lambda);
      bit_vector delta2(lambda);
      vole_flambda_inv(lambda, delta2.data(), delta1.data());

      vole_std_f2_deg1_uvq in(lambda, num_pairs);
      vole_cst_f2_deg1_uvq out(lambda, num_pairs);
      in.randomize(delta1.data());

      prover_f2_std_to_cst_vole_ct_ref(&vole_params, num_pairs,  //
                                       out.u.data(), out.v.data(), in.u.data(), in.v.data());
      verifier_f2_std_to_cst_vole_ref(&vole_params, num_pairs,  //
                                      out.q.data(), in.q.data(), delta2.data());

      // consistency check
      out.assert_correct(delta2.data());

      // check also the coeffs of u,v (paranoia mode)
      ASSERT_EQ(out.u, in.u);
      ASSERT_EQ(out.v, in.v);
    }
  }
}

// convert a degree-d vole from std to cst

TEST(vole_conversions, consistency_flambda_degd_std_to_cst_vole_ct_ref) {
  const uint64_t fake_kappa = 0;
  const uint64_t fake_tau = 0;
  for (const uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, fake_tau, fake_kappa);

    for (const int64_t degree : {0, 1, 2, 4, 7}) {
      flam_elem delta1 = flam_elem::random_non_zero(lambda);
      flam_elem delta2 = inv(delta1);
      flam_elem delta2_pow_degree = pow(delta2, degree);

      vole_flambda_poly in(lambda, degree, 1);
      vole_flambda_poly out(lambda, degree, 1);

      in.randomize(delta1.data());
      vole_flambda_poly in_copy = in;

      // out of place
      prover_flambda_degd_std_to_cst_vole_ct_ref(  //
          &vole_params, degree, out.f.data(), in.f.data());
      verifier_flambda_degd_std_to_cst_vole_ref(  //
          &vole_params, degree, out.q.data(), in.q.data(), delta2_pow_degree.data());

      // check that the output is the mirror of the input
      for (int64_t i = 0; i <= degree; ++i) {
        ASSERT_EQ(out.get_f(0, i), in.get_f(0, degree - i));
      }
      // check the consistency
      out.assert_correct(delta2.data());

      // in place test
      prover_flambda_degd_std_to_cst_vole_ct_ref(  //
          &vole_params, degree, in.f.data(), in.f.data());
      verifier_flambda_degd_std_to_cst_vole_ref(  //
          &vole_params, degree, in.q.data(), in.q.data(), delta2_pow_degree.data());

      // check that the output is the mirror of the input
      for (int64_t i = 0; i <= degree; ++i) {
        ASSERT_EQ(in.get_f(0, i), in_copy.get_f(0, degree - i));
      }
      // check the consistency
      in.assert_correct(delta2.data());
    }
  }
}
