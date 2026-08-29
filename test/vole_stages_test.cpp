#include <gtest/gtest.h>

#include <cstdint>

#include "sdith_vole_to_piop.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/testlib.h"
#include "testlib/vole_testlib.h"
#include "vole_generation.h"
#include "vole_private.h"

// Exhaustive per-function correctness tests for the round-3 "vole_stages"
// module (src/vole_expansion.c + src/vole_to_piop.c).
//
// Ground truth for expected inputs/outputs is the Python reference at
// sdith-py/round3 (vole.py + vole_to_piop.py). Each stage is isolated with a
// direct known-answer test where feasible, otherwise a deterministic property
// KAT (zero matrix, mirror, in-place, etc.).
//
// This file deliberately does NOT duplicate the coverage already provided by
// midsize_vole_test.cpp and vole_conversions_test.cpp; it fills the gaps:
//   - the consistency-check dimension helpers (never directly KAT'd),
//   - both_vole_consistency_check_matrix isolated (determinism/masking),
//   - prover/verifier consistency check isolated via a zero matrix,
//   - delta chain edge cases + grey-code KAT,
//   - the vole->piop conversions at the parameter sets / edges the exemplars
//     skip, and the in-place code paths.
//
// NOTE on coefficient order: the Python oracle (and the C reference) place the
// CONSTANT coefficient sum_pow2(v) at index 2i and the LINEAR coefficient u at
// index 2i+1 for prover_f2_to_flambda_deg1. The KATs below follow the oracle.
//
// The vole_stages module is reference-only: grep confirms there is NO *_avx2.c
// definition for any of its symbols, so there are no ref-vs-avx2 tests to gate
// behind #ifdef __x86_64__. All tests below are portable.

namespace {

struct pset {
  uint64_t lambda;
  uint64_t kappa;
  uint64_t tau;
};

// The six real SDitH round-3 parameter sets (see sdith_signature_parameters.c).
const pset PSETS[6] = {
    {128, 11, 11},  // CAT1_SHORT
    {192, 12, 16},  // CAT3_SHORT
    {256, 12, 21},  // CAT5_SHORT
    {128, 8, 16},   // CAT1_FAST
    {192, 8, 24},   // CAT3_FAST
    {256, 8, 32},   // CAT5_FAST
};

inline uint64_t grey_code(uint64_t p) { return p ^ (p >> 1); }

}  // namespace

// ---------------------------------------------------------------------------
// delta chain: delta1_from_delta0_ref
// ---------------------------------------------------------------------------

TEST(vole_stages, delta1_from_delta0_ref_grey_code_kat) {
  for (const pset& p : PSETS) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);

    bit_vector delta0(p.lambda);  // low tau*kappa bits carry the grey indices
    bit_vector delta1(p.lambda);
    const uint64_t mask = (UINT64_C(1) << p.kappa) - 1;

    for (uint64_t i = 0; i < p.tau; i++) {
      const uint64_t pos = (i * 37 + 5) & mask;
      xorto_kappabit_uint(p.kappa, i * p.kappa, delta0.data(), pos);
    }
    delta1_from_delta0_ref(&vp, delta1.data(), delta0.data());

    for (uint64_t i = 0; i < p.tau; i++) {
      const uint64_t pos = (i * 37 + 5) & mask;
      const uint64_t got = extract_kappabit_uint(p.kappa, i * p.kappa, delta1.data());
      ASSERT_EQ(got, grey_code(pos)) << "lambda=" << p.lambda << " block=" << i;
    }
    // Everything above tau*kappa must be zeroed by the ref implementation.
    for (uint64_t b = p.tau * p.kappa; b < p.lambda; b++) {
      ASSERT_FALSE(delta1.get(b)) << "unexpected high bit " << b;
    }
  }
}

TEST(vole_stages, delta1_from_delta0_ref_edge_zero_and_maxpos) {
  for (const pset& p : PSETS) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);

    bit_vector delta0(p.lambda);
    bit_vector delta1(p.lambda);
    // pre-dirty the output to make sure the function clears it
    for (uint64_t b = 0; b < p.lambda; b++) delta1.set(b, true);

    // delta0 == 0  ->  delta1 == 0  (grey(0) == 0)
    delta1_from_delta0_ref(&vp, delta1.data(), delta0.data());
    for (uint64_t b = 0; b < p.lambda; b++) ASSERT_FALSE(delta1.get(b)) << "bit " << b;

    // every block set to the maximum index 2^kappa-1
    const uint64_t maxpos = (UINT64_C(1) << p.kappa) - 1;
    for (uint64_t i = 0; i < p.tau; i++) {
      xorto_kappabit_uint(p.kappa, i * p.kappa, delta0.data(), maxpos);
    }
    delta1_from_delta0_ref(&vp, delta1.data(), delta0.data());
    for (uint64_t i = 0; i < p.tau; i++) {
      const uint64_t got = extract_kappabit_uint(p.kappa, i * p.kappa, delta1.data());
      ASSERT_EQ(got, grey_code(maxpos)) << "lambda=" << p.lambda << " block=" << i;
    }
  }
}

// ---------------------------------------------------------------------------
// delta chain: delta2_from_delta1_ref (field inverse)
// ---------------------------------------------------------------------------

TEST(vole_stages, delta2_from_delta1_ref_field_inverse) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, lambda, 0, 0);

    const flam_elem d1 = flam_elem::random_non_zero(lambda);
    flam_elem d2(lambda, false);
    delta2_from_delta1_ref(&vp, d2.data(), d1.data());

    ASSERT_EQ(d2, inv(d1));                           // matches testlib inverse
    ASSERT_EQ(d1 * d2, flam_elem::one(lambda));       // d1 * d1^-1 == 1

    // involution: inv(inv(x)) == x
    flam_elem d3(lambda, false);
    delta2_from_delta1_ref(&vp, d3.data(), d2.data());
    ASSERT_EQ(d3, d1);
  }
}

// ---------------------------------------------------------------------------
// consistency-check dimension helpers
// ---------------------------------------------------------------------------

TEST(vole_stages, vole_consistency_check_matrix_nrows_kat) {
  // round_up_8(kappa*tau + 16) for the six parameter sets.
  const uint64_t expect[6] = {144, 208, 272, 144, 208, 272};
  for (uint64_t s = 0; s < 6; s++) {
    const pset& p = PSETS[s];
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);

    const uint64_t nrows = vole_consistency_check_matrix_nrows(&vp);
    ASSERT_EQ(nrows, expect[s]) << "kappa=" << p.kappa << " tau=" << p.tau;
    ASSERT_EQ(nrows, ((p.kappa * p.tau + 16 + 7) / 8) * 8);
    ASSERT_EQ(nrows % 8, 0u);
  }
}

TEST(vole_stages, vole_consistency_check_matrix_ncols_kat) {
  for (const pset& p : PSETS) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);
    const uint64_t nrows = vole_consistency_check_matrix_nrows(&vp);

    for (uint64_t L : {nrows, nrows + 8, nrows + 1400}) {
      ASSERT_EQ(vole_consistency_check_matrix_ncols(&vp, L), L - nrows);
    }
    // edge: L == nrows  ->  ncols == 0
    ASSERT_EQ(vole_consistency_check_matrix_ncols(&vp, nrows), 0u);
  }
}

// ---------------------------------------------------------------------------
// both_vole_consistency_check_matrix : determinism, seed-sensitivity, masking
// ---------------------------------------------------------------------------

TEST(vole_stages, both_vole_consistency_check_matrix_determinism_and_mask) {
  for (const pset& p : PSETS) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);
    const uint64_t nrows = vole_consistency_check_matrix_nrows(&vp);
    // choose L so that ncols is NOT a multiple of 8 to exercise the masking
    const uint64_t L = nrows + 1403;  // ncols == 1403, 1403 % 8 == 3
    const uint64_t ncols = vole_consistency_check_matrix_ncols(&vp, L);
    const uint64_t colb = (ncols + 7) / 8;
    const uint64_t seed_bytes = 17;

    bit_vector seed = bit_vector::random(seed_bytes * 8);
    bit_matrix m1(nrows, ncols);
    bit_matrix m2(nrows, ncols);

    both_vole_consistency_check_matrix(&vp, L, m1.data(), seed.data(), seed_bytes);
    both_vole_consistency_check_matrix(&vp, L, m2.data(), seed.data(), seed_bytes);
    ASSERT_EQ(m1, m2) << "same seed must give same matrix, lambda=" << p.lambda;

    // trailing bits beyond ncols in the last column-byte must be masked to 0
    const uint8_t keep = (ncols & 7) ? (uint8_t)(0xFF >> (8 - (ncols & 7))) : (uint8_t)0xFF;
    for (uint64_t r = 0; r < nrows; r++) {
      const uint8_t lastb = ((const uint8_t*)m1.row_ptr(r))[colb - 1];
      ASSERT_EQ(lastb & ~keep, 0) << "unmasked trailing bits, row " << r;
    }

    // flipping the seed changes the matrix
    bit_vector seed2 = seed;
    seed2.set(0, !seed.get(0));
    both_vole_consistency_check_matrix(&vp, L, m2.data(), seed2.data(), seed_bytes);
    ASSERT_FALSE(m1 == m2) << "distinct seeds should give distinct matrices";
  }
}

// ---------------------------------------------------------------------------
// prover/verifier consistency check, isolated with a ZERO check matrix.
// With M == 0 the matrix products vanish, so the outputs reduce to the first
// nrows entries of the inputs (plus delta1 folding on the verifier side).
// ---------------------------------------------------------------------------

TEST(vole_stages, prover_vole_consistency_check_zero_matrix) {
  for (const pset& p : PSETS) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);
    const uint64_t nrows = vole_consistency_check_matrix_nrows(&vp);
    const uint64_t L = 1400;
    const uint64_t ncols = vole_consistency_check_matrix_ncols(&vp, L);

    bit_vector delta1 = bit_vector::random(p.lambda);
    vole_std_f2_deg1_uvq in(p.lambda, L);
    in.randomize(delta1.data());

    bit_matrix M = bit_matrix::zero(nrows, ncols);
    bit_vector chk_u(nrows);
    flam_vector chk_v(p.lambda, nrows);

    prover_vole_consistency_check(&vp, L, chk_u.data(), chk_v.data(), in.u.data(), in.v.data(), M.data());

    for (uint64_t i = 0; i < nrows; i++) {
      ASSERT_EQ(chk_u.get(i), in.get_u(i)) << "lambda=" << p.lambda << " i=" << i;
      ASSERT_EQ(chk_v.get(i), in.get_v(i)) << "lambda=" << p.lambda << " i=" << i;
    }
  }
}

TEST(vole_stages, verifier_vole_consistency_check_zero_matrix) {
  for (const pset& p : PSETS) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);
    const uint64_t nrows = vole_consistency_check_matrix_nrows(&vp);
    const uint64_t L = 1400;
    const uint64_t ncols = vole_consistency_check_matrix_ncols(&vp, L);

    bit_matrix M = bit_matrix::zero(nrows, ncols);
    flam_vector chk_v(p.lambda, nrows);
    bit_vector chk_u = bit_vector::random(nrows);
    bit_matrix q = bit_matrix::random(L, p.lambda);
    const flam_elem delta1 = flam_elem::random_non_zero(p.lambda);

    verifier_vole_consistency_check(&vp, L, chk_v.data(), chk_u.data(), q.data(), M.data(), delta1.data());

    for (uint64_t i = 0; i < nrows; i++) {
      const flam_elem qi(p.lambda, (const flambda_t*)q.row_ptr(i));
      const flam_elem expect = qi + (chk_u.get(i) * delta1);
      ASSERT_EQ(chk_v.get(i), expect) << "lambda=" << p.lambda << " i=" << i;
    }
  }
}

// ---------------------------------------------------------------------------
// vole -> piop : F2 -> Flambda degree-1 recombination
// (oracle layout: coeff[2i] = sum_pow2(v-block), coeff[2i+1] = u-block)
// ---------------------------------------------------------------------------

TEST(vole_stages, prover_f2_to_flambda_deg1_oracle_layout) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t num_pairs : {1, 7}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_vector in_u = bit_vector::random(lambda * num_pairs);
      bit_matrix in_v = bit_matrix::random(lambda * num_pairs, lambda);
      bit_matrix out_f(2 * num_pairs, lambda);
      out_f.randomize();  // catch "assumes zero" bugs

      prover_f2_to_flambda_deg1_std_vole_ct_ref(&vp, num_pairs, out_f.data(), in_u.data(), in_v.data());

      for (uint64_t i = 0; i < num_pairs; i++) {
        // constant coeff (row 2i) == sum_pow2 over the i-th lambda-block of v
        bit_vector expect(lambda);
        vp.flambda_sum_pow2(expect.data(), in_v.row_ptr(i * lambda));
        ASSERT_EQ(out_f.row(2 * i), expect) << "lambda=" << lambda << " pair=" << i;
        // linear coeff (row 2i+1) == the i-th lambda-block of u
        for (uint64_t j = 0; j < lambda; j++) {
          ASSERT_EQ(out_f.get(2 * i + 1, j), in_u.get(i * lambda + j))
              << "lambda=" << lambda << " pair=" << i << " bit=" << j;
        }
      }
    }
  }
}

TEST(vole_stages, verifier_f2_to_flambda_deg1_oracle_layout) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t num_pairs : {1, 7}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_matrix in_q = bit_matrix::random(lambda * num_pairs, lambda);
      bit_matrix out_q(num_pairs, lambda);
      out_q.randomize();

      verifier_f2_to_flambda_deg1_std_vole_ref(&vp, num_pairs, out_q.data(), in_q.data());

      for (uint64_t i = 0; i < num_pairs; i++) {
        bit_vector expect(lambda);
        vp.flambda_sum_pow2(expect.data(), in_q.row_ptr(i * lambda));
        ASSERT_EQ(out_q.row(i), expect) << "lambda=" << lambda << " pair=" << i;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// vole -> piop : degree-1 -> degree-d lift
// ---------------------------------------------------------------------------

TEST(vole_stages, prover_flambda_deg1_to_degd_coeff_kat) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t d : {1, 2, 5}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_matrix in_f = bit_matrix::random(2 * d, lambda);
      bit_matrix out_f(d + 1, lambda);
      out_f.randomize();

      prover_flambda_deg1_to_degd_vole_ref(&vp, d, out_f.data(), in_f.data());

      // out[0] = in[0]
      ASSERT_EQ(out_f.row(0), in_f.row(0)) << "lambda=" << lambda << " d=" << d;
      // out[i] = in[2i] + in[2i-1]   (1 <= i < d)
      for (uint64_t i = 1; i < d; i++) {
        bit_vector e(lambda);
        vole_flambda_xor(lambda, e.data(), (const flambda_t*)in_f.row_ptr(2 * i),
                         (const flambda_t*)in_f.row_ptr(2 * i - 1));
        ASSERT_EQ(out_f.row(i), e) << "lambda=" << lambda << " d=" << d << " i=" << i;
      }
      // out[d] = in[2d-1]
      ASSERT_EQ(out_f.row(d), in_f.row(2 * d - 1)) << "lambda=" << lambda << " d=" << d;

      // in-place variant (out aliases in) must yield the same coefficients
      bit_matrix io = in_f;
      prover_flambda_deg1_to_degd_vole_ref(&vp, d, io.data(), io.data());
      ASSERT_EQ(io.row(0), in_f.row(0));
      for (uint64_t i = 1; i < d; i++) {
        bit_vector e(lambda);
        vole_flambda_xor(lambda, e.data(), (const flambda_t*)in_f.row_ptr(2 * i),
                         (const flambda_t*)in_f.row_ptr(2 * i - 1));
        ASSERT_EQ(io.row(i), e) << "in-place lambda=" << lambda << " d=" << d << " i=" << i;
      }
      ASSERT_EQ(io.row(d), in_f.row(2 * d - 1));
    }
  }
}

TEST(vole_stages, verifier_flambda_deg1_to_degd_horner_kat) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, lambda, 0, 0);
    const flam_elem delta = flam_elem::random_non_zero(lambda);

    // out_degree == 1 : Horner loop is empty, out == in[0]
    {
      bit_matrix in_q = bit_matrix::random(1, lambda);
      bit_vector out_q(lambda);
      out_q.randomize();
      verifier_flambda_deg1_to_degd_vole_ref(&vp, 1, out_q.data(), in_q.data(), delta.data());
      ASSERT_EQ(out_q, in_q.row(0)) << "lambda=" << lambda;
    }

    // out_degree == 2 : out == in[1]*delta + in[0]
    {
      bit_matrix in_q = bit_matrix::random(2, lambda);
      bit_vector out_q(lambda);
      out_q.randomize();
      verifier_flambda_deg1_to_degd_vole_ref(&vp, 2, out_q.data(), in_q.data(), delta.data());
      const flam_elem q0(lambda, (const flambda_t*)in_q.row_ptr(0));
      const flam_elem q1(lambda, (const flambda_t*)in_q.row_ptr(1));
      const flam_elem got(lambda, out_q.data());
      ASSERT_EQ(got, q1 * delta + q0) << "lambda=" << lambda;
    }

    // out_degree == 3, in place, compared against a hand Horner evaluation
    {
      const uint64_t d = 3;
      bit_matrix in_q = bit_matrix::random(d, lambda);
      flam_elem acc(lambda, (const flambda_t*)in_q.row_ptr(d - 1));
      for (int64_t i = (int64_t)d - 2; i >= 0; i--) {
        acc = acc * delta + flam_elem(lambda, (const flambda_t*)in_q.row_ptr((uint64_t)i));
      }
      bit_matrix io = in_q;
      verifier_flambda_deg1_to_degd_vole_ref(&vp, d, io.data(), io.data(), delta.data());
      const flam_elem got(lambda, (const flambda_t*)io.row_ptr(0));
      ASSERT_EQ(got, acc) << "in-place lambda=" << lambda;
    }
  }
}

// ---------------------------------------------------------------------------
// vole -> piop : degree-d std -> cst
// ---------------------------------------------------------------------------

TEST(vole_stages, prover_flambda_degd_std_to_cst_mirror_kat) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t d : {0, 3}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_matrix in_f = bit_matrix::random(d + 1, lambda);
      bit_matrix out_f(d + 1, lambda);
      out_f.randomize();

      // out of place: out[i] = in[d-i]
      prover_flambda_degd_std_to_cst_vole_ct_ref(&vp, d, out_f.data(), in_f.data());
      for (uint64_t i = 0; i <= d; i++) {
        ASSERT_EQ(out_f.row(i), in_f.row(d - i)) << "lambda=" << lambda << " d=" << d << " i=" << i;
      }

      // in place: same mirror
      bit_matrix io = in_f;
      prover_flambda_degd_std_to_cst_vole_ct_ref(&vp, d, io.data(), io.data());
      for (uint64_t i = 0; i <= d; i++) {
        ASSERT_EQ(io.row(i), in_f.row(d - i)) << "in-place lambda=" << lambda << " d=" << d << " i=" << i;
      }
    }
  }
}

TEST(vole_stages, verifier_flambda_degd_std_to_cst_scale_kat) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t d : {0, 1, 4}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_vector in_q = bit_vector::random(lambda);
      const flam_elem delta_pow_d = flam_elem::random_non_zero(lambda);
      bit_vector out_q(lambda);
      out_q.randomize();

      // result is a single field product in_q * delta^d
      verifier_flambda_degd_std_to_cst_vole_ref(&vp, d, out_q.data(), in_q.data(), delta_pow_d.data());
      const flam_elem got(lambda, out_q.data());
      const flam_elem inq(lambda, in_q.data());
      ASSERT_EQ(got, inq * delta_pow_d) << "lambda=" << lambda << " d=" << d;
    }
  }
}

// ---------------------------------------------------------------------------
// vole -> piop : packed F2 std -> cst
// ---------------------------------------------------------------------------

TEST(vole_stages, prover_f2_std_to_cst_identity_and_inplace) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t num_pairs : {1, 37}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_vector in_u = bit_vector::random(num_pairs);
      bit_matrix in_v = bit_matrix::random(num_pairs, lambda);
      bit_vector out_u(num_pairs);
      bit_matrix out_v(num_pairs, lambda);
      out_v.randomize();

      // out of place: prover side is a plain copy
      prover_f2_std_to_cst_vole_ct_ref(&vp, num_pairs, out_u.data(), out_v.data(), in_u.data(), in_v.data());
      ASSERT_EQ(out_u, in_u) << "lambda=" << lambda << " num_pairs=" << num_pairs;
      ASSERT_EQ(out_v, in_v) << "lambda=" << lambda << " num_pairs=" << num_pairs;

      // in place (same pointers): early-return, data untouched
      bit_vector iu = in_u;
      bit_matrix iv = in_v;
      prover_f2_std_to_cst_vole_ct_ref(&vp, num_pairs, iu.data(), iv.data(), iu.data(), iv.data());
      ASSERT_EQ(iu, in_u);
      ASSERT_EQ(iv, in_v);
    }
  }
}

TEST(vole_stages, verifier_f2_std_to_cst_scale_kat) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t num_pairs : {1, 5}) {
      vole_parameters vp = {};
      vole_parameters_init_ref(&vp, lambda, 0, 0);

      bit_matrix in_q = bit_matrix::random(num_pairs, lambda);
      const flam_elem delta2 = flam_elem::random_non_zero(lambda);
      bit_matrix out_q(num_pairs, lambda);
      out_q.randomize();

      verifier_f2_std_to_cst_vole_ref(&vp, num_pairs, out_q.data(), in_q.data(), delta2.data());

      for (uint64_t i = 0; i < num_pairs; i++) {
        const flam_elem got(lambda, (const flambda_t*)out_q.row_ptr(i));
        const flam_elem inq(lambda, (const flambda_t*)in_q.row_ptr(i));
        ASSERT_EQ(got, inq * delta2) << "lambda=" << lambda << " i=" << i;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// midsize -> fullsize transposition, at the FAST parameter sets (kappa=8).
// vole_conversions_test.cpp already covers the SHORT sets (kappa 11/12); this
// complements it so all six parameter sets are exercised.
// ---------------------------------------------------------------------------

TEST(vole_stages, midsize_to_fullsize_std_vole_fast_params) {
  const pset FP[3] = {{128, 8, 16}, {192, 8, 24}, {256, 8, 32}};
  for (const pset& p : FP) {
    vole_parameters vp = {};
    vole_parameters_init_ref(&vp, p.lambda, p.tau, p.kappa);
    const uint64_t L = 1400;
    const uint64_t Lbytes = (L + 7) / 8;
    const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);

    bit_matrix in_u = bit_matrix::random(p.tau, Lslice * 8);
    bit_matrix in_v = bit_matrix::random(p.lambda, Lslice * 8);
    bit_vector out_u(L);
    bit_matrix out_corr(p.tau - 1, Lslice * 8);
    bit_matrix out_v(L, p.lambda);

    prover_midsize_to_fullsize_std_vole_ct_ref(&vp, L, out_u.data(), out_corr.data(), out_v.data(), in_u.data(),
                                               in_v.data());

    // out_u == in_u[0]
    for (uint64_t j = 0; j < L; j++) {
      ASSERT_EQ(out_u.get(j), in_u.get(0, j)) << "lambda=" << p.lambda;
    }
    // out_corr[i-1] == in_u[i] ^ in_u[0]  (all tau-1 correction rows)
    for (uint64_t i = 1; i < p.tau; i++) {
      for (uint64_t j = 0; j < L; j++) {
        ASSERT_EQ(out_corr.get(i - 1, j), in_u.get(i, j) ^ in_u.get(0, j)) << "lambda=" << p.lambda << " i=" << i;
      }
    }
    // out_v == transpose(in_v)
    for (uint64_t i = 0; i < p.lambda; i++) {
      for (uint64_t j = 0; j < L; j++) {
        ASSERT_EQ(out_v.get(j, i), in_v.get(i, j));
      }
    }

    bit_matrix in_q = bit_matrix::random(p.lambda, Lslice * 8);
    bit_matrix out_q(L, p.lambda);
    verifier_midsize_to_fullsize_std_vole_ref(&vp, L, out_q.data(), in_q.data());
    for (uint64_t i = 0; i < p.lambda; i++) {
      for (uint64_t j = 0; j < L; j++) {
        ASSERT_EQ(out_q.get(j, i), in_q.get(i, j));
      }
    }
  }
}
