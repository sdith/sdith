#include <gtest/gtest.h>

#include "ggm.h"
#include "sdith_prng.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/testlib.h"
#include "testlib/vole_testlib.h"
#include "vole_generation.h"

TEST(midsize_vole_test, delta1_from_delta0_ref) {
  for (uint64_t lambda : {128, 192, 256}) {
    for (uint64_t kappa : {8, 9, 10, 11, 12}) {
      for (uint64_t tau : {10, 11, 12, 20, 21, 22, 30, 31, 32}) {
        if (tau * kappa > lambda) continue;
        vole_parameters vole_params;
        vole_parameters_init_ref(&vole_params, lambda, tau, kappa);
        bit_vector delta0 = bit_vector::random(lambda);
        bit_vector expect_delta1 = delta1_from_delta0(kappa, tau, lambda, delta0);
        bit_vector delta1(lambda);
        delta1_from_delta0_ref(&vole_params, delta1.data(), delta0.data());
        ASSERT_EQ(delta1, expect_delta1);
      }
    }
  }
}

TEST(midsize_vole_test, delta2_from_delta1_ref) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params;
    vole_parameters_init_ref(&vole_params, lambda, 0, 0);
    flam_elem delta1 = flam_elem::random_non_zero(lambda);
    flam_elem expect_delta2 = inv(delta1);
    flam_elem delta2(lambda, false);
    delta2_from_delta1_ref(&vole_params, delta2.data(), delta1.data());
    ASSERT_EQ(delta2, expect_delta2);
  }
}


/* TODO: these tests will need to be reactivated (in another PR) */
struct prover_midsize_vole {
  bit_matrix u;
  bit_matrix v;
  bit_vector prover_hash;
};

prover_midsize_vole generate_prover_midsize_vole( //
  const vole_parameters* vole_params, //
  const uint64_t L, //
  const salt_t* global_salt, //
  const seed_t* ggm_root //
  ) {
  const uint64_t kappa = vole_params->KAPPA;
  const uint64_t lambda = vole_params->LAMBDA;
  const uint64_t tau = vole_params->TAU;
  const uint64_t Lbytes = L / 8;
  const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  prover_midsize_vole res;
  res.u = bit_matrix(tau, Lslice * 8);
  res.v = bit_matrix(tau * kappa, Lslice * 8);
  res.prover_hash = bit_vector(2 * lambda);
  std::vector<uint8_t> tmp( //
    prover_generate_midsize_grey_vole_from_seeds_bfs_ct_tmp_bytes( //
      vole_params, L));
  prover_generate_midsize_grey_vole_from_seeds_bfs_ct_ref( //
  vole_params, L, res.prover_hash.data(), //
  res.u.data(), res.v.data(), //
  global_salt,ggm_root, tmp.data()
    );
  return res;
}

struct prover_opening {
  uint64_t topen;
  std::vector<uint32_t> hidden_leaves_idx;
  bit_vector sibling_seeds;
  bit_vector hidden_leaves_commits;
  bit_vector delta1;
};

prover_opening generate_prover_opening( //
  const vole_parameters* vole_params, //
  const bit_vector& delta0, // tau x kappa bits
  const salt_t* global_salt, //
  const seed_t* ggm_root //
  ) {
  const uint64_t kappa = vole_params->KAPPA;
  const uint64_t lambda = vole_params->LAMBDA;
  const uint64_t tau = vole_params->TAU;
  const uint64_t max_topen = tau * kappa;
  prover_opening res;
  res.hidden_leaves_idx.resize(tau);
  hidden_leaves_indexes2(kappa, tau, res.hidden_leaves_idx.data(), delta0.data());
  uint64_t topen = max_topen;
  {
    std::vector<uint8_t> tmp(estimate_topen_tmp_bytes(tau, kappa));
    topen = estimate_topen(tau, kappa, max_topen, //
      res.hidden_leaves_idx.data(), //
      tmp.data());
  }
  REQUIRE_DRAMATICALLY(topen <= max_topen, "Bug! Impossible!!");
  std::cout << "Topen:" << topen << "/" << max_topen << std::endl;
  res.topen = topen;
  res.sibling_seeds = bit_vector(topen * lambda);
  res.hidden_leaves_commits = bit_vector(tau * 2 * lambda);
  {
    std::vector<uint8_t> tmp( //
      full_ggm_tree_open_sibling_path_from_root_tmp_bytes(vole_params, topen));
    full_ggm_tree_open_sibling_path_from_root(
      vole_params, res.sibling_seeds.data(), res.hidden_leaves_commits.data(), //
      ggm_root, global_salt, //
      res.hidden_leaves_idx.data(), topen, //
      tmp.data() //
      );
  }
  res.delta1 = delta1_from_delta0(kappa, tau, lambda, delta0);
  return res;
}

struct verifier_midsize_vole {
  bit_matrix q;
  bit_matrix corr_terms;
  bit_vector verifier_hash;
};

verifier_midsize_vole verifier_open_midsize_vole(
  const vole_parameters* vole_params,
  const uint64_t L,
  const prover_opening& opn,
  const salt_t* global_salt,
  const bit_matrix& in_corr_terms
  ) {
  const uint64_t kappa = vole_params->KAPPA;
  const uint64_t lambda = vole_params->LAMBDA;
  const uint64_t tau = vole_params->TAU;
  const uint64_t Lbytes = L / 8;
  const uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
  const uint64_t topen = opn.topen;
  verifier_midsize_vole res;
  res.verifier_hash = bit_vector(2 * lambda);
  res.corr_terms = in_corr_terms;
  res.q = bit_matrix(tau * kappa, Lslice * 8);

  {
    std::vector<uint8_t> tmp( //
      verifier_open_midsize_grey_vole_from_seeds_bfs_tmp_bytes( //
        vole_params, L, topen));
    verifier_open_midsize_grey_vole_from_seeds_bfs_ref(              //
        vole_params, L, res.verifier_hash.data(),       //
        res.q.data(), res.corr_terms.data(),
        opn.hidden_leaves_idx.data(),
        opn.hidden_leaves_commits.data(),
        opn.sibling_seeds.data(), topen, //
        global_salt, opn.delta1.data(), //
        tmp.data());
  }
  return res;
}

TEST(midsize_vole_test, midsize_vole_correctness) {
  for (const uint64_t lambda : {128, 192, 256}) {
    const uint64_t kappa = 10;
    const uint64_t tau = lambda / kappa;

    bit_vector delta0 = bit_vector::random(tau * kappa);
    bit_vector global_salt = bit_vector::random(lambda);
    bit_vector ggm_root = bit_vector::random(lambda);

    // execute the opening
    uint64_t L = 1000;
    uint64_t Lbytes = L / 8;
    uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, tau, kappa);
    // compute delta1 from delta0
    bit_matrix corr_terms = bit_matrix::random(tau, Lslice * 8);

    // execute the prover's side
    prover_midsize_vole prv = generate_prover_midsize_vole(
      &vole_params, L, global_salt.data(), ggm_root.data());

    // make an opening
    prover_opening opn = generate_prover_opening(
      &vole_params, delta0, global_salt.data(), ggm_root.data());

    // execute the verifier's side
    verifier_midsize_vole ver = verifier_open_midsize_vole(
      &vole_params, L, opn, global_salt.data(), corr_terms);

    // check that the commits hash is the same for prover and verifier
    ASSERT_EQ(prv.prover_hash, ver.verifier_hash);

    // verify that the vole pairs are correct
    for (uint64_t i = 0; i < tau; i++) {
      // recompute the corrected u
      bit_vector corrected_u = prv.u.row(i) ^ corr_terms.row(i);
      // check the correctness of the vole pair
      for (uint64_t k = 0; k < kappa; ++k) {
        if (opn.delta1.get(i * kappa + k)) {
          ASSERT_EQ(prv.v.row(i * kappa + k) ^ corrected_u, ver.q.row(i * kappa + k));
        } else {
          ASSERT_EQ(prv.v.row(i * kappa + k), ver.q.row(i * kappa + k));
        }
      }
    }
  }
}

TEST(midsize_vole_test, midsize_to_full_size_vole_correctness) {
  for (const uint64_t lambda : {128, 192, 256}) {
    const uint64_t kappa = 10;
    const uint64_t tau = lambda / kappa;

    bit_vector delta0 = bit_vector::random(tau * kappa);

    bit_vector global_salt = bit_vector::random(lambda);
    bit_vector ggm_root = bit_vector::random(lambda);

    // execute the opening
    uint64_t L = 1000;
    uint64_t Lbytes = L / 8;
    uint64_t Lslice = (Lbytes + 31) & UINT64_C(-32);
    vole_parameters vole_params = {};
    vole_parameters_init_ref(&vole_params, lambda, tau, kappa);
    vole_std_f2_deg1_uvq vole(lambda, L);

    // execute the prover's side
    prover_midsize_vole prv = generate_prover_midsize_vole(
      &vole_params, L, global_salt.data(), ggm_root.data());

    bit_matrix corr_terms(tau, Lslice * 8);
    bit_matrix u = prv.u;
    bit_matrix v = bit_matrix::zero(lambda, Lslice * 8);
    for (uint64_t i = 0; i < tau * kappa; i++) {
      memcpy(v.row_ptr(i), prv.v.row_ptr(i), Lslice);
    }

    prover_midsize_to_fullsize_std_vole_ct_ref(               //
    &vole_params, L,                                      //
    vole.u.data(), corr_terms.row_ptr(1), vole.v.data(),  //
    prv.u.data(), v.data());
    memset(corr_terms.row_ptr(0), 0, Lslice);

    // make an opening
    prover_opening opn = generate_prover_opening(
      &vole_params, delta0, global_salt.data(), ggm_root.data());

    // execute the verifier's side
    verifier_midsize_vole ver = verifier_open_midsize_vole(
      &vole_params, L, opn, global_salt.data(), corr_terms);

    // check that the commits hash is the same for prover and verifier
    ASSERT_EQ(prv.prover_hash, ver.verifier_hash);

    bit_matrix q = bit_matrix::zero(lambda, Lslice * 8);
    for (uint64_t i = 0; i < tau * kappa; i++) {
      memcpy(q.row_ptr(i), ver.q.row_ptr(i), Lslice);
    }

    verifier_midsize_to_fullsize_std_vole_ref(  //
        &vole_params, L,                        //
        vole.q.data(), q.data());

    // verify that the vole pairs are correct
    vole.assert_correct(opn.delta1.data());
  }
}
