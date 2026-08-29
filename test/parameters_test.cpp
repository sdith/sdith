// Per-function tests for the "parameters" module:
//   - src/sdith_signature_parameters.c   (the 12 constant parameter sets)
//   - src/vole_parameters.c              (vole_parameters_init{,_ref})
//   - src/vole_parameters_avx2.c         (vole_parameters_init_avx, x86 only)
// plus the derived-parameter machinery that consumes them:
//   - compute_extended_parameters()      (src/sdith_signature.c)
//   - sdith_{public_key,secret_key,signature}_bytes()
//
// The expectations are parameter-set agnostic: every derived quantity is
// recomputed here from the primitive inputs of the set under test, and the rest
// are invariants that any valid set must satisfy. Re-tuning (kappa, tau,
// target_topen, proofow_w) must therefore not require touching this file.
//
// The only pinned numbers are the ones such a re-tuning must NOT move: the RSD
// code dimensions and the public/secret key sizes. Their ground truth is the
// Python oracle python/round3/params.py (params + tests/test_params.py).
//
// Conventions mirror test/gf192_test.cpp: gtest harness, testlib helpers, and
// x86-only (avx2) tests gated behind #ifdef __x86_64__.

#include <cstring>

#include "gtest/gtest.h"
#include "testlib/testlib.h"
#include "vole_private.h"

namespace {

struct param_set_t {
  const char* name;
  const signature_parameters* params;
};

// Every shipped parameter set, base and cipher-grinding variants alike.
const param_set_t all_sets[] = {
    {"cat1-short", &CAT1_SHORT_PARAMETERS},
    {"cat1-fast", &CAT1_FAST_PARAMETERS},
    {"cat3-short", &CAT3_SHORT_PARAMETERS},
    {"cat3-fast", &CAT3_FAST_PARAMETERS},
    {"cat5-short", &CAT5_SHORT_PARAMETERS},
    {"cat5-fast", &CAT5_FAST_PARAMETERS},
    {"cat1-short-cipherpow", &CAT1_SHORT_CIPHERPOW_PARAMETERS},
    {"cat1-fast-cipherpow", &CAT1_FAST_CIPHERPOW_PARAMETERS},
    {"cat3-short-cipherpow", &CAT3_SHORT_CIPHERPOW_PARAMETERS},
    {"cat3-fast-cipherpow", &CAT3_FAST_CIPHERPOW_PARAMETERS},
    {"cat5-short-cipherpow", &CAT5_SHORT_CIPHERPOW_PARAMETERS},
    {"cat5-fast-cipherpow", &CAT5_FAST_CIPHERPOW_PARAMETERS},
};

uint64_t ceil8(uint64_t x) { return (x + 7) & ~UINT64_C(7); }
uint64_t ceil_div(uint64_t x, uint64_t y) { return (x + y - 1) / y; }

// The RSD code is a function of (rsd_n, rsd_w) only: compute_rsd_codim uses a
// floating-point log2, so its result is pinned rather than recomputed here.
// Ground truth: the Python oracle.
struct rsd_kat_t {
  uint64_t rsd_n;
  uint64_t rsd_w;
  uint64_t rsd_codim;
};
const rsd_kat_t rsd_kats[] = {
    {10360, 56, 432},
    {18396, 73, 592},
    {19864, 104, 800},
};

const rsd_kat_t& rsd_kat_of(const signature_parameters& p) {
  for (const rsd_kat_t& r : rsd_kats) {
    if (r.rsd_n == p.rsd_n && r.rsd_w == p.rsd_w) return r;
  }
  ADD_FAILURE() << "no RSD known answer for (rsd_n=" << p.rsd_n << ", rsd_w=" << p.rsd_w << ")";
  return rsd_kats[0];
}

// Key sizes depend on (lambda, rsd_n, rsd_w, mux_arities) only, i.e. they are
// invariant under a re-tuning of kappa/tau/target_topen/proofow_w. Pinned to the
// published round-3 sizes.
struct key_sizes_t {
  uint64_t lambda;
  uint64_t pk_bytes;
  uint64_t sk_bytes;
};
const key_sizes_t published_key_sizes[] = {
    {128, 70, 147},
    {192, 98, 208},
    {256, 132, 275},
};

const key_sizes_t& key_sizes_of(const signature_parameters& p) {
  for (const key_sizes_t& s : published_key_sizes) {
    if (s.lambda == p.lambda) return s;
  }
  ADD_FAILURE() << "no published key sizes for lambda=" << p.lambda;
  return published_key_sizes[0];
}

// Assert the scalar fields and non-null dispatch pointers that BOTH
// vole_parameters_init_ref and vole_parameters_init_avx must set identically.
void check_vole_params_scalars_and_ptrs(const param_set_t& k, const vole_parameters& vp) {
  const signature_parameters& p = *k.params;
  ASSERT_EQ(vp.LAMBDA, p.lambda) << k.name;
  ASSERT_EQ(vp.TAU, p.tau) << k.name;
  ASSERT_EQ(vp.KAPPA, p.kappa) << k.name;
  ASSERT_EQ(vp.lambda_bytes, (p.lambda + 7) >> 3) << k.name;

  ASSERT_TRUE(vp.bitvec_xor != nullptr) << k.name;
  ASSERT_TRUE(vp.bitvec_xor_to != nullptr) << k.name;
  ASSERT_TRUE(vp.bitvec_cascade_xor_to != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_set != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_inverse != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_product != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_product_f2 != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_sum != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_sum_pow2 != nullptr) << k.name;
  ASSERT_TRUE(vp.flambda_echelon_pow2 != nullptr) << k.name;
  ASSERT_TRUE(vp.matrix_lambda_transpose != nullptr) << k.name;
  ASSERT_TRUE(vp.matrix_vector_product_f2 != nullptr) << k.name;
  ASSERT_TRUE(vp.matrix_f2_times_vector_flambda != nullptr) << k.name;
  // TODO this test is incomplete
}

}  // namespace

// ---------------------------------------------------------------------------
// 1. The constant parameter sets are structurally well-formed.
// ---------------------------------------------------------------------------
TEST(parameters, param_set_constants_are_well_formed) {
  for (const param_set_t& k : all_sets) {
    const signature_parameters& p = *k.params;
    EXPECT_TRUE(p.lambda == 128 || p.lambda == 192 || p.lambda == 256) << k.name;
    EXPECT_GE(p.kappa, 1u) << k.name;
    EXPECT_GE(p.tau, 1u) << k.name;
    EXPECT_GE(p.rsd_w, 1u) << k.name;
    EXPECT_EQ(p.rsd_n % p.rsd_w, 0u) << k.name << ": rsd_n must be an exact multiple of rsd_w";
    EXPECT_GE(p.mux_depth, 1u) << k.name;
    EXPECT_LE(p.mux_depth, 8u) << k.name;
    for (uint64_t a = 0; a < p.mux_depth; ++a) {
      EXPECT_GE(p.mux_arities[a], 2u) << k.name << " arity[" << a << "]";
    }
    for (uint64_t a = p.mux_depth; a < 8; ++a) {
      EXPECT_EQ(p.mux_arities[a], 0u) << k.name << " arity[" << a << "] past mux_depth";
    }
    EXPECT_TRUE(p.proofow_variant == PROOFOW_VARIANT_SHAKE || p.proofow_variant == PROOFOW_VARIANT_CIPHER)
        << k.name;
  }
}

// ---------------------------------------------------------------------------
// 2. Soundness budget of the challenge: the delta0 challenge carries kappa*tau
//    bits and the proof-of-work grinds proofow_w more, for a claimed soundness
//    of kappa*tau + proofow_w bits. The tuning rule targets lambda+2.
// ---------------------------------------------------------------------------
TEST(parameters, param_set_soundness_budget) {
  for (const param_set_t& k : all_sets) {
    const signature_parameters& p = *k.params;
    EXPECT_GE(p.kappa * p.tau + p.proofow_w, p.lambda + 2) << k.name;
    // delta1 is written up to bit tau*kappa-1 into a lambda-bit buffer
    EXPECT_LE(p.kappa * p.tau, p.lambda) << k.name;
    // the sibling path of tau hidden leaves is at most tau*kappa nodes long and
    // needs at least one node per tree
    EXPECT_GE(p.target_topen, p.tau) << k.name;
    EXPECT_LE(p.target_topen, p.tau * p.kappa) << k.name;
  }
}

// ---------------------------------------------------------------------------
// 3. compute_extended_parameters: every derived field, recomputed from the
//    primitive inputs of the set under test.
// ---------------------------------------------------------------------------
TEST(parameters, compute_extended_parameters_derived) {
  for (const param_set_t& k : all_sets) {
    const signature_parameters& p = *k.params;
    extended_parameters_t par{};
    compute_extended_parameters(&par, k.params);

    // passthrough copies of the primitive inputs
    EXPECT_EQ(par.lambda, p.lambda) << k.name;
    EXPECT_EQ(par.kappa, p.kappa) << k.name;
    EXPECT_EQ(par.tau, p.tau) << k.name;
    EXPECT_EQ(par.target_topen, p.target_topen) << k.name;
    EXPECT_EQ(par.rsd_n, p.rsd_n) << k.name;
    EXPECT_EQ(par.rsd_w, p.rsd_w) << k.name;
    EXPECT_EQ(par.mux_depth, p.mux_depth) << k.name;
    EXPECT_EQ(par.proofow_w, p.proofow_w) << k.name;
    for (int a = 0; a < 8; ++a) {
      EXPECT_EQ(par.mux_arities[a], p.mux_arities[a]) << k.name << " arity[" << a << "]";
    }

    // the RSD code (pinned, see rsd_kats)
    const rsd_kat_t& rsd = rsd_kat_of(p);
    EXPECT_EQ(par.rsd_codim, rsd.rsd_codim) << k.name;
    EXPECT_EQ(par.rsd_npw, p.rsd_n / p.rsd_w) << k.name;
    EXPECT_EQ(par.rsd_codim_bytes, ceil_div(par.rsd_codim, 8)) << k.name;
    EXPECT_EQ(par.rsd_codim_limbs, ceil_div(par.rsd_codim, p.lambda)) << k.name;
    // the slice must hold the limbs and be an exact number of prng blocks
    const uint64_t prng_blk_bytes = p.lambda == 128 ? 16 : 32;
    EXPECT_EQ(par.rsd_codim_slice, ceil_div(par.rsd_codim_bytes, prng_blk_bytes) * prng_blk_bytes) << k.name;
    EXPECT_GE(par.rsd_codim_slice, par.rsd_codim_limbs * (p.lambda >> 3)) << k.name;

    // the mux circuit
    uint64_t mux_inputs = 0;
    uint64_t chall_unitary_powers = 0;
    for (uint64_t a = 0; a < p.mux_depth; ++a) {
      mux_inputs += p.mux_arities[a] - 1;
      if (p.mux_arities[a] > 2) chall_unitary_powers += 32;
    }
    EXPECT_EQ(par.mux_inputs, mux_inputs) << k.name;
    EXPECT_EQ(par.chall_unitary_powers, chall_unitary_powers) << k.name;
    EXPECT_EQ(par.degree, p.mux_depth > 2 ? p.mux_depth : 2) << k.name;

    // the VOLE layout
    EXPECT_EQ(par.lambda_bytes, p.lambda >> 3) << k.name;
    EXPECT_EQ(par.num_inputs_pairs, mux_inputs * p.rsd_w) << k.name;
    EXPECT_EQ(par.num_cchk_pairs, p.lambda + 16) << k.name;
    EXPECT_EQ(par.num_cz_pairs, p.lambda * (par.degree - 1)) << k.name;
    EXPECT_EQ(par.real_L, par.num_inputs_pairs + par.num_cchk_pairs + par.num_cz_pairs) << k.name;
    EXPECT_EQ(par.L, ceil8(par.real_L)) << k.name;
    EXPECT_EQ(par.Lbyte, par.L >> 3) << k.name;
    EXPECT_EQ(par.Lslice, (par.Lbyte + 31) & ~UINT64_C(31)) << k.name;
    EXPECT_EQ(par.cchk_matrix_nrows, par.num_cchk_pairs) << k.name;
    EXPECT_EQ(par.cchk_matrix_ncols, par.L - par.num_cchk_pairs) << k.name;

    // the delta0 challenge buffer
    EXPECT_EQ(par.delta0_bits, p.kappa * p.tau + p.proofow_w) << k.name;
    EXPECT_EQ(par.delta0_dwords, ceil_div(par.delta0_bits, 64)) << k.name;
    EXPECT_EQ(par.delta0_bytess, ceil_div(par.delta0_bits, 8)) << k.name;
    EXPECT_EQ(par.delta0_capacity, par.delta0_dwords << 3) << k.name;
  }
}

// ---------------------------------------------------------------------------
// 4. compute_extended_parameters wires up the nested vole_parameters correctly.
// ---------------------------------------------------------------------------
TEST(parameters, compute_extended_parameters_nested_vole_params) {
  for (const param_set_t& k : all_sets) {
    extended_parameters_t par{};
    compute_extended_parameters(&par, k.params);
    check_vole_params_scalars_and_ptrs(k, par.vole_params);
  }
}

// ---------------------------------------------------------------------------
// 5. Structural invariants the signer/verifier silently rely on (mirror of
//    test_params.py::test_static_invariants_the_code_assumes / test_derived).
// ---------------------------------------------------------------------------
TEST(parameters, compute_extended_parameters_invariants) {
  for (const param_set_t& k : all_sets) {
    extended_parameters_t par{};
    compute_extended_parameters(&par, k.params);

    // byte alignment assumptions in the VOLE slicing/transpose
    EXPECT_EQ(par.L % 8u, 0u) << k.name;
    EXPECT_EQ(par.num_cchk_pairs % 8u, 0u) << k.name;
    EXPECT_EQ(par.num_cz_pairs % 8u, 0u) << k.name;
    EXPECT_EQ((par.L - par.num_cchk_pairs) % 8u, 0u) << k.name;

    // chall_unitary_powers must fit in a lambda-bit challenge (CREQUIRE in C)
    EXPECT_LE(par.chall_unitary_powers, par.lambda) << k.name;
  }
}

// ---------------------------------------------------------------------------
// 6. compute_extended_parameters is deterministic (identical bytes each call).
// ---------------------------------------------------------------------------
TEST(parameters, compute_extended_parameters_deterministic) {
  for (const param_set_t& k : all_sets) {
    extended_parameters_t a{};
    extended_parameters_t b{};
    compute_extended_parameters(&a, k.params);
    compute_extended_parameters(&b, k.params);
    EXPECT_EQ(memcmp(&a, &b, sizeof(extended_parameters_t)), 0) << k.name;
  }
}

// ---------------------------------------------------------------------------
// 7. Public / secret key sizes: the serialization formula, and the published
//    sizes (which a re-tuning of kappa/tau/topen/w must leave untouched).
// ---------------------------------------------------------------------------
TEST(parameters, sdith_public_key_bytes_kat) {
  for (const param_set_t& k : all_sets) {
    const signature_parameters& p = *k.params;
    const uint64_t rsd_codim_bytes = ceil_div(rsd_kat_of(p).rsd_codim, 8);
    // pk = seed_pk || y
    EXPECT_EQ(sdith_public_key_bytes(k.params), (p.lambda >> 3) + rsd_codim_bytes) << k.name;
    EXPECT_EQ(sdith_public_key_bytes(k.params), key_sizes_of(p).pk_bytes) << k.name;
  }
}

TEST(parameters, sdith_secret_key_bytes_kat) {
  for (const param_set_t& k : all_sets) {
    const signature_parameters& p = *k.params;
    const uint64_t rsd_codim_bytes = ceil_div(rsd_kat_of(p).rsd_codim, 8);
    uint64_t mux_inputs = 0;
    for (uint64_t a = 0; a < p.mux_depth; ++a) mux_inputs += p.mux_arities[a] - 1;
    // sk = seed_pk || y || wit (no seed_sk)
    EXPECT_EQ(sdith_secret_key_bytes(k.params),
              (p.lambda >> 3) + ceil_div(p.rsd_w * mux_inputs, 8) + rsd_codim_bytes)
        << k.name;
    EXPECT_EQ(sdith_secret_key_bytes(k.params), key_sizes_of(p).sk_bytes) << k.name;
  }
}

// ---------------------------------------------------------------------------
// 8. Signature size: the serialization formula. The value itself moves with
//    every re-tuning, so only the formula is pinned here.
// ---------------------------------------------------------------------------
TEST(parameters, sdith_signature_bytes_kat) {
  for (const param_set_t& k : all_sets) {
    const signature_parameters& p = *k.params;
    extended_parameters_t par{};
    compute_extended_parameters(&par, k.params);
    const uint64_t lambda_bytes = par.lambda_bytes;
    const uint64_t expect =                            //
        lambda_bytes                                   // global_salt
        + p.target_topen * lambda_bytes                // sibling path
        + p.tau * 2 * lambda_bytes                     // ggm_hidden_leaf_cmt
        + par.Lbyte * (p.tau - 1)                      // corr_u
        + (par.num_cchk_pairs >> 3)                    // cchk_u
        + ceil_div(par.num_inputs_pairs, 8)            // circuit_in_pub
        + (par.degree - 1) * lambda_bytes              // circuit_cz_pub (alpha_1 omitted)
        + 2 * lambda_bytes                             // hash_piop
        + PROOFOW_CTR_REVEALED_BYTES;                  // proofow_ctr_reveal
    EXPECT_EQ(sdith_signature_bytes(k.params), expect) << k.name;
  }
}

// ---------------------------------------------------------------------------
// 9. vole_parameters_init_ref: scalar fields + non-null dispatch pointers.
// ---------------------------------------------------------------------------
TEST(parameters, vole_parameters_init_ref_kat) {
  for (const param_set_t& k : all_sets) {
    vole_parameters vp;
    memset(&vp, 0, sizeof(vp));
    vole_parameters_init_ref(&vp, k.params->lambda, k.params->tau, k.params->kappa);
    check_vole_params_scalars_and_ptrs(k, vp);
  }
}

// ---------------------------------------------------------------------------
// 10. vole_parameters_init (runtime dispatch) sets the same scalar fields as the
//     reference path. Compares dispatch result vs the ref result (never self).
// ---------------------------------------------------------------------------
TEST(parameters, vole_parameters_init_dispatch_matches_ref) {
  for (const param_set_t& k : all_sets) {
    vole_parameters vp_init;
    vole_parameters vp_ref;
    memset(&vp_init, 0, sizeof(vp_init));
    memset(&vp_ref, 0, sizeof(vp_ref));
    vole_parameters_init(&vp_init, k.params->lambda, k.params->tau, k.params->kappa);
    vole_parameters_init_ref(&vp_ref, k.params->lambda, k.params->tau, k.params->kappa);

    // scalar fields must be identical whichever backend was dispatched
    ASSERT_EQ(vp_init.LAMBDA, vp_ref.LAMBDA) << k.name;
    ASSERT_EQ(vp_init.TAU, vp_ref.TAU) << k.name;
    ASSERT_EQ(vp_init.KAPPA, vp_ref.KAPPA) << k.name;
    ASSERT_EQ(vp_init.lambda_bytes, vp_ref.lambda_bytes) << k.name;
    // and match the parameter set independently
    check_vole_params_scalars_and_ptrs(k, vp_init);
  }
}

#ifdef __x86_64__
// ---------------------------------------------------------------------------
// 11. vole_parameters_init_avx (x86 only): scalar fields + non-null pointers,
//     and scalar fields equal to the reference path (res_avx vs res_ref).
// ---------------------------------------------------------------------------
TEST(parameters, vole_parameters_init_avx_kat) {
  for (const param_set_t& k : all_sets) {
    vole_parameters vp_avx;
    vole_parameters vp_ref;
    memset(&vp_avx, 0, sizeof(vp_avx));
    memset(&vp_ref, 0, sizeof(vp_ref));
    vole_parameters_init_avx(&vp_avx, k.params->lambda, k.params->tau, k.params->kappa);
    vole_parameters_init_ref(&vp_ref, k.params->lambda, k.params->tau, k.params->kappa);

    check_vole_params_scalars_and_ptrs(k, vp_avx);

    ASSERT_EQ(vp_avx.LAMBDA, vp_ref.LAMBDA) << k.name;
    ASSERT_EQ(vp_avx.TAU, vp_ref.TAU) << k.name;
    ASSERT_EQ(vp_avx.KAPPA, vp_ref.KAPPA) << k.name;
    ASSERT_EQ(vp_avx.lambda_bytes, vp_ref.lambda_bytes) << k.name;
  }
}
#endif  // __x86_64__
