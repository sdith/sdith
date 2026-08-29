#include <inttypes.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "cpucycles.h"
#include "ggm.h"
#include "random"
#include "sdith_prng.h"
#include "sdith_rsd.h"
#include "sdith_vole_to_piop.h"
#include "testlib/testlib.h"
#include "testlib/vole_testlib.h"
#include "vole_generation.h"
#include "vole_private.h"

#define PARANOIA_CHECK

double get_time() {
  std::chrono::high_resolution_clock::time_point t = std::chrono::high_resolution_clock::now();
  return t.time_since_epoch().count() / 1e9;
}

// return somthing = alignment mod 2 * alignment (I am very paraoid)
void* my_test_aligned_alloc(uint64_t alignment, uint64_t size) {
  REQUIRE_DRAMATICALLY((alignment & (alignment - 1)) == 0, "Alignment must be a power of two");
  uint8_t* r = (uint8_t*)malloc(size + 2 * alignment + 1);
  REQUIRE_DRAMATICALLY(r, "OOM?");
  uint64_t addr = (uint64_t)r + 1;
  addr = (addr + alignment - 1) & (-alignment);
  if ((addr & (2 * alignment - 1)) == 0) addr += alignment;
  uint8_t* r2 = (uint8_t*)addr;
  r2[-1] = r2 - r;
  return r2;
}
void my_test_aligned_free(void* ptr) {
  if (!ptr) return;
  uint8_t* r2 = (uint8_t*)ptr;
  uint8_t* r = r2 - uint64_t(r2[-1]);
  free(r);
}
// non-copyable structure that just calls my_test_aligned_free in the end
struct my_unique_ptr {
  void* ptr;
  my_unique_ptr() : ptr(nullptr) {}
  explicit my_unique_ptr(void* ptr) : ptr(ptr) {}
  explicit my_unique_ptr(const void* ptr) : ptr((void*)ptr) {}
  ~my_unique_ptr() { my_test_aligned_free(ptr); }
  my_unique_ptr(const my_unique_ptr&) = delete;
  void operator=(const my_unique_ptr&) = delete;
};

#define DECLARE_SIGNATURE_VAR(ptr_type, varname, byte_size) \
  total_signature_bytes += (byte_size);                     \
  ptr_type const varname = (ptr_type)sign_fields;           \
  sign_fields += (byte_size)

#define DECLARE_LOCAL_ALIGNED_VAR(alignment, ptr_type, varname, byte_size)      \
  my_unique_ptr varname##_vec(my_test_aligned_alloc((alignment), (byte_size))); \
  ptr_type const varname = (ptr_type)varname##_vec.ptr

#define DECLARE_LOCAL_VAR(ptr_type, varname, byte_size)              \
  my_unique_ptr varname##_vec(my_test_aligned_alloc(32, byte_size)); \
  ptr_type const varname = (ptr_type)varname##_vec.ptr

#define DECLARE_SKEY_VAR(ptr_type, varname, byte_size)              \
  my_unique_ptr varname##_vec(my_test_aligned_alloc(1, byte_size)); \
  ptr_type const varname = (ptr_type)varname##_vec.ptr

#define DECLARE_PKEY_VAR(ptr_type, varname, byte_size)              \
  my_unique_ptr varname##_vec(my_test_aligned_alloc(1, byte_size)); \
  ptr_type const varname = (ptr_type)varname##_vec.ptr

// override sig_params.<field> when argument is exactly "<field>=<value>"
static bool apply_override(signature_parameters& p, const char* arg) {
  static const struct { const char* name; uint64_t signature_parameters::*field; } OVERRIDABLE[] = {
      {"kappa", &signature_parameters::kappa},
      {"tau", &signature_parameters::tau},
      {"proofow_w", &signature_parameters::proofow_w},
      {"target_topen", &signature_parameters::target_topen},
  };
  const char* eq = strchr(arg, '=');
  if (!eq) return false;
  const std::string name(arg, eq - arg);
  for (const auto& o : OVERRIDABLE) {
    if (name != o.name) continue;
    p.*(o.field) = strtoull(eq + 1, nullptr, 10);
    return true;
  }
  REQUIRE_DRAMATICALLY(false, "unknown parameter override: " << name);
  return false;
}

int main(int argc, char** argv) {
  signature_parameters sig_params = {};
#if defined(TARGET_CATEGORY)
#define CONCAT(A, B) A ## B
#define PARAM_STRUCT_NAME(CATG)  CONCAT(CATG, _PARAMETERS)
  sig_params = PARAM_STRUCT_NAME(TARGET_CATEGORY);
#else
#error NO parameter defined
#endif
  // "<field>=<value>" args patch the compiled-in parameter set; any other arg asks for the histogram
  bool do_histogram = false;
  for (int i = 1; i < argc; ++i) {
    if (!apply_override(sig_params, argv[i])) do_histogram = true;
  }
  extended_parameters_t par;
  compute_extended_parameters(&par, &sig_params);
  std::cout << "params...................: lambda=" << par.lambda << std::endl;
  std::cout << "ggm......................: tau=" << par.tau << ",kappa=" << par.kappa << std::endl;
  std::cout << "proof-of-work:...........: topen=" << par.target_topen << ",proofow_w=" << par.proofow_w << std::endl;
  std::cout << "rsd......................: n=" << par.rsd_n << ",w=" << par.rsd_w << ",codim=" << par.rsd_codim
            << std::endl;
  std::cout << "muxes....................: [";
  {
    for (uint64_t i = 0; i < par.mux_depth; ++i) {
      if (i > 0) std::cout << ",";
      std::cout << par.mux_arities[i];
    }
  }
  std::cout << "]" << std::endl;
  const uint64_t sign_bytes = sdith_signature_bytes(&sig_params);
  const uint64_t skey_bytes = sdith_secret_key_bytes(&sig_params);
  const uint64_t pkey_bytes = sdith_public_key_bytes(&sig_params);
  const uint64_t LBytes = (par.L + 7) >> 3;
  std::cout << "sign_bytes ..............: " << sign_bytes << std::endl;
  std::cout << "pkey_bytes ..............: " << pkey_bytes << std::endl;
  std::cout << "skey_bytes ..............: " << skey_bytes << std::endl;

  std::cout << std::endl;
  std::cout << "L........................: " << par.L << std::endl;
  std::cout << "LBytes...................: " << LBytes << " bin.valuation: " << ((LBytes ^ (LBytes - 1)) + 1) / 2
            << std::endl;
  std::cout << "log2(rsd_density)........: " << par.rsd_w * log2(par.rsd_npw) - par.rsd_codim << std::endl;
  std::cout << "rsd_codim_limbs..........: " << par.rsd_codim_limbs << std::endl;
  std::cout << "keygen tmp_space.........: " << sdith_keygen_tmp_bytes(&sig_params) << std::endl;
  std::cout << "signature tmp_space......: " << sdith_signature_tmp_bytes(&sig_params) << std::endl;
  std::cout << "verify tmp_space.........: " << sdith_verify_tmp_bytes(&sig_params) << std::endl;

  // secret key
  uint64_t skey_encoded_solution_bytes = (par.rsd_w * par.mux_inputs + 7) >> 3;
  DECLARE_LOCAL_ALIGNED_VAR(4, uint32_t*, skey_solution, par.rsd_w * sizeof(uint32_t));
  DECLARE_SKEY_VAR(uint8_t*, skey_encoded_solution, skey_encoded_solution_bytes);  // unary encoded

  // public key
  DECLARE_PKEY_VAR(uint8_t*, pkey_seed, par.lambda_bytes);
  DECLARE_PKEY_VAR(uint8_t*, skey_seed, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, pkey_y, par.rsd_codim_limbs* par.lambda_bytes);
  // Note: the real signature will use a real source of entropy here
  randomize(pkey_seed, par.lambda_bytes);
  randomize(skey_seed, par.lambda_bytes);

  std::vector<uint8_t> rsd_gen_tmp_space(
      rsd_generate_random_instance_tmp_bytes(&par.vole_params, par.rsd_w, par.rsd_n, par.rsd_codim));
  rsd_generate_random_instance_ref(par.rsd_w, par.rsd_n, par.rsd_codim,                  //
                                   &par.vole_params,                                     //
                                   pkey_y, par.rsd_codim_limbs * par.lambda_bytes,       //
                                   skey_solution,                                        //
                                   skey_seed, pkey_seed,                                 //
                                   rsd_gen_tmp_space.data());                            //
  rsd_encode_solution_ref(                                                                        //
      par.rsd_w, par.rsd_n, par.rsd_codim,                                                        //
      &par.vole_params,                                                                           //
      par.mux_depth, par.mux_arities,                                                             //
      skey_encoded_solution, skey_encoded_solution_bytes,                                         //
      skey_solution);

  uint8_t keygen_entropy[32 * 2];
  memcpy(keygen_entropy, pkey_seed, par.lambda_bytes);
  memcpy(keygen_entropy + par.lambda_bytes, skey_seed, par.lambda_bytes);
  std::vector<uint8_t> secret_key_vec(skey_bytes);
  std::vector<uint8_t> public_key_vec(pkey_bytes);
  std::vector<uint8_t> keygen_tmp_space(sdith_keygen_tmp_bytes(&sig_params));
  double keygen_stime = get_time();
  sdith_keygen(&sig_params, secret_key_vec.data(), public_key_vec.data(), keygen_entropy, keygen_tmp_space.data());
  double keygen_etime = get_time();

  const char message[] = "Hello World!";
  const uint64_t message_bytes = strlen(message);

  // signature fields
  uint64_t total_signature_bytes = 0;
  std::vector<uint8_t> test_signature_layout(sign_bytes + 1);
  uint8_t* const test_signature = test_signature_layout.data() + 1;  // make sure nothing is aligned
  uint8_t* sign_fields = test_signature;
  DECLARE_SIGNATURE_VAR(uint8_t*, global_salt, par.lambda_bytes);
  DECLARE_SIGNATURE_VAR(uint8_t*, ggm_sibling_path, par.target_topen* par.lambda_bytes);
  DECLARE_SIGNATURE_VAR(uint8_t*, ggm_hidden_leaf_cmt, par.tau * 2 * par.lambda_bytes);
  DECLARE_SIGNATURE_VAR(uint8_t*, corr_u, par.Lbyte*(par.tau - 1));
  DECLARE_SIGNATURE_VAR(uint8_t*, cchk_u, par.num_cchk_pairs >> 3);
  DECLARE_SIGNATURE_VAR(uint8_t*, circuit_in_pub, (par.num_inputs_pairs + 7) >> 3);
  DECLARE_SIGNATURE_VAR(uint8_t*, circuit_cz_pub, (par.degree - 1) * par.lambda_bytes);
  DECLARE_SIGNATURE_VAR(uint8_t*, hash_piop, 2 * par.lambda_bytes);  // (round5) round3 + check_zero + message :=> delta
  DECLARE_SIGNATURE_VAR(uint8_t*, proofow_ctr_reveal, PROOFOW_CTR_REVEALED_BYTES);
  REQUIRE_DRAMATICALLY(total_signature_bytes == sign_bytes, "sign size bug!");

  // local variables
  DECLARE_LOCAL_VAR(hash_t*, hash_com, 2 * par.lambda_bytes);  // commitment of the ggm tree
  DECLARE_LOCAL_VAR(hash_t*, hash_aux, 2 * par.lambda_bytes);  // (round1) ggm_cmt_hash + corr_terms :=> cchk matrix
  DECLARE_LOCAL_VAR(hash_t*, hash_lines,
                    2 * par.lambda_bytes);  // (round3) hash_aux + cchk_u + cchk_v + inputs_mask :=> chall
  DECLARE_LOCAL_VAR(seed_t*, root_seed, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, u, par.Lslice* par.tau);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, v, par.Lslice* par.lambda);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, v2, par.Lslice* par.lambda);  // copy needed during transposition
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, rvp_f_cz, par.lambda_bytes* par.degree * 2);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, res_f, par.lambda_bytes*(par.degree + 1));
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, mux_f, par.lambda_bytes*(par.degree + 1));
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, inputs_f, par.lambda_bytes * 2 * par.num_inputs_pairs);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, chall_unitary, par.lambda_bytes* par.rsd_w);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, chall_a, par.lambda_bytes* par.rsd_codim_limbs* par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, chall_a_H, par.lambda_bytes* par.rsd_n);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, chall_a_y, par.lambda_bytes);
  DECLARE_LOCAL_VAR(uint8_t*, cchk_matrix, par.cchk_matrix_nrows* par.cchk_matrix_ncols >> 3);
  DECLARE_LOCAL_VAR(uint8_t*, cchk_res_v, par.lambda_bytes* par.cchk_matrix_nrows);

  DECLARE_LOCAL_VAR(uint8_t*, delta0, par.delta0_capacity);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, delta1, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(4, uint32_t*, hidden_leaves_idx, par.tau * sizeof(uint32_t));
  DECLARE_LOCAL_VAR( //
    uint8_t*, midsize_vole_tmp_space, //
    prover_generate_midsize_grey_vole_from_seeds_bfs_ct_tmp_bytes(&par.vole_params, par.L)
    );
  DECLARE_LOCAL_VAR(uint8_t*, tmp_space, //
      prover_cst_mux_circuit_ct_ref_tmp_bytes(&par.vole_params, par.mux_depth, par.mux_arities, par.rsd_npw));
  DECLARE_LOCAL_VAR(uint8_t*, pk_times_chall_tmp_space, //
      rsd_public_key_times_challenge_tmp_bytes(&par.vole_params, par.rsd_w, par.rsd_n, par.rsd_codim));
  DECLARE_LOCAL_VAR(uint8_t*, topen_tmp_space, estimate_topen_tmp_bytes(par.tau, par.kappa));
  DECLARE_LOCAL_VAR(uint8_t*, open_sibling_tmp_space, //
    full_ggm_tree_open_sibling_path_from_root_tmp_bytes(&par.vole_params, par.target_topen));

  // for (auto _ : state) {
  {
    double t0 = get_time();
    // draw a random root seed
    randomize(global_salt, par.lambda_bytes);
    randomize(root_seed, par.lambda_bytes);
    double t1 = get_time();
    // initialize the tree structure
    double t2 = get_time();
    // generate vole pairs
    prover_generate_midsize_grey_vole_from_seeds_bfs_ct_ref( //
    &par.vole_params, par.L, hash_com, u, v, global_salt, root_seed, midsize_vole_tmp_space);
    double t3 = get_time();
    // ----- vole preprocessing ------
    // transpose vole
    memset(v + par.kappa * par.tau * par.Lslice, 0, (par.lambda - par.kappa * par.tau) * par.Lslice);
    prover_midsize_to_fullsize_std_vole_ct_ref(&par.vole_params, par.L, u, u + par.Lslice, v2, u, v);
    for (uint64_t i = 0; i < par.tau - 1; i++) {
      memcpy(corr_u + i * par.Lbyte, u + (i + 1) * par.Lslice, par.Lbyte);
    }

    xof_ctx hash_aux_ctx;  // round 1 hash: prefix, hash_com(ggm), aux(corr_terms) :=> cchk matrix
    par.vole_params.xof.xof_init_and_seed(&hash_aux_ctx, &HASH_AUX_PREFIX, 1);
    par.vole_params.xof.xof_seed(&hash_aux_ctx, hash_com, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&hash_aux_ctx, corr_u, (par.tau - 1) * par.Lbyte);
    par.vole_params.xof.xof_finalize_and_output(&hash_aux_ctx, hash_aux, 2 * par.lambda_bytes);

    double t4 = get_time();
    uint8_t* const rvp_u_cchk = u;
    uint8_t* const rvp_v_cchk = v2;
    const uint64_t num_inputs_padded = (par.num_inputs_pairs + 7) & UINT64_C(-8);
    uint8_t* const rvp_u_in = rvp_u_cchk + (par.num_cchk_pairs >> 3);
    uint8_t* const rvp_v_in = rvp_v_cchk + (par.num_cchk_pairs * par.lambda_bytes);
    uint8_t* const rvp_u_cz = rvp_u_cchk + ((par.num_cchk_pairs + num_inputs_padded) >> 3);
    uint8_t* const rvp_v_cz = rvp_v_cchk + ((par.num_cchk_pairs + num_inputs_padded) * par.lambda_bytes);

    // vole consistency check
    both_vole_consistency_check_matrix(&par.vole_params, par.L, cchk_matrix, hash_aux, 2 * par.lambda_bytes);
    prover_vole_consistency_check(&par.vole_params, par.L, cchk_u, cchk_res_v, u, v2, cchk_matrix);
    const double t5 = get_time();

    // f2 to flambda
    prover_f2_to_flambda_deg1_std_vole_ct_ref(&par.vole_params, par.degree - 1, rvp_f_cz, rvp_u_cz, rvp_v_cz);
    // deg1 to degd [in place]
    prover_flambda_deg1_to_degd_vole_ref(&par.vole_params, par.degree - 1, rvp_f_cz, rvp_f_cz);
    // std to cst: deg d [in place]
    prover_flambda_degd_std_to_cst_vole_ct_ref(&par.vole_params, par.degree - 1, rvp_f_cz, rvp_f_cz);
    // std to cst: deg 1 [in place]
    prover_f2_std_to_cst_vole_ct_ref(&par.vole_params, par.num_inputs_pairs, rvp_u_in, rvp_v_in, rvp_u_in, rvp_v_in);
    const double t6 = get_time();
    const double t100 = t6;  // end of vole operations

    // ----- circuit evaluation ------
    //  inputs + commit to it
    prover_cst_vole_packed_secret_input_ct_ref(  //
        &par.vole_params,                        //
        par.num_inputs_pairs,                    //
        circuit_in_pub,                          // publications -> signature
        inputs_f,                                // output vole
        skey_encoded_solution,                   // input secret key bits
        rvp_u_in, rvp_v_in);                     // rvp

    xof_ctx hash_lines_ctx;  // round1 + cchk_u + cchk_v + inputs_mask :=> chall
    par.vole_params.xof.xof_init_and_seed(&hash_lines_ctx, &HASH_LINES_PREFIX, 1);
    par.vole_params.xof.xof_seed(&hash_lines_ctx, hash_aux, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&hash_lines_ctx, cchk_u, (par.num_cchk_pairs + 7) >> 3);
    par.vole_params.xof.xof_seed(&hash_lines_ctx, cchk_res_v, par.cchk_matrix_nrows * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&hash_lines_ctx, circuit_in_pub, (par.num_inputs_pairs + 7) >> 3);
    par.vole_params.xof.xof_finalize_and_output(&hash_lines_ctx, hash_lines, 2 * par.lambda_bytes);

    const double t101 = get_time();
    //  generate the challenge points
    xof_ctx chall_rng;
    par.vole_params.xof.xof_init_and_seed(&chall_rng, hash_lines, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_finalize_and_output(&chall_rng, chall_a, par.lambda_bytes * par.rsd_codim_limbs);
    par.vole_params.xof.xof_output(&chall_rng, chall_unitary, par.lambda_bytes * par.rsd_w);
    const double t102 = get_time();
    rsd_public_key_times_challenge_ref(                         //
        &par.vole_params, par.rsd_w, par.rsd_n, par.rsd_codim,  //
        chall_a_H, chall_a_y,                                   //
        chall_a, pkey_seed,                                     //
        pkey_y, pk_times_chall_tmp_space);
    const double t103 = get_time();

    //  mux trees
    memset(res_f, 0, (par.degree + 1) * par.lambda_bytes);
    par.vole_params.flambda_set(res_f, chall_a_y);
    for (uint64_t i = 0; i < par.rsd_w; i++) {
      prover_cst_mux_circuit_ct_ref(                             //
          &par.vole_params,                                      //
          par.mux_depth, par.mux_arities, par.rsd_npw,           // circuit parameters
          mux_f,                                                 // mux output
          inputs_f + 2 * par.lambda_bytes * par.mux_inputs * i,  // secret input bits (bin, deg 1)
          chall_a_H + par.lambda_bytes * par.rsd_npw * i,        // challenge points (mul by H)
          chall_unitary + par.lambda_bytes * i,                  // check_unitary challenge (depth coeffs)
          tmp_space);
      prover_cst_vole_xor_gate_ct_ref(  //
          &par.vole_params,             //
          res_f,                        // result
          res_f, par.degree,            // lhs
          mux_f, par.degree);           // rhs
    }
    double t104 = get_time();
#ifdef PARANOIA_CHECK
    {
      // manual verification that res_f is consistent
      for (uint64_t i = 0; i < par.lambda_bytes; i++) {
        REQUIRE_DRAMATICALLY(res_f[i] == 0, "bug! res_f cst term is not zero!");
      }
    }
#endif  // PARANOIA_CHECK
    //  checkzero
    uint8_t cz_pub_full[4 * 32];
    prover_cst_vole_check_zero_gate_ct_ref(  //
        &par.vole_params,                    //
        par.degree,                          //
        cz_pub_full,                         //
        res_f,                               //
        rvp_f_cz);                           // rvp
    // alpha_1 is not serialized (verifier reconstructs it); only alpha_2..alpha_d.
    memcpy(circuit_cz_pub, cz_pub_full + par.lambda_bytes, (par.degree - 1) * par.lambda_bytes);
    // generate h3

    xof_ctx hash_piop_ctx;  // round3 + check_zero + message :=> delta
    par.vole_params.xof.xof_init_and_seed(&hash_piop_ctx, &HASH_PIOP_PREFIX, 1);
    par.vole_params.xof.xof_seed(&hash_piop_ctx, pkey_seed, par.lambda_bytes);
    par.vole_params.xof.xof_seed(&hash_piop_ctx, pkey_y, par.rsd_codim_bytes);
    par.vole_params.xof.xof_seed(&hash_piop_ctx, hash_lines, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&hash_piop_ctx, cz_pub_full, par.degree * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&hash_piop_ctx, message, message_bytes);
    par.vole_params.xof.xof_finalize_and_output(&hash_piop_ctx, hash_piop, 2 * par.lambda_bytes);

    const double t200 = get_time();

    // ----- open delta ------
    // generate delta0 != 0 s.t. topen is good (POW)
    uint64_t topen = 1e9;
    memset(delta0, 0, par.delta0_capacity);
    DECLARE_LOCAL_ALIGNED_VAR(32, proofow_ctx_t*, pow_ctx, par.vole_params.bytes_of_proofow_ctx());
    uint64_t pow_ctr = 0;
    par.vole_params.proofow_init(pow_ctx, par.lambda, par.kappa, par.tau, par.proofow_w, hash_piop);
    while (1) {
      int r = par.vole_params.proofow_grind_w(pow_ctx, delta0, &pow_ctr);
      if (!r) abort(); // SIGNATURE FAILED: impossible to do the proofow
      if (bitvec_is_zero_nonct(delta0, par.tau * par.kappa)) continue; // retry
      hidden_leaves_indexes2(par.kappa, par.tau, hidden_leaves_idx, delta0);
      topen = estimate_topen(par.tau, par.kappa, par.target_topen, hidden_leaves_idx, topen_tmp_space);
      if (topen <= par.target_topen) break; // success!
      ++pow_ctr;
    }
    memcpy(proofow_ctr_reveal, &pow_ctr, PROOFOW_CTR_REVEALED_BYTES);
    const double t201 = get_time();
    // generate delta1
    delta1_from_delta0_ref(&par.vole_params, delta1, delta0);

    // generate ggm_opening_data
    full_ggm_tree_open_sibling_path_from_root( //
      &par.vole_params, //
      ggm_sibling_path, ggm_hidden_leaf_cmt, //
      root_seed, global_salt, hidden_leaves_idx, topen, //
      open_sibling_tmp_space);
    // zero-out the unused ggm path
    uint8_t* ggm_sibling_path_zero_start = (uint8_t*)ggm_sibling_path + topen * par.lambda_bytes;
    memset(ggm_sibling_path_zero_start, 0, (par.target_topen - topen) * par.lambda_bytes);
    const double t202 = get_time();

    std::cout << "randomize seed + salt..: " << t1 - t0 << std::endl;
    std::cout << "other init.............: " << t2 - t1 << std::endl;
    std::cout << "midsize-vole...........: " << t3 - t2 << std::endl;
    std::cout << "vole-transpose-concat..: " << t4 - t3 << std::endl;
    std::cout << "vole-cchk..............: " << t5 - t4 << std::endl;
    std::cout << "vole-postprocess.......: " << t6 - t5 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "circuit-inputs.........: " << t101 - t100 << std::endl;
    std::cout << "chall-pts-gen..........: " << t102 - t101 << std::endl;
    std::cout << "chall-a.H-compute......: " << t103 - t102 << std::endl;
    std::cout << "mux-circuits...........: " << t104 - t103 << std::endl;
    std::cout << "check-zero.............: " << t200 - t104 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "pow-tau-topen..........: " << t201 - t200 << ": #pow_hashes: " << pow_ctr << std::endl;
    std::cout << "sibling-path-open......: " << t202 - t201 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "-----------------------" << std::endl;
    std::cout << "signature total:.......:" << t202 - t0 << std::endl;
    std::cout << "-----------------------" << std::endl;
    std::cout << "" << std::endl;
  }

  uint8_t sign_entropy[32 * 2];
  memcpy(sign_entropy, global_salt, par.lambda_bytes);
  memcpy(sign_entropy + par.lambda_bytes, root_seed, par.lambda_bytes);
  std::vector<uint8_t> signature(sdith_signature_bytes(&sig_params));
  std::vector<uint8_t> sign_tmp_space(sdith_signature_tmp_bytes(&sig_params));
  double full_sign_stime = get_time();
  sdith_sign(&sig_params, signature.data(), message, message_bytes, secret_key_vec.data(), sign_entropy,
             sign_tmp_space.data());
  double full_sign_etime = get_time();

  for (uint64_t i = 0; i < total_signature_bytes; ++i) {
    REQUIRE_DRAMATICALLY(signature[i] == test_signature[i], "bug!!");
  }

  DECLARE_LOCAL_VAR(hash_t*, verif_hash_aux, 2 * par.lambda_bytes);  // ggm_cmt_hash + corr_terms :=> cchk matrix
  DECLARE_LOCAL_VAR(hash_t*, verif_hash_lines,
                    2 * par.lambda_bytes);  // round1 + cchk_u + cchk_v + inputs_mask :=> chall
  DECLARE_LOCAL_VAR(hash_t*, verif_hash_piop, 2 * par.lambda_bytes);  // round3 + check_zero + message :=> delta
  DECLARE_LOCAL_VAR(uint32_t*, verif_hidden_leaves_idx, par.tau * sizeof(uint32_t));
  DECLARE_LOCAL_VAR(uint8_t*, verif_delta0, par.delta0_capacity);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_delta1, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_delta2, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_delta2_dm1, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_corr, par.Lslice* par.tau);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, q, par.Lslice* par.lambda);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, q2, par.Lslice* par.lambda);  // copy needed during transposition
  DECLARE_LOCAL_VAR(uint8_t*, verif_hash_com,
                    2 * par.lambda_bytes);  // ggm commitment hash (verify against the signature)
  DECLARE_LOCAL_VAR(uint8_t*, verif_cchk_matrix, par.Lbyte* par.num_cchk_pairs);
  DECLARE_LOCAL_VAR(uint8_t*, verif_cchk_res_v, par.lambda_bytes* par.num_cchk_pairs);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, inputs_q, par.lambda_bytes* par.num_inputs_pairs);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_chall_unitary, par.lambda_bytes* par.rsd_w);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_chall_a, par.lambda_bytes* par.rsd_codim_limbs);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, verif_chall_a_H, par.lambda_bytes* par.rsd_n);
  DECLARE_LOCAL_VAR(uint8_t*, verif_chall_a_y, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, mux_q, par.lambda_bytes);
  DECLARE_LOCAL_ALIGNED_VAR(32, uint8_t*, res_q, par.lambda_bytes);
  DECLARE_LOCAL_VAR(uint8_t*, verif_midsize_vole_tmp_space,  //
    verifier_open_midsize_grey_vole_from_seeds_bfs_tmp_bytes( //
      &par.vole_params, par.L, par.target_topen));
  DECLARE_LOCAL_VAR(
      uint8_t*, verif_tmp_space,
      verifier_cst_mux_circuit_ref_tmp_bytes(&par.vole_params, par.mux_depth, par.mux_arities, par.rsd_npw));

  // verifier side
  {
    uint64_t leftover_bits = par.num_inputs_pairs & 7;
    if (leftover_bits) {
      uint64_t mask = ((1 << (8 - leftover_bits)) - 1) << leftover_bits;
      uint64_t idx = ((par.num_inputs_pairs + 7) >> 3) - 1;
      CREQUIRE((circuit_in_pub[idx] & mask) == 0, "[in] publications does not have trailing zeros");
    }

    xof_ctx verif_hash_aux_ctx;  // prefix, hash_com(ggm), corr_terms :=> cchk matrix
    par.vole_params.xof.xof_init_and_seed(&verif_hash_aux_ctx, &HASH_AUX_PREFIX, 1);
    par.vole_params.xof.xof_seed(&verif_hash_aux_ctx, hash_com, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_aux_ctx, corr_u, (par.tau - 1) * par.Lbyte);
    par.vole_params.xof.xof_finalize_and_output(&verif_hash_aux_ctx, verif_hash_aux, 2 * par.lambda_bytes);
    REQUIRE_DRAMATICALLY(memcmp(verif_hash_aux, hash_aux, 2 * par.lambda_bytes) == 0, "bug!!");

    double verif_paranoia_checks_time = 0.;
    double vt0 = get_time();
    // ----- open delta ------
    // generate delta0 != 0 s.t. topen is good (POW)
    uint64_t topen = 1e9;
    uint64_t proof_of_work_counter = 0;
    memset(verif_delta0, 0, par.delta0_capacity);
    memcpy(&proof_of_work_counter, proofow_ctr_reveal, PROOFOW_CTR_REVEALED_BYTES);  // load the golden counter
    uint8_t proof_of_work_valid = 0;
    DECLARE_LOCAL_ALIGNED_VAR(32, proofow_ctx_t*, pow_ctx, par.vole_params.bytes_of_proofow_ctx());
    par.vole_params.proofow_init(pow_ctx, par.lambda, par.kappa, par.tau, par.proofow_w, hash_piop);
    do {
      int r = par.vole_params.proofow_verify_w(pow_ctx, verif_delta0, proof_of_work_counter);
      if (!r) break; // SIGNATURE FAILED: impossible to do the proofow
      if (bitvec_is_zero_nonct(verif_delta0, par.tau * par.kappa)) break; // SIG invalid: delta=0
      hidden_leaves_indexes2(par.kappa, par.tau, verif_hidden_leaves_idx, verif_delta0);
      topen = estimate_topen(par.tau, par.kappa, par.target_topen, verif_hidden_leaves_idx, topen_tmp_space);
      if (topen > par.target_topen) break; // SIG invalid: wrong topen!
      proof_of_work_valid = 1;
    } while (0);
    REQUIRE_DRAMATICALLY(proof_of_work_valid == 1, "bug: proof of work is invalid!!");
    // check that the sibling path has trailing zeroes (if needed)
    {
      uint64_t zero_values = par.target_topen - topen;
      uint8_t* ggm_sibling_path_zero_start = (uint8_t*)ggm_sibling_path + topen * par.lambda_bytes;
      for (uint64_t i = 0; i < zero_values * par.lambda_bytes; i++) {
        REQUIRE_DRAMATICALLY(ggm_sibling_path_zero_start[i] == 0, "error! sibling path not zero-ed out");
      }
    }
    // generate delta1
    delta1_from_delta0_ref(&par.vole_params, verif_delta1, verif_delta0);
#ifdef PARANOIA_CHECK
    {
      double pt = get_time();
      REQUIRE_DRAMATICALLY(memcmp(verif_delta0, delta0, par.lambda_bytes) == 0, "bug! verif delta differs!");
      REQUIRE_DRAMATICALLY(memcmp(verif_hidden_leaves_idx, hidden_leaves_idx, par.tau * sizeof(uint32_t)) == 0,
                           "bug! hidden leaves idx differ!");
      REQUIRE_DRAMATICALLY(memcmp(verif_delta1, delta1, par.lambda_bytes) == 0, "bug! verif delta differs!");
      verif_paranoia_checks_time += get_time() - pt;
    }
#endif
    delta2_from_delta1_ref(&par.vole_params, verif_delta2, verif_delta1);
    double vt1 = get_time();

    {
      uint64_t zero_values = par.target_topen - topen;
      uint8_t* ggm_sibling_path_zero_start = (uint8_t*)ggm_sibling_path + topen * par.lambda_bytes;
      for (uint64_t i = 0; i < zero_values * par.lambda_bytes; i++) {
        REQUIRE_DRAMATICALLY(ggm_sibling_path_zero_start[i] == 0, "error! sibling path not zero-ed out");
      }
    }

    // initialize the sibling tree structure (nope)
    double vt2 = get_time();
    // generate vole pairs
    memset(verif_corr, 0, par.Lslice * par.tau);
    for (uint64_t i = 0; i < par.tau - 1; i++) {
      memcpy(verif_corr + (i+1) * par.Lslice, corr_u + i * par.Lbyte, par.Lbyte);
    }
    verifier_open_midsize_grey_vole_from_seeds_bfs_ref( //
      &par.vole_params, par.L, //
      verif_hash_com, q, verif_corr, //
      verif_hidden_leaves_idx, ggm_hidden_leaf_cmt, //
      ggm_sibling_path, topen, global_salt, delta1,
      verif_midsize_vole_tmp_space
    );
    REQUIRE_DRAMATICALLY(memcmp(verif_hash_com, hash_com, 2 * par.lambda_bytes) == 0, "bug! verif cmt_hash differs!");

    double vt3 = get_time();
    // ----- vole preprocessing ------
    // transpose vole
    memset(q + par.kappa * par.tau * par.Lslice, 0, (par.lambda - par.kappa * par.tau) * par.Lslice);
    verifier_midsize_to_fullsize_std_vole_ref(&par.vole_params, par.L, q2, q);
    double vt4 = get_time();
    uint8_t* const rvp_q_cchk = q2;
    const uint64_t num_inputs_padded_v = (par.num_inputs_pairs + 7) & UINT64_C(-8);
    uint8_t* const rvp_q_in = rvp_q_cchk + (par.num_cchk_pairs * par.lambda_bytes);
    uint8_t* const rvp_q_cz = rvp_q_cchk + ((par.num_cchk_pairs + num_inputs_padded_v) * par.lambda_bytes);

    // vole consistency check
    both_vole_consistency_check_matrix(&par.vole_params, par.L, verif_cchk_matrix, verif_hash_aux,
                                       2 * par.lambda_bytes);
    verifier_vole_consistency_check(&par.vole_params, par.L, verif_cchk_res_v, cchk_u, q2, verif_cchk_matrix, delta1);

    xof_ctx verif_hash_lines_ctx;  // round1 + cchk_u + cchk_v + inputs_mask :=> chall
    par.vole_params.xof.xof_init_and_seed(&verif_hash_lines_ctx, &HASH_LINES_PREFIX, 1);
    par.vole_params.xof.xof_seed(&verif_hash_lines_ctx, verif_hash_aux, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_lines_ctx, cchk_u, (par.num_cchk_pairs + 7) >> 3);
    par.vole_params.xof.xof_seed(&verif_hash_lines_ctx, verif_cchk_res_v, par.cchk_matrix_nrows * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_lines_ctx, circuit_in_pub, (par.num_inputs_pairs + 7) >> 3);
    par.vole_params.xof.xof_finalize_and_output(&verif_hash_lines_ctx, verif_hash_lines, 2 * par.lambda_bytes);
    REQUIRE_DRAMATICALLY(memcmp(verif_hash_lines, hash_lines, 2 * par.lambda_bytes) == 0, "bug!!");

    const double vt5 = get_time();

    // f2 to flambda
    verifier_f2_to_flambda_deg1_std_vole_ref(&par.vole_params, par.degree - 1, rvp_q_cz, rvp_q_cz);
    // deg1 to degd [in place]
    verifier_flambda_deg1_to_degd_vole_ref(&par.vole_params, par.degree - 1, rvp_q_cz, rvp_q_cz, delta1);
    // std to cst: deg d [in place]
    flambda_power(&par.vole_params, verif_delta2_dm1, verif_delta2, par.degree - 1);
    verifier_flambda_degd_std_to_cst_vole_ref(&par.vole_params, par.degree - 1, rvp_q_cz, rvp_q_cz, verif_delta2_dm1);
    // std to cst: deg 1 [in place]
    verifier_f2_std_to_cst_vole_ref(&par.vole_params, par.num_inputs_pairs, rvp_q_in, rvp_q_in, verif_delta2);
    const double vt6 = get_time();
#ifdef PARANOIA_CHECK
    {
      double pt = get_time();
      // -------------------------------------------------------------------
      // manual vole consistency verification (not needed in production)
      // -------------------------------------------------------------------
      // verify rvp_cz
      vole_flambda_poly rvp_cz_chk(par.lambda, par.degree - 1, 1);
      memcpy(rvp_cz_chk.f.data(), rvp_f_cz, par.degree * par.lambda_bytes);
      memcpy(rvp_cz_chk.q.data(), rvp_q_cz, par.lambda_bytes);
      rvp_cz_chk.assert_correct(verif_delta2);
      // verify rvp_in (round-3 partition: inputs sit right after cchk)
      const uint8_t* const rvp_u_in = u + (par.num_cchk_pairs >> 3);
      const uint8_t* const rvp_v_in = v2 + (par.num_cchk_pairs * par.lambda_bytes);
      vole_cst_f2_deg1_uvq rvp_in_chk(par.lambda, par.num_inputs_pairs);
      memcpy(rvp_in_chk.u.data(), rvp_u_in, (par.num_inputs_pairs + 7) >> 3);
      memcpy(rvp_in_chk.v.data(), rvp_v_in, par.num_inputs_pairs * par.lambda_bytes);
      memcpy(rvp_in_chk.q.data(), rvp_q_in, par.num_inputs_pairs * par.lambda_bytes);
      rvp_in_chk.assert_correct(verif_delta2);

      verif_paranoia_checks_time += get_time() - pt;
    }
#endif
    const double vt100 = get_time();  // end of vole operations

    // ----- circuit evaluation ------
    //  inputs + commit to it
    verifier_cst_vole_packed_secret_input_ref(  //
        &par.vole_params,                       //
        par.num_inputs_pairs,                   //
        inputs_q,
        circuit_in_pub,  // publications -> signature
        rvp_q_in,
        verif_delta2);  // rvp
#ifdef PARANOIA_CHECK
    {
      double pt = get_time();
      // -------------------------------------------------------------------
      // manual vole consistency verification (not needed in production)
      // -------------------------------------------------------------------
      // verify inputs_
      vole_flambda_poly inputs_chk(par.lambda, 1, par.num_inputs_pairs);
      memcpy(inputs_chk.f.data(), inputs_f, par.num_inputs_pairs * 2 * par.lambda_bytes);
      memcpy(inputs_chk.q.data(), inputs_q, par.num_inputs_pairs * par.lambda_bytes);
      inputs_chk.assert_correct(verif_delta2);

      verif_paranoia_checks_time += get_time() - pt;
    }
#endif

    const double vt101 = get_time();
    //  generate the challenge points
    xof_ctx verif_chall_rng;
    par.vole_params.xof.xof_init_and_seed(&verif_chall_rng, verif_hash_lines, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_finalize_and_output(&verif_chall_rng, verif_chall_a,
                                                par.lambda_bytes * par.rsd_codim_limbs);
    // note: the chall unitary are only needed if the mux tree contains one non-binary arity
    par.vole_params.xof.xof_output(&verif_chall_rng, verif_chall_unitary, par.lambda_bytes * par.rsd_w);
    const double vt102 = get_time();

    std::vector<uint8_t> vtmpsp(
        rsd_public_key_times_challenge_tmp_bytes(&par.vole_params, par.rsd_w, par.rsd_n, par.rsd_codim));
    rsd_public_key_times_challenge_ref(&par.vole_params, par.rsd_w, par.rsd_n, par.rsd_codim,  //
                                       verif_chall_a_H, verif_chall_a_y,                       //
                                       verif_chall_a, pkey_seed, pkey_y, vtmpsp.data());
    REQUIRE_DRAMATICALLY(memcmp(verif_chall_unitary, chall_unitary, par.lambda_bytes * par.rsd_w) == 0,
                         "bug! chall_unitary differ");
    REQUIRE_DRAMATICALLY(memcmp(verif_chall_a, chall_a, par.lambda_bytes * par.rsd_codim_limbs) == 0,
                         "bug! chall_a differ");
    REQUIRE_DRAMATICALLY(memcmp(verif_chall_a_H, chall_a_H, par.lambda_bytes * par.rsd_n) == 0,
                         "bug! chall_a_H differ");
    REQUIRE_DRAMATICALLY(memcmp(verif_chall_a_y, chall_a_y, par.lambda_bytes) == 0, "bug! chall_a_y differ");
    const double vt103 = get_time();

    par.vole_params.flambda_set(res_q, chall_a_y);
    for (uint64_t i = 0; i < par.rsd_w; i++) {
      verifier_cst_mux_circuit_ref(                              //
          &par.vole_params,                                      //
          par.mux_depth, par.mux_arities, par.rsd_npw,           // circuit parameters
          mux_q,                                                 // mux output
          inputs_q + par.lambda_bytes * par.mux_inputs * i,      // secret input bits (bin, deg 1)
          verif_chall_a_H + par.lambda_bytes * par.rsd_npw * i,  // challenge points (mul by H)
          verif_chall_unitary + par.lambda_bytes * i,            // check_unitary challenge (depth coeffs)
          verif_delta2, verif_tmp_space);
      verifier_cst_vole_xor_gate_ref(  //
          &par.vole_params,            //
          res_q,                       // result
          res_q, par.degree,           // lhs
          mux_q, par.degree,           // rhs
          verif_delta2);
    }
#ifdef PARANOIA_CHECK
    {
      double pt = get_time();
      // -------------------------------------------------------------------
      // manual vole consistency verification (not needed in production)
      // -------------------------------------------------------------------
      // verify res
      vole_flambda_poly res_chk(par.lambda, par.degree, 1);
      memcpy(res_chk.f.data(), res_f, (par.degree + 1) * par.lambda_bytes);
      memcpy(res_chk.q.data(), res_q, par.lambda_bytes);
      res_chk.assert_correct(verif_delta2);

      verif_paranoia_checks_time += get_time() - pt;
    }
#endif  // PARANOIA_CHECK

    double vt104 = get_time();
    //  checkzero: reconstruct alpha_1 from alpha_2..alpha_d + VOLE evaluations,
    //  then hash the full alpha_1..alpha_d into h_piop and compare.
    uint8_t cz_pub_full[4 * 32];
    {
      const uint64_t lb = par.lambda_bytes;
      // partial holds a field element passed to flambda_product/flambda_sum, so it
      // needs the same alignment as the field type (like tmp/rq_dinv below). A bare
      // uint8_t[32] is only 1-byte aligned, which faults once the reference gf code
      // is auto-vectorized to aligned loads. Use the aligned field type instead.
      flambda_max_t partial;
      memcpy(partial, circuit_cz_pub + (par.degree - 2) * lb, lb);
      for (int64_t i = par.degree - 3; i >= 0; i--) {
        par.vole_params.flambda_product(partial, partial, verif_delta2);
        flambda_max_t tmp;
        memcpy(tmp, circuit_cz_pub + i * lb, lb);
        par.vole_params.flambda_sum(partial, partial, tmp);
      }
      par.vole_params.flambda_product(partial, partial, verif_delta2);
      par.vole_params.flambda_sum(partial, partial, rvp_q_cz);
      flambda_max_t rq_dinv;
      par.vole_params.flambda_product(rq_dinv, res_q, verif_delta1);
      par.vole_params.flambda_sum(partial, partial, rq_dinv);
      memcpy(cz_pub_full, partial, lb);
      memcpy(cz_pub_full + lb, circuit_cz_pub, (par.degree - 1) * lb);
    }
    xof_ctx verif_hash_piop_ctx;  // round3 + check_zero + message :=> delta
    par.vole_params.xof.xof_init_and_seed(&verif_hash_piop_ctx, &HASH_PIOP_PREFIX, 1);
    par.vole_params.xof.xof_seed(&verif_hash_piop_ctx, pkey_seed, par.lambda_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_piop_ctx, pkey_y, par.rsd_codim_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_piop_ctx, verif_hash_lines, 2 * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_piop_ctx, cz_pub_full, par.degree * par.lambda_bytes);
    par.vole_params.xof.xof_seed(&verif_hash_piop_ctx, message, message_bytes);
    par.vole_params.xof.xof_finalize_and_output(&verif_hash_piop_ctx, verif_hash_piop, 2 * par.lambda_bytes);
    REQUIRE_DRAMATICALLY(memcmp(verif_hash_piop, hash_piop, 2 * par.lambda_bytes) == 0, "bug!!");

    const double vt200 = get_time();

    std::cout << "verif: pow-tau-topen..........: " << vt1 - vt0 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "verif: sib tree init..........: " << vt2 - vt1 << std::endl;
    std::cout << "verif: midsize-vole...........: " << vt3 - vt2 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "verif: vole-transpose-concat..: " << vt4 - vt3 << std::endl;
    std::cout << "verif: vole-cchk..............: " << vt5 - vt4 << std::endl;
    std::cout << "verif: vole-postprocess.......: " << vt6 - vt5 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "verif: circuit-inputs.........: " << vt101 - vt100 << std::endl;
    std::cout << "verif: chall-pts-gen..........: " << vt102 - vt101 << std::endl;
    std::cout << "verif: chall-a.H-compute......: " << vt103 - vt102 << std::endl;
    std::cout << "verif: mux-circuits...........: " << vt104 - vt103 << std::endl;
    std::cout << "verif: check-zero.............: " << vt200 - vt104 << std::endl;
    std::cout << "" << std::endl;
    std::cout << "verif: paranoia checks........:" << verif_paranoia_checks_time << std::endl;
    std::cout << "-------------------------------" << std::endl;
    std::cout << "verif: verif total:...........:" << vt200 - vt0 - verif_paranoia_checks_time << std::endl;
    std::cout << "-------------------------------" << std::endl;
    std::cout << "" << std::endl;
  }

  std::vector<uint8_t> verify_tmp_space(sdith_verify_tmp_bytes(&sig_params));
  double full_verify_stime = get_time();
  uint8_t verif_chk = sdith_verify(&sig_params, signature.data(), message, message_bytes, public_key_vec.data(),
                                   verify_tmp_space.data());
  double full_verify_etime = get_time();
  REQUIRE_DRAMATICALLY(verif_chk, "bug: C signature is not valid!!");
  std::cout << std::endl;
  std::cout << "timings for a single run......:" << std::endl;
  std::cout << "C keygen total:........:" << keygen_etime - keygen_stime << std::endl;
  std::cout << "C signature total:.....:" << full_sign_etime - full_sign_stime << std::endl;
  std::cout << "C verify total:........:" << full_verify_etime - full_verify_stime << std::endl;

  if (!do_histogram) return 0;

  std::cout << std::endl;
  std::cout << "Making an histogram...........:" << std::endl;
  uint64_t num_sigs = 201;
  std::vector<double> tsig(num_sigs);
  std::vector<double> tver(num_sigs);
  std::vector<double> csig(num_sigs);
  std::vector<double> cver(num_sigs);
  for (uint64_t i = 0; i < num_sigs; i++) {
    if (++sign_entropy[0] == 0) ++sign_entropy[1];
    double t1 = get_time();
    uint64_t c1 = cpucycles();
    sdith_sign(&sig_params, signature.data(), message, message_bytes, secret_key_vec.data(), sign_entropy,
               sign_tmp_space.data());
    double t2 = get_time();
    uint64_t c2 = cpucycles();
    verif_chk = sdith_verify(&sig_params, signature.data(), message, message_bytes, public_key_vec.data(),
                             verify_tmp_space.data());
    double t3 = get_time();
    uint64_t c3 = cpucycles();
    REQUIRE_DRAMATICALLY(verif_chk, "bug!!");
    tsig[i] = (t2 - t1);
    tver[i] = (t3 - t2);
    csig[i] = (c2 - c1)/1e6;
    cver[i] = (c3 - c2)/1e6;
  }
  std::sort(tsig.begin(), tsig.end());
  std::sort(tver.begin(), tver.end());
  std::sort(csig.begin(), csig.end());
  std::sort(cver.begin(), cver.end());
  printf("percentile      sig_time     sig_Mcyc      ver_time     ver_Mcyc\n");
  for (uint64_t i : {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99}) {
    printf("%3" PRId64 "%%            %.6lf     %2.6lf     %.6lf     %2.6lf\n", i,
      tsig[i * 2], csig[i * 2], tver[i * 2], cver[i * 2]);
  }
}
