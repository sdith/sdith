#include <gtest/gtest.h>

#include "sdith_rsd.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/vole_testlib.h"
#include "vole_private.h"

// rsd_generate_random_instance_ref only emits the stored parts of the key (the
// solution and the syndrome y): H stays implicit in pk_seed, and is recovered
// here with rsd_expand_public_key_ref to check y against the definition
// y = sum_i H[i * npw + solution[i]].
TEST(rsd, generate_random_instance_ref) {
  for (uint64_t lambda : {128, 192, 256}) {
    vole_parameters vole_params;
    vole_parameters_init_ref(&vole_params, lambda, 0, 0);
    for (uint64_t rsd_w : {1, 5, 25, 43}) {
      for (uint64_t rsd_npw : {1, 7, 30, 45}) {
        const uint64_t rsd_n = rsd_w * rsd_npw;
        for (uint64_t rsd_codim : {1, 32, 42, 123}) {
          if (rsd_n < rsd_codim) continue;
          // The matrix prng emits limb-padded rows: rsd_codim_limbs limbs of
          // lambda_bytes each. min_col_bytes still holds the meaningful bits.
          const uint64_t min_col_bytes = (rsd_codim + 7) / 8;
          uint64_t rsd_codim_limbs, rsd_codim_slice;
          compute_rsd_codim_slice(&rsd_codim_limbs, &rsd_codim_slice, lambda, rsd_codim);
          const bit_vector sk_seed = bit_vector::random(lambda);
          const bit_vector pk_seed = bit_vector::random(lambda);
          bit_matrix hprime(rsd_n - rsd_codim, rsd_codim_slice * 8);
          bit_matrix h = bit_matrix::zero(rsd_n, rsd_codim);
          bit_vector y(rsd_codim);
          std::vector<uint32_t> solution(rsd_w);
          std::vector<uint8_t> tmp(rsd_generate_random_instance_tmp_bytes(&vole_params, rsd_w, rsd_n, rsd_codim));
          rsd_generate_random_instance_ref(  //
              rsd_w, rsd_n, rsd_codim,       //
              &vole_params,                  //
              y.data(), min_col_bytes,       //
              solution.data(),               //
              sk_seed.data(), pk_seed.data(), tmp.data());
          rsd_expand_public_key_ref(     //
              rsd_w, rsd_n, rsd_codim,   //
              &vole_params,              //
              hprime.data(), rsd_codim_slice, pk_seed.data());
          // reconstruct the full h
          for (uint64_t i = 0; i < rsd_n; ++i) {
            if (i < rsd_codim) {
              h.set(i, i, 1);  // identity block
            } else {
              memcpy(h.row_ptr(i), hprime.row_ptr(i - rsd_codim), min_col_bytes);
            }
          }

          // check that the solution is within the right bounds
          for (uint64_t i = 0; i < rsd_w; i++) {
            ASSERT_LT(solution[i], rsd_npw);
          }

          // check that y is the solution
          bit_vector expect_y = bit_vector::zero(rsd_codim);
          for (uint64_t i = 0; i < rsd_w; i++) {
            expect_y ^= h.row(i * rsd_npw + solution[i]);
          }
          ASSERT_EQ(y, expect_y);

          // check that the instance is independent from the y slice: y is
          // byte-packed, so its margins are byte-granular.
          for (uint64_t y_margin_bytes : {0, 3}) {
            const uint64_t y_slice_bytes = min_col_bytes + y_margin_bytes;
            bit_vector y_2(y_slice_bytes * 8);
            std::vector<uint32_t> solution_2(rsd_w);
            rsd_generate_random_instance_ref(  //
                rsd_w, rsd_n, rsd_codim,       //
                &vole_params,                  //
                y_2.data(), y_slice_bytes,     //
                solution_2.data(),             //
                sk_seed.data(), pk_seed.data(), tmp.data());

            // check equality
            ASSERT_EQ(solution_2, solution);

            // check y_2: the meaningful bytes match and everything past them is zero
            const uint8_t* y2 = (uint8_t*)y_2.data();
            ASSERT_TRUE(memcmp(y2, y.data(), min_col_bytes) == 0);
            for (uint64_t j = min_col_bytes; j < y_slice_bytes; j++) {
              ASSERT_EQ(y2[j], 0);
            }
          }

          // check that H is independent from its slice. H rows must stay
          // block-aligned, so its margins are whole extra blocks.
          for (uint64_t h_margin_blks : {2}) {
            const uint64_t h_slice_bytes = rsd_codim_slice + h_margin_blks * 32;
            bit_matrix hprime_2(rsd_n - rsd_codim, h_slice_bytes * 8);
            rsd_expand_public_key_ref(    //
                rsd_w, rsd_n, rsd_codim,  //
                &vole_params,             //
                hprime_2.data(), h_slice_bytes, pk_seed.data());
            for (uint64_t i = 0; i < rsd_n - rsd_codim; i++) {
              const uint8_t* h2i = (uint8_t*)hprime_2.row_ptr(i);
              ASSERT_TRUE(memcmp(h2i, hprime.row_ptr(i), min_col_bytes) == 0);
              for (uint64_t j = min_col_bytes; j < h_slice_bytes; j++) {
                ASSERT_EQ(h2i[j], 0);
              }
            }
          }
        }
      }
    }
  }
}

TEST(rsd, encode_solution_ref) {
  // the encoding does not depend on lambda: it only reaches vole_params for the
  // ct helpers. ct_utils_test checks that the ref and avx tables agree.
  vole_parameters vole_params;
  vole_parameters_init_ref(&vole_params, 128, 0, 0);
  for (uint64_t rsd_w : {1, 5, 25, 43}) {
    for (uint64_t rsd_npw : {1, 7, 30, 45}) {
      const uint64_t rsd_n = rsd_w * rsd_npw;
      for (uint64_t rsd_codim : {1, 35, 48, 123}) {
        // randomize the solutions
        std::vector<uint32_t> solution(rsd_w);
        randomize(solution.data(), rsd_w * sizeof(uint32_t));
        for (uint64_t j = 0; j < rsd_w; j++) {
          solution[j] %= rsd_npw;
        }
        std::vector<uint64_t> mux_arities;
        uint64_t mux_size = 1;
        uint64_t mux_inputs = 0;
        while (mux_size <= rsd_npw) {
          uint64_t aj = (uniform_u128() % 4) + 2;  // between 2 and 5
          mux_size *= aj;
          mux_inputs += aj - 1;
          mux_arities.push_back(aj);
        }
        const uint64_t mux_depth = mux_arities.size();
        uint64_t encoded_solution_bytes = (rsd_w * mux_inputs + 7) / 8;
        bit_vector encoded_solution(encoded_solution_bytes * 8);
        // call the encoding
        rsd_encode_solution_ref(      //
            rsd_w, rsd_n, rsd_codim,  //
            &vole_params,             //
            mux_depth, mux_arities.data(), encoded_solution.data(), encoded_solution_bytes, solution.data());

        // check that encoded_solution encodes solution
        uint64_t bitpos = 0;
        for (uint64_t i = 0; i < rsd_w; i++) {
          uint64_t si = solution[i];
          for (uint64_t j = 0; j < mux_depth; j++) {
            const uint64_t aj = mux_arities[j];
            const uint64_t sij = si % aj;
            si /= aj;
            for (uint64_t k = 0; k < aj - 1; k++) {
              uint64_t expect = (sij == k + 1);
              uint64_t actual = encoded_solution.get(bitpos + k);
              ASSERT_EQ(expect, actual);
            }
            bitpos += aj - 1;
          }
          ASSERT_EQ(si, 0);
          ASSERT_EQ(bitpos, mux_inputs * (i + 1));
        }

        // check that the instance is independent from the slice
        for (uint64_t margin_bytes : {1, 2, 5}) {
          uint64_t e2_bytes = encoded_solution_bytes + margin_bytes;
          bit_vector e2(e2_bytes * 8);
          // call the encoding
          rsd_encode_solution_ref(      //
              rsd_w, rsd_n, rsd_codim,  //
              &vole_params,             //
              mux_depth, mux_arities.data(), e2.data(), e2_bytes, solution.data());
          // check equality

          // check y_2
          const uint8_t* e2b = (uint8_t*)e2.data();
          ASSERT_TRUE(memcmp(e2b, encoded_solution.data(), encoded_solution_bytes) == 0);
          for (uint64_t j = encoded_solution_bytes; j < e2_bytes; j++) {
            ASSERT_EQ(e2b[j], 0);
          }
        }
      }
    }
  }
}

namespace {

typedef void (*vole_params_init_fn)(vole_parameters*, uint64_t, uint64_t, uint64_t);
struct vole_params_variant {
  const char* name;
  vole_params_init_fn init;
};
// Every implementation of the parameter table must satisfy the same spec, so the
// checks below run against all of them. As categories gain their fused
// rows_times_chall kernel they are covered here automatically, with no change to
// the tests: the oracle is the definition of chall_a_H, never another code path.
const std::vector<vole_params_variant> kVoleVariants = {
    {"ref", vole_parameters_init_ref},
#ifdef __x86_64__
    {"avx", vole_parameters_init_avx},
#endif
};

// compute_rsd_codim_slice requires the prng row (a whole number of cipher
// blocks) to be wide enough to hold rsd_codim_limbs limbs, and aborts otherwise.
// For lambda 128 and 256 that always holds, but lambda=192 packs 192-bit limbs
// into 256-bit rijndael blocks, so only some rsd_codim are representable (e.g.
// 192 is, 193 is not). Sweeps use this to skip the unsupported points.
bool rsd_codim_is_supported(uint64_t lambda, uint64_t rsd_codim) {
  const uint64_t prng_blk_bytes = lambda == 128 ? 16 : 32;
  const uint64_t rsd_codim_bytes = (rsd_codim + 7) >> 3;
  const uint64_t slice = ((rsd_codim_bytes + prng_blk_bytes - 1) / prng_blk_bytes) * prng_blk_bytes;
  const uint64_t limbs = (rsd_codim + lambda - 1) / lambda;
  return slice >= limbs * (lambda >> 3);
}

// Checks rsd_public_key_times_challenge_ref for one parameter point, against an
// independently computed
//     chall_a_H0[i] = sum_j chall_a[j] * H[i][j]
// built straight from the expanded H with the testlib field arithmetic. This
// oracle depends only on the public definition, so it stays valid however the
// production path is implemented -- it never compares one production path
// against another.
void check_pk_times_challenge(const vole_params_variant& v, uint64_t lambda, uint64_t rsd_w, uint64_t rsd_n,
                              uint64_t rsd_codim) {
  SCOPED_TRACE(testing::Message() << v.name << " lambda=" << lambda << " rsd_w=" << rsd_w << " rsd_n=" << rsd_n
                                  << " rsd_codim=" << rsd_codim);
  vole_parameters vole_params;
  v.init(&vole_params, lambda, 0, 0);
  const uint64_t lambda_bytes = vole_params.lambda_bytes;
  uint64_t rsd_codim_limbs, rsd_codim_bytes;
  compute_rsd_codim_slice(&rsd_codim_limbs, &rsd_codim_bytes, lambda, rsd_codim);
  const bit_vector sk_seed = bit_vector::random(lambda);
  const bit_vector pk_seed = bit_vector::random(lambda);
  bit_matrix hprime(rsd_n - rsd_codim, rsd_codim_bytes * 8);
  bit_matrix h(rsd_n, rsd_codim_bytes * 8);
  flam_vector y = flam_vector::zero(lambda, rsd_codim_limbs);
  const flam_vector chall_a = flam_vector::random(lambda, rsd_codim_limbs);
  std::vector<uint32_t> solution(rsd_w);
  std::vector<uint8_t> gen_tmp(rsd_generate_random_instance_tmp_bytes(&vole_params, rsd_w, rsd_n, rsd_codim));
  rsd_generate_random_instance_ref(  //
      rsd_w, rsd_n, rsd_codim,       //
      &vole_params,                  //
      y.data(), rsd_codim_bytes,     //
      solution.data(),               //
      sk_seed.data(), pk_seed.data(), gen_tmp.data());
  rsd_expand_public_key_ref(    //
      rsd_w, rsd_n, rsd_codim,  //
      &vole_params,             //
      hprime.data(), rsd_codim_bytes, pk_seed.data());
  // reconstruct the full h and the expected products
  flam_vector chall_a_H0(lambda, rsd_n);
  flam_elem chall_a_y0 = flam_elem::zero(lambda);
  for (uint64_t i = 0; i < rsd_n; ++i) {
    if (i < rsd_codim) {
      h.set(i, i, 1);  // identity block
    } else {
      memcpy(h.row_ptr(i), hprime.row_ptr(i - rsd_codim), rsd_codim_bytes);
    }
    flam_elem t = flam_elem::zero(lambda);
    for (uint64_t j = 0; j < rsd_codim_limbs; j++) {
      t += chall_a.get(j) * flam_elem(lambda, (uint8_t*)h.row_ptr(i) + j * lambda_bytes);
    }
    chall_a_H0.set(i, t);
  }
  {
    flam_elem t = flam_elem::zero(lambda);
    for (uint64_t j = 0; j < rsd_codim_limbs; j++) {
      t += chall_a.get(j) * y.get(j);
    }
    chall_a_y0 = t;
  }

  flam_vector chall_a_H(lambda, rsd_n);
  flam_elem chall_a_y = flam_elem::zero(lambda);
  std::vector<uint8_t> tmp(rsd_public_key_times_challenge_tmp_bytes(&vole_params, rsd_w, rsd_n, rsd_codim));
  rsd_public_key_times_challenge_ref(                      //
      &vole_params, rsd_w, rsd_n, rsd_codim,               //
      chall_a_H.data(), chall_a_y.data(), chall_a.data(),  //
      pk_seed.data(),                                      //
      y.data(),                                            //
      tmp.data());
  ASSERT_EQ(chall_a_y, chall_a_y0);
  for (uint64_t i = 0; i < rsd_n; i++) {
    ASSERT_EQ(chall_a_H.get(i), chall_a_H0.get(i)) << "from seed, row " << i;
  }
}

}  // namespace

TEST(rsd, rsd_public_key_times_challenge) {
  for (const vole_params_variant& v : kVoleVariants) {
    for (uint64_t lambda : {128, 192, 256}) {
      for (uint64_t rsd_w : {5, 25, 43}) {
        for (uint64_t rsd_npw : {7, 30, 102}) {
          const uint64_t rsd_n = rsd_w * rsd_npw;
          for (uint64_t rsd_codim : {43, 48, 157}) {
            if (rsd_n < rsd_codim) continue;
            check_pk_times_challenge(v, lambda, rsd_w, rsd_n, rsd_codim);
          }
        }
      }
    }
  }
}

// The fused row-times-challenge kernels specialise on the row word count
// ceil(rsd_codim/64) and fall back to a generic path beyond the specialised
// range, and they are software-pipelined over the rows. This sweeps rsd_codim so
// that every specialisation is instantiated (plus the generic path), crossing
// the cipher-block boundaries in both directions, and varies the number of
// generated rows over the pipeline's edge cases (1 and 2 rows, odd and even).
// rsd_w is 1 so that rsd_n - rsd_codim is exactly the requested row count.
TEST(rsd, rsd_public_key_times_challenge_row_sizes) {
  for (const vole_params_variant& v : kVoleVariants) {
    for (uint64_t lambda : {128, 192, 256}) {
      for (uint64_t nwords = 1; nwords <= 17; ++nwords) {
        for (uint64_t rsd_codim : {64 * nwords - 63, 64 * nwords - 8, 64 * nwords}) {
          if (!rsd_codim_is_supported(lambda, rsd_codim)) continue;
          for (uint64_t n_minus_k : {1, 2, 3, 9, 16}) {
            check_pk_times_challenge(v, lambda, /*rsd_w=*/1, rsd_codim + n_minus_k, rsd_codim);
          }
        }
      }
    }
  }
}
