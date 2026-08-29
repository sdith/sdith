// PRNG wrapper-layer tests (complements sdith_prng_kat_test.cpp, which pins the
// round-3 domain-separated GGM seed/commit PRGs).
//
// Coverage here:
//   * ref-vs-avx2 equivalence for the GGM and VOLE RNGs (x86 only).
//   * xof wrapper self-consistency (split vs combined, incremental vs concatenated).
//   * proofow (ctx API): grind/verify consistency and ref-vs-avx equivalence.
//   * matrix_rng: row-wise generation == one-shot contiguous CTR keystream,
//     determinism, get_rows == a get_row loop, and ref-vs-avx2 equivalence.
//   * keygen_rng: the plain CTR keystream of the secret-key seed, and ref-vs-avx2.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "aes128_ctrle.h"        // ctr128_t + aes128 low-level primitives
#include "sdith_prng.h"
#include "sdith_prng_private.h"  // matrix_rng_* / keygen_rng_* struct layouts
#include "testlib/testlib.h"

namespace {

std::vector<uint8_t> ramp(size_t n, uint8_t base) {
  std::vector<uint8_t> v(n);
  for (size_t i = 0; i < n; ++i) v[i] = (uint8_t)(base + i);
  return v;
}

}  // namespace

// --- extended leaf seed: extend + ext core == raw shim (runs everywhere) ---
// The whole point of the optimization: running the key schedule once (extend)
// and feeding the result to the ext commit/vole cores must produce exactly the
// same bytes as the original raw-seed path.

// --- ref vs avx2 (x86 only; compiled out on ARM) ---

#ifdef __x86_64__


namespace {
struct cat_ext_equiv {
  const char* name;
  EXTEND_LEAF_SEED_F* extend_ref;
  EXTEND_LEAF_SEED_F* extend_avx2;
  GGM_EXTSEED_RNG_COMMIT_F* commit_ref;
  GGM_EXTSEED_RNG_COMMIT_F* commit_avx2;
  VOLE_EXTSEED_RNG_F* vole_ref;
  VOLE_EXTSEED_RNG_F* vole_avx2;
  uint64_t seed_bytes;
  uint64_t ext_bytes;
  uint64_t commit_bytes;
};
const cat_ext_equiv kCatExtEquiv[] = {
    {"cat1", //
      extend_leaf_seed_cat1_aes128_ref, //
      extend_leaf_seed_cat1_aes128_avx2, //
      ggm_commit_rng_ext_cat1_aes128_ref,//
     ggm_commit_rng_ext_cat1_aes128_avx2, //
      vole_rng_ext_cat1_aes128_ctrle_ref, //
      vole_rng_ext_cat1_aes128_ctrle_nocarry_avx2, //
      16,extended_node_seed_bytes_cat1_aes128(), 32},
    {"cat3", //
      extend_leaf_seed_cat3_rijndael256_ref, //
      extend_leaf_seed_cat3_rijndael256_avx2, //
     ggm_commit_rng_ext_cat3_rijndael256_ref, //
      ggm_commit_rng_ext_cat3_rijndael256_avx2, //
     vole_rng_ext_cat3_rijndael256_ctrle_ref, //
      vole_rng_ext_cat3_rijndael256_ctrle_avx2, // TODO implement a nocarry version
      24,extended_node_seed_bytes_cat3_rijndael256(), 48},
    {"cat5", //
      extend_leaf_seed_cat5_rijndael256_ref, //
      extend_leaf_seed_cat5_rijndael256_avx2, //
     ggm_commit_rng_ext_cat5_rijndael256_ref, //
      ggm_commit_rng_ext_cat5_rijndael256_avx2, //
     vole_rng_ext_cat5_rijndael256_ctrle_ref, //
      vole_rng_ext_cat5_rijndael256_ctrle_avx2, // TODO implement a nocarry version
      32,extended_node_seed_bytes_cat5_rijndael256(), 64},
};
}  // namespace

TEST(prng_equiv, extended_seed_path) {
  // NOTE: the extended seed (expanded round keys) is an implementation-PRIVATE
  // layout — set_key_ref and set_key_avx2 legitimately store the round keys in
  // different byte orders. Production always pairs an impl's extend with the SAME
  // impl's cores, so only the final rng outputs need to match across ref/avx2;
  // never cross-feed a ref extended seed into an avx2 core (or vice versa).
  for (const cat_ext_equiv& c : kCatExtEquiv) {
    std::vector<uint64_t> salt(c.seed_bytes / 8);
    std::vector<uint8_t> seed(c.seed_bytes);
    randomize(salt.data(), salt.size());
    // the GGM_TWEAK_BITS lsb of the salt must be zero: they carry the tweak
    salt[0] <<= GGM_TWEAK_BITS;
    randomize(seed.data(), seed.size());
    std::vector<uint8_t> ext_r(c.ext_bytes), ext_a(c.ext_bytes);
    c.extend_ref(ext_r.data(), seed.data());
    c.extend_avx2(ext_a.data(), seed.data());
    // ext commit core: ref(ext_ref) == avx2(ext_avx2)
    std::vector<uint8_t> cr(c.commit_bytes), ca(c.commit_bytes);
    c.commit_ref(cr.data(), salt.data(), ext_r.data(), 5);
    c.commit_avx2(ca.data(), salt.data(), ext_a.data(), 5);
    EXPECT_EQ(cr, ca) << c.name << " ext commit ref!=avx2";
    // ext vole core: ref(ext_ref) == avx2(ext_avx2), for a few repetition indexes
    for (uint64_t n : {(uint64_t)1, (uint64_t)49, (uint64_t)200}) {
      uint64_t sliced_n = (n + 31) & UINT64_C(-32);
      for (uint64_t repet_idx : {(uint64_t)0, (uint64_t)1, (uint64_t)31}) {
        aligned_vector_u8 vr(32, sliced_n), va(32, sliced_n);
        c.vole_ref(vr.data(), sliced_n, salt.data(), ext_r.data(), repet_idx);
        c.vole_avx2(va.data(), sliced_n, salt.data(), ext_a.data(), repet_idx);
        EXPECT_EQ(memcmp(vr.data(), va.data(), sliced_n), 0)
            << c.name << " ext vole ref!=avx2 at n=" << n << " repet=" << repet_idx;
      }
    }
  }
}
#endif  // __x86_64__

// --- xof wrapper self-consistency ---

namespace {
void check_xof_consistency(const xof_functions& x) {
  std::vector<uint8_t> in = ramp(100, 1);
  // split (init/seed/finalize/output) == combined shortcuts
  xof_ctx c1 __attribute__((aligned(16))), c2 __attribute__((aligned(16)));
  uint8_t o1[64], o2[64];
  x.xof_init(&c1);
  x.xof_seed(&c1, in.data(), in.size());
  x.xof_finalize(&c1);
  x.xof_output(&c1, o1, sizeof(o1));
  x.xof_init_and_seed(&c2, in.data(), in.size());
  x.xof_finalize_and_output(&c2, o2, sizeof(o2));
  EXPECT_EQ(0, memcmp(o1, o2, sizeof(o1)));
  // incremental seed == one concatenated seed
  xof_ctx c3 __attribute__((aligned(16))), c4 __attribute__((aligned(16)));
  uint8_t o3[64], o4[64];
  x.xof_init(&c3);
  x.xof_seed(&c3, in.data(), 40);
  x.xof_seed(&c3, in.data() + 40, 60);
  x.xof_finalize(&c3);
  x.xof_output(&c3, o3, sizeof(o3));
  x.xof_init(&c4);
  x.xof_seed(&c4, in.data(), 100);
  x.xof_finalize(&c4);
  x.xof_output(&c4, o4, sizeof(o4));
  EXPECT_EQ(0, memcmp(o3, o4, sizeof(o3)));
}
}  // namespace

TEST(prng_xof, shake128_consistency) { check_xof_consistency(xof_shake128); }
TEST(prng_xof, shake256_consistency) { check_xof_consistency(xof_shake256); }

// --- proofow (cipher, cat1): grind/verify consistency + ref/avx equivalence ---
//
// The proofow_ctx is a (non-thread-safe) workspace: after init, each grind/verify
// call is stateless (it rederives the plaintext counter from its ctr argument), so
// a single initialized ctx can be reused across calls.

namespace {
// Aligned scratch large enough for a proofow_state128_t (which is aligned(32)).
struct alignas(32) proofow_ctx_buf {
  uint64_t raw[512];
  proofow_ctx_t* ptr() { return reinterpret_cast<proofow_ctx_t*>(raw); }
};

// cat1 params: kappa=tau=11 -> delta0 is (11*11+7)/8 = 16 bytes. w small so grind
// finds a solution in ~2^w iterations (instant) yet delta0 comparisons stay meaningful.
constexpr uint64_t kLambda = 128, kKappa = 11, kTau = 11, kW = 8;
uint64_t proofow_cat1_delta_bytes() { return (kTau * kKappa + 7) >> 3; }
}  // namespace

// The ctr produced by grind must be accepted by verify, yielding the same delta0;
// a guaranteed non-solution must be rejected.
TEST(prng_proofow, cipher_cat1_grind_verify_consistency) {
  std::vector<uint8_t> h_piop(32);
  randomize(h_piop.data(), h_piop.size());

  ASSERT_LE(bytes_of_proofow_ctx_cipher_cat1(), sizeof(proofow_ctx_buf::raw));
  proofow_ctx_buf ctx;
  proofow_init_cipher_cat1_ref(ctx.ptr(), kLambda, kKappa, kTau, kW, h_piop.data());

  const uint64_t delta_bytes = proofow_cat1_delta_bytes();
  std::vector<uint8_t> d_grind(delta_bytes, 0x00), d_verify(delta_bytes, 0xAA);

  uint64_t ctr = 0;
  ASSERT_EQ(1, proofow_grind_w_cipher_cat1_ref(ctx.ptr(), d_grind.data(), &ctr))
      << "grind found no solution (w too large?)";

  // verify at the grind ctr accepts and reproduces the same delta0.
  EXPECT_EQ(1, proofow_verify_w_cipher_cat1_ref(ctx.ptr(), d_verify.data(), ctr))
      << "verify rejected the ctr produced by grind";
  EXPECT_EQ(d_grind, d_verify) << "verify delta0 != grind delta0";

  // grind returns the FIRST solution >= start, so ctr-1 is a guaranteed non-solution.
  if (ctr > 0) {
    std::vector<uint8_t> tmp(delta_bytes);
    EXPECT_EQ(0, proofow_verify_w_cipher_cat1_ref(ctx.ptr(), tmp.data(), ctr - 1))
        << "verify accepted a non-solution ctr";
  }
}

// Same grind->verify consistency for the cat5 cipher proofow (rijndael256 + shake256).
// h_piop is 2*lambda = 512 bits = 64 bytes for cat5.
TEST(prng_proofow, cipher_cat5_grind_verify_consistency) {
  std::vector<uint8_t> h_piop(64);
  randomize(h_piop.data(), h_piop.size());

  ASSERT_LE(bytes_of_proofow_ctx_cipher_cat5(), sizeof(proofow_ctx_buf::raw));
  proofow_ctx_buf ctx;
  proofow_init_cipher_cat5_ref(ctx.ptr(), 256, kKappa, kTau, kW, h_piop.data());

  const uint64_t delta_bytes = proofow_cat1_delta_bytes();  // (kTau*kKappa+7)/8, same dims
  std::vector<uint8_t> d_grind(delta_bytes, 0x00), d_verify(delta_bytes, 0xAA);

  uint64_t ctr = 0;
  ASSERT_EQ(1, proofow_grind_w_cipher_cat5_ref(ctx.ptr(), d_grind.data(), &ctr))
      << "grind found no solution (w too large?)";

  // verify at the grind ctr accepts and reproduces the same delta0.
  EXPECT_EQ(1, proofow_verify_w_cipher_cat5_ref(ctx.ptr(), d_verify.data(), ctr))
      << "verify rejected the ctr produced by grind";
  EXPECT_EQ(d_grind, d_verify) << "verify delta0 != grind delta0";

  // grind returns the FIRST solution >= start, so ctr-1 is a guaranteed non-solution.
  if (ctr > 0) {
    std::vector<uint8_t> tmp(delta_bytes);
    EXPECT_EQ(0, proofow_verify_w_cipher_cat5_ref(ctx.ptr(), tmp.data(), ctr - 1))
        << "verify accepted a non-solution ctr";
  }
}

// Same grind->verify consistency for the cat3 cipher proofow (rijndael256 + shake256).
// h_piop is 2*lambda = 384 bits = 48 bytes for cat3.
TEST(prng_proofow, cipher_cat3_grind_verify_consistency) {
  std::vector<uint8_t> h_piop(48);
  randomize(h_piop.data(), h_piop.size());

  ASSERT_LE(bytes_of_proofow_ctx_cipher_cat3(), sizeof(proofow_ctx_buf::raw));
  proofow_ctx_buf ctx;
  proofow_init_cipher_cat3_ref(ctx.ptr(), 192, kKappa, kTau, kW, h_piop.data());

  const uint64_t delta_bytes = proofow_cat1_delta_bytes();  // (kTau*kKappa+7)/8, same dims
  std::vector<uint8_t> d_grind(delta_bytes, 0x00), d_verify(delta_bytes, 0xAA);

  uint64_t ctr = 0;
  ASSERT_EQ(1, proofow_grind_w_cipher_cat3_ref(ctx.ptr(), d_grind.data(), &ctr))
      << "grind found no solution (w too large?)";

  // verify at the grind ctr accepts and reproduces the same delta0.
  EXPECT_EQ(1, proofow_verify_w_cipher_cat3_ref(ctx.ptr(), d_verify.data(), ctr))
      << "verify rejected the ctr produced by grind";
  EXPECT_EQ(d_grind, d_verify) << "verify delta0 != grind delta0";

  // grind returns the FIRST solution >= start, so ctr-1 is a guaranteed non-solution.
  if (ctr > 0) {
    std::vector<uint8_t> tmp(delta_bytes);
    EXPECT_EQ(0, proofow_verify_w_cipher_cat3_ref(ctx.ptr(), tmp.data(), ctr - 1))
        << "verify accepted a non-solution ctr";
  }
}

// Same grind->verify consistency for the shake-based proofow variants (single
// impl, runs everywhere): the ctr found by grind is accepted by verify with the
// same delta0, and a guaranteed non-solution (ctr-1) is rejected.
namespace {
struct shake_proofow_variant {
  const char* name;
  BYTES_OF_PROOFOW_CTX_F* ctx_bytes;
  PROOFOW_INIT_F* init;
  PROOFOW_GRIND_W_F* grind;
  PROOFOW_VERIFY_W_F* verify;
  uint64_t lambda;  // h_piop is 2*lambda bits
};
const shake_proofow_variant kShakeProofow[] = {
    {"cat1", bytes_of_proofow_ctx_shake_cat1, proofow_init_shake_cat1, proofow_grind_w_shake_cat1,
     proofow_verify_w_shake_cat1, 128},
    {"cat3", bytes_of_proofow_ctx_shake_cat3, proofow_init_shake_cat3, proofow_grind_w_shake_cat3,
     proofow_verify_w_shake_cat3, 192},
    {"cat5", bytes_of_proofow_ctx_shake_cat5, proofow_init_shake_cat5, proofow_grind_w_shake_cat5,
     proofow_verify_w_shake_cat5, 256},
};
}  // namespace

TEST(prng_proofow, shake_grind_verify_consistency) {
  for (const shake_proofow_variant& v : kShakeProofow) {
    const uint64_t hp_bytes = (v.lambda * 2) >> 3;
    const uint64_t delta_bytes = (kKappa * kTau + 7) >> 3;
    std::vector<uint8_t> h_piop(hp_bytes);
    randomize(h_piop.data(), h_piop.size());

    ASSERT_LE(v.ctx_bytes(), sizeof(proofow_ctx_buf::raw)) << v.name;
    proofow_ctx_buf ctx;
    v.init(ctx.ptr(), v.lambda, kKappa, kTau, kW, h_piop.data());

    std::vector<uint8_t> d_grind(delta_bytes, 0x00), d_verify(delta_bytes, 0xAA);
    uint64_t ctr = 0;
    ASSERT_EQ(1, v.grind(ctx.ptr(), d_grind.data(), &ctr)) << v.name << " grind found no solution";
    EXPECT_EQ(1, v.verify(ctx.ptr(), d_verify.data(), ctr)) << v.name << " verify rejected grind ctr";
    EXPECT_EQ(d_grind, d_verify) << v.name << " verify delta0 != grind delta0";
    if (ctr > 0) {
      std::vector<uint8_t> tmp(delta_bytes);
      EXPECT_EQ(0, v.verify(ctx.ptr(), tmp.data(), ctr - 1)) << v.name << " verify accepted a non-solution";
    }
  }
}

#ifdef __x86_64__
// The ref and avx init must build a byte-identical context: everything is derived
// from the same shake stream, and the round keys (rk) now share one little-endian
// layout, so the whole workspace matches.
TEST(prng_proofow, cipher_cat1_init_ref_matches_avx) {
  std::vector<uint8_t> h_piop(32);
  randomize(h_piop.data(), h_piop.size());

  const uint64_t ctx_bytes = bytes_of_proofow_ctx_cipher_cat1();
  ASSERT_LE(ctx_bytes, sizeof(proofow_ctx_buf::raw));
  proofow_ctx_buf ctx_r, ctx_a;
  memset(ctx_r.raw, 0, sizeof(ctx_r.raw));  // zero the not-yet-written scratch (e.g. c[])
  memset(ctx_a.raw, 0, sizeof(ctx_a.raw));  // so the two contexts compare equal
  proofow_init_cipher_cat1_ref(ctx_r.ptr(), kLambda, kKappa, kTau, kW, h_piop.data());
  proofow_init_cipher_cat1_avx(ctx_a.ptr(), kLambda, kKappa, kTau, kW, h_piop.data());
  EXPECT_EQ(0, memcmp(ctx_r.raw, ctx_a.raw, ctx_bytes)) << "ref/avx init produced different contexts";
}

// ref and avx must agree on every grind result (ctr + delta0), and be freely
// cross-compatible now that they share the round-key layout. We drive a SINGLE
// shared context with both impls: this feeds the ref-written round keys into the
// avx kernels (and vice versa), so it fails if the layouts ever diverge again.
TEST(prng_proofow, cipher_cat1_ref_matches_avx) {
  std::vector<uint8_t> h_piop(32);
  randomize(h_piop.data(), h_piop.size());

  ASSERT_LE(bytes_of_proofow_ctx_cipher_cat1(), sizeof(proofow_ctx_buf::raw));
  proofow_ctx_buf ctx;
  proofow_init_cipher_cat1_ref(ctx.ptr(), kLambda, kKappa, kTau, kW, h_piop.data());

  const uint64_t delta_bytes = proofow_cat1_delta_bytes();

  // walk several consecutive solutions; ref and avx must agree at each step.
  uint64_t start = 0;
  for (int i = 0; i < 8; ++i) {
    std::vector<uint8_t> dr(delta_bytes, 0), da(delta_bytes, 0);
    uint64_t cr = start, ca = start;
    // both grinds run on the same (ref-initialized) context.
    ASSERT_EQ(1, proofow_grind_w_cipher_cat1_ref(ctx.ptr(), dr.data(), &cr)) << "ref grind iter " << i;
    ASSERT_EQ(1, proofow_grind_w_cipher_cat1_avx(ctx.ptr(), da.data(), &ca)) << "avx grind iter " << i;
    EXPECT_EQ(cr, ca) << "grind ctr mismatch at iter " << i;
    EXPECT_EQ(dr, da) << "grind delta0 mismatch at iter " << i;

    // cross-impl verify: each impl accepts the ctr with the same delta0.
    std::vector<uint8_t> dv(delta_bytes, 0);
    EXPECT_EQ(1, proofow_verify_w_cipher_cat1_avx(ctx.ptr(), dv.data(), cr)) << "avx verify iter " << i;
    EXPECT_EQ(dr, dv) << "avx verify delta0 != grind delta0 at iter " << i;
    dv.assign(delta_bytes, 0);
    EXPECT_EQ(1, proofow_verify_w_cipher_cat1_ref(ctx.ptr(), dv.data(), ca)) << "ref verify iter " << i;
    EXPECT_EQ(da, dv) << "ref verify delta0 != grind delta0 at iter " << i;

    start = cr + 1;  // continue the search past this solution
  }
}

// cat5/cat3 cipher proofow (rijndael256 + shake256): the dedicated avx init must build a
// byte-identical context to the ref init, and ref/avx grind+verify must agree at every step
// (the shared-context drive also proves the ref and avx round-key layouts stay compatible).
namespace {
struct cipher256_variant {
  const char* name;
  uint64_t hp_bytes;  // h_piop size (2*lambda/8)
  uint64_t lambda;
  BYTES_OF_PROOFOW_CTX_F* ctx_bytes;
  PROOFOW_INIT_F* init_ref;
  PROOFOW_INIT_F* init_avx;
  PROOFOW_GRIND_W_F* grind_ref;
  PROOFOW_GRIND_W_F* grind_avx;
  PROOFOW_VERIFY_W_F* verify_ref;
  PROOFOW_VERIFY_W_F* verify_avx;
};
const cipher256_variant kCipher256[] = {
    {"cat3", 48, 192, bytes_of_proofow_ctx_cipher_cat3, proofow_init_cipher_cat3_ref, proofow_init_cipher_cat3_avx,
     proofow_grind_w_cipher_cat3_ref, proofow_grind_w_cipher_cat3_avx, proofow_verify_w_cipher_cat3_ref,
     proofow_verify_w_cipher_cat3_avx},
    {"cat5", 64, 256, bytes_of_proofow_ctx_cipher_cat5, proofow_init_cipher_cat5_ref, proofow_init_cipher_cat5_avx,
     proofow_grind_w_cipher_cat5_ref, proofow_grind_w_cipher_cat5_avx, proofow_verify_w_cipher_cat5_ref,
     proofow_verify_w_cipher_cat5_avx},
};
}  // namespace

TEST(prng_proofow, cipher256_init_ref_matches_avx) {
  for (const cipher256_variant& v : kCipher256) {
    std::vector<uint8_t> h_piop(v.hp_bytes);
    randomize(h_piop.data(), h_piop.size());
    const uint64_t ctx_bytes = v.ctx_bytes();
    ASSERT_LE(ctx_bytes, sizeof(proofow_ctx_buf::raw)) << v.name;
    proofow_ctx_buf ctx_r, ctx_a;
    memset(ctx_r.raw, 0, sizeof(ctx_r.raw));  // zero the not-yet-written scratch (e.g. c[])
    memset(ctx_a.raw, 0, sizeof(ctx_a.raw));  // so the two contexts compare equal
    v.init_ref(ctx_r.ptr(), v.lambda, kKappa, kTau, kW, h_piop.data());
    v.init_avx(ctx_a.ptr(), v.lambda, kKappa, kTau, kW, h_piop.data());
    EXPECT_EQ(0, memcmp(ctx_r.raw, ctx_a.raw, ctx_bytes)) << v.name << " ref/avx init produced different contexts";
  }
}

TEST(prng_proofow, cipher256_ref_matches_avx) {
  for (const cipher256_variant& v : kCipher256) {
    std::vector<uint8_t> h_piop(v.hp_bytes);
    randomize(h_piop.data(), h_piop.size());
    ASSERT_LE(v.ctx_bytes(), sizeof(proofow_ctx_buf::raw)) << v.name;
    proofow_ctx_buf ctx;
    v.init_ref(ctx.ptr(), v.lambda, kKappa, kTau, kW, h_piop.data());

    const uint64_t delta_bytes = proofow_cat1_delta_bytes();  // (kTau*kKappa+7)/8, same dims
    // walk several consecutive solutions; ref and avx must agree at each step.
    uint64_t start = 0;
    for (int i = 0; i < 8; ++i) {
      std::vector<uint8_t> dr(delta_bytes, 0), da(delta_bytes, 0);
      uint64_t cr = start, ca = start;
      // both grinds run on the same (ref-initialized) context.
      ASSERT_EQ(1, v.grind_ref(ctx.ptr(), dr.data(), &cr)) << v.name << " ref grind iter " << i;
      ASSERT_EQ(1, v.grind_avx(ctx.ptr(), da.data(), &ca)) << v.name << " avx grind iter " << i;
      EXPECT_EQ(cr, ca) << v.name << " grind ctr mismatch at iter " << i;
      EXPECT_EQ(dr, da) << v.name << " grind delta0 mismatch at iter " << i;

      // cross-impl verify: each impl accepts the ctr with the same delta0.
      std::vector<uint8_t> dv(delta_bytes, 0);
      EXPECT_EQ(1, v.verify_avx(ctx.ptr(), dv.data(), cr)) << v.name << " avx verify iter " << i;
      EXPECT_EQ(dr, dv) << v.name << " avx verify delta0 != grind delta0 at iter " << i;
      dv.assign(delta_bytes, 0);
      EXPECT_EQ(1, v.verify_ref(ctx.ptr(), dv.data(), ca)) << v.name << " ref verify iter " << i;
      EXPECT_EQ(da, dv) << v.name << " ref verify delta0 != grind delta0 at iter " << i;

      start = cr + 1;  // continue the search past this solution
    }
  }
}
#endif  // __x86_64__

// TODO: missing truncated-Enc streaming: one-shot vs chunked ---

// --- matrix_rng: row-wise generation == one-shot contiguous CTR keystream ---
//
// matrix_rng generates an N x M bit matrix one row at a time: row i is the
// bpr = ceil(M/lambda) cipher blocks at counter [i*bpr, (i+1)*bpr), with the
// unused high bits of the last block masked to zero. lambda is the effective
// output block bit size: 128 for aes128 (cat1), 256 for rijndael256 (cat3/cat5).
//
// Because row i starts exactly where row i-1 ended, stacking all N rows is the
// same contiguous CTR keystream 0,1,2,... that a single "one-shot" cipher call
// would produce. These tests rebuild that one-shot keystream directly from the
// low-level primitives (independent of matrix_rng) and check:
//   * M a multiple of lambda: matrix_rng row i == one-shot row i verbatim
//     (the last full block is kept in its entirety, no bits masked off).
//   * M not a multiple: same, except the trailing bits [M, bpr*lambda) of each
//     row must be zero.

namespace {

typedef void (*matrix_init_fn)(matrix_rng_t*, const seed_t*, uint64_t);
typedef void (*matrix_get_row_fn)(const matrix_rng_t*, void*, uint64_t);
typedef void (*matrix_get_rows_fn)(const matrix_rng_t*, void*, uint64_t, uint64_t);

struct matrix_variant {
  const char* name;
  uint64_t lambda_bits;  // effective output bits per block
  uint64_t block_bytes;  // effective output bytes per block (lambda_bits / 8)
  uint64_t seed_bytes;
  matrix_init_fn init;
  matrix_get_row_fn get_row;
  matrix_get_rows_fn get_rows;
};

const matrix_variant kMatrixVariants[] = {
    {"cat1", 128, 16, 16, matrix_rng_init_aes128_cat1_ref, matrix_rng_get_row_aes128_cat1_ref,
     matrix_rng_get_rows_aes128_cat1_ref},
    {"cat3", 256, 32, 24, matrix_rng_init_rijndael256_cat3_ref, matrix_rng_get_row_rijndael256_cat3_ref,
     matrix_rng_get_rows_rijndael256_cat3_ref},
    {"cat5", 256, 32, 32, matrix_rng_init_rijndael256_cat5_ref, matrix_rng_get_row_rijndael256_cat5_ref,
     matrix_rng_get_rows_rijndael256_cat5_ref},
};

// Builds the untruncated one-shot reference: N rows of bpr blocks each, taken
// from the contiguous CTR keystream (counter 0,1,...). Every row is exactly
// bpr*block_bytes long with NO last-block masking. Uses only the low-level
// cipher primitives so it does not share code with matrix_rng.
std::vector<uint8_t> oneshot_reference(const matrix_variant& v, const uint8_t* seed, uint64_t N, uint64_t bpr) {
  const uint64_t total_blocks = N * bpr;
  std::vector<uint8_t> ref(total_blocks * v.block_bytes);
  if (strcmp(v.name, "cat1") == 0) {
    uint8_t rk[16 * 11] __attribute__((aligned(16)));
    aes128_key_schedule_x1_ref(rk, seed);
    ctr128_t ctr = {};
    aligned_vector_u8 out(32, total_blocks * 16);
    aes128_ctrle_nocarry_nblocks_ref(out.data(), rk, ctr.v8, total_blocks);
    memcpy(ref.data(), out.data(), ref.size());
  } else {
    // cat3 / cat5 both use rijndael256. cat3 zero-pads the 24-byte seed to a
    // 32-byte key and keeps only the low 24 bytes (192 bits) of each block.
    uint8_t key256[32] __attribute__((aligned(32))) = {};
    memcpy(key256, seed, v.seed_bytes);
    uint8_t rk[RIJNDAEL256_RK_BYTES] __attribute__((aligned(32)));
    rijndael256_key_schedule_x1_ref(rk, key256);
    ctr256_t ctr = {};
    aligned_vector_u8 out(32, total_blocks * 32);
    rijndael256_ctrle_nocarry_nblocks_ref(out.data(), rk, ctr.v8, total_blocks);
    if (v.block_bytes == 32) {
      memcpy(ref.data(), out.data(), ref.size());
    } else {
      for (uint64_t j = 0; j < total_blocks; ++j) memcpy(ref.data() + j * 24, out.data() + j * 32, 24);
    }
  }
  return ref;
}

// Zeroes every bit at index >= keep_bits (little-endian within each byte).
void zero_trailing_bits(std::vector<uint8_t>& row, uint64_t keep_bits) {
  uint64_t idx = keep_bits / 8;
  const uint64_t rem = keep_bits % 8;
  if (rem) {
    row[idx] &= (uint8_t)((1u << rem) - 1);
    ++idx;
  }
  for (; idx < row.size(); ++idx) row[idx] = 0;
}

void run_matrix_case(const matrix_variant& v, uint64_t N, uint64_t M) {
  const uint64_t bpr = (M + v.lambda_bits - 1) / v.lambda_bits;
  const uint64_t row_bytes = bpr * v.block_bytes;

  std::vector<uint8_t> seed(v.seed_bytes);
  randomize(seed.data(), seed.size());

  const std::vector<uint8_t> ref = oneshot_reference(v, seed.data(), N, bpr);

  matrix_rng_t rng;  // typedef is aligned(32)
  v.init(&rng, seed.data(), M);

  aligned_vector_u8 row(32, row_bytes);
  for (uint64_t i = 0; i < N; ++i) {
    v.get_row(&rng, row.data(), i);
    std::vector<uint8_t> got(row.data(), row.data() + row_bytes);
    std::vector<uint8_t> want(ref.begin() + i * row_bytes, ref.begin() + (i + 1) * row_bytes);
    if (M % v.lambda_bits != 0) zero_trailing_bits(want, M);
    EXPECT_EQ(got, want) << v.name << " N=" << N << " M=" << M << " row=" << i;
  }
}

}  // namespace

// M a multiple of lambda: matrix_rng == one-shot keystream, last block kept whole.
TEST(matrix_rng, oneshot_matches_rowwise_multiple_of_lambda) {
  for (const matrix_variant& v : kMatrixVariants) {
    for (uint64_t k : {(uint64_t)1, (uint64_t)2, (uint64_t)4, (uint64_t)7}) {
      run_matrix_case(v, 5, k * v.lambda_bits);
    }
  }
}

// M not a multiple of lambda: same as the ceil(M/lambda)-block matrix, but the
// trailing bits of every row are masked to zero.
TEST(matrix_rng, oneshot_matches_rowwise_non_multiple) {
  for (const matrix_variant& v : kMatrixVariants) {
    const std::vector<uint64_t> Ms = {1,
                                      v.lambda_bits - 1,
                                      v.lambda_bits + 1,
                                      v.lambda_bits + 7,
                                      2 * v.lambda_bits + 13,
                                      3 * v.lambda_bits - 5,
                                      100};
    for (uint64_t M : Ms) {
      if (M % v.lambda_bits == 0) continue;  // this test is for non-multiples only
      run_matrix_case(v, 4, M);
    }
  }
}

// Determinism / statelessness: same (seed, M) => identical rows regardless of
// call order or repetition; distinct rows and distinct seeds produce distinct
// output.
TEST(matrix_rng, determinism) {
  for (const matrix_variant& v : kMatrixVariants) {
    const uint64_t M = 3 * v.lambda_bits + 5;  // spans several blocks, non-multiple
    const uint64_t bpr = (M + v.lambda_bits - 1) / v.lambda_bits;
    const uint64_t row_bytes = bpr * v.block_bytes;

    std::vector<uint8_t> seed(v.seed_bytes);
    randomize(seed.data(), seed.size());

    matrix_rng_t a, b;
    v.init(&a, seed.data(), M);
    v.init(&b, seed.data(), M);

    aligned_vector_u8 ra(32, row_bytes), rb(32, row_bytes);
    // Same seed + stateless get_row: rows match across two contexts, and
    // repeated / out-of-order requests are stable.
    for (uint64_t i : {(uint64_t)0, (uint64_t)1, (uint64_t)2, (uint64_t)3, (uint64_t)7, (uint64_t)0, (uint64_t)2}) {
      v.get_row(&a, ra.data(), i);
      v.get_row(&b, rb.data(), i);
      EXPECT_EQ(0, memcmp(ra.data(), rb.data(), row_bytes)) << v.name << " determinism at row " << i;
    }
    // A single context re-queried for the same row is byte-identical.
    v.get_row(&a, ra.data(), 5);
    v.get_row(&a, rb.data(), 5);
    EXPECT_EQ(0, memcmp(ra.data(), rb.data(), row_bytes)) << v.name << " get_row not stateless";

    // Different rows use different counters -> different output.
    v.get_row(&a, ra.data(), 0);
    v.get_row(&a, rb.data(), 1);
    EXPECT_NE(0, memcmp(ra.data(), rb.data(), row_bytes)) << v.name << " rows 0 and 1 collided";

    // Flipping the seed changes every derived row.
    std::vector<uint8_t> seed2 = seed;
    seed2[0] ^= 0xFF;
    matrix_rng_t c;
    v.init(&c, seed2.data(), M);
    v.get_row(&a, ra.data(), 0);
    v.get_row(&c, rb.data(), 0);
    EXPECT_NE(0, memcmp(ra.data(), rb.data(), row_bytes)) << v.name << " seed change had no effect";
  }
}

// get_rows is the batched form of get_row: it must be byte-identical to the
// equivalent get_row loop (that identity is what makes it KAT-preserving), for
// every batch size and starting row, and it must not write past nrows rows.
TEST(matrix_rng, get_rows_matches_get_row_loop) {
  for (const matrix_variant& v : kMatrixVariants) {
    const std::vector<uint64_t> Ms = {1, v.lambda_bits, v.lambda_bits + 1, 2 * v.lambda_bits + 13,
                                      3 * v.lambda_bits - 5};
    for (uint64_t M : Ms) {
      const uint64_t bpr = (M + v.lambda_bits - 1) / v.lambda_bits;
      const uint64_t row_bytes = bpr * v.block_bytes;

      std::vector<uint8_t> seed(v.seed_bytes);
      randomize(seed.data(), seed.size());
      matrix_rng_t rng;
      v.init(&rng, seed.data(), M);

      for (uint64_t first : {(uint64_t)0, (uint64_t)1, (uint64_t)5, (uint64_t)64}) {
        for (uint64_t nrows : {(uint64_t)1, (uint64_t)2, (uint64_t)3, (uint64_t)4, (uint64_t)9}) {
          // reference: nrows successive get_row calls, packed at the natural stride
          std::vector<uint8_t> want(nrows * row_bytes);
          aligned_vector_u8 one(32, row_bytes);
          for (uint64_t i = 0; i < nrows; ++i) {
            v.get_row(&rng, one.data(), first + i);
            memcpy(want.data() + i * row_bytes, one.data(), row_bytes);
          }
          // batched: one call, plus a guard byte to catch writes past the batch
          aligned_vector_u8 got(32, nrows * row_bytes + v.block_bytes);
          memset(got.data(), 0xCD, nrows * row_bytes + v.block_bytes);
          v.get_rows(&rng, got.data(), first, nrows);
          EXPECT_EQ(0, memcmp(got.data(), want.data(), nrows * row_bytes))
              << v.name << " get_rows != get_row loop M=" << M << " first=" << first << " nrows=" << nrows;
          for (uint64_t b = 0; b < v.block_bytes; ++b) {
            EXPECT_EQ(0xCD, got.data()[nrows * row_bytes + b])
                << v.name << " get_rows wrote past the batch M=" << M << " nrows=" << nrows;
          }
        }
      }
    }
  }
}

// --- matrix_rng: ref vs avx2 equivalence (x86 only) ---
//
// The avx2 key schedule is bit-identical to the ref one, so init_ref and init_avx
// must build the same context and get_row_ref / get_row_avx must be freely
// cross-compatible (a ref-built context fed to an avx get_row and vice versa).
#ifdef __x86_64__
namespace {
struct matrix_variant_equiv {
  const char* name;
  uint64_t lambda_bits;
  uint64_t block_bytes;
  uint64_t seed_bytes;
  uint64_t ctx_bytes;  // size of the concrete context struct (fully written by init)
  matrix_init_fn init_ref;
  matrix_init_fn init_avx;
  matrix_get_row_fn get_row_ref;
  matrix_get_row_fn get_row_avx;
  matrix_get_rows_fn get_rows_ref;
  matrix_get_rows_fn get_rows_avx;
};
const matrix_variant_equiv kMatrixEquiv[] = {
    {"cat1", 128, 16, 16, sizeof(struct matrix_rng_aes128_cat1_t), matrix_rng_init_aes128_cat1_ref,
     matrix_rng_init_aes128_cat1_avx, matrix_rng_get_row_aes128_cat1_ref, matrix_rng_get_row_aes128_cat1_avx,
     matrix_rng_get_rows_aes128_cat1_ref, matrix_rng_get_rows_aes128_cat1_avx},
    {"cat3", 256, 32, 24, sizeof(struct matrix_rng_rijndael256_cat3_t), matrix_rng_init_rijndael256_cat3_ref,
     matrix_rng_init_rijndael256_cat3_avx, matrix_rng_get_row_rijndael256_cat3_ref,
     matrix_rng_get_row_rijndael256_cat3_avx, matrix_rng_get_rows_rijndael256_cat3_ref,
     matrix_rng_get_rows_rijndael256_cat3_avx},
    {"cat5", 256, 32, 32, sizeof(struct matrix_rng_rijndael256_cat5_t), matrix_rng_init_rijndael256_cat5_ref,
     matrix_rng_init_rijndael256_cat5_avx, matrix_rng_get_row_rijndael256_cat5_ref,
     matrix_rng_get_row_rijndael256_cat5_avx, matrix_rng_get_rows_rijndael256_cat5_ref,
     matrix_rng_get_rows_rijndael256_cat5_avx},
};

void run_matrix_equiv(const matrix_variant_equiv& v, uint64_t N, uint64_t M) {
  const uint64_t bpr = (M + v.lambda_bits - 1) / v.lambda_bits;
  const uint64_t row_bytes = bpr * v.block_bytes;

  std::vector<uint8_t> seed(v.seed_bytes);
  randomize(seed.data(), seed.size());

  // zero the whole opaque buffer so trailing struct padding compares equal.
  matrix_rng_t rr, ra;
  memset(&rr, 0, sizeof(rr));
  memset(&ra, 0, sizeof(ra));
  v.init_ref(&rr, seed.data(), M);
  v.init_avx(&ra, seed.data(), M);
  EXPECT_EQ(0, memcmp(&rr, &ra, v.ctx_bytes)) << v.name << " init ref!=avx (M=" << M << ")";

  aligned_vector_u8 a(32, row_bytes), b(32, row_bytes), c(32, row_bytes), d(32, row_bytes);
  for (uint64_t i = 0; i < N; ++i) {
    v.get_row_ref(&rr, a.data(), i);
    v.get_row_avx(&ra, b.data(), i);
    EXPECT_EQ(0, memcmp(a.data(), b.data(), row_bytes)) << v.name << " get_row ref!=avx M=" << M << " row=" << i;
    // cross-feed: each impl's get_row on the other impl's context.
    v.get_row_avx(&rr, c.data(), i);
    v.get_row_ref(&ra, d.data(), i);
    EXPECT_EQ(0, memcmp(a.data(), c.data(), row_bytes)) << v.name << " avx get_row on ref ctx M=" << M << " row=" << i;
    EXPECT_EQ(0, memcmp(a.data(), d.data(), row_bytes)) << v.name << " ref get_row on avx ctx M=" << M << " row=" << i;
  }
  // same for the batched form, on a batch that straddles the 4-block grouping of
  // the underlying CTR kernels.
  const uint64_t nrows = N;
  aligned_vector_u8 ba(32, nrows * row_bytes), bb(32, nrows * row_bytes);
  v.get_rows_ref(&rr, ba.data(), 0, nrows);
  v.get_rows_avx(&ra, bb.data(), 0, nrows);
  EXPECT_EQ(0, memcmp(ba.data(), bb.data(), nrows * row_bytes)) << v.name << " get_rows ref!=avx M=" << M;
  // and both must agree with the get_row loop they replace
  for (uint64_t i = 0; i < nrows; ++i) {
    v.get_row_ref(&rr, a.data(), i);
    EXPECT_EQ(0, memcmp(a.data(), ba.data() + i * row_bytes, row_bytes))
        << v.name << " get_rows != get_row loop M=" << M << " row=" << i;
  }
}
}  // namespace

TEST(matrix_rng, ref_matches_avx) {
  for (const matrix_variant_equiv& v : kMatrixEquiv) {
    // a mix of multiples and non-multiples of lambda, single- and multi-block.
    const std::vector<uint64_t> Ms = {1,
                                      v.lambda_bits,
                                      v.lambda_bits + 1,
                                      v.lambda_bits + 7,
                                      2 * v.lambda_bits,
                                      2 * v.lambda_bits + 13,
                                      3 * v.lambda_bits - 5,
                                      100};
    for (uint64_t M : Ms) run_matrix_equiv(v, 5, M);
  }
}
#endif  // __x86_64__

// --- keygen_rng: the plain CTR keystream of the secret-key seed -------------
//
// The keygen prng is nothing but a block-cipher CTR keystream with a zero IV,
// read as little-endian uint32s: cat1 is aes128 keyed with the 16-byte seed,
// cat3 and cat5 are rijndael256 keyed with the seed padded to 32 bytes (cat3's
// 24-byte seed gets 64 zero bits in the MSB). These tests rebuild that
// keystream directly from the low-level primitives (no keygen_rng code
// involved) and check the draws against it, refills included: the draws span
// several buffer batches, so a mistake in the refill counter shows up.

namespace {

typedef void (*keygen_init_fn)(keygen_rng_ctx*, const seed_t*);
typedef uint32_t (*keygen_next_fn)(keygen_rng_ctx*);

struct keygen_variant {
  const char* name;
  uint64_t block_bytes;  // cipher block size (16 = aes128, 32 = rijndael256)
  uint64_t seed_bytes;   // lambda / 8
  uint64_t ctx_bytes;    // size of the concrete context struct
  keygen_init_fn init_ref;
  keygen_next_fn next_ref;
  keygen_init_fn init_avx;
  keygen_next_fn next_avx;
};

const keygen_variant kKeygenVariants[] = {
#ifdef __x86_64__
    {"cat1", 16, 16, sizeof(struct keygen_rng_aes128_cat1_t), keygen_rng_init_aes128_cat1_ref,
     keygen_rng_next_u32_aes128_cat1_ref, keygen_rng_init_aes128_cat1_avx, keygen_rng_next_u32_aes128_cat1_avx},
    {"cat3", 32, 24, sizeof(struct keygen_rng_rijndael256_t), keygen_rng_init_rijndael256_cat3_ref,
     keygen_rng_next_u32_rijndael256_ref, keygen_rng_init_rijndael256_cat3_avx, keygen_rng_next_u32_rijndael256_avx},
    {"cat5", 32, 32, sizeof(struct keygen_rng_rijndael256_t), keygen_rng_init_rijndael256_cat5_ref,
     keygen_rng_next_u32_rijndael256_ref, keygen_rng_init_rijndael256_cat5_avx, keygen_rng_next_u32_rijndael256_avx},
#else
    {"cat1", 16, 16, sizeof(struct keygen_rng_aes128_cat1_t), keygen_rng_init_aes128_cat1_ref,
     keygen_rng_next_u32_aes128_cat1_ref, nullptr, nullptr},
    {"cat3", 32, 24, sizeof(struct keygen_rng_rijndael256_t), keygen_rng_init_rijndael256_cat3_ref,
     keygen_rng_next_u32_rijndael256_ref, nullptr, nullptr},
    {"cat5", 32, 32, sizeof(struct keygen_rng_rijndael256_t), keygen_rng_init_rijndael256_cat5_ref,
     keygen_rng_next_u32_rijndael256_ref, nullptr, nullptr},
#endif
};

// nblocks of the contiguous CTR keystream (counter 0,1,...), from the low-level
// cipher primitives only.
std::vector<uint8_t> keygen_keystream(const keygen_variant& v, const uint8_t* seed, uint64_t nblocks) {
  aligned_vector_u8 out(32, nblocks * v.block_bytes);
  if (v.block_bytes == 16) {
    uint8_t rk[16 * 11] __attribute__((aligned(16)));
    aes128_key_schedule_x1_ref(rk, seed);
    ctr128_t ctr = {};
    aes128_ctrle_nocarry_nblocks_ref(out.data(), rk, ctr.v8, nblocks);
  } else {
    uint8_t key256[32] __attribute__((aligned(32))) = {};  // the MSB padding of cat3
    memcpy(key256, seed, v.seed_bytes);
    uint8_t rk[RIJNDAEL256_RK_BYTES] __attribute__((aligned(32)));
    rijndael256_key_schedule_x1_ref(rk, key256);
    ctr256_t ctr = {};
    rijndael256_ctrle_nocarry_nblocks_ref(out.data(), rk, ctr.v8, nblocks);
  }
  return std::vector<uint8_t>(out.data(), out.data() + nblocks * v.block_bytes);
}

constexpr uint64_t kKeygenDraws = 64;  // spans several buffer refills in every category

}  // namespace

TEST(keygen_rng, matches_ctr_keystream) {
  for (const keygen_variant& v : kKeygenVariants) {
    std::vector<uint8_t> seed(v.seed_bytes);
    randomize(seed.data(), seed.size());
    const uint64_t nblocks = (4 * kKeygenDraws + v.block_bytes - 1) / v.block_bytes;
    const std::vector<uint8_t> ks = keygen_keystream(v, seed.data(), nblocks);

    keygen_rng_ctx rng;
    v.init_ref(&rng, seed.data());
    for (uint64_t i = 0; i < kKeygenDraws; ++i) {
      uint32_t want;
      memcpy(&want, ks.data() + 4 * i, 4);
      EXPECT_EQ(want, v.next_ref(&rng)) << v.name << " draw " << i;
    }
  }
}

// --- keygen_rng: ref vs avx2 equivalence (x86 only) ---
//
// The avx2 key schedule and CTR kernels are bit-identical to the ref ones, so
// the two inits must build the same context and the two draw functions must be
// freely cross-compatible (a ref-built context drawn from by the avx function
// and vice versa).
#ifdef __x86_64__
TEST(keygen_rng, ref_matches_avx) {
  for (const keygen_variant& v : kKeygenVariants) {
    std::vector<uint8_t> seed(v.seed_bytes);
    randomize(seed.data(), seed.size());

    // zero the whole opaque buffer so the untouched keystream buffer and the
    // trailing struct padding compare equal.
    keygen_rng_ctx rr, ra, cross;
    memset(&rr, 0, sizeof(rr));
    memset(&ra, 0, sizeof(ra));
    memset(&cross, 0, sizeof(cross));
    v.init_ref(&rr, seed.data());
    v.init_avx(&ra, seed.data());
    v.init_ref(&cross, seed.data());
    EXPECT_EQ(0, memcmp(&rr, &ra, v.ctx_bytes)) << v.name << " init ref!=avx";

    for (uint64_t i = 0; i < kKeygenDraws; ++i) {
      const uint32_t a = v.next_ref(&rr);
      EXPECT_EQ(a, v.next_avx(&ra)) << v.name << " draw ref!=avx at " << i;
      // cross-feed: the avx draw on a ref-built context
      EXPECT_EQ(a, v.next_avx(&cross)) << v.name << " avx draw on ref ctx at " << i;
    }
  }
}
#endif  // __x86_64__
