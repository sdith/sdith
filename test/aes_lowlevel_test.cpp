// Low-level lib/aes primitives: batched key schedules + no-carry CTR encryption.
//
// Coverage:
//   * ref no-carry CTR (aes128 / rijndael256) == a raw single-block CTR oracle,
//     including a low-64 wrap case that pins the "no middle carry" contract.
//   * ref fixed-size blocks (x1..x4) and the general nblocks agree.
//   * ref batched key schedule (xN) == the existing set_key round keys.
//   * ref vs avx2 equality for every function (x86 only; see the __x86_64__ block).

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "aes128_ctrle.h"
#include "aes_ansi_ref.h"
#include "rijndael256.h"
#include "rijndael256_ctrle.h"
#include "testlib/testlib.h"

namespace {

// raw AES-128 CTR oracle: block i = AES(key, ctr with low64 += i), low-64 increment only.
std::vector<uint8_t> aes_ctr_oracle(const uint8_t* key16, const uint8_t* ctr16, uint64_t n) {
  uint8_t rk[16 * 11];
  aes128_set_key_ref(rk, key16);
  ctr128_t c;
  memcpy(c.v8, ctr16, 16);
  std::vector<uint8_t> out(16 * n);
  for (uint64_t i = 0; i < n; ++i) {
    aes128_encrypt_1block_ref(out.data() + 16 * i, c.v8, rk);
    c.v64[0] += 1;
  }
  return out;
}

// raw Rijndael-256 CTR oracle (32-byte blocks), low-64 increment only.
std::vector<uint8_t> rij_ctr_oracle(const uint8_t* key32, const uint8_t* ctr32, uint64_t n) {
  rijndael256_rk_t rk;
  rijndael256_key_schedule_ref(&rk, key32);
  ctr256_t c;
  memcpy(c.v8, ctr32, 32);
  std::vector<uint8_t> out(32 * n);
  for (uint64_t i = 0; i < n; ++i) {
    rijndael256_encrypt_1block_ref(out.data() + 32 * i, c.v8, &rk);
    c.v64[0] += 1;
  }
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// ref no-carry CTR == raw oracle (aes128)
// ---------------------------------------------------------------------------
TEST(aes_lowlevel, aes128_nocarry_ref_matches_oracle) {
  uint8_t key[16], ctr[16];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  uint8_t rk[16 * 11];
  aes128_key_schedule_x1_ref(rk, key);

  uint8_t out[16 * 4];
  aes128_ctrle_nocarry_1block_ref(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 1).data(), 16));
  aes128_ctrle_nocarry_2block_ref(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 2).data(), 32));
  aes128_ctrle_nocarry_3blocks_ref(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 3).data(), 48));
  aes128_ctrle_nocarry_4blocks_ref(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 4).data(), 64));

  for (uint64_t n : {(uint64_t)1, (uint64_t)5, (uint64_t)16, (uint64_t)37}) {
    std::vector<uint8_t> got(16 * n);
    aes128_ctrle_nocarry_nblocks_ref(got.data(), rk, ctr, n);
    EXPECT_EQ(got, aes_ctr_oracle(key, ctr, n)) << "aes128 nblocks n=" << n;
  }
}

// low-64 wrap: no carry into the upper 64 bits (contract check).
TEST(aes_lowlevel, aes128_nocarry_ref_no_middle_carry) {
  uint8_t key[16];
  randomize(key, sizeof(key));
  uint8_t rk[16 * 11];
  aes128_key_schedule_x1_ref(rk, key);
  ctr128_t ctr;
  randomize(ctr.v8, 16);
  ctr.v64[0] = UINT64_C(0xFFFFFFFFFFFFFFFE);  // wraps within 4 blocks
  std::vector<uint8_t> got(16 * 4);
  aes128_ctrle_nocarry_4blocks_ref(got.data(), rk, ctr.v8);
  EXPECT_EQ(got, aes_ctr_oracle(key, ctr.v8, 4));
}

// ---------------------------------------------------------------------------
// ref no-carry CTR == raw oracle (rijndael256)
// ---------------------------------------------------------------------------
TEST(aes_lowlevel, rijndael256_nocarry_ref_matches_oracle) {
  uint8_t key[32], ctr[32];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  uint8_t rk[RIJNDAEL256_RK_BYTES];
  rijndael256_key_schedule_x1_ref(rk, key);

  uint8_t out[32 * 2];
  rijndael256_ctrle_nocarry_1block_ref(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, rij_ctr_oracle(key, ctr, 1).data(), 32));
  rijndael256_ctrle_nocarry_2block_ref(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, rij_ctr_oracle(key, ctr, 2).data(), 64));

  for (uint64_t n : {(uint64_t)1, (uint64_t)3, (uint64_t)8, (uint64_t)21}) {
    std::vector<uint8_t> got(32 * n);
    rijndael256_ctrle_nocarry_nblocks_ref(got.data(), rk, ctr, n);
    EXPECT_EQ(got, rij_ctr_oracle(key, ctr, n)) << "rijndael256 nblocks n=" << n;
  }
}

TEST(aes_lowlevel, rijndael256_nocarry_ref_no_middle_carry) {
  uint8_t key[32];
  randomize(key, sizeof(key));
  uint8_t rk[RIJNDAEL256_RK_BYTES];
  rijndael256_key_schedule_x1_ref(rk, key);
  ctr256_t ctr;
  randomize(ctr.v8, 32);
  ctr.v64[0] = UINT64_C(0xFFFFFFFFFFFFFFFF);  // wraps on the 2nd block
  std::vector<uint8_t> got(32 * 2);
  rijndael256_ctrle_nocarry_2block_ref(got.data(), rk, ctr.v8);
  EXPECT_EQ(got, rij_ctr_oracle(key, ctr.v8, 2));
}

// ---------------------------------------------------------------------------
// ref batched key schedule == existing set_key round keys
// ---------------------------------------------------------------------------
TEST(aes_lowlevel, aes128_key_schedule_ref_matches_set_key) {
  uint8_t k[4][16];
  for (auto& kk : k) randomize(kk, 16);
  uint8_t want[4][16 * 11], got[4][16 * 11];
  for (int i = 0; i < 4; ++i) aes128_key_schedule_x1_ref(want[i], k[i]);
  aes128_key_schedule_x1_ref(got[0], k[0]);
  aes128_key_schedule_x2_ref(got[0], got[1], k[0], k[1]);
  aes128_key_schedule_x3_ref(got[0], got[1], got[2], k[0], k[1], k[2]);
  aes128_key_schedule_x4_ref(got[0], got[1], got[2], got[3], k[0], k[1], k[2], k[3]);
  for (int i = 0; i < 4; ++i) EXPECT_EQ(0, memcmp(got[i], want[i], 16 * 11)) << "aes128 rk " << i;
}

TEST(aes_lowlevel, rijndael256_key_schedule_ref_matches_set_key) {
  uint8_t k[4][32];
  for (auto& kk : k) randomize(kk, 32);
  uint8_t want[4][RIJNDAEL256_RK_BYTES], got[4][RIJNDAEL256_RK_BYTES];
  for (int i = 0; i < 4; ++i) rijndael256_key_schedule_x1_ref(want[i], k[i]);
  rijndael256_key_schedule_x1_ref(got[0], k[0]);
  EXPECT_EQ(0, memcmp(got[0], want[0], RIJNDAEL256_RK_BYTES)) << "rijndael256 x1 rk";
  rijndael256_key_schedule_x2_ref(got[0], got[1], k[0], k[1]);
  rijndael256_key_schedule_x3_ref(got[0], got[1], got[2], k[0], k[1], k[2]);
  rijndael256_key_schedule_x4_ref(got[0], got[1], got[2], got[3], k[0], k[1], k[2], k[3]);
  for (int i = 0; i < 4; ++i) EXPECT_EQ(0, memcmp(got[i], want[i], RIJNDAEL256_RK_BYTES)) << "rijndael256 rk " << i;
}

// ---------------------------------------------------------------------------
// ref vs avx2 equality (x86 only).
// The little-endian reference key schedule produces round keys that are a 1-1
// (byte-for-byte) mapping with the AVX2 key schedule, so the x1 blobs are
// directly comparable across impls. The avx2 CTR output is additionally checked
// against the independent single-block oracle (which the ref path already
// matches), and the batched key schedules are blob-compared within the avx2
// impl (x2/x3/x4 vs x1).
// ---------------------------------------------------------------------------
#ifdef __x86_64__
TEST(aes_lowlevel, aes128_key_schedule_x1_avx_matches_ref) {
  uint8_t key[16], rk_ref[16 * 11], rk_avx[16 * 11];
  randomize(key, sizeof(key));
  aes128_key_schedule_x1_ref(rk_ref, key);
  aes128_key_schedule_x1_avx2(rk_avx, key);
  EXPECT_EQ(0, memcmp(rk_ref, rk_avx, 16 * 11));
}

TEST(aes_lowlevel, rijndael256_key_schedule_x1_avx_matches_ref) {
  uint8_t key[32], rk_ref[RIJNDAEL256_RK_BYTES], rk_avx[RIJNDAEL256_RK_BYTES];
  randomize(key, sizeof(key));
  rijndael256_key_schedule_x1_ref(rk_ref, key);
  rijndael256_key_schedule_x1_avx2(rk_avx, key);
  EXPECT_EQ(0, memcmp(rk_ref, rk_avx, RIJNDAEL256_RK_BYTES));
}

TEST(aes_lowlevel, aes128_avx_ctr_matches_oracle) {
  uint8_t key[16], ctr[16];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  uint8_t rk[16 * 11];
  aes128_key_schedule_x1_avx2(rk, key);

  uint8_t out[16 * 4];
  aes128_ctrle_nocarry_1block_avx2(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 1).data(), 16));
  aes128_ctrle_nocarry_2block_avx2(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 2).data(), 32));
  aes128_ctrle_nocarry_3blocks_avx2(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 3).data(), 48));
  aes128_ctrle_nocarry_4blocks_avx2(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, aes_ctr_oracle(key, ctr, 4).data(), 64));

  for (uint64_t n : {(uint64_t)1, (uint64_t)5, (uint64_t)16, (uint64_t)64, (uint64_t)128}) {
    std::vector<uint8_t> got(16 * n);
    aes128_ctrle_nocarry_nblocks_avx2(got.data(), rk, ctr, n);
    EXPECT_EQ(got, aes_ctr_oracle(key, ctr, n)) << "aes128 avx nblocks n=" << n;
  }
}

TEST(aes_lowlevel, aes128_avx_nocarry_no_middle_carry) {
  uint8_t key[16];
  randomize(key, sizeof(key));
  uint8_t rk[16 * 11];
  aes128_key_schedule_x1_avx2(rk, key);
  ctr128_t ctr;
  randomize(ctr.v8, 16);
  ctr.v64[0] = UINT64_C(0xFFFFFFFFFFFFFFFD);  // wraps within 4 blocks
  std::vector<uint8_t> got(16 * 4);
  aes128_ctrle_nocarry_4blocks_avx2(got.data(), rk, ctr.v8);
  EXPECT_EQ(got, aes_ctr_oracle(key, ctr.v8, 4));
}

// I8 kernel: 4 keys x 2 blocks in one interleaved call. Each key i writes its two
// CTR blocks at out + 32*i; check every key against the independent single-block
// oracle so the KAT-preserving contract stays continuously verified.
TEST(aes_lowlevel, aes128_2blk_x4keys_avx_matches_oracle) {
  uint8_t key[4][16], ctr[4][16];
  for (int i = 0; i < 4; ++i) {
    randomize(key[i], 16);
    randomize(ctr[i], 16);
  }
  uint8_t rk4[4 * 16 * 11], ctr4[4 * 16];
  for (int i = 0; i < 4; ++i) {
    aes128_key_schedule_x1_avx2(rk4 + i * 16 * 11, key[i]);
    memcpy(ctr4 + i * 16, ctr[i], 16);
  }
  uint8_t out[4 * 32];
  aes128_ctrle_nocarry_2blk_x4keys_avx2(out, rk4, ctr4);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(0, memcmp(out + 32 * i, aes_ctr_oracle(key[i], ctr[i], 2).data(), 32)) << "key " << i;
  }
}

// I8 kernel: pin the no-middle-carry contract (low-64 counter wraps to the next block
// without touching the high 64 bits) for all four independent counters.
TEST(aes_lowlevel, aes128_2blk_x4keys_avx_no_middle_carry) {
  uint8_t key[4][16];
  for (auto& kk : key) randomize(kk, 16);
  uint8_t rk4[4 * 16 * 11], ctr4[4 * 16];
  ctr128_t ctr[4];
  for (int i = 0; i < 4; ++i) {
    aes128_key_schedule_x1_avx2(rk4 + i * 16 * 11, key[i]);
    randomize(ctr[i].v8, 16);
    ctr[i].v64[0] = UINT64_C(0xFFFFFFFFFFFFFFFF);  // block 1 wraps the low 64 bits
    memcpy(ctr4 + i * 16, ctr[i].v8, 16);
  }
  uint8_t out[4 * 32];
  aes128_ctrle_nocarry_2blk_x4keys_avx2(out, rk4, ctr4);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(0, memcmp(out + 32 * i, aes_ctr_oracle(key[i], ctr[i].v8, 2).data(), 32)) << "wrap key " << i;
  }
}

TEST(aes_lowlevel, aes128_key_schedule_avx_batches_match_x1) {
  uint8_t k[4][16];
  for (auto& kk : k) randomize(kk, 16);
  uint8_t x1[4][16 * 11], x2[2][16 * 11], x3[3][16 * 11], x4[4][16 * 11];
  for (int i = 0; i < 4; ++i) aes128_key_schedule_x1_avx2(x1[i], k[i]);
  aes128_key_schedule_x2_avx2(x2[0], x2[1], k[0], k[1]);
  aes128_key_schedule_x3_avx2(x3[0], x3[1], x3[2], k[0], k[1], k[2]);
  aes128_key_schedule_x4_avx2(x4[0], x4[1], x4[2], x4[3], k[0], k[1], k[2], k[3]);
  for (int i = 0; i < 2; ++i) EXPECT_EQ(0, memcmp(x2[i], x1[i], 16 * 11)) << "x2 " << i;
  for (int i = 0; i < 3; ++i) EXPECT_EQ(0, memcmp(x3[i], x1[i], 16 * 11)) << "x3 " << i;
  for (int i = 0; i < 4; ++i) EXPECT_EQ(0, memcmp(x4[i], x1[i], 16 * 11)) << "x4 " << i;
}

TEST(aes_lowlevel, rijndael256_avx_ctr_matches_oracle) {
  uint8_t key[32], ctr[32];
  randomize(key, sizeof(key));
  randomize(ctr, sizeof(ctr));
  uint8_t rk[RIJNDAEL256_RK_BYTES];
  rijndael256_key_schedule_x1_avx2(rk, key);

  uint8_t out[32 * 2];
  rijndael256_ctrle_nocarry_1block_avx2(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, rij_ctr_oracle(key, ctr, 1).data(), 32));
  rijndael256_ctrle_nocarry_2block_avx2(out, rk, ctr);
  EXPECT_EQ(0, memcmp(out, rij_ctr_oracle(key, ctr, 2).data(), 64));

  for (uint64_t n : {(uint64_t)1, (uint64_t)3, (uint64_t)8, (uint64_t)32, (uint64_t)64}) {
    std::vector<uint8_t> got(32 * n);
    rijndael256_ctrle_nocarry_nblocks_avx2(got.data(), rk, ctr, n);
    EXPECT_EQ(got, rij_ctr_oracle(key, ctr, n)) << "rijndael256 avx nblocks n=" << n;
  }
}

TEST(aes_lowlevel, rijndael256_key_schedule_avx_batches_match_x1) {
  uint8_t k[4][32];
  for (auto& kk : k) randomize(kk, 32);
  uint8_t x1[4][RIJNDAEL256_RK_BYTES], x2[2][RIJNDAEL256_RK_BYTES], x3[3][RIJNDAEL256_RK_BYTES],
      x4[4][RIJNDAEL256_RK_BYTES];
  for (int i = 0; i < 4; ++i) rijndael256_key_schedule_x1_avx2(x1[i], k[i]);
  rijndael256_key_schedule_x2_avx2(x2[0], x2[1], k[0], k[1]);
  rijndael256_key_schedule_x3_avx2(x3[0], x3[1], x3[2], k[0], k[1], k[2]);
  rijndael256_key_schedule_x4_avx2(x4[0], x4[1], x4[2], x4[3], k[0], k[1], k[2], k[3]);
  for (int i = 0; i < 2; ++i) EXPECT_EQ(0, memcmp(x2[i], x1[i], RIJNDAEL256_RK_BYTES)) << "rij x2 " << i;
  for (int i = 0; i < 3; ++i) EXPECT_EQ(0, memcmp(x3[i], x1[i], RIJNDAEL256_RK_BYTES)) << "rij x3 " << i;
  for (int i = 0; i < 4; ++i) EXPECT_EQ(0, memcmp(x4[i], x1[i], RIJNDAEL256_RK_BYTES)) << "rij x4 " << i;
}

// ---------------------------------------------------------------------------
// aes128_proofow_grind_avx2 == scalar single-block grind oracle
// ---------------------------------------------------------------------------
namespace {
// scalar reference for the grind inner loop: same contract as aes128_proofow_grind_avx2.
int grind_oracle(uint8_t out_ct[32], uint64_t* ctr_io, const uint8_t pt[32], const uint8_t rk0[16 * 11],
                 const uint8_t rk1[16 * 11], uint64_t mask) {
  const uint64_t CTR_MAX = UINT64_C(1) << 32;
  ctr128_t p0, p1, c0, c1;
  memcpy(p0.v8, pt, 16);
  memcpy(p1.v8, pt + 16, 16);
  uint64_t ctr = *ctr_io;
  while (ctr < CTR_MAX) {
    aes128_ctrle_nocarry_1block_ref(c0.v8, rk0, p0.v8);
    aes128_ctrle_nocarry_1block_ref(c1.v8, rk1, p1.v8);
    if (((c0.v64[0] ^ c1.v64[0]) & mask) == 0) {
      memcpy(out_ct, c0.v8, 16);
      memcpy(out_ct + 16, c1.v8, 16);
      *ctr_io = ctr;
      return 1;
    }
    ++ctr;
    ++p0.v64[0];
    ++p1.v64[0];
  }
  *ctr_io = CTR_MAX;
  return 0;
}
}  // namespace

TEST(aes_lowlevel, aes128_proofow_grind_avx_matches_oracle) {
  uint8_t key[2][16], pt[32];
  for (auto& k : key) randomize(k, 16);
  randomize(pt, sizeof(pt));
  uint8_t rk[2][16 * 11];
  aes128_key_schedule_x2_avx2(rk[0], rk[1], key[0], key[1]);

  // a handful of mask widths; small w => a solution is found within ~2^w steps.
  for (uint64_t w : {(uint64_t)0, (uint64_t)1, (uint64_t)4, (uint64_t)8, (uint64_t)12}) {
    const uint64_t mask = (w == 64) ? ~UINT64_C(0) : ((UINT64_C(1) << w) - 1);
    const uint64_t start = 1234;  // arbitrary non-zero initial counter

    uint8_t ct_a[32], ct_o[32];
    uint64_t ctr_a = start, ctr_o = start;
    int ra = aes128_proofow_grind_avx2(ct_a, &ctr_a, pt, rk, mask);
    int ro = grind_oracle(ct_o, &ctr_o, pt, rk[0], rk[1], mask);

    ASSERT_EQ(ra, ro) << "return code mismatch at w=" << w;
    EXPECT_EQ(ctr_a, ctr_o) << "counter mismatch at w=" << w;
    if (ra) {
      EXPECT_EQ(0, memcmp(ct_a, ct_o, 32)) << "ciphertext mismatch at w=" << w;
    }
  }
}

// mask_w == 0 => the condition holds immediately: return the initial counter untouched.
TEST(aes_lowlevel, aes128_proofow_grind_avx_mask0_returns_immediately) {
  uint8_t key[2][16], pt[32];
  for (auto& k : key) randomize(k, 16);
  randomize(pt, sizeof(pt));
  uint8_t rk[2][16 * 11];
  aes128_key_schedule_x2_avx2(rk[0], rk[1], key[0], key[1]);

  uint8_t ct[32];
  uint64_t ctr = 987654;
  ASSERT_EQ(1, aes128_proofow_grind_avx2(ct, &ctr, pt, rk, /*mask=*/0));
  EXPECT_EQ(987654u, ctr);
  // ciphertexts must be AES(rk_i, pt_i) at the initial counter.
  uint8_t c0[16], c1[16];
  aes128_ctrle_nocarry_1block_ref(c0, rk[0], pt);
  aes128_ctrle_nocarry_1block_ref(c1, rk[1], pt + 16);
  EXPECT_EQ(0, memcmp(ct, c0, 16));
  EXPECT_EQ(0, memcmp(ct + 16, c1, 16));
}

// no-hit path: start near 2^32 with a full 64-bit mask (hit prob ~2^-64), so the
// loop runs the few remaining counters and returns 0 with the counter pinned at 2^32.
TEST(aes_lowlevel, aes128_proofow_grind_avx_exhausts_to_2p32) {
  uint8_t key[2][16], pt[32];
  for (auto& k : key) randomize(k, 16);
  randomize(pt, sizeof(pt));
  uint8_t rk[2][16 * 11];
  aes128_key_schedule_x2_avx2(rk[0], rk[1], key[0], key[1]);

  const uint64_t mask = ~UINT64_C(0);
  const uint64_t start = (UINT64_C(1) << 32) - 37;  // 37 iterations left

  uint8_t ct_a[32], ct_o[32];
  uint64_t ctr_a = start, ctr_o = start;
  int ra = aes128_proofow_grind_avx2(ct_a, &ctr_a, pt, rk, mask);
  int ro = grind_oracle(ct_o, &ctr_o, pt, rk[0], rk[1], mask);
  ASSERT_EQ(ra, ro);
  EXPECT_EQ(ctr_a, ctr_o);
  if (!ra) {
    EXPECT_EQ(UINT64_C(1) << 32, ctr_a);
  }
}
#endif  // __x86_64__
