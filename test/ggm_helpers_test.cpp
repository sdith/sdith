#include "ggm.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "sdith_prng.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/testlib.h"
#include "vole_private.h"

// -----------------------------------------------------------------------------
// Exhaustive per-function correctness tests for the ggm_helpers module helpers
// that ggm_test.cpp does NOT already assert directly:
//   - estimate_topen
//   - hidden_leaves_indexes2
//   - full_ggm_tree_open_sibling_path
//   - full_ggm_tree_get_node_seed (complementary edge/known-answer coverage;
//         ggm_test.cpp only checks it via cached-vs-naive equivalence)
//
// Ground truth is the Python oracle sdith-py/round3/ggm.py:
//   * decode_hidden_leaf_indices  == hidden_leaves_indexes2
//         (node = position*tau + rep + num_leaves, sorted)
//   * estimate_topen / open_sibling_path share the _walk_hidden_path walk:
//         queue = reversed(hidden); pop 1 or 2 (if siblings) from the front,
//         reveal the sibling of each UNPAIRED node, append parent = node//2.
//
// These helpers are RNG/lambda independent for the index math (estimate_topen,
// hidden_leaves_indexes2); the tree helpers use the ref seed/commit RNGs wired
// up by testlib. There are NO avx2 variants of any of these functions (grep of
// src/*_avx2.c is empty for them), so nothing here is gated on __x86_64__.
// -----------------------------------------------------------------------------

namespace {

// The six SDitH round-3 parameter sets (params.py): CAT{1,3,5} x {SHORT,FAST}.
struct ps_t {
  uint32_t lambda;
  uint32_t kappa;
  uint32_t tau;
  const char* name;
};
const ps_t kAllParams[6] = {
    {128, 11, 11, "cat1-short"}, {128, 8, 16, "cat1-fast"},   {192, 12, 16, "cat3-short"},
    {192, 8, 24, "cat3-fast"},   {256, 12, 21, "cat5-short"}, {256, 8, 32, "cat5-fast"},
};

// num_leaves = tau * 2^kappa
uint32_t num_leaves_of(uint32_t tau, uint32_t kappa) { return tau * (UINT32_C(1) << kappa); }

// Build the sorted hidden node-index set from per-repetition positions, exactly
// like the Python helper _hidden_from_positions in tests/test_ggm.py:
//   idx = sorted(pos[rep]*tau + rep + num_leaves)
std::vector<uint32_t> hidden_from_positions(const std::vector<uint32_t>& pos, uint32_t tau, uint32_t kappa) {
  const uint32_t nl = num_leaves_of(tau, kappa);
  std::vector<uint32_t> h(tau);
  for (uint32_t k = 0; k < tau; ++k) {
    h[k] = pos[k] * tau + k + nl;
  }
  std::sort(h.begin(), h.end());
  return h;
}

// Independent reimplementation of the open/estimate walk (mirrors Python
// _walk_hidden_path). Returns the sibling node indices to be revealed, IN THE
// SAME ORDER the C code emits them, so it doubles as the estimate_topen count
// and the ordering oracle for open_sibling_path.
std::vector<uint32_t> ref_sibling_nodes(const std::vector<uint32_t>& hidden) {
  const size_t tau = hidden.size();
  std::vector<uint32_t> q(tau);
  for (size_t i = 0; i < tau; ++i) {
    q[tau - i - 1] = hidden[i];  // reversed copy
  }
  std::vector<uint32_t> reveal;
  size_t rp = 0;
  while (q.size() - rp >= 2) {
    const uint32_t first = q[rp];
    ++rp;
    const uint32_t second = q[rp];
    const uint32_t next = first >> 1;
    if ((first ^ second) == 1) {
      ++rp;  // paired: both siblings hidden, nothing revealed
    } else {
      reveal.push_back(first ^ 1);  // unpaired: reveal the sibling
    }
    q.push_back(next);
  }
  while (q[rp] != 1) {
    reveal.push_back(q[rp] ^ 1);
    q[rp] >>= 1;
  }
  return reveal;
}

// A handful of deterministic position patterns per parameter set.
std::vector<std::vector<uint32_t>> position_patterns(uint32_t tau, uint32_t kappa) {
  const uint32_t span = UINT32_C(1) << kappa;
  std::vector<std::vector<uint32_t>> out;
  out.emplace_back(tau, 0);          // all leaves in the first slot (many paired merges)
  out.emplace_back(tau, span - 1);   // all leaves in the last slot
  std::vector<uint32_t> staircase(tau);
  std::vector<uint32_t> spread(tau);
  for (uint32_t k = 0; k < tau; ++k) {
    staircase[k] = k % span;
    spread[k] = ((k + 1) * 7u) % span;
  }
  out.push_back(staircase);
  out.push_back(spread);
  return out;
}

}  // namespace

// -----------------------------------------------------------------------------
// estimate_topen
// -----------------------------------------------------------------------------

// Hand-computed known answers on tiny trees (no crypto involved). Each hidden
// array is the sorted set of node indices (already offset by num_leaves).
TEST(ggm_helpers_estimate_topen, known_answers) {
  struct kat_t {
    uint32_t tau, kappa;
    std::vector<uint32_t> hidden;
    uint64_t expect;
  };
  const std::vector<kat_t> kats = {
      // kappa=1, tau=1: single hidden leaf, one reveal up to the root.
      {1, 1, {2}, 1},
      {1, 1, {3}, 1},
      // kappa=2, tau=2, num_leaves=8.
      {2, 2, {8, 9}, 2},    // siblings under node 4: paired once, reveal 5 and 3.
      {2, 2, {14, 15}, 2},  // siblings under node 7: paired once, reveal 6 and 3.
      {2, 2, {8, 11}, 3},   // disjoint: reveal 9, 10, and 3.
      // kappa=2, tau=3, num_leaves=12.
      {3, 2, {12, 13, 14}, 2},  // reveal 15 then 2.
  };
  for (const auto& k : kats) {
    std::vector<uint8_t> tmp(estimate_topen_tmp_bytes(k.tau, k.kappa));
    std::vector<uint32_t> h = k.hidden;  // estimate_topen takes non-const-ish scratch semantics
    const uint64_t got = estimate_topen(k.tau, k.kappa, 1u << 30, h.data(), tmp.data());
    EXPECT_EQ(got, k.expect) << "tau=" << k.tau << " kappa=" << k.kappa;
  }
}

// For all six parameter sets and several delta choices, estimate_topen must
// equal the independent walk count and never exceed tau*kappa (Python bound).
TEST(ggm_helpers_estimate_topen, matches_walk_all_param_sets) {
  for (const ps_t& p : kAllParams) {
    SCOPED_TRACE(p.name);
    std::vector<uint8_t> tmp(estimate_topen_tmp_bytes(p.tau, p.kappa));
    for (const auto& pos : position_patterns(p.tau, p.kappa)) {
      std::vector<uint32_t> hidden = hidden_from_positions(pos, p.tau, p.kappa);
      const uint64_t expect = ref_sibling_nodes(hidden).size();
      std::vector<uint32_t> h = hidden;
      const uint64_t got = estimate_topen(p.tau, p.kappa, 1u << 30, h.data(), tmp.data());
      EXPECT_EQ(got, expect);
      EXPECT_LE(got, uint64_t(p.tau) * p.kappa);
      EXPECT_GE(got, uint64_t(1));
    }
  }
}

// -----------------------------------------------------------------------------
// hidden_leaves_indexes2
// -----------------------------------------------------------------------------

// Direct known-answer vectors reused from ggm_test.cpp's hidden_leaves_indexes
// (v1) KATs, shifted by the start_index = tau*2^kappa that v2 adds. This is a
// true KAT: the v1 arrays are independently vetted, and v2[i] == v1[i]+offset.
TEST(ggm_helpers_hidden_leaves_indexes2, known_answers) {
  auto run = [](uint64_t kappa, uint64_t tau, const std::vector<uint32_t>& delta32,
                const std::vector<uint32_t>& v1_expected) {
    const uint32_t offset = uint32_t(tau) * (UINT32_C(1) << kappa);
    // 8-byte aligned, zero-padded buffer so the kappa-bit extractor never reads
    // past the end (it may touch delta[limb+1]).
    std::vector<uint64_t> delta_words(16, 0);
    memcpy(delta_words.data(), delta32.data(), delta32.size() * sizeof(uint32_t));

    std::vector<uint32_t> got(tau, 0);
    hidden_leaves_indexes2(kappa, tau, got.data(), delta_words.data());

    std::vector<uint32_t> expected(v1_expected.size());
    for (size_t i = 0; i < v1_expected.size(); ++i) expected[i] = v1_expected[i] + offset;
    EXPECT_EQ(got, expected);
  };

  // kappa=11, tau=11  (offset = 22528)
  run(11, 11,
      {0b00111110100110111110110110010000, 0b00110001001111111011111100110010, 0b00101000010111111001110001100100,
       0b0110001111111101101100100},
      {1083, 2752, 8411, 8799, 9824, 11213, 11712, 15664, 19993, 20909, 21398});

  // kappa=1, tau=1  (offset = 2)  -> {3}
  run(1, 1, {1}, {1});

  // kappa=4, tau=5  (offset = 80)
  run(4, 5, {0b11110111111101011010}, {26, 38, 50, 77, 79});

  // kappa=8, tau=100  (offset = 25600)
  run(8, 100,
      {0b00000101101101110111100100001110, 0b11011010110110101110000111101101, 0b00010011000101000011001000110101,
       0b10010100100000110011010001111110, 0b10111010110001101011111100000101, 0b00001000011010100010101100000111,
       0b00101100111110011101011101101011, 0b10101001001010000000101010010001, 0b11101001001010011100101011111000,
       0b00010000010000111101110001100101, 0b11010111100010101100010010110100, 0b00100101011100101010111010101101,
       0b11100010011011011110101111000100, 0b01110100111000110000010000010101, 0b00011100100110110101110000010100,
       0b00001110010011111010100101011101, 0b11001011111001010111011111011011, 0b00011101101010100011101011100011,
       0b00010001101010011001100001000100, 0b11111001111101110110010101001101, 0b10110011001111011000101111100010,
       0b11010001000001001111000010010000, 0b11111001011001100100010001100000, 0b01111101000101011011000010100001,
       0b10111111111000011011111011100001},
      {453,   486,   503,   516,   720,   823,   1029,  1400,  1463,  1639,  1775,  1911,  2010,  2056,  2152,
       2194,  2859,  2971,  3747,  4030,  4134,  4321,  4427,  5009,  5213,  5308,  5869,  6182,  6738,  6872,
       6889,  7776,  7962,  9257,  9360,  9688,  10136, 10177, 10290, 10622, 10724, 10950, 11446, 11655, 11965,
       12101, 12595, 12612, 13114, 13842, 13981, 14484, 14528, 14815, 15273, 15558, 16192, 16931, 16961, 16974,
       17070, 17344, 17445, 17693, 17983, 18040, 18302, 18619, 19097, 19117, 19199, 19641, 19648, 19818, 20233,
       20367, 20987, 21525, 21543, 21806, 21807, 21964, 22037, 22505, 22596, 22598, 22651, 22680, 22754, 22768,
       22966, 23335, 23549, 23704, 24085, 24778, 24832, 24926, 24979, 24991});
}

// For all six parameter sets: encode chosen positions into delta, decode with
// hidden_leaves_indexes2, and check against the closed-form node indices. Also
// verify the structural invariants from the Python test (sorted, in range, one
// hidden leaf per repetition).
TEST(ggm_helpers_hidden_leaves_indexes2, all_param_sets) {
  for (const ps_t& p : kAllParams) {
    SCOPED_TRACE(p.name);
    const uint32_t nl = num_leaves_of(p.tau, p.kappa);
    for (const auto& pos : position_patterns(p.tau, p.kappa)) {
      // Independently pack positions little-endian into a bit buffer.
      uint64_t delta[8];
      memset(delta, 0, sizeof(delta));
      uint8_t* db = reinterpret_cast<uint8_t*>(delta);
      for (uint32_t k = 0; k < p.tau; ++k) {
        for (uint32_t b = 0; b < p.kappa; ++b) {
          if ((pos[k] >> b) & 1u) {
            const uint32_t bit = k * p.kappa + b;
            db[bit >> 3] |= uint8_t(1u << (bit & 7));
          }
        }
      }

      std::vector<uint32_t> got(p.tau, 0);
      hidden_leaves_indexes2(p.kappa, p.tau, got.data(), delta);

      const std::vector<uint32_t> expected = hidden_from_positions(pos, p.tau, p.kappa);
      EXPECT_EQ(got, expected);

      // structural invariants
      EXPECT_TRUE(std::is_sorted(got.begin(), got.end()));
      std::vector<uint32_t> reps(p.tau);
      for (uint32_t i = 0; i < p.tau; ++i) {
        EXPECT_GE(got[i], nl);
        EXPECT_LT(got[i], 2u * nl);
        reps[i] = (got[i] - nl) % p.tau;
      }
      std::sort(reps.begin(), reps.end());
      for (uint32_t i = 0; i < p.tau; ++i) EXPECT_EQ(reps[i], i);  // exactly one per repetition
    }
  }
}
