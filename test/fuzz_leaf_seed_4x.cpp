// libFuzzer harness: 4x leaf-seed expansion must equal four 1x calls, for every
// cat and impl, on arbitrary seed bytes. A mismatch would silently change KATs
// once the BFS traversal adopts the 4x path, so any divergence aborts.
//
// Opt-in, Clang only: cmake -DBUILD_FUZZERS=ON (see CMakeLists.txt).

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "sdith_prng.h"

using extend_fn = void (*)(void*, const void*);

// Fill 4 contiguous seeds of seed_sz bytes from the fuzz input (cycled so short
// inputs still vary the seeds), run 4x, and abort if it differs from 4x 1x.
static void check(const uint8_t* data, size_t size, size_t seed_sz, size_t ext_sz, extend_fn fn1x, extend_fn fn4x) {
  std::vector<uint8_t> seeds(4 * seed_sz);
  for (size_t i = 0; i < seeds.size(); ++i) seeds[i] = data[i % size];

  std::vector<uint8_t> got(4 * ext_sz);
  fn4x(got.data(), seeds.data());

  std::vector<uint8_t> want(4 * ext_sz);
  for (int i = 0; i < 4; ++i) fn1x(want.data() + i * ext_sz, seeds.data() + i * seed_sz);

  if (memcmp(got.data(), want.data(), 4 * ext_sz) != 0) abort();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  check(data, size, 16, 16 * 11, extend_leaf_seed_cat1_aes128_ref, extend_leaf_seed_cat1_aes128_4x_ref);
  check(data, size, 24, 480, extend_leaf_seed_cat3_rijndael256_ref, extend_leaf_seed_cat3_rijndael256_4x_ref);
  check(data, size, 32, 480, extend_leaf_seed_cat5_rijndael256_ref, extend_leaf_seed_cat5_rijndael256_4x_ref);
#ifdef __x86_64__
  check(data, size, 16, 16 * 11, extend_leaf_seed_cat1_aes128_avx2, extend_leaf_seed_cat1_aes128_4x_avx2);
  check(data, size, 24, 480, extend_leaf_seed_cat3_rijndael256_avx2, extend_leaf_seed_cat3_rijndael256_4x_avx2);
  check(data, size, 32, 480, extend_leaf_seed_cat5_rijndael256_avx2, extend_leaf_seed_cat5_rijndael256_4x_avx2);
#endif
  return 0;
}
