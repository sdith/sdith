// libFuzzer harness: sdith_verify must never crash and never accept an
// attacker-controlled signature against a fixed public key.
//
// sdith_verify returns 1 = accept, 0 = reject. Any accept here would be a forgery.
//
// Opt-in, Clang only: cmake -DBUILD_FUZZERS=ON (see CMakeLists.txt).

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "sdith_signature.h"

// Parameter set selected at compile time (same CATxy tokens as stress_test_single.c).
#if defined(CAT5B)
static const signature_parameters kP = CAT5_FAST_PARAMETERS;
#elif defined(CAT5A)
static const signature_parameters kP = CAT5_SHORT_PARAMETERS;
#elif defined(CAT3B)
static const signature_parameters kP = CAT3_FAST_PARAMETERS;
#elif defined(CAT3A)
static const signature_parameters kP = CAT3_SHORT_PARAMETERS;
#elif defined(CAT1B)
static const signature_parameters kP = CAT1_FAST_PARAMETERS;
#else
static const signature_parameters kP = CAT1_SHORT_PARAMETERS;
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const uint64_t pk_bytes = sdith_public_key_bytes(&kP);
  const uint64_t sig_bytes = sdith_signature_bytes(&kP);
  const uint64_t tmp_bytes = sdith_verify_tmp_bytes(&kP);

  std::vector<uint8_t> pk(pk_bytes, 0), sig(sig_bytes, 0), tmp(tmp_bytes, 0);
  memcpy(sig.data(), data, size < sig_bytes ? size : sig_bytes);

  uint8_t r = sdith_verify(&kP, sig.data(), data, size, pk.data(), tmp.data());
  if (r != 0) abort();  // accepted a forged/garbage signature -> bug
  return 0;
}
