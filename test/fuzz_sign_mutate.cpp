// libFuzzer harness: structure-aware sign-then-mutate.
//
// A genuine keygen+sign produces a signature that must verify (1); a single-byte
// mutation of it must be rejected (0). Never crash.
//
// sdith_verify returns 1 = accept, 0 = reject.
//
// Opt-in, Clang only: cmake -DBUILD_FUZZERS=ON (see CMakeLists.txt).

#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
  if (size < 3) return 0;
  const signature_parameters P = kP;

  std::vector<uint8_t> sk(sdith_secret_key_bytes(&P)), pk(sdith_public_key_bytes(&P));
  std::vector<uint8_t> kent(sdith_keygen_entropy_bytes(&P), 7);
  std::vector<uint8_t> ktmp(sdith_keygen_tmp_bytes(&P));
  sdith_keygen(&P, sk.data(), pk.data(), kent.data(), ktmp.data());  // canonical sk, pk order

  std::vector<uint8_t> sig(sdith_signature_bytes(&P));
  std::vector<uint8_t> sent(sdith_signature_entropy_bytes(&P), data[0]);
  std::vector<uint8_t> stmp(sdith_signature_tmp_bytes(&P));
  const uint8_t* msg = data + 1;
  const uint64_t mlen = size - 1;
  sdith_sign(&P, sig.data(), msg, mlen, sk.data(), sent.data(), stmp.data());

  std::vector<uint8_t> vtmp(sdith_verify_tmp_bytes(&P));
  if (!sdith_verify(&P, sig.data(), msg, mlen, pk.data(), vtmp.data())) abort();  // valid must accept
  sig[data[1] % sig.size()] ^= (uint8_t)(data[2] | 1);                            // flip a real bit
  if (sdith_verify(&P, sig.data(), msg, mlen, pk.data(), vtmp.data())) abort();   // mutant must reject
  return 0;
}
