// libFuzzer harness: sdith_verify must never crash and never accept a signature that
// sdith_sign did not produce.
//
// One keypair and four genuine signatures (message lengths 0, 1, 32 and 4096 bytes) are
// built once in LLVMFuzzerInitialize from fixed entropy, so every input starts from a
// signature that already clears the proof-of-work check at the head of sdith_verify and
// reaches the GGM rebuild, the VOLE opening and the PIOP.  An all-zero signature does
// not clear that check, and mutation cannot make it clear it, because passing means
// matching a SHAKE output.
//
// sdith_verify returns 1 = accept, 0 = reject.  An accept is correct for the genuine
// signature and a forgery for any other bytes.
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

// Message lengths of the genuine fixtures: empty, one byte, one block, long.
static const uint64_t kMsgBytes[] = {0, 1, 32, 4096};
static const size_t kNumFixtures = sizeof(kMsgBytes) / sizeof(kMsgBytes[0]);

static std::vector<uint8_t> g_pk;                 // fixture public key
static std::vector<uint8_t> g_msg;                // 4096 bytes; fixture i signs its first kMsgBytes[i]
static std::vector<uint8_t> g_sig[kNumFixtures];  // genuine signature per message length

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
  const signature_parameters P = kP;

  // Fixed entropy, so the fixture is the same on every run and no key here is secret.
  std::vector<uint8_t> sk(sdith_secret_key_bytes(&P));
  std::vector<uint8_t> kent(sdith_keygen_entropy_bytes(&P), 7);
  std::vector<uint8_t> ktmp(sdith_keygen_tmp_bytes(&P));
  g_pk.resize(sdith_public_key_bytes(&P));
  sdith_keygen(&P, sk.data(), g_pk.data(), kent.data(), ktmp.data());  // canonical sk, pk order

  g_msg.assign(kMsgBytes[kNumFixtures - 1], 0xA5);
  std::vector<uint8_t> stmp(sdith_signature_tmp_bytes(&P));
  std::vector<uint8_t> vtmp(sdith_verify_tmp_bytes(&P));
  for (size_t i = 0; i < kNumFixtures; ++i) {
    std::vector<uint8_t> sent(sdith_signature_entropy_bytes(&P), (uint8_t)(i + 1));
    g_sig[i].resize(sdith_signature_bytes(&P));
    sdith_sign(&P, g_sig[i].data(), g_msg.data(), kMsgBytes[i], sk.data(), sent.data(), stmp.data());
    // Positive control: a harness whose fixture does not verify is testing nothing.
    if (!sdith_verify(&P, g_sig[i].data(), g_msg.data(), kMsgBytes[i], g_pk.data(), vtmp.data())) abort();
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const signature_parameters P = kP;
  const uint64_t sig_bytes = sdith_signature_bytes(&P);

  // data[0] picks the fixture, data[1..2] the offset to overwrite from, and the rest
  // is copied over the genuine signature.  Under three bytes nothing is overwritten,
  // so the empty input is the genuine signature and libFuzzer grows its mutants from
  // there.
  size_t fx = 0, off = 0, n = 0;
  const uint8_t* over = data;
  if (size >= 3) {
    fx = data[0] % kNumFixtures;
    off = (size_t)(((uint32_t)data[1] << 8) | data[2]) % (size_t)sig_bytes;
    over = data + 3;
    n = size - 3;
    if (n > (size_t)sig_bytes - off) n = (size_t)sig_bytes - off;
  }

  // LLVMFuzzerInitialize builds the fixtures; without it there is nothing to copy.
  if (g_sig[fx].size() != (size_t)sig_bytes) return 0;

  std::vector<uint8_t> sig(g_sig[fx]);
  if (n) memcpy(sig.data() + off, over, n);

  std::vector<uint8_t> tmp(sdith_verify_tmp_bytes(&P), 0);
  const uint8_t r = sdith_verify(&P, sig.data(), g_msg.data(), kMsgBytes[fx], g_pk.data(), tmp.data());
  if (r != 0 && memcmp(sig.data(), g_sig[fx].data(), sig_bytes) != 0) abort();  // forgery -> bug
  return 0;
}
