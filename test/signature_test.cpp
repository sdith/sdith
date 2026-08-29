// Top-level keygen/sign/verify tests for all six parameter sets.
//
// sdith_verify returns 1 on success and 0 on any failure (see the VERIFY_SUCCESS
// / VERIFY_OR_FAIL macros in sdith_signature.c), and never aborts. Tamper tests
// rely on that: any single-byte flip of a load-bearing field must drop verify
// to 0, and restoring the byte must bring it back to 1.
//
// The signature field layout is internal to sdith_signature.c (map_signature is
// not exported), so we reconstruct the field offsets here from the same
// extended_parameters_t values that map_signature uses. If the mapping in
// sdith_signature.c changes, these offsets must be kept in sync.

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "sdith_signature.h"
#include "testlib/testlib.h"
#include "vole_private.h"

namespace {

struct param_set {
  const signature_parameters* params;
  const char* name;
};

const param_set kSets[] = {
    {&CAT1_SHORT_PARAMETERS, "cat1_short"}, {&CAT3_SHORT_PARAMETERS, "cat3_short"},
    {&CAT5_SHORT_PARAMETERS, "cat5_short"}, {&CAT1_FAST_PARAMETERS, "cat1_fast"},
    {&CAT3_FAST_PARAMETERS, "cat3_fast"},   {&CAT5_FAST_PARAMETERS, "cat5_fast"},
    // cat3/cat5 cipher-based proof-of-work (rijndael256 + shake256)
    {&CAT3_SHORT_CIPHERPOW_PARAMETERS, "cat3_short_cipherpow"},
    {&CAT3_FAST_CIPHERPOW_PARAMETERS, "cat3_fast_cipherpow"},
    {&CAT5_SHORT_CIPHERPOW_PARAMETERS, "cat5_short_cipherpow"},
    {&CAT5_FAST_CIPHERPOW_PARAMETERS, "cat5_fast_cipherpow"},
};

// Buffers + a freshly generated keypair for one parameter set.
struct keypair {
  const signature_parameters* p;
  std::vector<uint8_t> sk, pk;
  std::vector<uint8_t> sign_tmp, verify_tmp;

  explicit keypair(const signature_parameters* params, const void* kg_entropy)
      : p(params),
        sk(sdith_secret_key_bytes(params)),
        pk(sdith_public_key_bytes(params)),
        sign_tmp(sdith_signature_tmp_bytes(params)),
        verify_tmp(sdith_verify_tmp_bytes(params)) {
    std::vector<uint8_t> kg_tmp(sdith_keygen_tmp_bytes(params));
    sdith_keygen(params, sk.data(), pk.data(), kg_entropy, kg_tmp.data());
  }

  std::vector<uint8_t> sign(const void* msg, uint64_t msg_bytes, const void* sg_entropy) {
    std::vector<uint8_t> sig(sdith_signature_bytes(p));
    sdith_sign(p, sig.data(), msg, msg_bytes, sk.data(), sg_entropy, sign_tmp.data());
    return sig;
  }

  uint8_t verify(const void* sig, const void* msg, uint64_t msg_bytes) {
    return sdith_verify(p, sig, msg, msg_bytes, pk.data(), verify_tmp.data());
  }
};

// entropy for both keygen and sign is 2*lambda_bytes, at most 64 bytes.
std::vector<uint8_t> random_entropy(uint64_t nbytes) {
  std::vector<uint8_t> e(nbytes);
  randomize(e.data(), nbytes);
  return e;
}

// The signature field (offset, length) map, reconstructed from
// map_signature in sdith_signature.c (fields in signature order).
struct sig_field {
  const char* name;
  uint64_t offset;
  uint64_t length;
};

std::vector<sig_field> signature_layout(const signature_parameters* params) {
  extended_parameters_t par;
  compute_extended_parameters(&par, params);
  const uint64_t lb = par.lambda_bytes;
  const uint64_t sizes[] = {
      lb,                              // global_salt
      par.target_topen * lb,           // ggm_sibling_path
      par.tau * 2 * lb,                // ggm_hidden_leaf_cmt
      par.Lbyte * (par.tau - 1),       // corr_u
      par.num_cchk_pairs >> 3,         // cchk_u
      (par.num_inputs_pairs + 7) >> 3, // circuit_in_pub
      (par.degree - 1) * lb,           // circuit_cz_pub
      2 * lb,                          // hash_piop
      PROOFOW_CTR_REVEALED_BYTES,      // proofow_ctr_reveal
  };
  const char* names[] = {"global_salt", "ggm_sibling_path", "ggm_hidden_leaf_cmt",
                         "corr_u",       "cchk_u",           "circuit_in_pub",
                         "circuit_cz_pub", "hash_piop",      "proofow_ctr_reveal"};
  std::vector<sig_field> fields;
  uint64_t offset = 0;
  for (int i = 0; i < 9; ++i) {
    fields.push_back({names[i], offset, sizes[i]});
    offset += sizes[i];
  }
  return fields;
}

const char kMessage[] = "The quick brown fox jumps over the lazy dog.";
const uint64_t kMessageBytes = sizeof(kMessage) - 1;

}  // namespace

TEST(signature, round_trip) {
  for (const param_set& s : kSets) {
    auto kg = random_entropy(sdith_keygen_entropy_bytes(s.params));
    auto sg = random_entropy(sdith_signature_entropy_bytes(s.params));
    keypair kp(s.params, kg.data());
    std::vector<uint8_t> sig = kp.sign(kMessage, kMessageBytes, sg.data());
    ASSERT_EQ(kp.verify(sig.data(), kMessage, kMessageBytes), 1) << "round-trip failed for " << s.name;
  }
}

TEST(signature, deterministic_signing) {
  for (const param_set& s : kSets) {
    auto kg = random_entropy(sdith_keygen_entropy_bytes(s.params));
    auto sg = random_entropy(sdith_signature_entropy_bytes(s.params));
    keypair kp(s.params, kg.data());
    // Same key, message and entropy must yield byte-identical signatures.
    std::vector<uint8_t> sig1 = kp.sign(kMessage, kMessageBytes, sg.data());
    std::vector<uint8_t> sig2 = kp.sign(kMessage, kMessageBytes, sg.data());
    ASSERT_EQ(sig1, sig2) << "signing not deterministic for " << s.name;
    ASSERT_EQ(kp.verify(sig1.data(), kMessage, kMessageBytes), 1) << s.name;
  }
}

TEST(signature, cross_key_rejected) {
  for (const param_set& s : kSets) {
    auto kg1 = random_entropy(sdith_keygen_entropy_bytes(s.params));
    auto kg2 = random_entropy(sdith_keygen_entropy_bytes(s.params));
    auto sg = random_entropy(sdith_signature_entropy_bytes(s.params));
    keypair kp1(s.params, kg1.data());
    keypair kp2(s.params, kg2.data());
    std::vector<uint8_t> sig = kp1.sign(kMessage, kMessageBytes, sg.data());
    // Signed under kp1, verified under kp2's public key -> reject.
    ASSERT_EQ(kp2.verify(sig.data(), kMessage, kMessageBytes), 0) << "wrong key accepted for " << s.name;
  }
}

TEST(signature, tamper_each_field_rejected) {
  for (const param_set& s : kSets) {
    auto kg = random_entropy(sdith_keygen_entropy_bytes(s.params));
    auto sg = random_entropy(sdith_signature_entropy_bytes(s.params));
    keypair kp(s.params, kg.data());
    std::vector<uint8_t> sig = kp.sign(kMessage, kMessageBytes, sg.data());
    ASSERT_EQ(kp.verify(sig.data(), kMessage, kMessageBytes), 1) << s.name;

    for (const sig_field& f : signature_layout(s.params)) {
      if (f.length == 0) continue;  // nothing to flip in an empty field
      const uint8_t saved = sig[f.offset];
      sig[f.offset] ^= 0x01;
      EXPECT_EQ(kp.verify(sig.data(), kMessage, kMessageBytes), 0)
          << "tampering " << f.name << " (offset " << f.offset << ") was accepted for " << s.name;
      sig[f.offset] = saved;  // restore
    }
    // The restored signature must verify again -> proves the flips caused the failures.
    ASSERT_EQ(kp.verify(sig.data(), kMessage, kMessageBytes), 1) << "restore failed for " << s.name;
  }
}

TEST(signature, wrong_message_rejected) {
  for (const param_set& s : kSets) {
    auto kg = random_entropy(sdith_keygen_entropy_bytes(s.params));
    auto sg = random_entropy(sdith_signature_entropy_bytes(s.params));
    keypair kp(s.params, kg.data());
    std::vector<uint8_t> sig = kp.sign(kMessage, kMessageBytes, sg.data());

    // Different message of the same length.
    std::string other(kMessage, kMessageBytes);
    other[0] ^= 0x01;
    EXPECT_EQ(kp.verify(sig.data(), other.data(), kMessageBytes), 0) << "altered message accepted for " << s.name;

    // Truncated message length.
    EXPECT_EQ(kp.verify(sig.data(), kMessage, kMessageBytes - 1), 0) << "short message accepted for " << s.name;
  }
}
