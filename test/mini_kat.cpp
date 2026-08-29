/* mini_kat_main.c - deterministic mini-KAT smoke for CI.
 *
 * For a fixed DRBG seed, this signs three fixed messages and prints the detached
 * signature of each as hex, one line per message:
 *
 *     empty      <hex signature of the empty message>
 *     zeros256   <hex signature of 256 bytes of 0x00>
 *     inc999     <hex signature of 999 bytes 0x01,0x02,0x03,...>
 *
 * Each signature is SHAKE128-256'd and compared against the committed
 * kat_r3/SDITH_<SET>/mini_kat.shake128 golden. This is a cheap per-commit guard: any
 * change that alters keygen or sign output flips these signatures.
 *
 * The full 100-record NIST KAT in the same directory is too slow to run here, so this
 * also checks that each PQCsignKAT_<sk>.rsp still records the sizes of the parameter set
 * it belongs to -- enough to catch a golden left behind by a parameter retune.
 */
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "KeccakHash.h"
#include "sdith_prng.h"
#include "sdith_signature.h"
#include "testlib/testlib.h"

/* Fixed DRBG seed: bytes 0x00..0x2F (the NIST PQCgenKAT entropy convention). Re-seeded
 * before each record so every (keygen+sign) is independently reproducible and the records
 * do not depend on each other's order. */
static std::vector<uint8_t> get_entropy(uint64_t n_bytes) {
  std::vector<uint8_t> res(n_bytes);
  for (uint64_t i = 0; i < n_bytes; i++) res[i] = (unsigned char)i;
  return res;
}

std::string to_hex(const std::vector<uint8_t>& bytes) {
  uint64_t n = bytes.size();
  std::string res(2 * n, '.');
  for (uint64_t i = 0; i < n; i++) {
    snprintf(&res[2 * i], 3, "%02x", bytes[i]);
  }
  return res;
}

typedef std::map<std::string, std::string> kat_t;

static void write_kat(const std::string& filename, const kat_t& kat) {
  // create the parent directory (e.g. kat_r3/SDITH_<SET>/) if it does not exist yet
  std::filesystem::path path(filename);
  if (path.has_parent_path()) {
    std::filesystem::create_directories(path.parent_path());
  }
  std::ofstream out(filename, std::ios::binary);
  REQUIRE_DRAMATICALLY(out, "Failed to open " << filename << "for writing");
  for (const auto& it : kat) {
    out << it.first << " " << it.second << "\n";
  }
  out.close();
}

static kat_t read_kat(const std::string& filename) {
  kat_t kat;
  std::ifstream in(filename, std::ios::binary);
  REQUIRE_DRAMATICALLY(in, "Failed to open " << filename);
  std::string id;
  std::string hexval;
  while (in) {
    in >> id >> hexval;
    kat[id] = hexval;
  }
  return kat;
}

/* Sign one message under a fresh deterministic keypair and print the detached signature
 * (the CRYPTO_BYTES tail of sm = message || signature). Returns 0 on success. */
static std::string sign_and_hexdump(const signature_parameters* sig_params,   // signature parameters
                                    const unsigned char* msg, size_t msglen)  // test id
{
  std::vector<uint8_t> skey(sdith_secret_key_bytes(sig_params));
  std::vector<uint8_t> pkey(sdith_public_key_bytes(sig_params));
  std::vector<uint8_t> signature(sdith_signature_bytes(sig_params));
  {
    std::vector<uint8_t> entropy = get_entropy(sdith_keygen_entropy_bytes(sig_params));
    aligned_vector_u8 tmp_space(32, sdith_keygen_tmp_bytes(sig_params));
    sdith_keygen(sig_params, skey.data(), pkey.data(), entropy.data(), tmp_space.data());
  }
  {
    std::vector<uint8_t> entropy = get_entropy(sdith_signature_entropy_bytes(sig_params));
    aligned_vector_u8 tmp_space(32, sdith_signature_tmp_bytes(sig_params));
    sdith_sign(sig_params, signature.data(), msg, msglen, skey.data(), entropy.data(), tmp_space.data());
  }
  {
    std::vector<uint8_t> hash(32);
    xof_ctx xof;
    xof_init_and_seed_shake128(&xof, signature.data(), signature.size());
    xof_finalize_and_output_shake128(&xof, hash.data(), hash.size());
    return to_hex(hash);
  }
}

kat_t generate_kat(const signature_parameters* sig_params) {
  kat_t actual_kat;
  /* m0: the empty message */
  actual_kat["empty"] = sign_and_hexdump(sig_params, nullptr, 0);

  /* m1: 256 bytes of 0x00 */
  unsigned char m1[256];
  memset(m1, 0, sizeof(m1));
  actual_kat["zeros256"] = sign_and_hexdump(sig_params, m1, sizeof(m1));

  /* m2: 999 bytes, byte[i] = i+1  (0x01, 0x02, 0x03, ...) */
  unsigned char m2[999];
  for (int i = 0; i < 999; i++) m2[i] = (unsigned char)(i + 1);
  actual_kat["inc999"] = sign_and_hexdump(sig_params, m2, sizeof(m2));
  return actual_kat;
}

int verify_kat(const std::string& filename, const signature_parameters* sig_params) {
  kat_t expect_kat = read_kat(filename);
  kat_t actual_kat = generate_kat(sig_params);
  int rc = 0;

  for (const auto& it : actual_kat) {
    std::string id = it.first;
    std::string expected = expect_kat.at(it.first);
    std::string actual = it.second;
    if (actual != expected) {
      std::cerr << filename << ":" << id << "\n"
                << " -- expected: " << expected << "\n"
                << " -- actual  : " << actual << std::endl;
      rc = 1;
    }
  }
  return rc;
}

void regen_kat(const std::string& filename, const signature_parameters* sig_params) {
  kat_t new_kat = generate_kat(sig_params);
  write_kat(filename, new_kat);
}

/* Check that kat_r3/SDITH_<SET>/PQCsignKAT_<sk>.rsp still belongs to this parameter set.
 *
 * Only the first record is read, and only its lengths: the .rsp is named after
 * CRYPTO_SECRETKEYBYTES, and each record carries pk, sk and smlen = mlen + CRYPTO_BYTES.
 * A parameter retune moves all three, so a .rsp left unrewritten after one is caught here.
 * The mini-KAT above cannot see it: it never reads the .rsp files.
 */
int check_rsp_sizes(const std::string& dirname, const signature_parameters* sig_params) {
  const uint64_t want_sk = sdith_secret_key_bytes(sig_params);
  const uint64_t want_pk = sdith_public_key_bytes(sig_params);
  const uint64_t want_sig = sdith_signature_bytes(sig_params);
  const std::string filename = dirname + "/PQCsignKAT_" + std::to_string(want_sk) + ".rsp";

  std::ifstream in(filename);
  if (!in) {
    std::cerr << filename << ": missing.  The name carries CRYPTO_SECRETKEYBYTES (" << want_sk
              << "), so a renamed parameter set looks like this; regenerate the goldens "
                 "(see the full-KAT recipe in README.md)."
              << std::endl;
    return 1;
  }

  uint64_t got_pk = 0, got_sk = 0, mlen = 0, smlen = 0;
  bool seen_pk = false, seen_sk = false, seen_mlen = false, seen_smlen = false;
  std::string line;
  while (std::getline(in, line) && !seen_smlen) {
    while (!line.empty() && std::isspace((unsigned char)line.back())) line.pop_back();
    // "pk = <hex>" and "sk = <hex>"; two hex digits per byte.
    if (line.rfind("pk = ", 0) == 0) {
      got_pk = (line.size() - 5) / 2;
      seen_pk = true;
    } else if (line.rfind("sk = ", 0) == 0) {
      got_sk = (line.size() - 5) / 2;
      seen_sk = true;
    } else if (line.rfind("mlen = ", 0) == 0) {
      mlen = std::stoull(line.substr(7));
      seen_mlen = true;
    } else if (line.rfind("smlen = ", 0) == 0) {
      smlen = std::stoull(line.substr(8));
      seen_smlen = true;
    }
  }
  if (!(seen_pk && seen_sk && seen_mlen && seen_smlen) || smlen < mlen) {
    std::cerr << filename << ": not a well-formed NIST .rsp (no complete first record)" << std::endl;
    return 1;
  }

  const uint64_t got_sig = smlen - mlen;
  if (got_sk == want_sk && got_pk == want_pk && got_sig == want_sig) return 0;
  std::cerr << filename << ": stale, it was produced by different parameters\n"
            << " -- expected sk=" << want_sk << " pk=" << want_pk << " sig=" << want_sig << "\n"
            << " -- found    sk=" << got_sk << " pk=" << got_pk << " sig=" << got_sig << "\n"
            << " -- regenerate the goldens (see the full-KAT recipe in README.md)" << std::endl;
  return 1;
}

int main(int argc, char* argv[]) {
  int rc = 0;
  std::vector<std::pair<std::string, const signature_parameters*>> testset = {
      {"SDITH_CAT1_SHORT", &CAT1_SHORT_PARAMETERS},
      {"SDITH_CAT1_FAST", &CAT1_FAST_PARAMETERS},
      {"SDITH_CAT1_SHORT_CIPHERPOW", &CAT1_SHORT_CIPHERPOW_PARAMETERS},
      {"SDITH_CAT1_FAST_CIPHERPOW", &CAT1_FAST_CIPHERPOW_PARAMETERS},
      {"SDITH_CAT3_SHORT", &CAT3_SHORT_PARAMETERS},
      {"SDITH_CAT3_FAST", &CAT3_FAST_PARAMETERS},
      {"SDITH_CAT3_SHORT_CIPHERPOW", &CAT3_SHORT_CIPHERPOW_PARAMETERS},
      {"SDITH_CAT3_FAST_CIPHERPOW", &CAT3_FAST_CIPHERPOW_PARAMETERS},
      {"SDITH_CAT5_SHORT", &CAT5_SHORT_PARAMETERS},
      {"SDITH_CAT5_FAST", &CAT5_FAST_PARAMETERS},
      {"SDITH_CAT5_SHORT_CIPHERPOW", &CAT5_SHORT_CIPHERPOW_PARAMETERS},
      {"SDITH_CAT5_FAST_CIPHERPOW", &CAT5_FAST_CIPHERPOW_PARAMETERS},
  };
  std::string dirname = "../kat_r3";
  if (argc == 1) {
    // verify mode
    for (const auto& it : testset) {
      std::string setdir = dirname + "/" + it.first;
      std::cerr << "Checking " << it.first << std::endl;
      rc |= verify_kat(setdir + "/mini_kat.shake128", it.second);
      rc |= check_rsp_sizes(setdir, it.second);
    }
    return rc;
  }
  if (argc == 2 && std::string(argv[1]) == std::string("--regen")) {
    for (const auto& it : testset) {
      std::string filename = dirname + "/" + it.first + "/mini_kat.shake128";
      std::cerr << "Generating " << it.first << "/mini_kat.shake128" << std::endl;
      regen_kat(filename, it.second);
    }
    return rc;
  }
  std::cerr << "invalid argument" << std::endl;
  return 1;
}
