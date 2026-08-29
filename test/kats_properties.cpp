#include <sdith_signature.h>

#include <iostream>

int main() {
  std::cout << "CAT1_FAST_ALGNAME: " << "\"SDiTH-CAT1-FAST\"" << std::endl;
  std::cout << "CAT1_FAST_PARAMS: " << "CAT1_FAST_PARAMETERS" << std::endl;
  std::cout << "CAT1_FAST_SECRETKEYBYTES: " << sdith_secret_key_bytes(&CAT1_FAST_PARAMETERS) << std::endl;
  std::cout << "CAT1_FAST_PUBLICKEYBYTES: " << sdith_public_key_bytes(&CAT1_FAST_PARAMETERS) << std::endl;
  std::cout << "CAT1_FAST_BYTES: " << sdith_signature_bytes(&CAT1_FAST_PARAMETERS) << std::endl;

  std::cout << "CAT3_FAST_ALGNAME: " << "\"SDiTH-CAT3-FAST\"" << std::endl;
  std::cout << "CAT3_FAST_PARAMS: " << "CAT3_FAST_PARAMETERS" << std::endl;
  std::cout << "CAT3_FAST_SECRETKEYBYTES: " << sdith_secret_key_bytes(&CAT3_FAST_PARAMETERS) << std::endl;
  std::cout << "CAT3_FAST_PUBLICKEYBYTES: " << sdith_public_key_bytes(&CAT3_FAST_PARAMETERS) << std::endl;
  std::cout << "CAT3_FAST_BYTES: " << sdith_signature_bytes(&CAT3_FAST_PARAMETERS) << std::endl;

  std::cout << "CAT5_FAST_ALGNAME: " << "\"SDiTH-CAT5-FAST\"" << std::endl;
  std::cout << "CAT5_FAST_PARAMS: " << "CAT5_FAST_PARAMETERS" << std::endl;
  std::cout << "CAT5_FAST_SECRETKEYBYTES: " << sdith_secret_key_bytes(&CAT5_FAST_PARAMETERS) << std::endl;
  std::cout << "CAT5_FAST_PUBLICKEYBYTES: " << sdith_public_key_bytes(&CAT5_FAST_PARAMETERS) << std::endl;
  std::cout << "CAT5_FAST_BYTES: " << sdith_signature_bytes(&CAT5_FAST_PARAMETERS) << std::endl;

  std::cout << "CAT1_SHORT_ALGNAME: " << "\"SDiTH-CAT1-SHORT\"" << std::endl;
  std::cout << "CAT1_SHORT_PARAMS: " << "CAT1_SHORT_PARAMETERS" << std::endl;
  std::cout << "CAT1_SHORT_SECRETKEYBYTES: " << sdith_secret_key_bytes(&CAT1_SHORT_PARAMETERS) << std::endl;
  std::cout << "CAT1_SHORT_PUBLICKEYBYTES: " << sdith_public_key_bytes(&CAT1_SHORT_PARAMETERS) << std::endl;
  std::cout << "CAT1_SHORT_BYTES: " << sdith_signature_bytes(&CAT1_SHORT_PARAMETERS) << std::endl;

  std::cout << "CAT3_SHORT_ALGNAME: " << "\"SDiTH-CAT3-SHORT\"" << std::endl;
  std::cout << "CAT3_SHORT_PARAMS: " << "CAT3_SHORT_PARAMETERS" << std::endl;
  std::cout << "CAT3_SHORT_SECRETKEYBYTES: " << sdith_secret_key_bytes(&CAT3_SHORT_PARAMETERS) << std::endl;
  std::cout << "CAT3_SHORT_PUBLICKEYBYTES: " << sdith_public_key_bytes(&CAT3_SHORT_PARAMETERS) << std::endl;
  std::cout << "CAT3_SHORT_BYTES: " << sdith_signature_bytes(&CAT3_SHORT_PARAMETERS) << std::endl;

  std::cout << "CAT5_SHORT_ALGNAME: " << "\"SDiTH-CAT5-SHORT\"" << std::endl;
  std::cout << "CAT5_SHORT_PARAMS: " << "CAT5_SHORT_PARAMETERS" << std::endl;
  std::cout << "CAT5_SHORT_SECRETKEYBYTES: " << sdith_secret_key_bytes(&CAT5_SHORT_PARAMETERS) << std::endl;
  std::cout << "CAT5_SHORT_PUBLICKEYBYTES: " << sdith_public_key_bytes(&CAT5_SHORT_PARAMETERS) << std::endl;
  std::cout << "CAT5_SHORT_BYTES: " << sdith_signature_bytes(&CAT5_SHORT_PARAMETERS) << std::endl;
}
