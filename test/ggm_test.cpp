#include "ggm.h"

#include <gtest/gtest.h>

#include "sdith_prng.h"
#include "testlib/bit_matrix_layout.h"
#include "testlib/testlib.h"
#include "vole_private.h"


TEST(ggm_hidden_leaves_indexes, hidden_leaves_indexes) {
  // test for kappa = 11, tau = 11
  std::vector<uint32_t> delta = {0b00111110100110111110110110010000, 0b00110001001111111011111100110010,
                                 0b00101000010111111001110001100100, 0b0110001111111101101100100};
  uint64_t kappa = 11;
  uint64_t tau = 11;
  std::vector<uint32_t> hidden_leaves(tau, 0);
  std::vector<uint32_t> expected = {1083, 2752, 8411, 8799, 9824, 11213, 11712, 15664, 19993, 20909, 21398};

  hidden_leaves_indexes(kappa, tau, hidden_leaves.data(), delta.data());
  ASSERT_EQ(hidden_leaves, expected);

  // test for kappa = 1, and tau = 1
  delta = {1};
  kappa = 1;
  tau = 1;
  hidden_leaves = {0};
  expected = {1};
  hidden_leaves_indexes(kappa, tau, hidden_leaves.data(), delta.data());
  ASSERT_EQ(hidden_leaves, expected);

  // test for kappa = 4, and tau = 5
  delta = {0b11110111111101011010};  // 50, 26, 77, 38, 79
  kappa = 4;
  tau = 5;
  hidden_leaves = {0, 0, 0, 0, 0};
  expected = {26, 38, 50, 77, 79};
  hidden_leaves_indexes(kappa, tau, hidden_leaves.data(), delta.data());
  ASSERT_EQ(hidden_leaves, expected);

  // test for kappa = 8, and tau = 100
  delta = {0b00000101101101110111100100001110, 0b11011010110110101110000111101101, 0b00010011000101000011001000110101,
           0b10010100100000110011010001111110, 0b10111010110001101011111100000101, 0b00001000011010100010101100000111,
           0b00101100111110011101011101101011, 0b10101001001010000000101010010001, 0b11101001001010011100101011111000,
           0b00010000010000111101110001100101, 0b11010111100010101100010010110100, 0b00100101011100101010111010101101,
           0b11100010011011011110101111000100, 0b01110100111000110000010000010101, 0b00011100100110110101110000010100,
           0b00001110010011111010100101011101, 0b11001011111001010111011111011011, 0b00011101101010100011101011100011,
           0b00010001101010011001100001000100, 0b11111001111101110110010101001101, 0b10110011001111011000101111100010,
           0b11010001000001001111000010010000, 0b11111001011001100100010001100000, 0b01111101000101011011000010100001,
           0b10111111111000011011111011100001};
  kappa = 8;
  tau = 100;
  hidden_leaves = std::vector<uint32_t>(tau, 0);
  expected = {453,   486,   503,   516,   720,   823,   1029,  1400,  1463,  1639,  1775,  1911,  2010,  2056,  2152,
              2194,  2859,  2971,  3747,  4030,  4134,  4321,  4427,  5009,  5213,  5308,  5869,  6182,  6738,  6872,
              6889,  7776,  7962,  9257,  9360,  9688,  10136, 10177, 10290, 10622, 10724, 10950, 11446, 11655, 11965,
              12101, 12595, 12612, 13114, 13842, 13981, 14484, 14528, 14815, 15273, 15558, 16192, 16931, 16961, 16974,
              17070, 17344, 17445, 17693, 17983, 18040, 18302, 18619, 19097, 19117, 19199, 19641, 19648, 19818, 20233,
              20367, 20987, 21525, 21543, 21806, 21807, 21964, 22037, 22505, 22596, 22598, 22651, 22680, 22754, 22768,
              22966, 23335, 23549, 23704, 24085, 24778, 24832, 24926, 24979, 24991};
  hidden_leaves_indexes(kappa, tau, hidden_leaves.data(), delta.data());
  ASSERT_EQ(hidden_leaves, expected);

  // test vectors for the hidden_leaves_indexes python reference:
  /* python reference implementation:

  def quick_sort(arr):
      if len(arr) <= 1:
          return arr
      else:
          pivot = arr[len(arr) // 2]
          left = [x for x in arr if x < pivot]
          middle = [x for x in arr if x == pivot]
          right = [x for x in arr if x > pivot]
          return quick_sort(left) + middle + quick_sort(right)



  def hidden_leaves_indices(kappa, tau, delta):
      hidden_leaves = []
      for i in range(tau):
          small_bit_array = delta[i*kappa:(i+1)*kappa]
          number = int(small_bit_array[::-1], 2)
          number = number * tau + i
          hidden_leaves.append(number)
      return quick_sort(hidden_leaves)

    test vectors for the hidden_leaves_indexes python reference:

  //test vector generation
  import random
  kappa = 11
  tau = 11
  delta = ''.join(random.choice('01') for _ in range(kappa * tau))
  print('{', end='')
  for i in range(0, len(delta), 32):
      a = (delta[i:i+32])
      bit_reverse = a[::-1]
      print('0b'+bit_reverse+',', end=' ')
  print('}')
  hidden_leaves = hidden_leaves_indices(kappa, tau, delta)
  print("hidden leaves =", hidden_leaves)
    */
}
