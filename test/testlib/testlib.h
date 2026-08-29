#ifndef AQ_VOLE_IMPL_TESTLIB_H
#define AQ_VOLE_IMPL_TESTLIB_H

#include <cstdint>
#include <cstring>
#include <random>

#define UNUSED_OK __attribute((unused))

typedef std::mt19937_64 rand_t;

rand_t& randgen();

void randomize(void* u, uint64_t size);
__uint128_t uniform_u128();

#define randomize_static_array(data_array) randomize(data_array, sizeof(data_array))
#define randomize_primitive_var(primitive_var) randomize(&primitive_var, sizeof(primitive_var))

#define REQUIRE_DRAMATICALLY(condition, message)                                    \
  do {                                                                              \
    if (!(condition)) {                                                             \
      std::cerr << "REQUIREMENT FAILED: " __FILE__ << ": " << message << std::endl; \
      abort();                                                                      \
    }                                                                               \
  } while (0)

void* my_aligned_alloc(uint64_t alignment, uint64_t size);

void my_aligned_free(void* ptr);

class aligned_vector_u8 {
  uint64_t _alignment;
  uint64_t _size;
  uint8_t* _data;

 public:
  aligned_vector_u8();
  aligned_vector_u8(uint64_t alignment, uint64_t size);
  aligned_vector_u8(uint64_t alignment, uint64_t size, uint8_t value);
  ~aligned_vector_u8();
  aligned_vector_u8& operator=(const aligned_vector_u8& other);
  aligned_vector_u8(const aligned_vector_u8& other);
  uint64_t size() const;
  uint8_t* data();
  const uint8_t* data() const;
  uint8_t operator[](uint64_t index) const;
  uint8_t& operator[](uint64_t index);
};

#endif  // AQ_VOLE_IMPL_TESTLIB_H
