#include "testlib.h"

rand_t& randgen() {
  static std::mt19937_64 gen;
  return gen;
}

void randomize(void* u, uint64_t size) {
  rand_t& gen = randgen();
  uint8_t* uu = (uint8_t*)u;
  std::uniform_int_distribution<uint8_t> dist;
  for (uint64_t i = 0; i < size; ++i) uu[i] = dist(gen);
}
__uint128_t uniform_u128() {
  rand_t& gen = randgen();
  std::uniform_int_distribution<__uint128_t> dist;
  return dist(gen);
}

void* my_aligned_alloc(uint64_t alignment, uint64_t size) {
  if (alignment < 8) {
    return malloc(size);
  } else {
    return aligned_alloc(alignment, (size + alignment - 1) & (-alignment));
  }
}

void my_aligned_free(void* ptr) { free(ptr); }

aligned_vector_u8::aligned_vector_u8() : _alignment(1), _size(0), _data(nullptr) {}
aligned_vector_u8::aligned_vector_u8(uint64_t alignment, uint64_t size)
    : _alignment(alignment), _size(size), _data((uint8_t*)my_aligned_alloc(alignment, size)) {}
aligned_vector_u8::aligned_vector_u8(uint64_t alignment, uint64_t size, uint8_t value)
    : aligned_vector_u8(alignment, size) {
  memset(_data, value, size);
}
aligned_vector_u8::~aligned_vector_u8() { my_aligned_free(_data); }
aligned_vector_u8& aligned_vector_u8::operator=(const aligned_vector_u8& other) {
  if (this == &other) {
    return *this;
  }
  this->~aligned_vector_u8();
  new (this) aligned_vector_u8(other._alignment, other._size);
  memcpy(_data, other._data, other._size);
  return *this;
}
aligned_vector_u8::aligned_vector_u8(const aligned_vector_u8& other)
    : aligned_vector_u8(other._alignment, other._size) {
  memcpy(_data, other._data, other._size);
}
uint64_t aligned_vector_u8::size() const { return _size; }
uint8_t* aligned_vector_u8::data() { return _data; }
const uint8_t* aligned_vector_u8::data() const { return _data; }
uint8_t aligned_vector_u8::operator[](uint64_t index) const { return _data[index]; }
uint8_t& aligned_vector_u8::operator[](uint64_t index) { return _data[index]; }
