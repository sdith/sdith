#ifndef BIT_MATRIX_LAYOUT_H
#define BIT_MATRIX_LAYOUT_H

#include "testlib.h"

class bit_matrix_view {
  uint8_t* dat;
  uint64_t nrows;
  uint64_t ncols;
  uint64_t byte_slice;
  uint64_t col_byte_size;
  uint64_t last_mask;

public:
  bit_matrix_view(void* data, uint64_t nrows, uint64_t ncols);
  [[nodiscard]] bool get(uint64_t row, uint64_t col) const;
  void set(uint64_t row, uint64_t col, bool value);
  [[nodiscard]] uint8_t* data() const;
  void randomize();
};

class bit_vector;

class bit_matrix {
  uint64_t nrows;
  uint64_t ncols;
  uint64_t byte_slice;
  uint64_t col_byte_size;
  uint64_t last_mask;
  aligned_vector_u8 dat;

 public:
  bit_matrix();
  bit_matrix(uint64_t nrows, uint64_t ncols);
  [[nodiscard]] uint64_t num_rows() const;
  [[nodiscard]] uint64_t num_cols() const;
  [[nodiscard]] bool get(uint64_t row, uint64_t col) const;
  void set(uint64_t row, uint64_t col, bool value);
  [[nodiscard]] const uint8_t* data() const;
  [[nodiscard]] uint8_t* data();
  void randomize();
  static bit_matrix random(uint64_t nrows, uint64_t ncols);
  static bit_matrix zero(uint64_t nrows, uint64_t ncols);
  [[nodiscard]] bit_vector row(uint64_t row) const;
  [[nodiscard]] const void* row_ptr(uint64_t row) const;
  [[nodiscard]] void* row_ptr(uint64_t row);
  friend bool operator==(const bit_matrix& a, const bit_matrix& b);
};

bool operator==(const bit_matrix& a, const bit_matrix& b);

class bit_vector_view {
  uint8_t* const dat;
  const uint64_t size;
  uint64_t byte_size;
  uint8_t last_mask;

 public:
  bit_vector_view(void* data, uint64_t size);
  [[nodiscard]] bool get(uint64_t pos) const;
  void set(uint64_t pos, bool value);
  [[nodiscard]] uint8_t* data() const;
  void randomize();
};

class bit_vector {
  aligned_vector_u8 dat;
  uint64_t size;
  uint64_t byte_size;
  uint8_t last_mask;

 public:
  explicit bit_vector(uint64_t size = 0);
  [[nodiscard]] bool get(uint64_t pos) const;
  [[nodiscard]] uint64_t bit_size() const;
  void set(uint64_t pos, bool value);
  [[nodiscard]] uint8_t* data() const;
  void randomize();
  static bit_vector random(uint64_t size);
  static bit_vector zero(uint64_t size);
  bit_vector& operator^=(const bit_vector& v);
  bool operator==(const bit_vector& v) const;
};

bit_vector operator^(const bit_vector& u, const bit_vector& v);

#endif  // BIT_MATRIX_LAYOUT_H
