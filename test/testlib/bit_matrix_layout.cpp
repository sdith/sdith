#include "bit_matrix_layout.h"

#include <cstdlib>
#include <cstring>
#include <iostream>

bit_matrix_view::bit_matrix_view(void* data, uint64_t nrows, uint64_t ncols)
    : dat((uint8_t*)data), nrows(nrows), ncols(ncols), byte_slice((ncols + 7) / 8) {
  col_byte_size = (ncols + 7) >> 3;
  if (ncols & 7) {
    last_mask = 0xFF >> (8 - (ncols & 7));
  } else {
    last_mask = 0XFF;
  }
}

bool bit_matrix_view::get(uint64_t row, uint64_t col) const {
  REQUIRE_DRAMATICALLY(row < nrows, "row overflow " << row << " / " << nrows);
  REQUIRE_DRAMATICALLY(col < ncols, "col overflow " << col << " / " << nrows);
  return (dat[row * byte_slice + col / 8] >> (col % 8)) & 1;
}

void bit_matrix_view::set(uint64_t row, uint64_t col, bool val) {
  REQUIRE_DRAMATICALLY(row < nrows, "row overflow " << row << " / " << nrows);
  REQUIRE_DRAMATICALLY(col < ncols, "col overflow " << col << " / " << nrows);
  uint8_t& b = dat[row * byte_slice + col / 8];
  if (val) {
    b |= (1 << col % 8);
  } else {
    b &= ~(1 << col % 8);
  }
}
uint8_t* bit_matrix_view::data() const { return dat; }
void bit_matrix_view::randomize() {
  for (uint64_t i = 0; i < nrows; ++i) {
    uint8_t* v = dat + i * byte_slice;
    ::randomize(v, col_byte_size);
    v[col_byte_size - 1] &= last_mask;
  }
}

bit_matrix::bit_matrix() : bit_matrix(0, 0) {}
bit_matrix::bit_matrix(uint64_t nrows, uint64_t ncols)  //
    : nrows(nrows),
      ncols(ncols),
      byte_slice((ncols + 7) >> 3),  //
      dat(32, nrows * byte_slice, 0) {
  col_byte_size = (ncols + 7) >> 3;
  if (ncols & 7) {
    last_mask = 0XFF >> (8 - (ncols & 7));
  } else {
    last_mask = 0xFF;
  }
}
uint64_t bit_matrix::num_rows() const { return nrows; }
uint64_t bit_matrix::num_cols() const { return ncols; }

bool bit_matrix::get(uint64_t row, uint64_t col) const {
  REQUIRE_DRAMATICALLY(row < nrows, "row overflow " << row << " / " << nrows);
  REQUIRE_DRAMATICALLY(col < ncols, "col overflow " << col << " / " << nrows);
  return (dat[row * byte_slice + col / 8] >> (col % 8)) & 1;
}

void bit_matrix::set(uint64_t row, uint64_t col, bool val) {
  REQUIRE_DRAMATICALLY(row < nrows, "row overflow " << row << " / " << nrows);
  REQUIRE_DRAMATICALLY(col < ncols, "col overflow " << col << " / " << nrows);
  uint8_t& b = dat[row * byte_slice + col / 8];
  if (val) {
    b |= (1 << col % 8);
  } else {
    b &= ~(1 << col % 8);
  }
}
const uint8_t* bit_matrix::data() const { return dat.data(); }
uint8_t* bit_matrix::data() { return dat.data(); }

void bit_matrix::randomize() {
  for (uint64_t i = 0; i < nrows; ++i) {
    uint8_t* v = dat.data() + i * byte_slice;
    ::randomize(v, col_byte_size);
    v[col_byte_size - 1] &= last_mask;
  }
}
bit_matrix bit_matrix::random(uint64_t nrows, uint64_t ncols) {
  bit_matrix ret(nrows, ncols);
  ret.randomize();
  return ret;
}
bit_matrix bit_matrix::zero(uint64_t nrows, uint64_t ncols) { return bit_matrix(nrows, ncols); }
bit_vector bit_matrix::row(uint64_t row) const {
  REQUIRE_DRAMATICALLY(row < nrows, "row overflow " << row << " / " << nrows);
  bit_vector ret(ncols);
  memcpy(ret.data(), dat.data() + row * byte_slice, col_byte_size);
  return ret;
}
const void* bit_matrix::row_ptr(uint64_t row) const { return dat.data() + row * byte_slice; }
void* bit_matrix::row_ptr(uint64_t row) { return dat.data() + row * byte_slice; }
bool operator==(const bit_matrix& a, const bit_matrix& b) {
  REQUIRE_DRAMATICALLY(a.nrows == b.nrows, "nrows mismatch: " << a.nrows << " vs. " << b.nrows);
  REQUIRE_DRAMATICALLY(a.ncols == b.ncols, "ncols mismatch: " << a.ncols << " vs. " << b.ncols);
  for (uint64_t i = 0; i < a.nrows; ++i) {
    if (memcmp(a.row_ptr(i), b.row_ptr(i), a.col_byte_size) != 0) return false;
  }
  return true;
}

bit_vector_view::bit_vector_view(void* data, uint64_t size) : dat((uint8_t*)data), size(size) {
  byte_size = (size + 7) >> 3;
  if (size & 7) {
    last_mask = 0xFF >> (8 - (size & 7));
  } else {
    last_mask = 0xFF;
  }
}

bool bit_vector_view::get(uint64_t pos) const {
  REQUIRE_DRAMATICALLY(pos < size, "pos overflow " << pos << " / " << size);
  return (dat[pos / 8] >> (pos % 8)) & 1;
}

void bit_vector_view::set(uint64_t pos, bool value) {
  REQUIRE_DRAMATICALLY(pos < size, "pos overflow " << pos << " / " << size);
  uint8_t& b = dat[pos / 8];
  if (value) {
    b |= (1 << pos % 8);
  } else {
    b &= ~(1 << pos % 8);
  }
}
uint8_t* bit_vector_view::data() const { return dat; }

void bit_vector_view::randomize() {
  ::randomize(dat, byte_size);
  dat[byte_size-1] &= last_mask;
}

bit_vector::bit_vector(uint64_t size) : size(size) {
  byte_size = (size + 7) >> 3;
  dat = aligned_vector_u8(32, byte_size, 0);
  if (size & 7) {
    last_mask = 0xFF >> (8 - (size & 7));
  } else {
    last_mask = 0xFF;
  }
}

bool bit_vector::get(uint64_t pos) const {
  REQUIRE_DRAMATICALLY(pos < size, "pos overflow " << pos << " / " << size);
  return (dat[pos / 8] >> (pos % 8)) & 1;
}
uint64_t bit_vector::bit_size() const { return size; }

void bit_vector::set(uint64_t pos, bool value) {
  REQUIRE_DRAMATICALLY(pos < size, "pos overflow " << pos << " / " << size);
  uint8_t& b = dat[pos / 8];
  if (value) {
    b |= (1 << pos % 8);
  } else {
    b &= ~(1 << pos % 8);
  }
}
uint8_t* bit_vector::data() const { return (uint8_t*)dat.data(); }

void bit_vector::randomize() {
  ::randomize(dat.data(), byte_size);
  dat[byte_size - 1] &= last_mask;
}
bit_vector bit_vector::random(uint64_t size) {
  bit_vector ret(size);
  ret.randomize();
  return ret;
}
bit_vector bit_vector::zero(uint64_t size) { return bit_vector(size); }

bit_vector operator^(const bit_vector& u, const bit_vector& v) {
  bit_vector u1(u);
  u1 ^= v;
  return u1;
}

bit_vector& bit_vector::operator^=(const bit_vector& v) {
  REQUIRE_DRAMATICALLY(size == v.size, "bitvecctor size mismatch");
  for (uint64_t i = 0; i < byte_size; ++i) {
    dat[i] ^= v.dat[i];
  }
  return *this;
}

bool bit_vector::operator==(const bit_vector& v) const {
  REQUIRE_DRAMATICALLY(size == v.size, "bitvecctor size mismatch");
  for (uint64_t i = 0; i < byte_size; ++i) {
    if (dat[i] != v.dat[i]) return false;
  }
  return true;
}

