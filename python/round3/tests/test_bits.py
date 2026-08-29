"""
L1 - bit/byte + F2 matrix utilities (utils.py).

These are the classic off-by-one hiding spots (bit packing, transpose, matrix
products). Checked against straightforward numpy/int references and exhaustive
small cases.
"""
from utils import (extract_bits, xor_bits_into, get_bit, parity,
                   lowest_set_bit, bitvec_is_zero,
                   transpose_vole_matrix,
                   matrix_vector_product_f2, matrix_f2_times_vector_gf)
from deps import given, settings, st


# ---- scalar bit helpers ----

@given(x=st.integers(min_value=0, max_value=(1 << 64) - 1))
def test_parity(x):
    assert parity(x & 0xFF) == (bin(x & 0xFF).count('1') & 1)


@given(x=st.integers(min_value=0, max_value=(1 << 200) - 1))
def test_lowest_set_bit(x):
    if x == 0:
        assert lowest_set_bit(0) == 0
    else:
        assert lowest_set_bit(x) == (x & -x).bit_length() - 1


@given(data=st.data())
def test_extract_bits_matches_int_shift(data):
    nbytes = data.draw(st.integers(min_value=1, max_value=16))
    raw = data.draw(st.binary(min_size=nbytes, max_size=nbytes))
    total = nbytes * 8
    offset = data.draw(st.integers(min_value=0, max_value=total - 1))
    width = data.draw(st.integers(min_value=1, max_value=total - offset))
    val = int.from_bytes(raw, 'little')
    assert extract_bits(width, offset, raw) == ((val >> offset) & ((1 << width) - 1))


@given(data=st.data())
def test_xor_bits_into_roundtrip(data):
    nbytes = data.draw(st.integers(min_value=1, max_value=16))
    total = nbytes * 8
    offset = data.draw(st.integers(min_value=0, max_value=total - 1))
    width = data.draw(st.integers(min_value=1, max_value=total - offset))
    buf = bytearray(data.draw(st.binary(min_size=nbytes, max_size=nbytes)))
    value = data.draw(st.integers(min_value=0, max_value=(1 << width) - 1))
    before = extract_bits(width, offset, buf)
    xor_bits_into(width, offset, buf, value)
    assert extract_bits(width, offset, buf) == (before ^ value)


@given(data=st.data())
def test_get_bit(data):
    raw = data.draw(st.binary(min_size=1, max_size=32))
    i = data.draw(st.integers(min_value=0, max_value=len(raw) * 8 - 1))
    assert get_bit(raw, i) == ((raw[i // 8] >> (i % 8)) & 1)


@given(data=st.data())
def test_bitvec_is_zero(data):
    raw = bytearray(data.draw(st.binary(min_size=1, max_size=32)))
    nbits = data.draw(st.integers(min_value=0, max_value=len(raw) * 8))
    expected = all(((raw[i // 8] >> (i % 8)) & 1) == 0 for i in range(nbits))
    assert bitvec_is_zero(raw, nbits) == expected


# ---- F2 matrix ops ----

def _bits_lsb(data, nbits):
    return [(data[i // 8] >> (i % 8)) & 1 for i in range(nbits)]


@given(data=st.data())
@settings(max_examples=100, deadline=None)
def test_transpose_vole_matrix(data):
    num_rows = data.draw(st.integers(min_value=1, max_value=40))
    num_cols = 8 * data.draw(st.integers(min_value=1, max_value=8))  # mult of 8
    col_bytes = num_cols // 8
    flat = data.draw(st.binary(min_size=num_rows * col_bytes,
                               max_size=num_rows * col_bytes))
    out = transpose_vole_matrix(flat, num_rows, num_cols)
    # reference: out[c] has bit r set iff matrix[r][c] == 1
    for c in range(num_cols):
        expect = 0
        for r in range(num_rows):
            row = flat[r * col_bytes:(r + 1) * col_bytes]
            if (row[c // 8] >> (c % 8)) & 1:
                expect |= (1 << r)
        assert out[c] == expect


@given(data=st.data())
@settings(max_examples=100, deadline=None)
def test_matrix_vector_product_f2(data):
    # This function ANDs whole bytes and takes their parity, so it reads any
    # padding bits in the last column byte. Its real callers always pass
    # num_cols that is a multiple of 8 (locked by test_params:
    # (L_total - num_cchk_pairs) % 8 == 0), so test it under that contract.
    num_rows = data.draw(st.integers(min_value=1, max_value=40))
    num_cols = 8 * data.draw(st.integers(min_value=1, max_value=8))
    col_bytes = (num_cols + 7) // 8
    matrix = data.draw(st.binary(min_size=num_rows * col_bytes,
                                 max_size=num_rows * col_bytes))
    vector = data.draw(st.binary(min_size=col_bytes, max_size=col_bytes))
    result = matrix_vector_product_f2(num_rows, num_cols, matrix, vector)
    vbits = _bits_lsb(vector, num_cols)
    for r in range(num_rows):
        row = matrix[r * col_bytes:(r + 1) * col_bytes]
        rbits = _bits_lsb(row, num_cols)
        expect = sum(rb & vb for rb, vb in zip(rbits, vbits)) & 1
        assert ((result[r // 8] >> (r % 8)) & 1) == expect


@given(data=st.data())
@settings(max_examples=100, deadline=None)
def test_matrix_f2_times_vector_gf(data):
    num_rows = data.draw(st.integers(min_value=1, max_value=30))
    num_cols = data.draw(st.integers(min_value=1, max_value=40))
    col_bytes = (num_cols + 7) // 8
    matrix = data.draw(st.binary(min_size=num_rows * col_bytes,
                                 max_size=num_rows * col_bytes))
    gf_vec = [data.draw(st.integers(min_value=0, max_value=(1 << 32) - 1))
              for _ in range(num_cols)]
    result = matrix_f2_times_vector_gf(num_rows, num_cols, matrix, gf_vec)
    for r in range(num_rows):
        row = matrix[r * col_bytes:(r + 1) * col_bytes]
        expect = 0
        for c in range(num_cols):
            if (row[c // 8] >> (c % 8)) & 1:
                expect ^= gf_vec[c]
        assert result[r] == expect
