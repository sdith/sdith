"""
Bit/byte utilities and F2 matrix operations for SDitH v2.
"""


def bytes_xor(a, b):
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_xor_into(dst, src):
    """XOR src into mutable dst in place."""
    for i in range(len(src)):
        dst[i] ^= src[i]


def get_bit(data, bit_index):
    """Get a single bit from a byte array."""
    return (data[bit_index // 8] >> (bit_index % 8)) & 1


def extract_bits(width, bit_offset, data):
    """Extract a `width`-bit unsigned integer starting at `bit_offset` in data."""
    mask = (1 << width) - 1
    value = int.from_bytes(data, 'little')
    return (value >> bit_offset) & mask


def xor_bits_into(width, bit_offset, data, value):
    """XOR a `width`-bit value into data at the given bit offset."""
    mask = (1 << width) - 1
    value &= mask
    current = int.from_bytes(data, 'little')
    current ^= value << bit_offset
    data[:] = current.to_bytes(len(data), 'little')


def bitvec_is_zero(data, num_bits):
    """Check whether the first `num_bits` bits of data are all zero."""
    full_bytes = num_bits // 8
    for i in range(full_bytes):
        if data[i]:
            return False
    remainder = num_bits % 8
    if remainder and (data[full_bytes] & ((1 << remainder) - 1)):
        return False
    return True


def lowest_set_bit(n):
    """Position of the lowest set bit (0-indexed). Returns 0 for n=0."""
    if n == 0:
        return 0
    return (n & -n).bit_length() - 1


def parity(byte):
    """Compute the parity (XOR of all bits) of a single byte."""
    byte ^= byte >> 4
    byte ^= byte >> 2
    byte ^= byte >> 1
    return byte & 1


def matrix_vector_product_f2(num_rows, num_cols, matrix, vector):
    """Binary matrix-vector product over F2.

    The matrix is stored row-major as a flat byte array.
    The vector is a byte array of packed bits.
    Returns a byte array of packed result bits.
    """
    col_bytes = (num_cols + 7) // 8
    result = bytearray((num_rows + 7) // 8)
    for row in range(num_rows):
        row_offset = row * col_bytes
        row_parity = 0
        for j in range(col_bytes):
            row_parity ^= parity(matrix[row_offset + j] & vector[j])
        if row_parity:
            result[row // 8] |= 1 << (row % 8)
    return result


def matrix_f2_times_vector_gf(num_rows, num_cols, matrix, gf_vector):
    """Multiply a binary matrix by a vector of GF(2^n) elements.

    Returns a list of num_rows GF elements.
    """
    col_bytes = (num_cols + 7) // 8
    result = [0] * num_rows
    for row in range(num_rows):
        for col in range(num_cols):
            if (matrix[row * col_bytes + col // 8] >> (col % 8)) & 1:
                result[row] ^= gf_vector[col]
    return result


def transpose_vole_matrix(flat_data, num_rows, num_cols):
    """Transpose a num_rows x num_cols bit matrix into a list of num_cols GF elements.

    Each output element packs one column of the input matrix as an integer.
    """
    col_bytes = num_cols // 8
    result = [0] * num_cols
    for row in range(num_rows):
        for col in range(num_cols):
            if (flat_data[row * col_bytes + col // 8] >> (col % 8)) & 1:
                result[col] |= 1 << row
    return result
