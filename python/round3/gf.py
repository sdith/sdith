"""
GF(2^n) finite field arithmetic.

Supports GF(2^128), GF(2^192), GF(2^256) with their respective
irreducible polynomials. Elements are arbitrary-precision integers;
byte encoding is little-endian.

Reduction polynomials (without the leading x^n term):
  GF(2^128): x^7 + x^2 + x + 1       = 0x87
  GF(2^192): x^7 + x^2 + x + 1       = 0x87
  GF(2^256): x^10 + x^5 + x^2 + 1    = 0x425
"""


class GF:
    """Finite field GF(2^n) with schoolbook multiplication."""

    def __init__(self, bits, reduction_poly):
        self.bits = bits
        self.reduction_poly = reduction_poly
        self.mask = (1 << bits) - 1
        self.byte_size = bits // 8

    def mul(self, a, b):
        """Multiply two field elements."""
        result = 0
        for _ in range(self.bits):
            if b & 1:
                result ^= a
            carry = a >> (self.bits - 1)
            a = (a << 1) & self.mask
            if carry:
                a ^= self.reduction_poly
            b >>= 1
        return result

    def inv(self, a):
        """Multiplicative inverse via Fermat's little theorem: a^(2^n - 2)."""
        result = a
        for _ in range(self.bits - 2):
            result = self.mul(result, result)
            result = self.mul(result, a)
        return self.mul(result, result)

    def power(self, base, exponent):
        """Exponentiation by squaring."""
        result = 1
        current = base
        while exponent > 0:
            if exponent & 1:
                result = self.mul(result, current)
            exponent >>= 1
            if exponent:
                current = self.mul(current, current)
        return result

    def reduce(self, wide_value):
        """Reduce a polynomial wider than n bits back into the field."""
        while wide_value >> self.bits:
            high = wide_value >> self.bits
            wide_value = (wide_value & self.mask) ^ high
            for bit_pos in range(1, self.reduction_poly.bit_length()):
                if (self.reduction_poly >> bit_pos) & 1:
                    wide_value ^= high << bit_pos
        return wide_value

    def sum_pow2(self, elements):
        """Compute sum(elements[i] * x^i) for i in range(len(elements))."""
        wide_value = 0
        for i, element in enumerate(elements):
            wide_value ^= element << i
        return self.reduce(wide_value)

    def echelon_pow2(self, stride, elements):
        """Compute sum(elements[i] * x^(stride*i)) for i in range(len(elements))."""
        wide_value = 0
        for i, element in enumerate(elements):
            wide_value ^= element << (stride * i)
        return self.reduce(wide_value)

    def from_bytes(self, data):
        """Deserialize a field element from little-endian bytes."""
        return int.from_bytes(data[:self.byte_size], 'little')

    def to_bytes(self, element):
        """Serialize a field element to little-endian bytes."""
        return (element & self.mask).to_bytes(self.byte_size, 'little')


GF128 = GF(128, 0x87)
GF192 = GF(192, 0x87)
GF256 = GF(256, 0x425)
