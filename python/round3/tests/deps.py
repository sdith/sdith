"""
Single point of contact for the audit suite's third-party test dependencies.

The core round3 implementation imports only pycryptodome + stdlib. To keep it a
clean spec-mirror, every extra dependency used purely for testing (hypothesis,
numpy, sympy) is imported HERE and nowhere else; the test modules pull these
symbols from `deps` rather than importing the packages directly.

Also provides an independent GF(2^n) reference (a different multiply algorithm
than gf.py) so the field arithmetic can be checked against something other than
itself.
"""

# ---- third-party test-only imports (the only place these appear) ----
import numpy as np                                    # noqa: F401
from hypothesis import (                              # noqa: F401
    given, settings, strategies as st, assume, example, HealthCheck, note,
)


# ---- independent GF(2^n) reference ----------------------------------------
class GFRef:
    """GF(2^n) using product-then-reduce, deliberately unlike gf.py's
    interleaved shift-and-reduce, so agreement between the two is meaningful.

    `red` is the reduction polynomial with the implicit x^n term dropped
    (e.g. 0x87 for x^128 + x^7 + x^2 + x + 1)."""

    def __init__(self, n, red):
        self.n = n
        self.red = red
        self.mask = (1 << n) - 1
        self.modpoly = (1 << n) | red

    def mul(self, a, b):
        a &= self.mask
        b &= self.mask
        # full carry-less product first...
        prod = 0
        shift = 0
        while b:
            if b & 1:
                prod ^= a << shift
            b >>= 1
            shift += 1
        # ...then reduce the (up to 2n-2)-degree result.
        for i in range(2 * self.n - 2, self.n - 1, -1):
            if (prod >> i) & 1:
                prod ^= self.modpoly << (i - self.n)
        return prod & self.mask

    def pow(self, base, exp):
        result = 1
        for _ in range(exp):
            result = self.mul(result, base)
        return result


def _poly_gcd_gf2(a, b):
    """GCD of two GF(2) polynomials represented as ints."""
    while b:
        while a.bit_length() >= b.bit_length() and a:
            a ^= b << (a.bit_length() - b.bit_length())
        a, b = b, a
    return a


def _prime_factors(n):
    fs, d = set(), 2
    while d * d <= n:
        while n % d == 0:
            fs.add(d)
            n //= d
        d += 1
    if n > 1:
        fs.add(n)
    return fs


def is_irreducible_gf2(n, red):
    """True if x^n + red is irreducible over GF(2).

    Rabin's test: x^(2^n) == x (mod f), and gcd(x^(2^(n/p)) - x, f) == 1 for
    every prime p | n. Uses GFRef for mul mod f, so it is independent of gf.py
    and fast even for n=256 (unlike a full factorisation)."""
    ref = GFRef(n, red)
    f = (1 << n) | red
    X = 2  # the polynomial 'x'

    def x_pow_2exp(e):
        """x^(2^e) mod f, by squaring x e times."""
        r = X
        for _ in range(e):
            r = ref.mul(r, r)
        return r

    if x_pow_2exp(n) != X:
        return False
    for p in _prime_factors(n):
        if _poly_gcd_gf2(x_pow_2exp(n // p) ^ X, f) != 1:
            return False
    return True
