"""
L1 - GF(2^n) arithmetic vs an independent reference.

gf.py is byte-identical to round2 (KAT-passing), but a field bug that is also
present in the C reference would pass every KAT. So this checks gf.py against
GFRef (a different multiply algorithm) and against the field axioms, on random
+ edge inputs including ones honest signatures never touch (inv(0), power(_,0),
large echelon strides).
"""
import pytest

from gf import GF128, GF192, GF256
from deps import given, settings, st, GFRef

FIELDS = {
    'gf128': (GF128, GFRef(128, 0x87)),
    'gf192': (GF192, GFRef(192, 0x87)),
    'gf256': (GF256, GFRef(256, 0x425)),
}


def _elem(bits):
    return st.integers(min_value=0, max_value=(1 << bits) - 1)


@pytest.mark.parametrize('name', list(FIELDS))
def test_edge_values_mul(name):
    gf, ref = FIELDS[name]
    hi = (1 << gf.bits) - 1
    edges = [0, 1, 2, 3, hi, hi - 1, 1 << (gf.bits - 1)]
    for a in edges:
        for b in edges:
            assert gf.mul(a, b) == ref.mul(a, b), (name, a, b)


@pytest.mark.parametrize('name', list(FIELDS))
@settings(max_examples=200, deadline=None)
@given(st.data())
def test_mul_matches_reference(name, data):
    gf, ref = FIELDS[name]
    a = data.draw(_elem(gf.bits))
    b = data.draw(_elem(gf.bits))
    assert gf.mul(a, b) == ref.mul(a, b)


@pytest.mark.parametrize('name', list(FIELDS))
@settings(max_examples=100, deadline=None)
@given(st.data())
def test_field_axioms(name, data):
    gf, _ = FIELDS[name]
    a = data.draw(_elem(gf.bits))
    b = data.draw(_elem(gf.bits))
    c = data.draw(_elem(gf.bits))
    assert gf.mul(a, b) == gf.mul(b, a)                      # commutative
    assert gf.mul(gf.mul(a, b), c) == gf.mul(a, gf.mul(b, c))  # associative
    assert gf.mul(a, b ^ c) == gf.mul(a, b) ^ gf.mul(a, c)   # distributive
    assert gf.mul(a, 1) == a and gf.mul(a, 0) == 0


@pytest.mark.parametrize('name', list(FIELDS))
@settings(max_examples=150, deadline=None)
@given(st.data())
def test_inverse(name, data):
    gf, _ = FIELDS[name]
    a = data.draw(_elem(gf.bits))
    if a == 0:
        assert gf.inv(0) == 0          # documented Fermat behaviour
    else:
        assert gf.mul(a, gf.inv(a)) == 1
        # Fermat: a^(2^n - 1) == 1 for a != 0
        assert gf.power(a, (1 << gf.bits) - 1) == 1


@pytest.mark.parametrize('name', list(FIELDS))
@settings(max_examples=80, deadline=None)
@given(st.data())
def test_power(name, data):
    gf, ref = FIELDS[name]
    a = data.draw(_elem(gf.bits))
    e = data.draw(st.integers(min_value=0, max_value=40))
    assert gf.power(a, 0) == 1
    assert gf.power(a, 1) == a
    assert gf.power(a, e) == ref.pow(a, e)


@pytest.mark.parametrize('name', list(FIELDS))
def test_bytes_roundtrip(name):
    gf, _ = FIELDS[name]
    for v in [0, 1, (1 << gf.bits) - 1, 0x1234567890abcdef]:
        b = gf.to_bytes(v & ((1 << gf.bits) - 1))
        assert len(b) == gf.byte_size
        assert gf.from_bytes(b) == (v & ((1 << gf.bits) - 1))


@pytest.mark.parametrize('name', list(FIELDS))
@settings(max_examples=60, deadline=None)
@given(st.data())
def test_sum_pow2_matches_reference(name, data):
    gf, ref = FIELDS[name]
    n = data.draw(st.integers(min_value=1, max_value=40))
    elems = [data.draw(_elem(gf.bits)) for _ in range(n)]
    expected = 0
    for i, e in enumerate(elems):
        expected ^= ref.mul(e, ref.pow(2, i))
    assert gf.sum_pow2(elems) == expected


@pytest.mark.parametrize('name', list(FIELDS))
@settings(max_examples=60, deadline=None)
@given(st.data())
def test_echelon_pow2_matches_reference(name, data):
    gf, ref = FIELDS[name]
    n = data.draw(st.integers(min_value=1, max_value=20))
    stride = data.draw(st.integers(min_value=1, max_value=6))
    elems = [data.draw(_elem(gf.bits)) for _ in range(n)]
    expected = 0
    for i, e in enumerate(elems):
        expected ^= ref.mul(e, ref.pow(2, stride * i))
    assert gf.echelon_pow2(stride, elems) == expected
