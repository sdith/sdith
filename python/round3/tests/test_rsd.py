"""
L2 - regular syndrome decoding (rsd.py).

The mixed-radix unary witness encoding is fiddly (each block's position is split
into per-level digits, each written as arity-1 unary bits), and the last MUX
group is always truncated. Checked with an independent decoder (bijection) plus
an independent syndrome recomputation and a rejection-sampling coverage check.
"""
import os

import pytest

from params import CAT1_SHORT, CAT3_SHORT, CAT5_SHORT
from rsd import rsd_generate_instance, rsd_encode_solution
from deps import given, settings, st

SETS = {'cat1': CAT1_SHORT, 'cat3': CAT3_SHORT, 'cat5': CAT5_SHORT}


def _independent_decode(p, encoded):
    """Recover block positions from the unary/mixed-radix encoding."""
    sol = []
    bit = 0
    for _ in range(p.rsd_w):
        pos, mult = 0, 1
        for level in range(p.mux_depth):
            arity = p.mux_arities[level]
            digit = 0
            for k in range(arity - 1):
                if (encoded[(bit + k) // 8] >> ((bit + k) % 8)) & 1:
                    digit = k + 1
            pos += digit * mult
            mult *= arity
            bit += arity - 1
        sol.append(pos)
    return sol


@pytest.mark.parametrize('name', list(SETS))
@settings(max_examples=60, deadline=None)
@given(st.data())
def test_encode_decode_bijection(name, data):
    p = SETS[name]
    solution = [data.draw(st.integers(0, p.npw - 1)) for _ in range(p.rsd_w)]
    encoded = rsd_encode_solution(p, solution)
    assert _independent_decode(p, encoded) == solution


@pytest.mark.parametrize('name', list(SETS))
def test_encoded_length_and_bounds(name):
    p = SETS[name]
    solution = [p.npw - 1] * p.rsd_w        # max positions
    encoded = rsd_encode_solution(p, solution)
    assert len(encoded) == (p.rsd_w * p.mux_inputs + 7) // 8
    assert _independent_decode(p, encoded) == solution


def test_generate_instance_in_range():
    # cat1 only: H expansion for cat3/cat5 is tens of thousands of cipher calls.
    p = CAT1_SHORT
    sol, y = rsd_generate_instance(p, os.urandom(p.lambda_bytes),
                                   os.urandom(p.lambda_bytes))
    assert len(sol) == p.rsd_w
    assert all(0 <= s < p.npw for s in sol)
    assert len(y) == p.rsd_codim_bytes


def test_syndrome_recomputation_cat1():
    """Independently recompute y = H e (H = [I | H']) and compare to pkey_y."""
    p = CAT1_SHORT
    sk_seed, pk_seed = os.urandom(p.lambda_bytes), os.urandom(p.lambda_bytes)
    sol, y = rsd_generate_instance(p, sk_seed, pk_seed)

    # rebuild H' rows exactly as rsd does (same PRG), then apply to e. Each row
    # is read in whole cipher blocks (16B for cat1, 32B for cat3/cat5) so the
    # next row starts on a block boundary, then truncated to rsd_codim bits;
    # this must mirror _h_random_row or the PRG stream desyncs after row 0.
    prg = p.new_prg(pk_seed)
    num_random_rows = p.rsd_n - p.rsd_codim
    block_bytes = 16 if p.lambda_ == 128 else 32
    n_blocks = (p.rsd_codim + block_bytes * 8 - 1) // (block_bytes * 8)
    row_bytes = n_blocks * block_bytes
    h_rows = []
    for _ in range(num_random_rows):
        row = bytearray(prg.get_bytes(row_bytes)[:p.rsd_codim_bytes])
        row[-1] &= p.rsd_codim_byte_mask
        h_rows.append(row)

    syndrome = bytearray(p.rsd_codim_bytes)
    for block in range(p.rsd_w):
        absolute = block * p.npw + sol[block]
        if absolute < p.rsd_codim:            # identity part
            syndrome[absolute // 8] ^= 1 << (absolute % 8)
        else:
            for i in range(p.rsd_codim_bytes):
                syndrome[i] ^= h_rows[absolute - p.rsd_codim][i]
    assert bytes(syndrome) == y


def test_rejection_sampling_coverage():
    """Over many keygens, sampled positions should roughly cover [0, npw)."""
    p = CAT1_SHORT
    seen = set()
    for _ in range(40):
        sol, _ = rsd_generate_instance(p, os.urandom(p.lambda_bytes),
                                       os.urandom(p.lambda_bytes))
        seen.update(sol)
    # 40 * rsd_w samples over npw buckets: expect the vast majority covered
    assert len(seen) > 0.6 * p.npw
    assert max(seen) < p.npw and min(seen) >= 0
