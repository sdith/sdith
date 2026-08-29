"""
L3 - PIOP gate duality (piop.py).

For every gate, the prover builds a polynomial and the verifier evaluates the
same relation at the point delta2. The invariant is:
    eval(prover_gate(polys), delta2) == verifier_gate(eval(polys, delta2), delta2)
This catches *symmetric* bugs in the gate algebra (prover and verifier wrong the
same way) that honest sign/verify round-trips cannot. Pure and fast: exercises
the MUX tree (incl. the truncated last group) and the unitary-challenge ladder
without any VOLE/signing.

Control polynomials carry a bit constant (0/1) as in the real protocol; the
prover uses control_constant & 1 while the verifier uses the full evaluation, so
they only agree when the constant is a genuine bit.
"""
import os

import pytest

from params import CAT1_SHORT, CAT3_SHORT
from piop import (prover_qary_mux_gate, verifier_qary_mux_gate,
                  prover_check_unitary_gate, verifier_check_unitary_gate,
                  prover_mux_circuit, verifier_mux_circuit)

SETS = {'cat1': CAT1_SHORT, 'cat3': CAT3_SHORT}


def _rand_elem(p):
    return int.from_bytes(os.urandom(p.lambda_bytes), 'little') % (1 << p.lambda_)


def _ev(gf, poly, d2):
    """Evaluate a coefficient list (ascending) at d2 via Horner."""
    acc = 0
    for c in reversed(poly):
        acc = gf.mul(acc, d2) ^ c
    return acc


def _ctrl_poly(p):
    """Degree-1 control polynomial [bit, linear] as used in the protocol."""
    return [os.urandom(1)[0] & 1, _rand_elem(p)]


@pytest.mark.parametrize('name', list(SETS))
def test_qary_mux_gate_duality(name):
    p = SETS[name]
    gf = p.gf
    for _ in range(50):
        d2 = _rand_elem(p) or 1
        arity = p.mux_arities[0]
        controls = [_ctrl_poly(p) for _ in range(arity - 1)]
        inputs = [[_rand_elem(p), _rand_elem(p)] for _ in range(arity)]
        prover_poly = prover_qary_mux_gate(p, arity, 1, controls, inputs)
        c_vals = [_ev(gf, c, d2) for c in controls]
        i_vals = [_ev(gf, i, d2) for i in inputs]
        v = verifier_qary_mux_gate(p, arity, 1, c_vals, i_vals, d2)
        assert _ev(gf, prover_poly, d2) == v


@pytest.mark.parametrize('name', list(SETS))
def test_check_unitary_gate_duality(name):
    p = SETS[name]
    gf = p.gf
    for _ in range(50):
        d2 = _rand_elem(p) or 1
        arity = max(a for a in p.mux_arities if a > 2)
        controls = [_ctrl_poly(p) for _ in range(arity - 1)]
        coeff = _rand_elem(p)
        prover_poly = prover_check_unitary_gate(p, arity, controls, coeff)
        c_vals = [_ev(gf, c, d2) for c in controls]
        v = verifier_check_unitary_gate(p, arity, c_vals, coeff, d2)
        assert _ev(gf, prover_poly, d2) == v


@pytest.mark.parametrize('name', list(SETS))
def test_full_mux_circuit_duality(name):
    p = SETS[name]
    gf = p.gf
    for _ in range(20):
        d2 = _rand_elem(p) or 1
        # controls: one degree-1 witness poly per mux input
        input_polys = [_ctrl_poly(p) for _ in range(p.mux_inputs)]
        chall_a_H = [_rand_elem(p) for _ in range(p.npw)]
        chall_unitary = _rand_elem(p)

        prover_poly = prover_mux_circuit(p, input_polys, chall_a_H,
                                         chall_unitary)
        input_vals = [_ev(gf, poly, d2) for poly in input_polys]
        v = verifier_mux_circuit(p, input_vals, chall_a_H, chall_unitary, d2)
        assert _ev(gf, prover_poly, d2) == v


def test_unitary_gate_rejects_non_unary_control():
    """A control vector with two bits set (non-unary) must make the check
    contribute nonzero for a generic point (soundness of unitarity)."""
    p = CAT1_SHORT
    gf = p.gf
    arity = max(a for a in p.mux_arities if a > 2)
    # controls all zero -> unitary satisfied -> contribution zero
    zero_controls = [[0, 0] for _ in range(arity - 1)]
    d2 = _rand_elem(p) or 1
    assert _ev(gf, prover_check_unitary_gate(p, arity, zero_controls, 1), d2) \
        == verifier_check_unitary_gate(
            p, arity, [0] * (arity - 1), 1, d2)
    # two control bits set -> not unary; the prover polynomial should be
    # nonzero (the constraint is violated), i.e. not identically zero.
    if arity - 1 >= 2:
        two = [[0, 0] for _ in range(arity - 1)]
        two[0][0] = 1
        two[1][0] = 1
        poly = prover_check_unitary_gate(p, arity, two, 1)
        assert any(c != 0 for c in poly)
