"""
L3 - the load-bearing VOLE correlation (vole.py + ggm.py + transpose).

The whole MPCitH construction rests on: for every VOLE column j,
    q_trans[j] == v_trans[j] ^ (Delta * u[j])
where Delta = delta1 as a field element and u[j] is bit j of u_flat. If this
holds for all columns, grey ordering, correction terms, the transpose bit
packing, and the delta1 masking are all correct together. This is checked
directly against the vole.py subroutines (no full sign/verify needed), which
also confirms the prover/verifier two-level hash_com agree.
"""
import os

import pytest

from params import CAT1_FAST
from vole import (prover_generate_midsize_grey_vole,
                  prover_midsize_to_fullsize,
                  verifier_open_midsize_grey_vole,
                  verifier_midsize_to_fullsize)
from ggm import GGMTree, GGMSiblingTree, decode_hidden_leaf_indices
from sdith import compute_tweaked_salts
from vole_to_piop import delta1_from_delta0
from utils import get_bit
from deps import given, settings, st

P = CAT1_FAST


def _run(delta0):
    salt = os.urandom(P.lambda_bytes)
    ggm_salt, vole_salt = compute_tweaked_salts(P, salt)
    root = os.urandom(P.lambda_bytes)
    tree = GGMTree(P, ggm_salt, root)

    u, v, hcom = prover_generate_midsize_grey_vole(P, tree, salt, vole_salt)
    u_flat, corr_u, v_trans = prover_midsize_to_fullsize(P, u, v)

    hidden = decode_hidden_leaf_indices(P.kappa, P.tau, delta0)
    delta1 = delta1_from_delta0(P, delta0)
    d1g = P.gf.from_bytes(delta1)

    sibs, commits = tree.open_sibling_path(hidden)
    stree = GGMSiblingTree(P, ggm_salt, hidden, sibs, commits)

    corr_terms = [bytearray(P.L_total_bytes)]
    for i in range(P.tau - 1):
        corr_terms.append(
            bytearray(corr_u[i * P.L_total_bytes:(i + 1) * P.L_total_bytes]))

    q, vhcom = verifier_open_midsize_grey_vole(
        P, stree, corr_terms, delta1, salt, vole_salt)
    q_trans = verifier_midsize_to_fullsize(P, q)
    return u_flat, v_trans, q_trans, d1g, hcom, vhcom


def test_vole_correlation_and_subhash():
    delta0 = bytearray(os.urandom(P.delta0_capacity))
    u_flat, v_trans, q_trans, d1g, hcom, vhcom = _run(delta0)

    # two-level BAVC hash_com must agree between prover and verifier
    assert vhcom == hcom

    # the VOLE correlation for every column
    for j in range(P.L_total):
        expect = d1g if get_bit(u_flat, j) else 0
        assert (q_trans[j] ^ v_trans[j]) == expect, f"column {j}"

    # padding rows above tau*kappa must be zero in both v and q
    hi = P.lambda_ - P.tau * P.kappa
    if hi:
        for j in range(P.L_total):
            assert v_trans[j] >> (P.tau * P.kappa) == 0
            assert q_trans[j] >> (P.tau * P.kappa) == 0


@settings(max_examples=8, deadline=None)
@given(delta0=st.binary(min_size=1, max_size=64))
def test_vole_correlation_random_delta(delta0):
    d0 = bytearray(P.delta0_capacity)
    d0[:min(len(delta0), P.delta0_capacity)] = delta0[:P.delta0_capacity]
    u_flat, v_trans, q_trans, d1g, hcom, vhcom = _run(d0)
    assert vhcom == hcom
    # spot-check a spread of columns (full sweep is in the deterministic test)
    for j in range(0, P.L_total, 7):
        expect = d1g if get_bit(u_flat, j) else 0
        assert (q_trans[j] ^ v_trans[j]) == expect, f"column {j}"
