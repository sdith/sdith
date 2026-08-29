"""
L2 - GGM tree open/reconstruct (ggm.py).

The prover-open and verifier-reconstruct walks must agree exactly, including the
rare "both siblings hidden" merge branch that honest random signing almost never
hits. Tested directly on hidden-index sets (no signing needed), including
crafted adjacent-sibling and extreme configurations.
"""
import os

import pytest

from params import CAT1_FAST
from ggm import (GGMTree, GGMSiblingTree, estimate_topen,
                 decode_hidden_leaf_indices)
from deps import given, settings, st

P = CAT1_FAST
N_LEAVES = P.num_leaves
KAPPA_N = 1 << P.kappa       # positions per repetition


def _hidden_from_positions(positions):
    """positions[rep] in [0, 2^kappa); returns sorted hidden node indices."""
    idx = sorted(pos * P.tau + rep + N_LEAVES
                 for rep, pos in enumerate(positions))
    return idx


def _fresh_tree():
    return GGMTree(P, os.urandom(P.lambda_bytes), os.urandom(P.lambda_bytes))


def _check_reconstruction(tree, hidden_idx, sample_leaves):
    sibs, commits = tree.open_sibling_path(hidden_idx)
    # prover-open count == verifier's independent recomputation
    assert len(sibs) == estimate_topen(P.tau, P.kappa, P.target_topen, hidden_idx)

    stree = GGMSiblingTree(P, tree.salt, hidden_idx, sibs, commits)
    hidden_set = set(hidden_idx)

    # hidden leaves: no seed, stored commitment matches the prover's
    for pos_node in hidden_idx:
        leaf = pos_node - N_LEAVES
        seed, com = stree.get_leaf_seed_commit(leaf)
        assert seed is None
        _, full_com = tree.get_leaf_seed_commit(leaf)
        assert com == full_com

    # sampled revealed leaves: seed + commitment reconstruct exactly
    for leaf in sample_leaves:
        if leaf + N_LEAVES in hidden_set:
            continue
        s_seed, s_com = stree.get_leaf_seed_commit(leaf)
        f_seed, f_com = tree.get_leaf_seed_commit(leaf)
        assert s_seed == f_seed and s_com == f_com


@settings(max_examples=25, deadline=None)
@given(st.data())
def test_random_hidden_sets_reconstruct(data):
    positions = [data.draw(st.integers(0, KAPPA_N - 1)) for _ in range(P.tau)]
    hidden = _hidden_from_positions(positions)
    tree = _fresh_tree()
    sample = [data.draw(st.integers(0, N_LEAVES - 1)) for _ in range(30)]
    _check_reconstruction(tree, hidden, sample)


def test_extreme_positions():
    for positions in ([0] * P.tau,
                      [KAPPA_N - 1] * P.tau,
                      list(range(P.tau))):
        hidden = _hidden_from_positions(positions)
        tree = _fresh_tree()
        _check_reconstruction(tree, hidden, list(range(0, N_LEAVES, 137)))


def test_adjacent_sibling_merge_branch():
    """Force two hidden leaves to share a parent (node indices differ by 1),
    exercising the 'both siblings hidden' merge in _walk_hidden_path."""
    found = False
    for pos in range(KAPPA_N):
        for rep in range(P.tau - 1):
            n = pos * P.tau + rep + N_LEAVES
            if n % 2 == 0 and (n + 1) == (pos * P.tau + (rep + 1) + N_LEAVES):
                positions = [0] * P.tau
                positions[rep] = pos
                positions[rep + 1] = pos
                hidden = _hidden_from_positions(positions)
                # sanity: the two are indeed sibling nodes
                assert (hidden[hidden.index(n)] ^ (n + 1)) == 1 or (n ^ (n + 1)) == 1
                tree = _fresh_tree()
                _check_reconstruction(tree, hidden, list(range(0, N_LEAVES, 97)))
                found = True
                break
        if found:
            break
    assert found, "no adjacent-sibling configuration found"


@settings(max_examples=30, deadline=None)
@given(st.data())
def test_estimate_topen_within_bound_and_matches_open(data):
    positions = [data.draw(st.integers(0, KAPPA_N - 1)) for _ in range(P.tau)]
    hidden = _hidden_from_positions(positions)
    est = estimate_topen(P.tau, P.kappa, P.target_topen, hidden)
    tree = _fresh_tree()
    sibs, _ = tree.open_sibling_path(hidden)
    assert est == len(sibs)
    assert est <= P.tau * P.kappa      # can never exceed total tree height sum


@settings(max_examples=40, deadline=None)
@given(delta0=st.binary(min_size=16, max_size=16))
def test_decode_hidden_leaf_indices_structure(delta0):
    idx = decode_hidden_leaf_indices(P.kappa, P.tau, bytearray(delta0))
    assert len(idx) == P.tau
    assert idx == sorted(idx)
    # exactly one hidden leaf per repetition
    reps = [(n - N_LEAVES) % P.tau for n in idx]
    assert sorted(reps) == list(range(P.tau))
    # deterministic
    idx2 = decode_hidden_leaf_indices(P.kappa, P.tau, bytearray(delta0))
    assert idx == idx2
