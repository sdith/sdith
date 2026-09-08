"""
L5 - parameter / spec conformance.

Re-derives every value in params.py independently from the primitive inputs
(lambda, kappa, tau, rsd_w, rsd_n, mux_arities, ...) using the spec
(docs/sdith-v3.0.pdf) sections 4.2/4.3, and compares to the Params object. It
recomputes rather than trusting the constructor, so that a mistake in params.py
cannot make the test agree with itself.
"""
import math

import pytest

from params import ALL_PARAMS
from deps import is_irreducible_gf2


def ceil8_bits(nbits):
    """Round a bit-count up to a whole number of bytes, in bits."""
    return 8 * ((nbits + 7) // 8)


# Reduction polynomials the spec pins in section 4.3 (implicit x^n term dropped).
SPEC_REDUCTION = {
    128: 0x87,    # x^128 + x^7 + x^2 + x + 1
    192: 0x87,    # x^192 + x^7 + x^2 + x + 1
    256: 0x425,   # x^256 + x^10 + x^5 + x^2 + 1
}

# Published sizes (bytes): short = cat*-short, fast = cat*-fast.
EXPECTED_PK = {'cat1-short': 70, 'cat1-fast': 70,
               'cat3-short': 98, 'cat3-fast': 98,
               'cat5-short': 132, 'cat5-fast': 132}
EXPECTED_SK = {'cat1-short': 147, 'cat1-fast': 147,
               'cat3-short': 208, 'cat3-fast': 208,
               'cat5-short': 275, 'cat5-fast': 275}
EXPECTED_SIG_SHORT = {'cat1-short': 3721, 'cat3-short': 8484, 'cat5-short': 15147}


@pytest.mark.parametrize('name', list(ALL_PARAMS))
def test_derived_quantities(name):
    p = ALL_PARAMS[name]
    lam = p.lambda_
    num_leaves = p.tau * (1 << p.kappa)

    assert p.num_leaves == num_leaves
    assert p.theta == math.ceil(math.log2(num_leaves)) + 2
    assert p.npw == p.rsd_n // p.rsd_w

    mux_inputs = sum(a - 1 for a in p.mux_arities[:p.mux_depth])
    assert p.mux_inputs == mux_inputs
    assert p.degree == max(p.mux_depth, 2)

    assert p.num_inputs_pairs == mux_inputs * p.rsd_w
    assert p.num_inputs_pairs_padded == ceil8_bits(p.num_inputs_pairs)
    assert p.num_cz_pairs == lam * (p.degree - 1)

    # L_total must exactly cover [cchk | wit(padded) | rnd], i.e. the layout the
    # signer/verifier actually slice.
    assert p.L_total == (p.num_cchk_pairs
                         + p.num_inputs_pairs_padded
                         + p.num_cz_pairs)
    assert p.L_total % 8 == 0
    assert p.L_total_bytes == p.L_total // 8

    assert p.delta0_bits == p.kappa * p.tau + p.proofow_w


@pytest.mark.parametrize('name', list(ALL_PARAMS))
def test_sizes_match_spec_formulas(name):
    p = ALL_PARAMS[name]
    lam = p.lambda_
    codim = p.rsd_codim
    wit_bits = ceil8_bits(p.rsd_w * p.mux_inputs)     # |wit|_2
    cchk_bits = p.num_cchk_pairs                       # lambda + B region

    # |pk| = (lambda + (n-k)) / 8
    pk_bits = lam + codim
    assert p.pk_bytes == pk_bits // 8

    # |sk| = ceil8(lambda + (n-k) + |wit|) / 8   (seed_sk removed)
    sk_bits = ceil8_bits(lam + codim + p.rsd_w * p.mux_inputs)
    assert p.sk_bytes == sk_bits // 8

    # |sigma| per the section 4.2 bit formula.
    d = p.degree
    sig_bits = (
        3 * lam                                         # salt + hpiop
        + (p.tau - 1) * (wit_bits + (d - 1) * lam + cchk_bits)   # aux
        + cchk_bits                                     # alpha'_plain (cchk_u)
        + wit_bits                                      # delta_wit (in_pub)
        + (d - 1) * lam                                 # alpha_2..alpha_d
        + lam * p.target_topen + p.tau * (2 * lam) + 32  # pdecom
    )
    assert p.sig_bytes == sig_bits // 8


@pytest.mark.parametrize('name', ['cat1-short', 'cat3-short', 'cat5-short'])
def test_published_sizes(name):
    p = ALL_PARAMS[name]
    assert (p.pk_bytes, p.sk_bytes, p.sig_bytes) == (
        EXPECTED_PK[name], EXPECTED_SK[name], EXPECTED_SIG_SHORT[name])


@pytest.mark.parametrize('name', list(ALL_PARAMS))
def test_fast_sets_published_pk_sk(name):
    p = ALL_PARAMS[name]
    # cipherpow sets share pk/sk with the base set (keygen is variant-agnostic)
    base = name.replace('-cipherpow', '')
    assert p.pk_bytes == EXPECTED_PK[base]
    assert p.sk_bytes == EXPECTED_SK[base]


@pytest.mark.parametrize('name', list(ALL_PARAMS))
def test_reduction_poly_and_dispatch(name):
    p = ALL_PARAMS[name]
    assert p.gf.reduction_poly == SPEC_REDUCTION[p.lambda_]
    assert p.gf.bits == p.lambda_
    # the pinned polynomials must actually be irreducible over GF(2)
    assert is_irreducible_gf2(p.lambda_, p.gf.reduction_poly)


@pytest.mark.parametrize('name', list(ALL_PARAMS))
def test_static_invariants_the_code_assumes(name):
    """Invariants the implementation silently relies on. A future param edit
    that breaks one of these would otherwise surface as a deep, confusing
    failure (or a security break)."""
    p = ALL_PARAMS[name]
    N = p.num_leaves

    # byte-alignment assumptions in the VOLE slicing/transpose
    assert p.L_total % 8 == 0
    assert p.num_cchk_pairs % 8 == 0
    assert p.num_cz_pairs % 8 == 0
    # transpose_vole_matrix uses num_cols//8 (exact) for the cchk sub-block
    assert (p.L_total - p.num_cchk_pairs) % 8 == 0

    # delta1 is written up to bit tau*kappa-1 into a lambda-bit buffer
    assert p.kappa * p.tau <= p.lambda_

    # seed-tree domain separation: every consumed cipher block (incl. the +1
    # right-child / second-commit block) must stay < 2^theta, else the tweak
    # would collide with the truncated salt. Margin is exactly 0 for the
    # power-of-two-tau sets, so this is a genuine landmine.
    assert 4 * N - 1 < (1 << p.theta), f"{name}: theta margin negative"
    # seed tweaks live in [2, 2N-1], commit tweaks in [2N, 4N-1]: disjoint.
    assert 2 * N - 1 < 2 * N

    # the last MUX group is always truncated (npw not a multiple of the arity
    # product); npw < product keeps the tree one level deeper than needed.
    prod = 1
    for a in p.mux_arities[:p.mux_depth]:
        prod *= a
    assert p.npw < prod


@pytest.mark.parametrize('name', list(ALL_PARAMS))
def test_cchk_region_basis(name):
    """num_cchk_pairs is 'lambda + B' (B=16), the spec/FAEST form, and is the
    authoritative definition. The old 'kappa*tau + 16' form only coincided
    with it by chance for the round-2 sets; the round-3 retune (smaller
    kappa*tau for cat1-fast-cipherpow and cat3-fast-cipherpow) breaks that
    coincidence, which is exactly why lambda+B, not kappa*tau, is the basis."""
    p = ALL_PARAMS[name]
    assert p.num_cchk_pairs == p.lambda_ + 16  # lambda + B (multiple of 8)
