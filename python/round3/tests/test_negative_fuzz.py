"""
L4 - negative / tamper fuzzing.

Every mutation of a valid signature must be rejected. Two styles:
  * structure-aware: unpack -> mutate one field -> repack -> verify is False
  * byte/bit flips: random (hypothesis) in the fast lane, exhaustive as `slow`.
"""
import pytest

from params import CAT1_SHORT, CAT1_FAST
from sdith import verify, unpack_signature, pack_signature
from deps import given, settings, st
from helpers import make_sample

FAST = [CAT1_SHORT, CAT1_FAST]


@pytest.fixture(params=FAST, ids=lambda p: f"lam{p.lambda_}k{p.kappa}t{p.tau}")
def sample(request):
    p = request.param
    sk, pk, msg, sig = make_sample(p)
    return p, pk, msg, sig


def _repack(p, parts):
    return pack_signature(p, *parts)


def test_structured_field_mutations(sample):
    p, pk, msg, sig = sample
    (salt, path, commits, corr_u, cchk_u, in_pub, cz, hpiop, ctr) = \
        unpack_signature(p, sig)

    def flip_bytes(b, i=0, bit=0):
        m = bytearray(b)
        m[i] ^= (1 << bit)
        return bytes(m)

    cases = {}
    cases['salt'] = (flip_bytes(salt), path, commits, corr_u, cchk_u,
                     in_pub, cz, hpiop, ctr)
    cases['corr_u'] = (salt, path, commits, flip_bytes(corr_u), cchk_u,
                       in_pub, cz, hpiop, ctr)
    cases['cchk_u'] = (salt, path, commits, corr_u, flip_bytes(cchk_u),
                       in_pub, cz, hpiop, ctr)
    cases['in_pub'] = (salt, path, commits, corr_u, cchk_u,
                       flip_bytes(in_pub), cz, hpiop, ctr)
    cases['hpiop'] = (salt, path, commits, corr_u, cchk_u, in_pub, cz,
                      flip_bytes(hpiop), ctr)

    # a commitment byte, and swapping two commitments
    commits_mut = list(commits)
    commits_mut[0] = flip_bytes(commits_mut[0])
    cases['commit_flip'] = (salt, path, commits_mut, corr_u, cchk_u,
                            in_pub, cz, hpiop, ctr)
    if len(commits) >= 2:
        swapped = list(commits)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        cases['commit_swap'] = (salt, path, swapped, corr_u, cchk_u,
                                in_pub, cz, hpiop, ctr)

    # a sibling-path entry (first one is normally used)
    path_mut = list(path)
    path_mut[0] = flip_bytes(path_mut[0]) if any(path_mut[0]) \
        else b'\x01' + path_mut[0][1:]
    cases['path_flip'] = (salt, path_mut, commits, corr_u, cchk_u,
                          in_pub, cz, hpiop, ctr)

    # cz field values -> 0, 1, max
    for tag, val in [('cz_zero', 0), ('cz_one', 1),
                     ('cz_max', (1 << p.lambda_) - 1)]:
        cz_mut = [val] + list(cz[1:]) if cz else cz
        if cz_mut and cz_mut != list(cz):
            cases[tag] = (salt, path, commits, corr_u, cchk_u, in_pub,
                          cz_mut, hpiop, ctr)

    # PoW counter -> 0, max, +1
    for tag, val in [('ctr_zero', 0), ('ctr_max', (1 << 32) - 1),
                     ('ctr_inc', (ctr + 1) & 0xFFFFFFFF)]:
        if val != ctr:
            cases[tag] = (salt, path, commits, corr_u, cchk_u, in_pub,
                          cz, hpiop, val)

    for tag, parts in cases.items():
        assert verify(p, pk, msg, _repack(p, parts)) is False, tag


def test_in_pub_padding_bits_checked(sample):
    p, pk, msg, sig = sample
    leftover = p.num_inputs_pairs % 8
    if not leftover:
        pytest.skip("no padding bits for this set")
    parts = list(unpack_signature(p, sig))
    in_pub = bytearray(parts[5])
    last = (p.num_inputs_pairs + 7) // 8 - 1
    in_pub[last] |= (1 << leftover)
    parts[5] = bytes(in_pub)
    assert verify(p, pk, msg, _repack(p, parts)) is False


# cat1-fast only: smaller GGM tree -> faster per-example verify. cat1-short is
# covered deterministically by test_exhaustive_byteflip_cat1_short (slow).
@settings(max_examples=64, deadline=None)
@given(data=st.data())
def test_random_bitflip_rejected(data):
    p = CAT1_FAST
    _sk, pk, msg, sig = make_sample(p)
    idx = data.draw(st.integers(min_value=0, max_value=len(sig) - 1))
    bit = data.draw(st.integers(min_value=0, max_value=7))
    mutated = bytearray(sig)
    mutated[idx] ^= (1 << bit)
    assert verify(p, pk, msg, bytes(mutated)) is False


@pytest.mark.slow
def test_exhaustive_byteflip_cat1_short():
    p = CAT1_SHORT
    _sk, pk, msg, sig = make_sample(p)
    for i in range(len(sig)):
        m = bytearray(sig)
        m[i] ^= 1
        assert verify(p, pk, msg, bytes(m)) is False, f"byte {i}"


@pytest.mark.slow
def test_cat3_negative_and_padding():
    """cat3 is the only set with witness padding bits (num_inputs%8==4), so its
    in_pub canonicality check is otherwise never exercised."""
    from params import CAT3_SHORT as p
    _sk, pk, msg, sig = make_sample(p)
    assert verify(p, pk, msg, sig) is True

    # in_pub high padding bit must be rejected
    leftover = p.num_inputs_pairs % 8
    assert leftover
    parts = list(unpack_signature(p, sig))
    in_pub = bytearray(parts[5])
    last = (p.num_inputs_pairs + 7) // 8 - 1
    in_pub[last] |= (1 << leftover)
    parts[5] = bytes(in_pub)
    assert verify(p, pk, msg, pack_signature(p, *parts)) is False

    # length + a few region flips
    assert verify(p, pk, msg, sig + b'\x00') is False
    assert verify(p, pk, msg, sig[:-1]) is False
    for off in (0, 5, len(sig) - 5):
        m = bytearray(sig)
        m[off] ^= 1
        assert verify(p, pk, msg, bytes(m)) is False, off
