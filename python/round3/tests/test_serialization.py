"""
L4 - serialization / parsing robustness.

verify() and the unpack_* deserializers must fail closed on malformed input:
never accept, never raise. Also locks pack/unpack round-trips and the
signature-length check (append-malleability + short-input crash were real bugs).
"""
import os

import pytest

from params import CAT1_SHORT, CAT1_FAST
from sdith import (keygen, verify,
                   unpack_signature, unpack_skey, unpack_pkey,
                   pack_signature)
from deps import given, settings, st, HealthCheck
from helpers import make_sample

FAST = [CAT1_SHORT, CAT1_FAST]


def _mk(params):
    return make_sample(params)


@pytest.mark.parametrize('params', FAST)
def test_valid_roundtrip(params):
    sk, pk, msg, sig = _mk(params)
    assert len(sig) == params.sig_bytes
    assert verify(params, pk, msg, sig) is True


@pytest.mark.parametrize('params', FAST)
def test_wrong_length_rejected_not_crash(params):
    sk, pk, msg, sig = _mk(params)
    for bad in (b'', sig[:-1], sig[:-4], sig[:len(sig) // 2],
                sig + b'\x00', sig + os.urandom(64), sig + sig):
        assert verify(params, pk, msg, bad) is False, len(bad)


@pytest.mark.parametrize('params', FAST)
def test_append_is_not_malleable(params):
    sk, pk, msg, sig = _mk(params)
    for n in (1, 2, 4, 33, 256):
        assert verify(params, pk, msg, sig + os.urandom(n)) is False


# cat1-fast only: smaller GGM tree -> faster per-example verify.
@pytest.mark.parametrize('params', [CAT1_FAST])
@settings(max_examples=120, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(blob=st.binary(min_size=0, max_size=6000))
def test_verify_never_crashes_on_garbage(params, blob):
    sk, pk, msg, sig = _mk(params)
    # Must return a bool for any input, never raise.
    assert verify(params, pk, msg, blob) in (True, False)
    # Random bytes of the exact right length must not be accepted.
    if len(blob) == params.sig_bytes:
        assert verify(params, pk, msg, blob) is False


@pytest.mark.parametrize('params', FAST)
def test_pack_unpack_signature_roundtrip(params):
    sk, pk, msg, sig = _mk(params)
    parts = unpack_signature(params, sig)
    repacked = pack_signature(params, *parts)
    assert repacked == sig


@pytest.mark.parametrize('params', FAST)
def test_key_unpack_roundtrip(params):
    sk, pk, _, _ = _mk(params)
    pk_seed, enc, y = unpack_skey(params, sk)
    assert pk_seed + y + enc == sk        # sk = seed_pk || y || wit
    seed2, y2 = unpack_pkey(params, pk)
    assert seed2 + y2 == pk
    assert seed2 == pk_seed and y2 == y


@pytest.mark.parametrize('params', FAST)
def test_wrong_key_rejected(params):
    sk, pk, msg, sig = _mk(params)
    _, pk2 = keygen(params, os.urandom(2 * params.lambda_bytes))
    assert verify(params, pk2, msg, sig) is False


@pytest.mark.parametrize('params', FAST)
def test_message_binding(params):
    sk, pk, msg, sig = _mk(params)
    assert verify(params, pk, msg + b'x', sig) is False
    if msg:
        flipped = bytearray(msg)
        flipped[0] ^= 1
        assert verify(params, pk, bytes(flipped), sig) is False
