"""
L3 - differential vs round2 (the byte-exact-vs-C baseline).

round2 and round3 share 8 byte-identical modules and differ only in
crypto/params/vole/sdith. The keygen refactor (drop seed_sk, reorder sk) must be
value-preserving: for the same entropy, the *public key* (seed_pk || y) must be
identical in both, since the RSD instance generation is unchanged. Meanwhile the
signature must differ, confirming the round-3 transcript changes actually took
effect.

round2 is run in a subprocess (both trees expose top-level modules named `sdith`
/`params`, so they cannot be imported into the same interpreter).
"""
import os
import subprocess
import sys

import pytest

from params import CAT1_FAST
from sdith import keygen, sign, verify
from conftest import ROUND3

ROUND2 = os.path.join(os.path.dirname(ROUND3), 'round2')

_R2_SCRIPT = r"""
import sys
sys.path.insert(0, sys.argv[1])
from params import CAT1_FAST as P
from sdith import keygen, sign, verify
ke = bytes.fromhex(sys.argv[2]); se = bytes.fromhex(sys.argv[3])
msg = bytes.fromhex(sys.argv[4])
sk, pk = keygen(P, ke)
sig = sign(P, sk, msg, se)
assert verify(P, pk, msg, sig)
print(pk.hex())
print(sig.hex())
"""

pytestmark = pytest.mark.skipif(
    not os.path.isdir(ROUND2), reason="round2/ sibling not present")


def _round2(ke, se, msg):
    out = subprocess.run(
        [sys.executable, '-c', _R2_SCRIPT, ROUND2, ke.hex(), se.hex(), msg.hex()],
        cwd=ROUND2, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    pk_hex, sig_hex = out.stdout.split()
    return bytes.fromhex(pk_hex), bytes.fromhex(sig_hex)


def test_keygen_value_preserving_vs_round2():
    p = CAT1_FAST
    ke = os.urandom(2 * p.lambda_bytes)
    se = os.urandom(2 * p.lambda_bytes)
    msg = os.urandom(32)

    sk3, pk3 = keygen(p, ke)
    sig3 = sign(p, sk3, msg, se)
    assert verify(p, pk3, msg, sig3)

    pk2, sig2 = _round2(ke, se, msg)

    # public key (seed_pk || y) must be identical: RSD instance is unchanged.
    assert pk3 == pk2
    # the round-3 transcript changes (domain sep, sub-hash, salt binding,
    # partition, alpha_1 removal) must actually alter the signature bytes.
    assert sig3 != sig2
