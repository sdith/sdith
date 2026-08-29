"""
Shared helpers for the audit suite.

keygen+sign are expensive in pure Python (~1-2 s for cat1-short), so a valid
(sk, pk, msg, sig) sample is built once per parameter set and reused across the
many negative/serialization tests that only need *a* valid signature to mutate.
"""
import os

from sdith import keygen, sign, verify

_CACHE = {}


def make_sample(params, msg=b"audit-sample"):
    """Cached valid (sk, pk, msg, sig) for a parameter set."""
    key = (params.lambda_, params.kappa, params.tau, msg)
    if key not in _CACHE:
        sk, pk = keygen(params, os.urandom(2 * params.lambda_bytes))
        sig = sign(params, sk, msg, os.urandom(2 * params.lambda_bytes))
        assert verify(params, pk, msg, sig)
        _CACHE[key] = (sk, pk, msg, sig)
    return _CACHE[key]
