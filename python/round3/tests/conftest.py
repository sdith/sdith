"""
pytest configuration for the round3 audit suite.

Puts the round3 package dir on sys.path so tests can `import sdith`, `import gf`,
etc., and registers the `slow` marker used to gate the pure-Python cat3/cat5
sets (which are minutes-per-op). Run the fast lane with `-m "not slow"`.
"""
import os
import sys

ROUND3 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROUND3 not in sys.path:
    sys.path.insert(0, ROUND3)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "slow: exercises cat3/cat5 (minutes per op in pure Python)")


# Param-set groupings shared by the tests.
FAST_SETS = ['cat1-short', 'cat1-fast']
SLOW_SETS = ['cat3-short', 'cat3-fast', 'cat5-short', 'cat5-fast']
ALL_SETS = FAST_SETS + SLOW_SETS
