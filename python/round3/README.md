# SDitH round 3 — Python reference

A readable Python implementation of the round-3 SDitH signature scheme, built
on the round2 code. It follows the specification in `../../docs/sdith-v3.0.pdf`
and is meant for clarity and KAT checking, not speed. It covers the six
parameter sets (CAT1/3/5, short/fast), each in both proof-of-work variants, so
twelve sets in total.

## Changes from round2

- BAVC commitments are sub-hashed: a per-repetition digest over that
  repetition's N seed commitments, then a hash over the tau digests (round2
  used one flat hash). `vole.py`.
- The seed tree and the VOLE keystream are both salted with `TweakSalt`
  (Algorithm 5): the low 24 bits of the salt carry the tweak, and the top bits
  carry a prefix that separates the two. round2 xor-ed the tweak into the salt
  instead. `sdith.compute_tweaked_salts` builds the two prefixed salts once;
  each call then ORs its own tweak into the cleared low field. The seed tree uses
  `2*node_idx`, and repetition `e` of the VOLE keystream starts at `e << 16`,
  which leaves the low 16 bits for the block counter. `crypto.py`, `params.py`,
  `sdith.py`, `vole.py`.
- alpha_1 is dropped from the signature: it is still hashed into `h_piop`, but
  only alpha_2..alpha_d are serialized and the verifier reconstructs alpha_1.
  `sdith.py`.
- seed_sk is dropped from the secret key (it is only used inside keygen).
  `sk = seed_pk || y || wit`.
- Category III uses full Rijndael-256-256 for its VOLE keystream and matrix
  PRG (the seed tree and commitment still use the truncated 24-byte Enc).
- The VOLE pairs are laid out `[cchk | wit | rnd]` (wit padded to a byte).
- `verify` rejects any input whose length is not exactly `sig_bytes` (otherwise
  trailing bytes were ignored — append malleability — and short inputs raised).

Sizes: pk 70/98/132, sk 147/208/275, sig 3721/8484/15147 (short variants).

## Proof-of-work variants

Each category has two grinding variants, matching the C reference
(`proofow_variant`):

- **shake** (base sets, e.g. `cat1-short`): grind directly on a SHAKE stream.
  The w grinding bits follow delta0 in the same `SHAKE(h_piop || ctr)` output.
- **cipher** (`*-cipherpow` sets, e.g. `cat1-short-cipherpow`): grind with a
  block cipher (AES-128 for cat1, Rijndael-256 for cat3/cat5). Derive
  `p0,p1,k0,k1` from `SHAKE(0x05 || h_piop)`, grind `c0=Enc(k0,p0)`,
  `c1=Enc(k1,p1)` over a 32-bit counter until the low w bits of `c0 xor c1` are
  zero, then `delta0 = SHAKE(0x06 || h_piop || ctr || c0 || c1)`. The cipher
  variant reserves the most-significant salt bit for the proof of work, so its
  `TweakSalt` prefix moves down one bit. `crypto.py`, `params.py`, `sdith.py`.

The cipher-pow sets reuse the base parameters (same keys), so pk/sk are
identical to the base set; only the signature differs.

## Running

    python sdith.py                  # print sizes for all six sets
    python sdith.py --test           # one keygen/sign/verify round-trip

    python gen_kat.py cat1-short 3            # (re)generate vectors into the shared kat_r3/
    python gen_kat.py cat1-short-cipherpow 3  # the cipher-grinding variant
    python test_kat.py cat1-short 3           # regenerate from seed, byte-match, verify

## KATs

The vectors live in the repo-root `kat_r3/`, the same folder the C reference
uses: `gen_kat.py` writes there and `test_kat.py` reads there. There is one set
of vectors per parameter set for both grinding variants (12 in total, the six
base sets under `SDITH_<SET>` and the six cipher sets under
`SDITH_<SET>_CIPHERPOW`). The C and Python references produce the same bytes.
`test_kat.py` regenerates each vector from its seed, byte-matches pk/sk/sm, and
round-trips it through verify; the C side runs its NIST generator and compares
record-by-record against these files via `test/kat_differential.py` (and
`mini_kat` hashes the same signatures).

## Audit test suite

`tests/` is a pytest suite that goes beyond the KATs (which only exercise honest
transcripts). It uses independent oracles and property/metamorphic testing to
find soundness/malleability/edge-case bugs the KATs cannot see. All test-only
dependencies (`hypothesis`, `numpy`) are confined to `tests/deps.py`; the core
modules stay import-clean.

    pip install hypothesis
    python -m pytest tests/ -m "not slow"   # fast lane (cat1 + pure checks)
    python -m pytest tests/                  # + slow cat3/cat5 + exhaustive sweep

Coverage: field arithmetic vs an independent GF(2^n) reference; bit/matrix
utilities; the domain-separation `ptx` packing and CTR/cat3 ciphers; GGM
open/reconstruct (incl. the adjacent-sibling merge branch); RSD encode/decode
bijection and syndrome; the VOLE correlation `q = v + Delta*u` across all
columns; PIOP gate duality (prover polynomial at delta2 == verifier scalar);
parameter re-derivation vs the spec formulas for all six sets; and exhaustive
signature-tamper / malformed-input rejection.
