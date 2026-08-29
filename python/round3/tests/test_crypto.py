"""
L1 - symmetric primitives (crypto.py).

The seed-tree domain separation and cat3 truncated-Rijndael are round3-changed
and have no C oracle, so this checks the internal invariants the design relies
on: AES-CTR-LE against pycryptodome, the ptx packing (tweak in the low theta
bits) and the CTR-increment == tweak+1 property, cat3 LSB_192 truncation, and
that no two cipher input blocks collide across a whole seed tree.
"""
from dataclasses import replace

from Crypto.Cipher import AES

from crypto import (AesCtrLE, Cat3EncCtrLE, _cat3_enc, _domain_sep_ptx,
                    cat1_ggm_seed_rng, cat1_ggm_commit_rng,
                    cat1_vole_rng, cat3_ggm_seed_rng,
                    GGM_TWEAK_BITS, VOLE_RNG_REPET_SHIFT)
from params import ALL_PARAMS, CAT1_FAST
from sdith import compute_tweaked_salts
from deps import given, settings, st


# ---- AES-128 CTR little-endian ----

@given(key=st.binary(min_size=16, max_size=16),
       nblocks=st.integers(min_value=1, max_value=6))
def test_aes_ctr_le_matches_pycryptodome(key, nblocks):
    stream = AesCtrLE(key).get_bytes(16 * nblocks)
    ecb = AES.new(key, AES.MODE_ECB)
    ref = b''.join(ecb.encrypt((i).to_bytes(16, 'little'))
                   for i in range(nblocks))
    assert stream == ref


@given(key=st.binary(min_size=16, max_size=16),
       ctr=st.integers(min_value=0, max_value=(1 << 32)),
       nblocks=st.integers(min_value=1, max_value=4))
def test_aes_ctr_le_initial_counter(key, ctr, nblocks):
    init = (ctr & ((1 << 128) - 1)).to_bytes(16, 'little')
    stream = AesCtrLE(key, init).get_bytes(16 * nblocks)
    ecb = AES.new(key, AES.MODE_ECB)
    ref = b''.join(ecb.encrypt(((ctr + i) & ((1 << 128) - 1)).to_bytes(16, 'little'))
                   for i in range(nblocks))
    assert stream == ref


# ---- domain-separated plaintext block ----

@given(salt=st.binary(min_size=16, max_size=16),
       tweak=st.integers(min_value=0, max_value=(1 << 17) - 2))
def test_domain_sep_low_bits_are_tweak(salt, tweak):
    theta = 17
    ptx = _domain_sep_ptx(salt, tweak, theta, 16)
    val = int.from_bytes(ptx, 'little')
    assert val & ((1 << theta) - 1) == tweak
    # CTR +1 must map tweak -> tweak+1 (the sibling/right-child relationship).
    ptx2 = _domain_sep_ptx(salt, tweak + 1, theta, 16)
    assert int.from_bytes(ptx2, 'little') == val + 1


@given(salt=st.binary(min_size=16, max_size=16),
       tweak=st.integers(min_value=0, max_value=(1 << 17) - 1))
def test_domain_sep_salt_above_tweak(salt, tweak):
    theta = 17
    ptx = _domain_sep_ptx(salt, tweak, theta, 16)
    val = int.from_bytes(ptx, 'little')
    # _domain_sep_ptx overlays the tweak on the low theta bits and keeps the
    # rest of the salt above it: ptx = (salt & ~(2^theta-1)) | tweak.
    salt_above = int.from_bytes(salt, 'little') >> theta
    assert (val >> theta) == salt_above


# ---- cat3 truncated Rijndael ----

@given(key=st.binary(min_size=24, max_size=24),
       ptx=st.binary(min_size=24, max_size=24))
def test_cat3_enc_is_lsb192(key, ptx):
    out = _cat3_enc(key, ptx)
    assert len(out) == 24
    from rijndael256 import rijndael256_encrypt
    full = rijndael256_encrypt(bytes(key) + b'\x00' * 8, bytes(ptx) + b'\x00' * 8)
    assert out == full[:24]           # LSB_192 = low 24 bytes (little-endian)


@given(key=st.binary(min_size=24, max_size=24),
       nblocks=st.integers(min_value=1, max_value=4))
def test_cat3_ctr_chains_enc(key, nblocks):
    stream = Cat3EncCtrLE(key).get_bytes(24 * nblocks)
    ref = b''.join(_cat3_enc(key, (i).to_bytes(24, 'little'))
                   for i in range(nblocks))
    assert stream == ref


# ---- GGM RNG wiring ties domain-sep to the cipher ----

@given(salt=st.binary(min_size=16, max_size=16),
       seed=st.binary(min_size=16, max_size=16),
       idx=st.integers(min_value=2, max_value=4000))
def test_cat1_seed_rng_is_enc_tweak_and_tweak_plus1(salt, seed, idx):
    idx &= ~1  # even left-child index
    theta = 20
    out = cat1_ggm_seed_rng(salt, seed, idx, theta)
    assert len(out) == 32
    ecb = AES.new(seed[:16], AES.MODE_ECB)
    left = ecb.encrypt(_domain_sep_ptx(salt, idx, theta, 16))
    right = ecb.encrypt(_domain_sep_ptx(salt, idx + 1, theta, 16))
    assert out == left + right


# ---- no cipher-block collisions across a whole seed tree ----

def test_no_ptx_collisions_full_tree():
    p = CAT1_FAST                      # smallest tree (num_leaves 4096)
    N = p.num_leaves
    theta = p.theta
    salt = b'\xa5' * p.lambda_bytes
    blocks = set()
    # ExpandSeed consumes tweak=2*idx and 2*idx+1 for internal nodes 1..N-1
    for idx in range(1, N):
        for t in (2 * idx, 2 * idx + 1):
            blocks.add(int.from_bytes(_domain_sep_ptx(salt, t, theta, 16), 'little'))
    # CommitSeed consumes 2*node and 2*node+1 for leaf nodes N..2N-1
    for node in range(N, 2 * N):
        for t in (2 * node, 2 * node + 1):
            blocks.add(int.from_bytes(_domain_sep_ptx(salt, t, theta, 16), 'little'))
    expected = 2 * (N - 1) + 2 * N     # every consumed block distinct
    assert len(blocks) == expected


# ---- tweaked salts: the two families never share a cipher input block ----

@given(salt=st.binary(min_size=16, max_size=16))
def test_tweaked_salts_separate_ggm_from_vole(salt):
    for p in (CAT1_FAST, replace(CAT1_FAST, proofow_variant='cipher')):
        ggm_salt, vole_salt = compute_tweaked_salts(p, salt)
        # both reserve the whole tweak field
        tweak_mask = (1 << GGM_TWEAK_BITS) - 1
        assert int.from_bytes(ggm_salt, 'little') & tweak_mask == 0
        assert int.from_bytes(vole_salt, 'little') & tweak_mask == 0
        # the prefix bit differs, so no tweak can make the two blocks collide
        prefix = 1 << (p.lambda_ - 1 if p.proofow_variant == 'shake'
                       else p.lambda_ - 2)
        assert int.from_bytes(ggm_salt, 'little') & prefix
        assert not int.from_bytes(vole_salt, 'little') & prefix


@given(salt=st.binary(min_size=16, max_size=16),
       seed=st.binary(min_size=16, max_size=16),
       repet_idx=st.integers(min_value=0, max_value=255),
       nblocks=st.integers(min_value=1, max_value=4))
def test_cat1_vole_rng_starts_at_the_repetition_tweak(salt, seed, repet_idx,
                                                      nblocks):
    _, vole_salt = compute_tweaked_salts(CAT1_FAST, salt)
    out = cat1_vole_rng(vole_salt, seed, 16 * nblocks, repet_idx)
    base = int.from_bytes(vole_salt, 'little') | (repet_idx
                                                  << VOLE_RNG_REPET_SHIFT)
    ecb = AES.new(seed[:16], AES.MODE_ECB)
    ref = b''.join(ecb.encrypt((base + i).to_bytes(16, 'little'))
                   for i in range(nblocks))
    assert out == ref
