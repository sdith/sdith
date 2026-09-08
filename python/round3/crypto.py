"""
Symmetric primitives for SDitH round 3.

AES-128 and Rijndael-256 in CTR-LE mode, SHAKE128/256 XOF wrappers,
and per-category dispatch for GGM seed/commit RNGs, VOLE RNG, and PRG.

Security categories:
  CAT I   (lambda=128): Enc = AES-128,                     SHAKE128
  CAT III (lambda=192): Enc = truncated Rijndael-256-256,  SHAKE256
  CAT V   (lambda=256): Enc = Rijndael-256-256,            SHAKE256

The seed tree derives its plaintexts by overlaying the tweak onto the low
theta bits of the salt: ptx = (salt & ~THETA_MASK) | tweak, THETA_MASK =
2^theta - 1, theta = ceil(log2(tau*N)) + 2 (so all but the low theta salt
bits fill the block). ExpandSeed uses tweak = 2*idx, CommitSeed uses tweak =
2*(tau*N + idx), and the right child is tweak+1 (see _domain_sep_ptx). For
lambda=192 the block cipher is LSB_192(Rijndael-256-256((k || 0^64),
(p || 0^64))) (see _cat3_enc).

CommitSeed and the VOLE keystream take a salt whose low GGM_TWEAK_BITS bits
are already cleared and whose top bits carry the family prefix (see
sdith.compute_tweaked_salts), so their tweak field is that fixed width rather
than theta. The VOLE tweak is repet_idx << VOLE_RNG_REPET_SHIFT, which leaves
the low VOLE_RNG_REPET_SHIFT bits of the block for the CTR counter: a single
keystream is therefore bounded to 2^VOLE_RNG_REPET_SHIFT blocks.
"""

from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128, SHAKE256
import struct

from rijndael256 import rijndael256_encrypt
from utils import extract_bits

# Width of the tweak field reserved in the low bits of a tweaked salt, and the
# position of the repetition index inside it for the VOLE keystream (mirrors
# GGM_TWEAK_BITS / VOLE_RNG_REPET_SHIFT in src/sdith_prng.h).
GGM_TWEAK_BITS = 24
VOLE_RNG_REPET_SHIFT = 16


class XOF:
    """Thin wrapper around SHAKE for streaming reads."""

    def __init__(self, shake_cls):
        self._hash = shake_cls.new()

    def update(self, data):
        self._hash.update(data)

    def read(self, num_bytes):
        return self._hash.read(num_bytes)


class AesCtrLE:
    """AES-128 CTR mode with little-endian 128-bit counter."""

    def __init__(self, key, initial_counter=None):
        self._cipher = AES.new(key[:16], AES.MODE_ECB)
        if initial_counter is not None:
            self._counter = int.from_bytes(initial_counter, 'little')
        else:
            self._counter = 0
        self._mask = (1 << 128) - 1
        self._buffer = b''

    def get_bytes(self, num_bytes):
        output = bytearray()
        while len(output) < num_bytes:
            if self._buffer:
                take = min(len(self._buffer), num_bytes - len(output))
                output.extend(self._buffer[:take])
                self._buffer = self._buffer[take:]
            else:
                counter_block = (self._counter & self._mask).to_bytes(16, 'little')
                self._buffer = self._cipher.encrypt(counter_block)
                self._counter += 1
        return bytes(output)


class Rijndael256CtrLE:
    """Rijndael-256 CTR mode with little-endian 256-bit counter."""

    def __init__(self, key, initial_counter=None):
        self._key = bytes(key[:32])
        if initial_counter is not None:
            self._counter = int.from_bytes(initial_counter, 'little')
        else:
            self._counter = 0
        self._mask = (1 << 256) - 1
        self._buffer = b''

    def get_bytes(self, num_bytes):
        output = bytearray()
        while len(output) < num_bytes:
            if self._buffer:
                take = min(len(self._buffer), num_bytes - len(output))
                output.extend(self._buffer[:take])
                self._buffer = self._buffer[take:]
            else:
                counter_block = (self._counter & self._mask).to_bytes(32, 'little')
                self._buffer = rijndael256_encrypt(self._key, counter_block)
                self._counter += 1
        return bytes(output)


def _cat3_enc(key24, ptx24):
    """Category-III (lambda=192) block cipher.

    Enc(k, p) = LSB_192( Rijndael-256-256( (k || 0^64), (p || 0^64) ) ).
    Inputs are 24-byte (192-bit) values; each is padded with 8 trailing zero
    bytes to a 256-bit block.  LSB_192 = the 192 least-significant bits = the
    low 24 bytes of the 32-byte Rijndael output (little-endian convention).
    """
    key32 = bytes(key24[:24]) + b'\x00' * 8   # k || 0^64
    ptx32 = bytes(ptx24[:24]) + b'\x00' * 8   # p || 0^64
    return rijndael256_encrypt(key32, ptx32)[:24]


class Cat3EncCtrLE:
    """CTR-mode PRG built on the Category-III Enc (24-byte blocks)."""

    def __init__(self, key, initial_counter=None):
        self._key = bytes(key[:24])
        if initial_counter is not None:
            self._counter = int.from_bytes(initial_counter, 'little')
        else:
            self._counter = 0
        self._mask = (1 << 192) - 1
        self._buffer = b''

    def get_bytes(self, num_bytes):
        output = bytearray()
        while len(output) < num_bytes:
            if self._buffer:
                take = min(len(self._buffer), num_bytes - len(output))
                output.extend(self._buffer[:take])
                self._buffer = self._buffer[take:]
            else:
                counter_block = (self._counter & self._mask).to_bytes(24, 'little')
                self._buffer = _cat3_enc(self._key, counter_block)
                self._counter += 1
        return bytes(output)


def _domain_sep_ptx(salt, tweak, theta, block_bytes):
    """Domain-separated plaintext block: the salt with its low theta bits
    replaced by MapToBits(tweak).

    Realized as a little-endian block of `block_bytes`:
        ptx = (salt & ~THETA_MASK) | (tweak & THETA_MASK)
    with THETA_MASK = 2^theta - 1, so the tweak occupies the low theta bits
    and the rest of the salt fills the whole block above it (all but the low
    theta salt bits are used). theta = ceil(log2(tau*N)) + 2 bounds every
    tweak (tweak & THETA_MASK == tweak), so CTR-incrementing the block maps
    tweak -> tweak+1 and yields the sibling (right-child) plaintext exactly.
    """
    theta_mask = (1 << theta) - 1
    salt_int = int.from_bytes(salt, 'little')
    ptx_int = (salt_int & ~theta_mask) | (tweak & theta_mask)
    return ptx_int.to_bytes(block_bytes, 'little')


# ---- CAT I (lambda=128): AES-128, SHAKE128 ----

def cat1_ggm_seed_rng(salt, key, node_index, theta):
    # ExpandSeed: tweak = 2*idx (node_index is already the even left-child index)
    ptx = _domain_sep_ptx(salt, node_index, theta, 16)
    return AesCtrLE(key, ptx).get_bytes(32)   # left = Enc(ptx), right = Enc(ptx+1)


def cat1_ggm_commit_rng(salt, key, node_index):
    # CommitSeed: tweak = 2*(tau*N + idx) = 2*node_index
    ptx = _domain_sep_ptx(salt, node_index << 1, GGM_TWEAK_BITS, 16)
    return AesCtrLE(key, ptx).get_bytes(32)   # com = Enc(ptx) || Enc(ptx+1)


def cat1_vole_rng(salt, seed, num_bytes, repet_idx):
    ptx = _domain_sep_ptx(
        salt, repet_idx << VOLE_RNG_REPET_SHIFT, GGM_TWEAK_BITS, 16)
    return AesCtrLE(seed, ptx).get_bytes(num_bytes)


def cat1_new_prg(seed, initial_counter=None):
    return AesCtrLE(seed, initial_counter)


def cat1_proofow_rng(hash_piop, counter, num_bytes):
    xof = SHAKE128.new()
    xof.update(hash_piop[:32])
    xof.update(struct.pack('<I', counter))
    return xof.read(num_bytes)


# ---- CAT III (lambda=192): Rijndael-256-256, SHAKE256 ----
# The seed tree and commitment still use the truncated Enc (24-byte seeds and
# commitments). The VOLE keystream and the matrix PRG use the full 256-bit
# Rijndael-256 output, same as CAT V. Only the low rsd_codim / lambda bits are
# kept downstream, so the extra bytes per block are just consumed from the
# stream.

def cat3_ggm_seed_rng(salt, key, node_index, theta):
    ptx = _domain_sep_ptx(salt, node_index, theta, 24)
    return Cat3EncCtrLE(key, ptx).get_bytes(48)   # two 24-byte seeds


def cat3_ggm_commit_rng(salt, key, node_index):
    ptx = _domain_sep_ptx(salt, node_index << 1, GGM_TWEAK_BITS, 24)
    return Cat3EncCtrLE(key, ptx).get_bytes(48)   # 2*lambda commitment


def cat3_vole_rng(salt, seed, num_bytes, repet_idx):
    key32 = bytes(seed[:24]) + b'\x00' * 8   # k || 0^64 (C cat3)
    # the 24-byte salt sits in the low bytes of the 32-byte Rijndael block,
    # the top 8 bytes stay zero (matches the C ctr256 zero-padding).
    ptx = _domain_sep_ptx(
        salt, repet_idx << VOLE_RNG_REPET_SHIFT, GGM_TWEAK_BITS, 32)
    return Rijndael256CtrLE(key32, ptx).get_bytes(num_bytes)


def cat3_new_prg(seed, initial_counter=None):
    key32 = bytes(seed[:24]) + b'\x00' * 8   # k || 0^64
    if initial_counter:
        return Rijndael256CtrLE(key32, initial_counter)
    return Rijndael256CtrLE(key32)


def cat3_proofow_rng(hash_piop, counter, num_bytes):
    xof = SHAKE256.new()
    xof.update(hash_piop[:48])
    xof.update(struct.pack('<I', counter))
    return xof.read(num_bytes)


# ---- CAT V (lambda=256): Rijndael-256, SHAKE256 ----

def cat5_ggm_seed_rng(salt, key, node_index, theta):
    ptx = _domain_sep_ptx(salt, node_index, theta, 32)
    return Rijndael256CtrLE(key, ptx).get_bytes(64)   # two 32-byte seeds


def cat5_ggm_commit_rng(salt, key, node_index):
    ptx = _domain_sep_ptx(salt, node_index << 1, GGM_TWEAK_BITS, 32)
    return Rijndael256CtrLE(key, ptx).get_bytes(64)   # 2*lambda commitment


def cat5_vole_rng(salt, seed, num_bytes, repet_idx):
    ptx = _domain_sep_ptx(
        salt, repet_idx << VOLE_RNG_REPET_SHIFT, GGM_TWEAK_BITS, 32)
    return Rijndael256CtrLE(seed, ptx).get_bytes(num_bytes)


def cat5_new_prg(seed, initial_counter=None):
    if initial_counter:
        return Rijndael256CtrLE(seed, initial_counter)
    return Rijndael256CtrLE(seed)


def cat5_proofow_rng(hash_piop, counter, num_bytes):
    xof = SHAKE256.new()
    xof.update(hash_piop[:64])
    xof.update(struct.pack('<I', counter))
    return xof.read(num_bytes)


# ---- Proof-of-work engines (SHAKE and CIPHER grinding variants) ----
#
# Both engines expose the same interface:
#   grind(start) -> (ctr, delta0_buf): scan ctr >= start and return the first
#       ctr whose w grinding condition holds, plus its delta0 buffer. The caller
#       still applies the delta0 is-zero / t_open filters and re-grinds from
#       ctr+1 on reject.
#   verify(ctr) -> delta0_buf | None: check that single ctr's w condition.
#
# SHAKE is the base variant; CIPHER matches the *_CIPHERPOW parameter sets.

_PROOFOW_CTR_MAX = 1 << 32          # counter is 32 bits (4 revealed bytes)
_PROOFOW_H0_PREFIX = b'\x05'        # src/sdith_signature.c PROOFOW_H0_PREFIX
_PROOFOW_H1_PREFIX = b'\x06'        # src/sdith_signature.c PROOFOW_H1_PREFIX
_PROOFOW_CTR_BYTES = 4             # PROOFOW_CTR_REVEALED_BYTES


def aes128_ecb(key, block):
    """Single-block AES-128 ECB (cat1 cipher grind)."""
    return AES.new(bytes(key[:16]), AES.MODE_ECB).encrypt(bytes(block))


class ShakeProofow:
    """SHAKE grinding proof of work (base parameter sets).

    delta0_and_vgrind = SHAKE(h_piop || ctr_LE4); the w grinding bits sit right
    after the tau*kappa delta0 bits in the same stream, so the accepted counter
    is the first one whose w bits at offset kappa*tau are zero. Byte-identical to
    the original inline loop in sdith.sign / sdith.verify.
    """

    def __init__(self, proofow_rng, h_piop, proofow_w, kappa_tau, delta0_bytes):
        self._rng = proofow_rng
        self._h = h_piop
        self._w = proofow_w
        self._kappa_tau = kappa_tau
        self._delta0_bytes = delta0_bytes

    def _w_is_zero(self, buf):
        return extract_bits(self._w, self._kappa_tau, buf) == 0

    def grind(self, start):
        for ctr in range(start, _PROOFOW_CTR_MAX):
            buf = self._rng(self._h, ctr, self._delta0_bytes)
            if self._w_is_zero(buf):
                return ctr, buf
        return None, None

    def verify(self, ctr):
        buf = self._rng(self._h, ctr, self._delta0_bytes)
        if not self._w_is_zero(buf):
            return None
        return buf


class CipherProofow:
    """Cipher grinding proof of work (*_CIPHERPOW parameter sets).

    Mirrors src/sdith_prng.c proofow_*_cipher_*: derive p0,p1,k0,k1 from
    SHAKE(0x05 || h_piop); grind c0 = Enc(k0, p0), c1 = Enc(k1, p1) over a 32-bit
    counter (written into the low 4 bytes of each plaintext, little-endian) until
    the low w-1 bits of (c0 xor c1) are zero; then
    delta0 = SHAKE(0x06 || h_piop || ctr_LE4 || c0 || c1). Enc is AES-128 for
    cat1 (16-byte block) and Rijndael-256 for cat3/cat5 (32-byte block).
    """

    def __init__(self, enc, block_bytes, shake_cls, h_piop, h_piop_bytes,
                 proofow_w, delta0_out_bytes):
        self._enc = enc
        self._shake_cls = shake_cls
        self._h = bytes(h_piop[:h_piop_bytes])
        # each iteration runs the block cipher twice, so 2^(w-1) iterations already
        # cost 2^w cipher calls: the check must cover w-1 bits, not w.
        self._mask_w = (1 << (proofow_w - 1)) - 1
        self._delta0_out_bytes = delta0_out_bytes
        # H0: derive p0, p1, k0, k1 from SHAKE(0x05 || h_piop).
        xof = shake_cls.new()
        xof.update(_PROOFOW_H0_PREFIX)
        xof.update(self._h)
        s = xof.read(4 * block_bytes)
        p0 = bytearray(s[0 * block_bytes:1 * block_bytes])
        p1 = bytearray(s[1 * block_bytes:2 * block_bytes])
        k0 = bytearray(s[2 * block_bytes:3 * block_bytes])
        k1 = bytearray(s[3 * block_bytes:4 * block_bytes])
        p0[block_bytes - 1] |= 0x80   # msb of p0 = 1
        p1[block_bytes - 1] |= 0x80   # msb of p1 = 1
        k0[0] &= 0xFE                 # lsb of k0 = 0
        k1[0] |= 0x01                 # lsb of k1 = 1
        self._p0, self._p1 = p0, p1
        self._k0, self._k1 = bytes(k0), bytes(k1)

    def _cipher_pair(self, ctr):
        ctr_le = ctr.to_bytes(_PROOFOW_CTR_BYTES, 'little')
        self._p0[0:_PROOFOW_CTR_BYTES] = ctr_le
        self._p1[0:_PROOFOW_CTR_BYTES] = ctr_le
        return self._enc(self._k0, self._p0), self._enc(self._k1, self._p1)

    def _w_is_zero(self, c0, c1):
        x = int.from_bytes(c0[:8], 'little') ^ int.from_bytes(c1[:8], 'little')
        return (x & self._mask_w) == 0

    def _delta0(self, ctr, c0, c1):
        xof = self._shake_cls.new()
        xof.update(_PROOFOW_H1_PREFIX)
        xof.update(self._h)
        xof.update(ctr.to_bytes(_PROOFOW_CTR_BYTES, 'little'))
        xof.update(bytes(c0))
        xof.update(bytes(c1))
        return xof.read(self._delta0_out_bytes)

    def grind(self, start):
        for ctr in range(start, _PROOFOW_CTR_MAX):
            c0, c1 = self._cipher_pair(ctr)
            if self._w_is_zero(c0, c1):
                return ctr, self._delta0(ctr, c0, c1)
        return None, None

    def verify(self, ctr):
        c0, c1 = self._cipher_pair(ctr)
        if not self._w_is_zero(c0, c1):
            return None
        return self._delta0(ctr, c0, c1)
