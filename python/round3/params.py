"""
SDitH round 3 parameter sets.

Six parameter sets: CAT1/3/5 x SHORT/FAST.
Each bundles the scheme parameters with the appropriate finite field
and symmetric primitive dispatch.

Variable naming follows the C reference implementation.
  npw            n/w, positions per RSD block (spec: m)
  L_total        total number of VOLE pairs (C: L)
  L_total_bytes  L_total // 8 (C: Lbyte)
  theta          seed-tree salt-truncation width, ceil(log2(tau*N)) + 2
"""

from dataclasses import dataclass, field, replace
from functools import partial
from math import ceil, log2

from Crypto.Hash import SHAKE128, SHAKE256

from gf import GF128, GF192, GF256
from crypto import (
    XOF,
    cat1_ggm_seed_rng, cat1_ggm_commit_rng,
    cat1_vole_rng, cat1_new_prg, cat1_proofow_rng,
    cat3_ggm_seed_rng, cat3_ggm_commit_rng,
    cat3_vole_rng, cat3_new_prg, cat3_proofow_rng,
    cat5_ggm_seed_rng, cat5_ggm_commit_rng,
    cat5_vole_rng, cat5_new_prg, cat5_proofow_rng,
    ShakeProofow, CipherProofow, aes128_ecb, rijndael256_encrypt,
)


HASH_BAVC_PREFIX = b'\x01'
HASH_AUX_PREFIX = b'\x02'
HASH_LINES_PREFIX = b'\x03'
HASH_PIOP_PREFIX = b'\x04'


def _round_up_to_multiple_of_8(n):
    return (n + 7) & (-8)


def _compute_rsd_codim(rsd_n, rsd_w):
    LOG2_100 = 6.643856189774724
    npw = rsd_n // rsd_w
    min_codim = ceil(rsd_w * log2(npw) + LOG2_100)
    return _round_up_to_multiple_of_8(min_codim)


@dataclass
class Params:
    """SDitH v2 parameter set with derived values and crypto dispatch."""

    lambda_: int = 128
    kappa: int = 11
    tau: int = 11
    target_topen: int = 109
    proofow_w: int = 9
    rsd_w: int = 56
    rsd_n: int = 10360
    mux_depth: int = 4
    mux_arities: list = field(
        default_factory=lambda: [4, 4, 4, 3])
    # Proof-of-work grinding variant: 'shake' (base sets) or 'cipher'
    # (*_CIPHERPOW sets, AES-128 for cat1 / Rijndael-256 for cat3/cat5).
    proofow_variant: str = 'shake'

    def __post_init__(self):
        self.lambda_bytes = self.lambda_ // 8

        # RSD parameters
        self.npw = self.rsd_n // self.rsd_w
        self.rsd_codim = _compute_rsd_codim(self.rsd_n, self.rsd_w)
        self.rsd_codim_bytes = (self.rsd_codim + 7) // 8
        self.rsd_codim_limbs = (
            (self.rsd_codim + self.lambda_ - 1) // self.lambda_)

        # Byte mask for the last byte of a codim-sized vector
        if self.rsd_codim % 8:
            self.rsd_codim_byte_mask = 0xFF >> (8 - self.rsd_codim % 8)
        else:
            self.rsd_codim_byte_mask = 0xFF

        # MUX circuit dimensions
        self.mux_inputs = sum(
            arity - 1 for arity in self.mux_arities[:self.mux_depth])
        self.degree = max(self.mux_depth, 2)
        self.num_inputs_pairs = self.mux_inputs * self.rsd_w
        # VOLE pairs are laid out [cchk | wit(inputs) | rnd(cz)]; the witness
        # region is padded to a byte boundary so the cz region stays aligned.
        self.num_inputs_pairs_padded = _round_up_to_multiple_of_8(
            self.num_inputs_pairs)
        # num_cchk_pairs = lambda + B, B=16 (per Thibauld Feneuil / the FAEST
        # spec): the cchk-matrix size needed for the claimed soundness level.
        # lambda+16 is already a multiple of 8, and is value-identical to the old
        # ceil8(kappa*tau+16) for every shipped set (KAT-neutral), but correct.
        self.num_cchk_pairs = self.lambda_ + 16
        self.num_cz_pairs = self.lambda_ * (self.degree - 1)

        # Total VOLE length (rounded up to multiple of 8). num_cchk_pairs and
        # num_cz_pairs are already multiples of 8, so this equals
        # num_cchk_pairs + num_inputs_pairs_padded + num_cz_pairs.
        total_pairs = (self.num_inputs_pairs
                       + self.num_cchk_pairs
                       + self.num_cz_pairs)
        self.L_total = _round_up_to_multiple_of_8(total_pairs)
        self.L_total_bytes = self.L_total // 8

        # Delta0 (proof-of-work challenge) carries kappa*tau + w bits for both
        # grinding variants, matching the C reference (sdith_signature.c always
        # sizes it kappa*tau + w). The SHAKE variant needs the trailing w bits
        # (it grinds on the w bits that follow the kappa*tau delta0 bits in the
        # same stream); the cipher variant grinds on the block-cipher output and
        # consumes only the first kappa*tau bits, so its trailing w bits are
        # unused padding. Sizing both the same is KAT-neutral (the hidden
        # indices read only the first kappa*tau bits either way) and keeps
        # Python byte-identical to C.
        self.kappa_tau = self.kappa * self.tau
        self.delta0_bits = self.kappa_tau + self.proofow_w
        self.delta0_bytes = (self.delta0_bits + 7) // 8
        self.delta0_capacity = ((self.delta0_bits + 63) // 64) * 8

        # Tree and key sizes
        self.num_leaves = self.tau * (1 << self.kappa)
        # Seed-tree domain separation overlays the tweak (bounded by
        # 2*tau*N < 2^theta) onto the low theta bits of the salt, keeping the
        # rest of the salt: ptx = (salt & ~(2^theta - 1)) | tweak.
        self.theta = ceil(log2(self.num_leaves)) + 2
        self.skey_encoded_solution_bytes = (
            (self.rsd_w * self.mux_inputs + 7) // 8)
        # sk = seed_pk || y || wit (no seed_sk), so lambda not 2*lambda.
        self.sk_bytes = (
            self.lambda_bytes
            + self.skey_encoded_solution_bytes
            + self.rsd_codim_bytes)
        self.pk_bytes = self.lambda_bytes + self.rsd_codim_bytes

        # Signature size (alpha_1 is not serialized, so degree-1 cz values)
        self.sig_bytes = (
            self.lambda_bytes                                    # global salt
            + self.target_topen * self.lambda_bytes              # sibling path
            + self.tau * 2 * self.lambda_bytes                   # hidden commits
            + self.L_total_bytes * (self.tau - 1)            # correction u
            + self.num_cchk_pairs // 8                           # cchk u
            + (self.num_inputs_pairs + 7) // 8                   # circuit input pub
            + (self.degree - 1) * self.lambda_bytes              # check-zero pub
            + 2 * self.lambda_bytes                              # hash_piop
            + 4)                                                 # PoW counter

        # Finite field and symmetric crypto dispatch. The GGM seed RNG takes the
        # salt-truncation width theta; bind it here so ggm.py can keep calling it
        # with (salt, seed, idx). The commit and VOLE RNGs tweak a fixed
        # GGM_TWEAK_BITS-wide field instead, so they need no binding.
        if self.lambda_ == 128:
            self.gf = GF128
            self.shake_cls = SHAKE128
            self.ggm_seed_rng_lr = partial(cat1_ggm_seed_rng, theta=self.theta)
            self.ggm_commit_rng = cat1_ggm_commit_rng
            self.vole_rng = cat1_vole_rng
            self.new_prg = cat1_new_prg
            self.proofow_rng = cat1_proofow_rng
        elif self.lambda_ == 192:
            self.gf = GF192
            self.shake_cls = SHAKE256
            self.ggm_seed_rng_lr = partial(cat3_ggm_seed_rng, theta=self.theta)
            self.ggm_commit_rng = cat3_ggm_commit_rng
            self.vole_rng = cat3_vole_rng
            self.new_prg = cat3_new_prg
            self.proofow_rng = cat3_proofow_rng
        elif self.lambda_ == 256:
            self.gf = GF256
            self.shake_cls = SHAKE256
            self.ggm_seed_rng_lr = partial(cat5_ggm_seed_rng, theta=self.theta)
            self.ggm_commit_rng = cat5_ggm_commit_rng
            self.vole_rng = cat5_vole_rng
            self.new_prg = cat5_new_prg
            self.proofow_rng = cat5_proofow_rng

    def make_proofow(self, h_piop):
        """Build the proof-of-work engine for one h_piop, per grinding variant.

        Both engines expose grind(start) and verify(ctr); see crypto.py.
        """
        if self.proofow_variant == 'cipher':
            if self.lambda_ == 128:
                enc, block_bytes = aes128_ecb, 16
            else:
                enc, block_bytes = rijndael256_encrypt, 32
            return CipherProofow(
                enc, block_bytes, self.shake_cls, h_piop,
                2 * self.lambda_bytes, self.proofow_w, self.delta0_bytes)
        return ShakeProofow(
            self.proofow_rng, h_piop, self.proofow_w,
            self.kappa_tau, self.delta0_bytes)

    def xof_new(self, *parts):
        """Create a new XOF instance, optionally absorbing initial data."""
        xof = XOF(self.shake_cls)
        for part in parts:
            xof.update(part)
        return xof

    def deserialize_field_elements(self, raw_bytes, count):
        """Deserialize `count` field elements from a contiguous byte buffer."""
        step = self.lambda_bytes
        return [self.gf.from_bytes(raw_bytes[i * step:(i + 1) * step])
                for i in range(count)]


CAT1_SHORT = Params()

CAT1_FAST = Params(
    lambda_=128, kappa=7, tau=18, target_topen=107, proofow_w=4,
    rsd_w=56, rsd_n=10360, mux_depth=4, mux_arities=[4, 4, 4, 3])

CAT3_SHORT = Params(
    lambda_=192, kappa=11, tau=17, target_topen=169, proofow_w=7,
    rsd_w=73, rsd_n=18396, mux_depth=4, mux_arities=[4, 4, 4, 4])

CAT3_FAST = Params(
    lambda_=192, kappa=7, tau=27, target_topen=161, proofow_w=5,
    rsd_w=73, rsd_n=18396, mux_depth=4, mux_arities=[4, 4, 4, 4])

CAT5_SHORT = Params(
    lambda_=256, kappa=11, tau=23, target_topen=228, proofow_w=5,
    rsd_w=104, rsd_n=19864, mux_depth=4, mux_arities=[4, 4, 4, 3])

CAT5_FAST = Params(
    lambda_=256, kappa=7, tau=36, target_topen=216, proofow_w=6,
    rsd_w=104, rsd_n=19864, mux_depth=4, mux_arities=[4, 4, 4, 3])

# Cipher-grinding (CIPHERPOW) sets. kappa and the RSD parameters are shared
# with the base set, so keygen output (pk/sk) is identical; the grinding
# variant and, for two fast sets, a re-tuned (tau, target_topen, proofow_w)
# change only the signature. The round-3 tuning gives cat1-fast and cat3-fast
# their own cipher parameters (specs/sections/04-parameters.tex,
# tab:params-voleith-aespow); the short sets and cat5-fast keep the base
# tuning, so only the variant differs.
CAT1_SHORT_CIPHERPOW = replace(CAT1_SHORT, proofow_variant='cipher')
CAT1_FAST_CIPHERPOW = replace(
    CAT1_FAST, tau=17, target_topen=101, proofow_w=11,
    proofow_variant='cipher')
CAT3_SHORT_CIPHERPOW = replace(CAT3_SHORT, proofow_variant='cipher')
CAT3_FAST_CIPHERPOW = replace(
    CAT3_FAST, tau=26, target_topen=155, proofow_w=12,
    proofow_variant='cipher')
CAT5_SHORT_CIPHERPOW = replace(CAT5_SHORT, proofow_variant='cipher')
CAT5_FAST_CIPHERPOW = replace(CAT5_FAST, proofow_variant='cipher')

ALL_PARAMS = {
    'cat1-short': CAT1_SHORT, 'cat1-fast': CAT1_FAST,
    'cat3-short': CAT3_SHORT, 'cat3-fast': CAT3_FAST,
    'cat5-short': CAT5_SHORT, 'cat5-fast': CAT5_FAST,
    'cat1-short-cipherpow': CAT1_SHORT_CIPHERPOW,
    'cat1-fast-cipherpow': CAT1_FAST_CIPHERPOW,
    'cat3-short-cipherpow': CAT3_SHORT_CIPHERPOW,
    'cat3-fast-cipherpow': CAT3_FAST_CIPHERPOW,
    'cat5-short-cipherpow': CAT5_SHORT_CIPHERPOW,
    'cat5-fast-cipherpow': CAT5_FAST_CIPHERPOW,
}
