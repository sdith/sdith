"""
VOLE generation, transposition, and consistency check for SDitH round 3.

Generates correlated pairs (u, v) for the prover and (q) for the verifier
from the GGM seed tree, using Grey-code ordering and midsize-to-fullsize
transposition.

The seed commitments are hashed in two levels: a per-repetition digest
hash_com[e] over that repetition's N commitments, then h_com over the tau
sub-digests. This two-level shape is what lets an optimized build batch the
Keccak 4-way.

Variable naming follows the C reference implementation.
  u, v, q       VOLE pair vectors (prover: u,v; verifier: q)
  corr_u        VOLE correction terms (C: corr_u, spec: delta_r)
  v_trans       transposed v matrix as list of GF elements (C: v_trans)
  q_trans       transposed q matrix as list of GF elements (C: q_trans)
  d1g           delta1 as a GF(2^lambda) element (C: d1g)
  L_total       total number of VOLE pairs (C: L)
"""

from params import HASH_BAVC_PREFIX
from utils import (bytes_xor, bytes_xor_into, get_bit, lowest_set_bit,
                   extract_bits, matrix_vector_product_f2,
                   matrix_f2_times_vector_gf, transpose_vole_matrix)


def _bavc_subhash(params, sub_xofs, global_salt):
    """Finalize the two-level BAVC commitment hash.

    Each sub_xofs[e] has absorbed repetition e's N commitments; squeeze the
    per-repetition digests hash_com[e] and hash them together into h_com. The
    full salt is absorbed first (all lambda bits, whereas the tweaked salts drop
    the low GGM_TWEAK_BITS and the top prefix bits) so it is bound into hash_com
    rather than hash_aux: h_com = H(HASH_BAVC_PREFIX || salt || subhashes).
    """
    digest_len = 2 * params.lambda_bytes
    global_xof = params.xof_new(HASH_BAVC_PREFIX)
    global_xof.update(global_salt)
    for xof in sub_xofs:
        global_xof.update(xof.read(digest_len))
    return global_xof.read(digest_len)


def prover_generate_midsize_grey_vole(params, ggm_tree, global_salt,
                                      vole_salt):
    """Generate midsize Grey-code VOLE pairs from the full GGM tree.

    global_salt is the untweaked salt bound into hash_com; vole_salt is the
    tweaked salt the keystream of each repetition starts from (see
    sdith.compute_tweaked_salts).

    Returns (u, v, hash_com) where u and v are lists of bytearrays
    and hash_com is the commitment hash.
    """
    num_leaves = 1 << params.kappa
    u = [bytearray(params.L_total_bytes) for _ in range(params.tau)]
    v = [bytearray(params.L_total_bytes)
         for _ in range(params.tau * params.kappa)]

    # one XOF per repetition absorbs that repetition's N commitments (in leaf
    # order), then the sub-digests are hashed together.
    sub_xofs = [params.xof_new(HASH_BAVC_PREFIX) for _ in range(params.tau)]
    leaf_index = 0

    for leaf in range(num_leaves):
        grey_level = (lowest_set_bit(leaf + 1)
                      if leaf + 1 < num_leaves
                      else params.kappa - 1)
        for rep in range(params.tau):
            seed, commitment = ggm_tree.get_leaf_seed_commit(leaf_index)
            sub_xofs[rep].update(commitment)

            expanded = bytearray(params.vole_rng(
                vole_salt, seed, params.L_total_bytes, rep))
            bytes_xor_into(u[rep], expanded)
            bytes_xor_into(v[rep * params.kappa + grey_level], u[rep])

            leaf_index += 1

    hash_com = _bavc_subhash(params, sub_xofs, global_salt)
    return u, v, hash_com


def prover_midsize_to_fullsize(params, u, v):
    """Convert midsize VOLE pairs to fullsize standard form.

    Returns (u_flat, corr_u, v_trans).
    """
    u_flat = bytearray(u[0])
    corr_u = bytearray()
    for i in range(params.tau - 1):
        corr_u.extend(bytes_xor(u[i + 1], u[0]))

    v_flat = bytearray()
    for row in v:
        v_flat.extend(row)
    padding_rows = params.lambda_ - params.tau * params.kappa
    v_flat.extend(bytearray(padding_rows * params.L_total_bytes))

    v_trans = transpose_vole_matrix(
        v_flat, params.lambda_, params.L_total)
    return u_flat, corr_u, v_trans


def verifier_open_midsize_grey_vole(params, sibling_tree,
                                    corr_terms, delta1, global_salt,
                                    vole_salt):
    """Verifier: reconstruct midsize Grey VOLE from sibling tree.

    global_salt is the untweaked salt bound into hash_com; vole_salt is the
    tweaked salt the keystream of each repetition starts from (see
    sdith.compute_tweaked_salts).

    Returns (q, hash_com).
    """
    num_leaves = 1 << params.kappa
    accumulators = [bytearray(ct) for ct in corr_terms]
    q = [bytearray(params.L_total_bytes)
         for _ in range(params.tau * params.kappa)]

    # per-repetition XOFs, matching the prover's two-level h_com.
    sub_xofs = [params.xof_new(HASH_BAVC_PREFIX) for _ in range(params.tau)]
    leaf_index = 0

    for leaf in range(num_leaves):
        grey_level = (lowest_set_bit(leaf + 1)
                      if leaf + 1 < num_leaves
                      else params.kappa - 1)
        for rep in range(params.tau):
            seed, commitment = sibling_tree.get_leaf_seed_commit(leaf_index)
            sub_xofs[rep].update(commitment)

            if seed is not None:
                expanded = bytearray(params.vole_rng(
                    vole_salt, seed, params.L_total_bytes, rep))
                bytes_xor_into(accumulators[rep], expanded)

            bytes_xor_into(
                q[rep * params.kappa + grey_level],
                accumulators[rep])

            leaf_index += 1

    for rep in range(params.tau):
        delta_bits = extract_bits(
            params.kappa, rep * params.kappa, delta1)
        for bit in range(params.kappa):
            if (delta_bits >> bit) & 1:
                bytes_xor_into(
                    q[rep * params.kappa + bit],
                    accumulators[rep])

    hash_com = _bavc_subhash(params, sub_xofs, global_salt)
    return q, hash_com


def verifier_midsize_to_fullsize(params, q):
    """Transpose verifier's q matrix to fullsize form."""
    q_flat = bytearray()
    for row in q:
        q_flat.extend(row)
    padding_rows = params.lambda_ - params.tau * params.kappa
    q_flat.extend(bytearray(padding_rows * params.L_total_bytes))
    return transpose_vole_matrix(
        q_flat, params.lambda_, params.L_total)


def generate_cchk_matrix(params, hash_aux):
    """Generate the consistency-check matrix from hash_aux."""
    num_rows = params.num_cchk_pairs
    num_cols = params.L_total - num_rows
    col_bytes = (num_cols + 7) // 8

    xof = params.xof_new(hash_aux)
    matrix = bytearray(xof.read(num_rows * col_bytes))

    last_byte_mask = 0xFF >> ((-num_cols) % 8) if num_cols % 8 else 0xFF
    for row in range(num_rows):
        matrix[row * col_bytes + col_bytes - 1] &= last_byte_mask

    return matrix


def prover_vole_consistency_check(params, u_flat, v_trans, matrix):
    """Prover: compute consistency check values.

    Returns (check_u, check_v) where check_u is a bytearray
    and check_v is a list of GF elements.
    """
    num_rows = params.num_cchk_pairs
    num_cols = params.L_total - num_rows

    check_u = matrix_vector_product_f2(
        num_rows, num_cols, matrix, u_flat[num_rows // 8:])
    bytes_xor_into(check_u, u_flat[:num_rows // 8])

    check_v = matrix_f2_times_vector_gf(
        num_rows, num_cols, matrix, v_trans[num_rows:])
    for i in range(num_rows):
        check_v[i] ^= v_trans[i]

    return check_u, check_v


def verifier_vole_consistency_check(params, q_trans, cchk_u,
                                    matrix, delta1):
    """Verifier: compute consistency check values.

    Returns check_v as a list of GF elements.
    """
    num_rows = params.num_cchk_pairs
    num_cols = params.L_total - num_rows

    check_v = matrix_f2_times_vector_gf(
        num_rows, num_cols, matrix, q_trans[num_rows:])
    for i in range(num_rows):
        check_v[i] ^= q_trans[i]

    d1g = params.gf.from_bytes(delta1)
    for i in range(num_rows):
        if get_bit(cchk_u, i):
            check_v[i] ^= d1g

    return check_v
