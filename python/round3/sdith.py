"""
SDitH round 3 — Python Reference Implementation

Syndrome-Decoding-in-the-Head: a post-quantum signature scheme based on the
syndrome decoding problem over F2, using the VOLEitH framework. This tracks
the round-3 spec (../../docs/sdith-v3.0.pdf), built on the round2
implementation.

Supports all 6 parameter sets, CAT1/3/5 x SHORT/FAST, in both proof-of-work
variants, so 12 sets in total.

Dependencies: pycryptodome (AES-128 ECB, SHAKE128/256)

Usage:
    from sdith import keygen, sign, verify
    from params import CAT1_SHORT

    skey, pkey = keygen(CAT1_SHORT, entropy_32)
    sig = sign(CAT1_SHORT, skey, message, entropy_32)
    ok = verify(CAT1_SHORT, pkey, message, sig)

Variable naming follows the C reference implementation.
  sk_seed       secret key seed (spec: seed_sk); used only in keygen
  pk_seed       public key seed (spec: seed_pk)
  pkey_y        public syndrome y = Hx (C: pkey_y)
  corr_u        VOLE correction terms (spec: delta_r)
  chall_a       batching challenge gamma for H (spec: gamma)
  chall_u       batching challenge gamma' for unitary (spec: gamma')
  chall_a_H     gamma^T * Phi(h_j) per column
  chall_a_y     gamma^T * Phi(y)
  d1g, d2g      delta1/delta2 as GF(2^lambda) elements
  mi            mux_inputs per weight block
  v_trans       transposed v matrix (C: v_trans)
  q_trans       transposed q matrix (C: q_trans)
"""

import struct

from crypto import GGM_TWEAK_BITS
from params import (HASH_AUX_PREFIX, HASH_LINES_PREFIX,
                    HASH_PIOP_PREFIX, ALL_PARAMS)
from ggm import (GGMTree, GGMSiblingTree,
                 estimate_topen, decode_hidden_leaf_indices)
from vole import (prover_generate_midsize_grey_vole,
                  prover_midsize_to_fullsize,
                  verifier_open_midsize_grey_vole,
                  verifier_midsize_to_fullsize,
                  generate_cchk_matrix,
                  prover_vole_consistency_check,
                  verifier_vole_consistency_check)
from vole_to_piop import (prover_f2_to_flambda_deg1,
                          verifier_f2_to_flambda_deg1,
                          prover_deg1_to_degd,
                          verifier_deg1_to_degd,
                          prover_std_to_cst,
                          verifier_std_to_cst,
                          delta1_from_delta0,
                          delta2_from_delta1)
from piop import (prover_xor_gate,
                  prover_packed_secret_input,
                  verifier_packed_secret_input,
                  prover_check_zero_gate,
                  prover_mux_circuit,
                  verifier_mux_circuit)
from rsd import (rsd_generate_instance,
                 rsd_encode_solution,
                 rsd_public_key_times_challenge)
from utils import bitvec_is_zero

from params import (CAT1_SHORT, CAT1_FAST,
                    CAT3_SHORT, CAT3_FAST,
                    CAT5_SHORT, CAT5_FAST,
                    Params)
from nist_drbg import NistDRBG


def compute_tweaked_salts(params, global_salt):
    """Derive the (ggm_salt, vole_salt) pair from the global salt.

    Both are the global salt with its low GGM_TWEAK_BITS bits cleared -- that
    field carries the per-call tweak -- and its top bits replaced by a family
    prefix that separates the seed tree from the VOLE keystream: "1"/"0" for the
    shake-grinding sets, "01"/"00" for the cipher-grinding ones (which reserve
    the second bit for the proof of work). Mirrors compute_tweaked_salts in
    src/vole_expansion.c. The salt hashed elsewhere (hash_com) and serialized
    into the signature stays the original global_salt.
    """
    body = (int.from_bytes(global_salt, 'little')
            & ~((1 << GGM_TWEAK_BITS) - 1))
    if params.proofow_variant == 'cipher':
        body &= ~(0b11 << (params.lambda_ - 2))
        ggm_salt = body | (1 << (params.lambda_ - 2))
        vole_salt = body
    else:
        ggm_salt = body | (1 << (params.lambda_ - 1))
        vole_salt = body & ~(1 << (params.lambda_ - 1))
    return (ggm_salt.to_bytes(params.lambda_bytes, 'little'),
            vole_salt.to_bytes(params.lambda_bytes, 'little'))


# ======================================================================
# Key and Signature Serialization
# ======================================================================

def pack_skey(params, pk_seed, encoded_solution, pkey_y):
    # sk = seed_pk || y || wit  (seed_sk is not stored)
    return pk_seed + pkey_y + encoded_solution


def unpack_skey(params, skey):
    lambda_bytes = params.lambda_bytes
    solution_len = params.skey_encoded_solution_bytes
    offset = 0

    pk_seed = skey[offset:offset + lambda_bytes]
    offset += lambda_bytes
    pkey_y = skey[offset:offset + params.rsd_codim_bytes]
    offset += params.rsd_codim_bytes
    encoded_solution = skey[offset:offset + solution_len]

    return pk_seed, encoded_solution, pkey_y


def pack_pkey(params, pk_seed, pkey_y):
    return pk_seed + pkey_y


def unpack_pkey(params, pkey):
    lambda_bytes = params.lambda_bytes
    return pkey[:lambda_bytes], pkey[lambda_bytes:lambda_bytes + params.rsd_codim_bytes]


def pack_signature(params, global_salt, sibling_path,
                   hidden_commitments, corr_u, cchk_u,
                   circuit_in_pub, circuit_cz_pub,
                   hash_piop, proofow_counter):
    field = params.gf
    lambda_bytes = params.lambda_bytes

    sig = bytearray(global_salt)

    # Sibling path (zero-padded to target_topen entries)
    path_data = bytearray()
    for seed in sibling_path:
        path_data.extend(seed)
    path_data.extend(
        b'\x00' * (params.target_topen * lambda_bytes - len(path_data)))
    sig.extend(path_data)

    for commitment in hidden_commitments:
        sig.extend(commitment)

    sig.extend(corr_u)
    sig.extend(cchk_u)
    sig.extend(circuit_in_pub)

    for value in circuit_cz_pub:
        sig.extend(field.to_bytes(value))

    sig.extend(hash_piop)
    sig.extend(struct.pack('<I', proofow_counter))
    return bytes(sig)


def unpack_signature(params, sig):
    field = params.gf
    lambda_bytes = params.lambda_bytes
    offset = 0

    global_salt = sig[offset:offset + lambda_bytes]
    offset += lambda_bytes

    path_data = sig[offset:offset + params.target_topen * lambda_bytes]
    offset += params.target_topen * lambda_bytes
    sibling_path = [
        path_data[i * lambda_bytes:(i + 1) * lambda_bytes]
        for i in range(params.target_topen)]

    hidden_commitments = []
    for _ in range(params.tau):
        hidden_commitments.append(sig[offset:offset + 2 * lambda_bytes])
        offset += 2 * lambda_bytes

    correction_len = params.L_total_bytes * (params.tau - 1)
    corr_u = sig[offset:offset + correction_len]
    offset += correction_len

    cchk_len = params.num_cchk_pairs // 8
    cchk_u = sig[offset:offset + cchk_len]
    offset += cchk_len

    input_pub_len = (params.num_inputs_pairs + 7) // 8
    circuit_in_pub = sig[offset:offset + input_pub_len]
    offset += input_pub_len

    # The signature carries (alpha_2, ..., alpha_d); alpha_1 is reconstructed
    # by the verifier.
    circuit_cz_pub = []
    for _ in range(params.degree - 1):
        circuit_cz_pub.append(field.from_bytes(sig[offset:offset + lambda_bytes]))
        offset += lambda_bytes

    hash_piop = sig[offset:offset + 2 * lambda_bytes]
    offset += 2 * lambda_bytes

    proofow_counter = struct.unpack('<I', sig[offset:offset + 4])[0]

    return (global_salt, sibling_path, hidden_commitments,
            corr_u, cchk_u, circuit_in_pub,
            circuit_cz_pub, hash_piop, proofow_counter)


# ======================================================================
# Signature API
# ======================================================================

def keygen(params, entropy):
    """Deterministic key generation from 2*lambda_bytes of entropy."""
    lambda_bytes = params.lambda_bytes
    pk_seed = entropy[:lambda_bytes]
    # seed_sk is used only here to sample the RSD instance; it is not stored.
    sk_seed = entropy[lambda_bytes:2 * lambda_bytes]

    solution, pkey_y = rsd_generate_instance(
        params, sk_seed, pk_seed)
    encoded_solution = rsd_encode_solution(params, solution)

    skey = pack_skey(params, pk_seed, encoded_solution, pkey_y)
    pkey = pack_pkey(params, pk_seed, pkey_y)
    return skey, pkey


def sign(params, skey, message, entropy):
    """Deterministic signing."""
    field = params.gf
    lambda_bytes = params.lambda_bytes

    pk_seed, encoded_solution, pkey_y = unpack_skey(params, skey)

    global_salt = entropy[:lambda_bytes]
    root_seed = entropy[lambda_bytes:2 * lambda_bytes]

    # ---- Phase 0: VOLE generation ----
    ggm_salt, vole_salt = compute_tweaked_salts(params, global_salt)
    ggm_tree = GGMTree(params, ggm_salt, root_seed)
    u, v, hash_com = prover_generate_midsize_grey_vole(
        params, ggm_tree, global_salt, vole_salt)
    u_flat, corr_u, v_trans = prover_midsize_to_fullsize(params, u, v)

    # The full salt is bound into hash_com (see prover_generate_midsize_grey_vole);
    # everything downstream (matrix M, hash_lines, hash_piop) inherits it.
    hash_aux = params.xof_new(
        HASH_AUX_PREFIX, hash_com, corr_u
    ).read(2 * lambda_bytes)

    # Partition VOLE pairs: [cchk | wit(inputs) | rnd(cz)]. The witness region
    # is padded to a byte boundary so cz stays byte-aligned.
    cchk_count = params.num_cchk_pairs
    inputs_padded = params.num_inputs_pairs_padded
    cz_count = params.num_cz_pairs

    inputs_byte = cchk_count // 8
    cz_byte = (cchk_count + inputs_padded) // 8

    u_inputs = u_flat[inputs_byte:inputs_byte + inputs_padded // 8]
    v_inputs = v_trans[cchk_count:cchk_count + params.num_inputs_pairs]
    u_cz = u_flat[cz_byte:cz_byte + cz_count // 8]
    v_cz = v_trans[cchk_count + inputs_padded:
                   cchk_count + inputs_padded + cz_count]

    cchk_matrix = generate_cchk_matrix(params, hash_aux)
    cchk_u, cchk_v = prover_vole_consistency_check(
        params, u_flat, v_trans, cchk_matrix)

    # ---- Phase 1: VOLE-to-PIOP conversion ----
    degree = params.degree

    cz_polys = prover_f2_to_flambda_deg1(params, u_cz, v_cz, degree - 1)
    cz_polys = prover_std_to_cst(
        params, degree - 1,
        prover_deg1_to_degd(params, degree - 1, cz_polys))

    circuit_in_pub, input_polynomials = prover_packed_secret_input(
        params, encoded_solution, u_inputs, v_inputs)

    cchk_u_bytes = bytes(cchk_u)
    cchk_v_bytes = b''.join(field.to_bytes(v) for v in cchk_v)

    hash_lines = params.xof_new(
        HASH_LINES_PREFIX, hash_aux,
        cchk_u_bytes, cchk_v_bytes, circuit_in_pub
    ).read(2 * lambda_bytes)

    # ---- Phase 2: PIOP protocol ----
    chall_xof = params.xof_new(hash_lines)

    chall_a = params.deserialize_field_elements(
        chall_xof.read(lambda_bytes * params.rsd_codim_limbs),
        params.rsd_codim_limbs)
    chall_u = params.deserialize_field_elements(
        chall_xof.read(lambda_bytes * params.rsd_w),
        params.rsd_w)

    chall_a_H, chall_a_y = rsd_public_key_times_challenge(
        params, chall_a, pk_seed, pkey_y)

    # Evaluate MUX circuit for each weight position
    result_poly = [chall_a_y] + [0] * degree
    mi = params.mux_inputs

    for block in range(params.rsd_w):
        input_start = block * mi
        input_end = input_start + mi
        h_start = block * params.npw
        h_end = h_start + params.npw

        mux_result = prover_mux_circuit(
            params,
            input_polynomials[input_start:input_end],
            chall_a_H[h_start:h_end],
            chall_u[block])
        result_poly = prover_xor_gate(params, result_poly, mux_result)

    # circuit_cz_pub = [alpha_1, alpha_2, ..., alpha_d]
    circuit_cz_pub = prover_check_zero_gate(
        params, degree, result_poly, cz_polys)

    # h_piop is hashed over all of alpha_1..alpha_d; only the serialization
    # into the signature drops alpha_1.
    cz_bytes = b''.join(field.to_bytes(c) for c in circuit_cz_pub)
    hash_piop = params.xof_new(
        HASH_PIOP_PREFIX, pk_seed, pkey_y, hash_lines,
        cz_bytes, message
    ).read(2 * lambda_bytes)

    # ---- Phase 3: Proof-of-work and tree opening ----
    # grind() returns the first counter whose grinding (w) condition holds; we
    # still reject a delta0 that is all zero or needs too many opened nodes and
    # resume grinding from the next counter.
    proofow = params.make_proofow(hash_piop)
    delta0 = bytearray(params.delta0_capacity)
    start = 0
    while True:
        proofow_counter, d0buf = proofow.grind(start)
        delta0[:len(d0buf)] = d0buf
        for i in range(len(d0buf), params.delta0_capacity):
            delta0[i] = 0

        if bitvec_is_zero(delta0, params.tau * params.kappa):
            start = proofow_counter + 1
            continue

        hidden_indices = decode_hidden_leaf_indices(
            params.kappa, params.tau, delta0)
        if estimate_topen(
                params.tau, params.kappa, params.target_topen,
                hidden_indices) <= params.target_topen:
            break
        start = proofow_counter + 1

    sibling_path, hidden_commitments = (
        ggm_tree.open_sibling_path(hidden_indices))

    # Serialize only (alpha_2, ..., alpha_d); the verifier reconstructs alpha_1.
    return pack_signature(
        params, global_salt, sibling_path, hidden_commitments,
        corr_u, cchk_u_bytes, circuit_in_pub,
        circuit_cz_pub[1:], hash_piop, proofow_counter)


def verify(params, pkey, message, signature):
    """Verify a signature. Returns True if valid."""
    field = params.gf
    lambda_bytes = params.lambda_bytes

    # Reject anything that is not exactly a serialized signature. Without this,
    # trailing bytes are ignored (append malleability) and short inputs raise
    # inside the deserializer instead of failing closed.
    if len(signature) != params.sig_bytes:
        return False

    pk_seed, pkey_y = unpack_pkey(params, pkey)

    (global_salt, sibling_path, hidden_commitments,
     corr_u, cchk_u, circuit_in_pub,
     circuit_cz_pub, hash_piop, proofow_counter
     ) = unpack_signature(params, signature)

    # Check trailing bits of circuit_in_pub are zero
    leftover_bits = params.num_inputs_pairs % 8
    if leftover_bits:
        high_mask = ((1 << (8 - leftover_bits)) - 1) << leftover_bits
        last_byte_index = (params.num_inputs_pairs + 7) // 8 - 1
        if circuit_in_pub[last_byte_index] & high_mask:
            return False

    # ---- Reconstruct delta0 and verify PoW ----
    d0buf = params.make_proofow(hash_piop).verify(proofow_counter)
    if d0buf is None:            # grinding (w) condition not met for this counter
        return False
    delta0 = bytearray(params.delta0_capacity)
    delta0[:len(d0buf)] = d0buf

    if bitvec_is_zero(delta0, params.tau * params.kappa):
        return False

    hidden_indices = decode_hidden_leaf_indices(
        params.kappa, params.tau, delta0)
    topen = estimate_topen(
        params.tau, params.kappa, params.target_topen, hidden_indices)
    if topen > params.target_topen:
        return False

    # Unused sibling path slots must be zero
    for i in range(topen, params.target_topen):
        if sibling_path[i] != b'\x00' * lambda_bytes:
            return False

    # ---- Compute deltas ----
    delta1 = delta1_from_delta0(params, delta0)
    delta2 = delta2_from_delta1(params, delta1)
    d1g = field.from_bytes(delta1)
    d2g = field.from_bytes(delta2)

    # ---- Rebuild verifier's VOLE ----
    ggm_salt, vole_salt = compute_tweaked_salts(params, global_salt)
    sibling_tree = GGMSiblingTree(
        params, ggm_salt, hidden_indices,
        [sibling_path[i] for i in range(topen)],
        hidden_commitments)

    corr_terms = [bytearray(params.L_total_bytes)]
    for i in range(params.tau - 1):
        corr_terms.append(
            bytearray(corr_u[i * params.L_total_bytes:(i + 1) * params.L_total_bytes]))

    q, verifier_hash_com = verifier_open_midsize_grey_vole(
        params, sibling_tree, corr_terms, delta1, global_salt, vole_salt)
    q_trans = verifier_midsize_to_fullsize(params, q)

    # The full salt is bound into hash_com (mirrors the signer); not here.
    verifier_hash_aux = params.xof_new(
        HASH_AUX_PREFIX, verifier_hash_com, corr_u
    ).read(2 * lambda_bytes)

    cchk_matrix = generate_cchk_matrix(params, verifier_hash_aux)
    verifier_cchk_v = verifier_vole_consistency_check(
        params, q_trans, cchk_u, cchk_matrix, delta1)

    verifier_cchk_v_bytes = b''.join(
        field.to_bytes(v) for v in verifier_cchk_v)
    verifier_hash_lines = params.xof_new(
        HASH_LINES_PREFIX, verifier_hash_aux,
        cchk_u, verifier_cchk_v_bytes, circuit_in_pub
    ).read(2 * lambda_bytes)

    # ---- Verify PIOP circuit ----
    # h_piop is checked only after reconstructing alpha_1 below, since alpha_1
    # depends on p_alpha (= result_q) computed here.
    degree = params.degree
    cchk_count = params.num_cchk_pairs
    inputs_padded = params.num_inputs_pairs_padded
    cz_count = params.num_cz_pairs

    # Partition: [cchk | wit(inputs) | rnd(cz)].
    q_inputs = q_trans[cchk_count:cchk_count + params.num_inputs_pairs]
    q_cz = q_trans[cchk_count + inputs_padded:
                   cchk_count + inputs_padded + cz_count]

    cz_value = verifier_f2_to_flambda_deg1(params, q_cz, degree - 1)
    cz_value = verifier_deg1_to_degd(
        params, degree - 1, cz_value, d1g)
    cz_value = verifier_std_to_cst(
        params, cz_value, field.power(d2g, degree - 1))

    q_inputs = [field.mul(q, d2g) for q in q_inputs]
    input_values = verifier_packed_secret_input(
        params, circuit_in_pub, q_inputs, d2g)

    chall_xof = params.xof_new(verifier_hash_lines)

    chall_a = params.deserialize_field_elements(
        chall_xof.read(lambda_bytes * params.rsd_codim_limbs),
        params.rsd_codim_limbs)
    chall_u = params.deserialize_field_elements(
        chall_xof.read(lambda_bytes * params.rsd_w),
        params.rsd_w)

    chall_a_H, chall_a_y = rsd_public_key_times_challenge(
        params, chall_a, pk_seed, pkey_y)

    # Evaluate MUX circuit for each weight position
    result_q = chall_a_y
    mi = params.mux_inputs

    for block in range(params.rsd_w):
        input_start = block * mi
        input_end = input_start + mi
        h_start = block * params.npw
        h_end = h_start + params.npw

        result_q ^= verifier_mux_circuit(
            params,
            input_values[input_start:input_end],
            chall_a_H[h_start:h_end],
            chall_u[block],
            d2g)

    # Reconstruct the omitted alpha_1 from p_alpha (carried by result_q and
    # cz_value through the check-zero relation) and the transmitted
    # alpha_2..alpha_d, then check h_piop over the full alpha_1..alpha_d.
    # Solving the check-zero relation E == 0 for the leading term gives
    #   alpha_1 = sum_j cz[j]*d2g^(j+1)  ^  cz_value  ^  result_q*d1g
    # with d1g = delta1 = d2g^-1. There is no separate check on a transmitted
    # alpha_1 any more; its binding comes from h_piop.
    alpha_1 = cz_value ^ field.mul(result_q, d1g)
    power = d2g
    for coeff in circuit_cz_pub:       # circuit_cz_pub = [alpha_2..alpha_d]
        alpha_1 ^= field.mul(coeff, power)
        power = field.mul(power, d2g)

    circuit_cz_pub_full = [alpha_1] + list(circuit_cz_pub)
    cz_bytes = b''.join(field.to_bytes(c) for c in circuit_cz_pub_full)
    verifier_hash_piop = params.xof_new(
        HASH_PIOP_PREFIX, pk_seed, pkey_y, verifier_hash_lines,
        cz_bytes, message
    ).read(2 * lambda_bytes)

    return verifier_hash_piop == hash_piop


if __name__ == '__main__':
    import sys
    import os

    for name, params in ALL_PARAMS.items():
        print(f"{name}: pk={params.pk_bytes} sk={params.sk_bytes}"
              f" sig={params.sig_bytes}")

    if '--test' in sys.argv:
        params = CAT1_SHORT
        skey, pkey = keygen(params, os.urandom(32))
        sig = sign(params, skey, b"test", os.urandom(32))
        print(f"verify: {verify(params, pkey, b'test', sig)}")
