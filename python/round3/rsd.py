"""
Regular Syndrome Decoding (RSD) instance generation for SDitH v2.

Generates the secret witness (solution vector), the public parity-check
matrix H (expanded from a seed), and the syndrome y = H * e.
Also handles unary encoding of the solution and the challenge
multiplication chall_a * H.

Variable naming follows the C reference implementation.
  sk_seed       secret key seed (spec: seed_sk)
  pk_seed       public key seed (spec: seed_pk)
  pkey_y        public syndrome y = Hx (C: pkey_y)
  npw           n/w, positions per RSD block (C: rsd_npw, spec: m)
  chall_a       batching challenge gamma for linear constraints
  chall_a_H     gamma^T * Phi(h_j) per column of H
  chall_a_y     gamma^T * Phi(y)
"""

import struct
from utils import bytes_xor_into


def _h_random_row(h_prg, params):
    """One random row of the public matrix H from the block-aligned matrix PRG.

    The PRG is read in whole cipher blocks so every row starts on a
    block boundary, then truncated to the low rsd_codim bits. Rows are
    contiguous in the PRG stream, matching the C matrix_rng which seeds
    each row at counter row_index * blocks_per_row. The cipher block is
    16 bytes for cat1 (AES-128) and 32 bytes for cat3/cat5 (full
    Rijndael-256), so the read aligns to that, not lambda.
    """
    block_bytes = 16 if params.lambda_ == 128 else 32
    n_blocks = (params.rsd_codim + block_bytes * 8 - 1) // (block_bytes * 8)
    row_bytes = n_blocks * block_bytes
    row = bytearray(h_prg.get_bytes(row_bytes)[:params.rsd_codim_bytes])
    row[-1] &= params.rsd_codim_byte_mask
    return row


def rsd_generate_instance(params, sk_seed, pk_seed):
    """Generate an RSD instance from key seeds.

    Returns (solution, pkey_y) where solution is a list of
    w position indices and pkey_y is the syndrome bytes.
    """
    prg = params.new_prg(sk_seed)
    npw = params.npw

    # Rejection sampling threshold to avoid modular bias
    max_unbiased = 0xFFFFFFFF - (0xFFFFFFFF % npw)

    solution = []
    for _ in range(params.rsd_w):
        while True:
            candidate = struct.unpack('<I', prg.get_bytes(4))[0]
            if candidate < max_unbiased:
                break
        solution.append(candidate % npw)

    # Expand H from public seed (random part only), one block-aligned row at a
    # time (see _h_random_row).
    h_prg = params.new_prg(pk_seed)
    num_random_rows = params.rsd_n - params.rsd_codim
    h_rows = [_h_random_row(h_prg, params) for _ in range(num_random_rows)]

    # Compute syndrome y = H * e
    syndrome = bytearray(params.rsd_codim_bytes)
    for block_index in range(params.rsd_w):
        absolute_pos = block_index * npw + solution[block_index]
        if absolute_pos < params.rsd_codim:
            syndrome[absolute_pos // 8] ^= 1 << (absolute_pos % 8)
        else:
            bytes_xor_into(syndrome, h_rows[absolute_pos - params.rsd_codim])

    return solution, bytes(syndrome)


def rsd_encode_solution(params, solution):
    """Unary-encode the solution for MUX circuit input.

    Each position in each block is decomposed into mixed-radix digits
    (one per MUX depth level), then encoded as (arity-1) unary bits.
    """
    total_bits = params.rsd_w * params.mux_inputs
    encoded = bytearray((total_bits + 7) // 8)
    bit_position = 0

    for block_index in range(params.rsd_w):
        remaining = solution[block_index]
        for level in range(params.mux_depth):
            arity = params.mux_arities[level]
            digit = remaining % arity
            remaining //= arity
            if digit != 0:
                target_bit = bit_position + digit - 1
                encoded[target_bit // 8] |= 1 << (target_bit % 8)
            bit_position += arity - 1

    return bytes(encoded)


def rsd_public_key_times_challenge(params, chall_a, pk_seed,
                                   pkey_y):
    """Compute chall_a * H and chall_a * y.

    Returns (chall_a_H, chall_a_y) where chall_a_H is a list
    of GF elements (one per column of H) and chall_a_y is a single
    GF element.
    """
    field = params.gf
    lambda_bytes = params.lambda_bytes

    # Pad syndrome into full-limb representation
    syndrome_padded = bytearray(params.rsd_codim_limbs * lambda_bytes)
    syndrome_padded[:params.rsd_codim_bytes] = (
        pkey_y[:params.rsd_codim_bytes])
    if params.rsd_codim_bytes > 0:
        syndrome_padded[params.rsd_codim_bytes - 1] &= params.rsd_codim_byte_mask

    # chall_a * y
    syndrome_limbs = params.deserialize_field_elements(
        syndrome_padded, params.rsd_codim_limbs)
    chall_a_y = 0
    for i in range(params.rsd_codim_limbs):
        chall_a_y ^= field.mul(syndrome_limbs[i], chall_a[i])

    # Identity block of H: chall_a * I_k
    chall_a_H = []
    remaining_codim = params.rsd_codim
    for limb_index in range(params.rsd_codim_limbs):
        block_size = min(params.lambda_, remaining_codim)
        value = chall_a[limb_index]
        chall_a_H.append(value)
        for _ in range(1, block_size):
            value = field.mul(value, 2)
            chall_a_H.append(value)
        remaining_codim -= block_size

    # Random rows of H (block-aligned matrix PRG, see rsd_generate_instance)
    h_prg = params.new_prg(pk_seed)
    num_random_rows = params.rsd_n - params.rsd_codim
    for _ in range(num_random_rows):
        h_row = _h_random_row(h_prg, params)
        h_row_padded = bytearray(params.rsd_codim_limbs * lambda_bytes)
        h_row_padded[:params.rsd_codim_bytes] = h_row
        dot_product = 0
        for j in range(params.rsd_codim_limbs):
            dot_product ^= field.mul(
                field.from_bytes(
                    h_row_padded[j * lambda_bytes:(j + 1) * lambda_bytes]),
                chall_a[j])
        chall_a_H.append(dot_product)

    return chall_a_H, chall_a_y
