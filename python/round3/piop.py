"""
PIOP circuit gates for SDitH v2.

Polynomial gates for both prover (operating on polynomial coefficient
lists) and verifier (operating on point evaluations at delta2).

Gates: XOR, MUL, check-unitary, q-ary MUX, packed secret input, check-zero.

Variable naming follows the C reference implementation.
  FLAMBDA_2P32      2^32, used to separate unitary challenges (C: FLAMBDA_2P32)
  chall_a_H_slice   γ^T * Φ(h_j) for one weight block
  chall_unitary     γ' batching coefficient for unitary checks
  npw               n/w, positions per RSD block (C: rsd_npw)
"""

FLAMBDA_2P32 = 1 << 32


# ---- Prover gates (polynomials over GF(2^lambda)) ----

def prover_xor_gate(params, poly_a, poly_b):
    """XOR (add) two polynomials coefficient-wise."""
    max_len = max(len(poly_a), len(poly_b))
    result = [0] * max_len
    for i in range(len(poly_a)):
        result[i] ^= poly_a[i]
    for i in range(len(poly_b)):
        result[i] ^= poly_b[i]
    return result


def prover_mul_gate(params, poly_a, poly_b):
    """Multiply two polynomials over GF(2^lambda)."""
    field = params.gf
    deg_a = len(poly_a) - 1
    deg_b = len(poly_b) - 1
    result = [0] * (deg_a + deg_b + 1)
    for i in range(deg_a + 1):
        for j in range(deg_b + 1):
            result[i + j] ^= field.mul(poly_a[i], poly_b[j])
    return result


def prover_echelon_pow2_gate(params, stride, degree1_polys):
    """Apply echelon_pow2 to the constant and linear coefficients separately."""
    field = params.gf
    constants = [poly[0] for poly in degree1_polys]
    linears = [poly[1] for poly in degree1_polys]
    return [field.echelon_pow2(stride, constants),
            field.echelon_pow2(stride, linears)]


def prover_check_unitary_gate(params, arity, control_polys, coefficient):
    """Check-unitary constraint: verifies MUX control bits sum to at most 1."""
    num_controls = arity - 1
    term1 = prover_echelon_pow2_gate(params, 1, control_polys[:num_controls])
    term2 = prover_echelon_pow2_gate(params, num_controls, control_polys[:num_controls - 1])
    product = prover_mul_gate(params, term1, term2)
    term3 = prover_echelon_pow2_gate(params, num_controls + 1, control_polys[:num_controls - 1])
    combined = prover_xor_gate(params, product, term3)
    return prover_mul_gate(params, combined, [coefficient])


def prover_qary_mux_gate(params, real_arity, in_degree,
                          control_polys, input_polys):
    """q-ary MUX: result = input[0] + sum(control[i-1] * (input[i] - input[0]))."""
    field = params.gf
    num_coeffs = in_degree + 1
    result = list(input_polys[0]) + [0]

    for i in range(1, real_arity):
        difference = [
            (input_polys[i][j] if j < len(input_polys[i]) else 0)
            ^ (input_polys[0][j] if j < len(input_polys[0]) else 0)
            for j in range(num_coeffs)]

        control_constant = control_polys[i - 1][0]
        control_linear = control_polys[i - 1][1]

        for j in range(num_coeffs):
            if control_constant & 1:
                result[j] ^= difference[j]
            result[j + 1] ^= field.mul(control_linear, difference[j])

    return result


def prover_packed_secret_input(params, secret_bits, u_bytes, v_elements):
    """Commit secret bits as degree-1 polynomial shares.

    Returns (public_bits, input_polynomials).
    """
    from utils import bytes_xor, get_bit
    num_inputs = params.num_inputs_pairs
    pub_bytes = (num_inputs + 7) // 8

    public_bits = bytearray(bytes_xor(
        u_bytes[:pub_bytes], secret_bits[:pub_bytes]))
    leftover = num_inputs % 8
    if leftover:
        public_bits[pub_bytes - 1] &= (1 << leftover) - 1

    input_polynomials = [
        [get_bit(secret_bits, i), v_elements[i]]
        for i in range(num_inputs)]

    return public_bits, input_polynomials


def prover_check_zero_gate(params, degree, result_poly, random_poly):
    """Extract the check-zero public values from the prover's result polynomial."""
    return [random_poly[i] ^ result_poly[i + 1]
            for i in range(degree)]


def prover_mux_circuit(params, input_polys, chall_a_H_slice,
                       chall_unitary):
    """Full MUX tree evaluation (prover side).

    Walks the MUX tree from leaves to root, applying q-ary MUX gates
    at each depth level.
    """
    field = params.gf
    depth = params.mux_depth
    arities = params.mux_arities
    num_current = params.npw

    result_poly = [0] * (depth + 1)
    control_pos = 0
    current_inputs = [[chall_a_H_slice[j]]
                      if j < len(chall_a_H_slice) else [0]
                      for j in range(num_current)]

    unitary_challenge = 0
    unitary_power = 0

    for level in range(depth):
        arity = arities[level]
        controls = input_polys[control_pos:control_pos + arity - 1]

        if arity > 2:
            if unitary_power == 0:
                unitary_challenge = chall_unitary
            else:
                unitary_challenge = field.mul(
                    unitary_challenge, FLAMBDA_2P32)
            unitary_power += 32
            result_poly = prover_xor_gate(
                params, result_poly,
                prover_check_unitary_gate(
                    params, arity, controls, unitary_challenge))

        num_outputs = (num_current + arity - 1) // arity
        next_inputs = []
        for j in range(num_outputs):
            start = j * arity
            actual_arity = min(arity, num_current - start)
            next_inputs.append(prover_qary_mux_gate(
                params, actual_arity, level, controls,
                current_inputs[start:start + actual_arity]))

        if level == depth - 1:
            result_poly = prover_xor_gate(
                params, result_poly, next_inputs[0])

        control_pos += arity - 1
        num_current = num_outputs
        current_inputs = next_inputs

    return result_poly


# ---- Verifier gates (evaluations at delta2) ----

def verifier_check_unitary_gate(params, arity, control_values,
                                coefficient, delta2):
    """Verifier's check-unitary at evaluation point delta2."""
    field = params.gf
    num_controls = arity - 1
    term1 = field.echelon_pow2(1, control_values[:num_controls])
    term2 = field.echelon_pow2(num_controls, control_values[:num_controls - 1])
    product = field.mul(term1, term2)
    term3 = field.echelon_pow2(num_controls + 1, control_values[:num_controls - 1])
    return field.mul(product ^ term3, coefficient)


def verifier_qary_mux_gate(params, real_arity, in_degree,
                            control_values, input_values, delta2):
    """Verifier's q-ary MUX at evaluation point delta2."""
    field = params.gf
    result = input_values[0]
    for i in range(1, real_arity):
        result ^= field.mul(
            control_values[i - 1],
            input_values[i] ^ input_values[0])
    return result


def verifier_packed_secret_input(params, public_bits, q_values, delta2):
    """Reconstruct verifier's input polynomial evaluations from public bits."""
    from utils import get_bit
    return [q_values[i] ^ get_bit(public_bits, i)
            for i in range(params.num_inputs_pairs)]


def verifier_check_zero_gate(params, degree, check_zero_pub,
                              result_q, random_q, delta2):
    """Verify the check-zero gate at evaluation point delta2."""
    field = params.gf
    evaluated = check_zero_pub[degree - 1]
    for i in range(degree - 2, -1, -1):
        evaluated = field.mul(evaluated, delta2) ^ check_zero_pub[i]
    evaluated = field.mul(evaluated ^ random_q, delta2) ^ result_q
    return evaluated == 0


def verifier_mux_circuit(params, input_values, chall_a_H_slice,
                         chall_unitary, delta2):
    """Full MUX tree evaluation (verifier side)."""
    field = params.gf
    depth = params.mux_depth
    arities = params.mux_arities
    num_current = params.npw

    result_q = 0
    control_pos = 0
    current_inputs = (list(chall_a_H_slice)
                      + [0] * max(0, num_current - len(chall_a_H_slice)))

    unitary_challenge = 0
    unitary_power = 0

    for level in range(depth):
        arity = arities[level]
        controls = input_values[control_pos:control_pos + arity - 1]

        if arity > 2:
            if unitary_power == 0:
                unitary_challenge = chall_unitary
            else:
                unitary_challenge = field.mul(
                    unitary_challenge, FLAMBDA_2P32)
            unitary_power += 32
            result_q ^= verifier_check_unitary_gate(
                params, arity, controls,
                unitary_challenge, delta2)

        num_outputs = (num_current + arity - 1) // arity
        next_inputs = []
        for j in range(num_outputs):
            start = j * arity
            actual_arity = min(arity, num_current - start)
            next_inputs.append(verifier_qary_mux_gate(
                params, actual_arity, level, controls,
                current_inputs[start:start + actual_arity],
                delta2))

        if level == depth - 1:
            result_q ^= next_inputs[0]

        control_pos += arity - 1
        num_current = num_outputs
        current_inputs = next_inputs

    return result_q
