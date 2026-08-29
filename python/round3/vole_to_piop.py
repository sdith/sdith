"""
VOLE-to-PIOP conversions for SDitH v2.

Converts between F2 VOLE pairs and F_lambda polynomial representations,
handles degree elevation, standard-to-constant coefficient conversion,
and the delta0 -> delta1 -> delta2 chain.
"""

from utils import extract_bits, xor_bits_into


def prover_f2_to_flambda_deg1(params, u_bytes, v_elements, num_pairs):
    """Convert F2 VOLE pairs to degree-1 polynomials over F_lambda.

    Each pair becomes [constant_coeff, linear_coeff].
    """
    field = params.gf
    lambda_bytes = params.lambda_bytes
    lambda_bits = params.lambda_

    result = []
    for i in range(num_pairs):
        constant = field.sum_pow2(
            v_elements[i * lambda_bits:(i + 1) * lambda_bits])
        linear = field.from_bytes(
            u_bytes[i * lambda_bytes:(i + 1) * lambda_bytes])
        result.append([constant, linear])
    return result


def verifier_f2_to_flambda_deg1(params, q_elements, num_pairs):
    """Convert verifier's F2 VOLE evaluations to F_lambda scalars."""
    field = params.gf
    lambda_bits = params.lambda_
    return [field.sum_pow2(q_elements[i * lambda_bits:(i + 1) * lambda_bits])
            for i in range(num_pairs)]


def prover_deg1_to_degd(params, out_degree, degree1_polys):
    """Combine out_degree degree-1 polynomials into one degree-d polynomial."""
    coefficients = [degree1_polys[0][0]]
    for i in range(1, out_degree):
        coefficients.append(
            degree1_polys[i][0] ^ degree1_polys[i - 1][1])
    coefficients.append(degree1_polys[out_degree - 1][1])
    return coefficients


def verifier_deg1_to_degd(params, out_degree, q_values, delta):
    """Evaluate the combined polynomial at delta (Horner's method)."""
    result = q_values[out_degree - 1]
    for i in range(out_degree - 2, -1, -1):
        result = params.gf.mul(result, delta) ^ q_values[i]
    return result


def prover_std_to_cst(params, degree, polynomial):
    """Convert standard form to constant-coefficient form (reverse coefficients)."""
    return list(reversed(polynomial))


def verifier_std_to_cst(params, q_value, delta_power_d):
    """Verifier's std-to-cst conversion: multiply by delta^d."""
    return params.gf.mul(q_value, delta_power_d)


def delta1_from_delta0(params, delta0):
    """Convert delta0 (position indices) to delta1 (Grey-coded).

    Each kappa-bit block is Grey-coded: pos -> pos ^ (pos >> 1).
    """
    delta1 = bytearray(params.lambda_bytes)
    for i in range(params.tau):
        position = extract_bits(
            params.kappa, i * params.kappa, delta0)
        grey_coded = position ^ (position >> 1)
        xor_bits_into(
            params.kappa, i * params.kappa, delta1, grey_coded)
    return bytes(delta1)


def delta2_from_delta1(params, delta1):
    """Compute delta2 as the field inverse of delta1."""
    field = params.gf
    return field.to_bytes(field.inv(field.from_bytes(delta1)))
