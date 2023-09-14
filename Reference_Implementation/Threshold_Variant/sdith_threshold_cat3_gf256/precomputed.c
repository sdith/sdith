#include "parameters.h"
#include "precomputed.h"

// Coefficient of polynomial with all factors
const uint8_t f_poly[177] = {0, 214, 24, 229, 158, 219, 70, 124, 154, 224, 238, 50, 248, 42, 5, 0, 233, 89, 197, 228, 238, 252, 108, 0, 150, 244, 171, 0, 200, 0, 0, 0, 205, 217, 166, 13, 168, 157, 210, 0, 160, 246, 205, 0, 99, 0, 0, 0, 107, 25, 207, 0, 5, 0, 0, 0, 41, 0, 0, 0, 0, 0, 0, 0, 155, 58, 128, 18, 134, 247, 57, 0, 229, 180, 207, 0, 143, 0, 0, 0, 226, 89, 105, 0, 233, 0, 0, 0, 34, 0, 0, 0, 0, 0, 0, 0, 232, 8, 141, 0, 168, 0, 0, 0, 214, 0, 0, 0, 0, 0, 0, 0, 251, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 147, 27, 181, 135, 192, 254, 0, 222, 174, 158, 0, 11, 0, 0, 0, 116, 172, 133, 0, 180, 0, 0, 0, 156, 0, 0, 0, 0, 0, 0, 0, 20, 119, 80, 0, 129, 0, 0, 0, 167, 0, 0, 0, 0, 0, 0, 0, 1};

// Leading Coefficients for Lagrangian Polynomials
const uint8_t leading_coefficients_of_lj_for_S[176] = {226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 226, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 243, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 242, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 163, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 173, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 158, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 78, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208, 208};