#ifndef PARAMETERS_H
#define PARAMETERS_H

#define PARAM_SECURITY 128
#define PARAM_LABEL "sdith-251-L1-threshold"

// SD Parameters
#define PARAM_FIELD_SIZE 251
#define PARAM_CODE_LENGTH 230
#define PARAM_CODE_DIMENSION 126
#define PARAM_CODE_WEIGHT 79

// MPC Parameters
#define PARAM_NB_EVALS_PER_POLY 7
#define PARAM_EXT_DEGREE 4

// MPCitH Parameters
#define PARAM_NB_PARTIES PARAM_FIELD_SIZE
#define PARAM_LOG_NB_PARTIES 8
#define PARAM_NB_EXECUTIONS 6
#define PARAM_NB_REVEALED 3
#define PARAM_TREE_NB_MAX_OPEN_LEAVES 19

// Signature Parameters
#define PARAM_SEED_SIZE (128/8)
#define PARAM_SALT_SIZE (256/8)
#define PARAM_DIGEST_SIZE (256/8)


// Hash Domain Separation
#define HASH_PREFIX_COMMITMENT 0
#define HASH_PREFIX_FIRST_CHALLENGE 1
#define HASH_PREFIX_SECOND_CHALLENGE 2
#define HASH_PREFIX_MERKLE_TREE 3

// Misc
#ifndef PARAM_SPLITTING_FACTOR
#define PARAM_SPLITTING_FACTOR 1
#endif
#ifndef PARAM_NB_EVALS_PER_POLY
#define PARAM_NB_EVALS_PER_POLY 1
#endif

#define PARAM_CHUNK_LENGTH (PARAM_CODE_LENGTH/PARAM_SPLITTING_FACTOR)
#define PARAM_CHUNK_WEIGHT (PARAM_CODE_WEIGHT/PARAM_SPLITTING_FACTOR)

#define PARAM_SYNDROME_LENGTH (PARAM_CODE_LENGTH-PARAM_CODE_DIMENSION)
#define PARAM_SYNDROME_LENGTH_CEIL32 (((PARAM_SYNDROME_LENGTH+31)>>5)<<5)
#define PARAM_CODEWORD_LENGTH (PARAM_CODE_LENGTH)
#define PARAM_CODEWORD_LENGTH_CEIL32 (((PARAM_CODEWORD_LENGTH+31)>>5)<<5)
#define PARAM_PLAINTEXT_LENGTH (PARAM_CODE_DIMENSION)
#define PARAM_PCMATRIX_BYTESIZE (PARAM_CODE_DIMENSION*PARAM_SYNDROME_LENGTH_CEIL32)

#define PARAM_ALL_EVALS_BYTESIZE_CEIL16  (((PARAM_EXT_DEGREE*PARAM_NB_EVALS_PER_POLY+15)>>4)<<4)

#endif /* PARAMETERS_H */
