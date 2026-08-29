set(AES_SRCS_GENERIC
        rijndael256.c
        rijndael256.h
        aes_ansi_littleendian_ref.c
        aes128_ctrle.h
        aes128_ctrle_special_ref.c
        rijndael256_ctrle.h
        rijndael256_ctrle_special_ref.c
)
set(AES_SRCS_AVX2
        rijndael256_avx.c
        rijndael256_avx.h
        aes128_ctrle_special_avx2.c
        rijndael256_ctrle_special_avx2.c
)
set_source_files_properties(${AES_SRCS_AVX2} PROPERTIES COMPILE_FLAGS "-mpclmul -msse2 -mavx2 -maes")


# Compile the AVX2/AES-NI sources only on x86 Linux, and only when the user did
# not ask for a reference-only build. With USE_REFERENCE_CODE_ONLY the aes
# library is the portable C code alone, so the "reference only" build has no
# AES-NI code at all (matching the NIST Reference_Implementation package).
if (X86_LINUX AND NOT USE_REFERENCE_CODE_ONLY)
    add_library(aes STATIC ${AES_SRCS_GENERIC} ${AES_SRCS_AVX2})
    target_include_directories(aes PUBLIC .)
    target_link_libraries(aes)
else ()
    add_library(aes STATIC ${AES_SRCS_GENERIC})
    target_include_directories(aes PUBLIC .)
    target_link_libraries(aes)
endif ()
