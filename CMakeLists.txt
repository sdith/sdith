cmake_minimum_required(VERSION 3.10)
project(aq_vole_impl)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Default build type: Release" FORCE)
endif()

# the main library is in C and low-level crypto contain assembly files
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -Wall -Werror")
set(CMAKE_C_FLAGS_RELEASE "-O3 -g3 -Wall -Werror -DNDEBUG")
enable_language(ASM)

# some test files are in C++ (only needed if ENABLE_TESTING is set)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g3 -Wall -Werror")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -g3 -Wall -Werror -DNDEBUG")

set(BUILD_TESTING ON CACHE BOOL "Build Tests")
set(BUILD_KATS ON CACHE BOOL "Build KATs")
# USE_REFERENCE_CODE_ONLY selects the portable C reference *algorithm*: it drops the
# hand-written AVX2/AES-NI backend (vole, aes and sha3 all build the C path only).
# It does NOT change the instruction set the compiler emits: with a toolchain whose
# default -march enables AVX (e.g. x86-64-v3), -O3 can still auto-vectorize the C to
# AVX. For a binary that runs on any x86-64, also pass -DCMAKE_C_FLAGS=-march=x86-64.
set(USE_REFERENCE_CODE_ONLY OFF CACHE BOOL "Build the reference C code only (no AVX2/AES-NI backend; not constant time)")

# detect architecture
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86_LINUX)|(amd64)|(AMD64)")
    set(X86_LINUX ON)
    set(AARCH64 OFF)
else ()
    set(X86_LINUX OFF)
endif ()
if (CMAKE_SYSTEM_PROCESSOR MATCHES "(aarch64)|(arm64)")
    set(AARCH64 ON)
endif ()

if (CMAKE_SYSTEM_NAME MATCHES "(Windows)|(MSYS)")
    set(WIN32 ON)
endif ()
if (WIN32)
    #overrides for win32
    set(X86_LINUX OFF)
    set(AARCH64 OFF)
    set(X86_WIN32 ON)
else()
    set(X86_WIN32 OFF)
    set(WIN32 OFF)
endif (WIN32)

message(STATUS "--> WIN32: ${WIN32}")
message(STATUS "--> X86_WIN32: ${X86_WIN32}")
message(STATUS "--> X86_LINUX: ${X86_LINUX}")
message(STATUS "--> AARCH64: ${AARCH64}")

message(STATUS "BUILD_TESTING: ${BUILD_TESTING}")
message(STATUS "BUILD_KATS: ${BUILD_KATS}")
message(STATUS "USE_REFERENCE_CODE_ONLY: ${USE_REFERENCE_CODE_ONLY}")

# The 12 parameter sets, in the order the submission lists them.  Both the KAT
# generators and the per-set test executables iterate over this list.
set(
        PARAMS_CATEGORIES
        CAT1_SHORT
        CAT1_FAST
        CAT1_SHORT_CIPHERPOW
        CAT1_FAST_CIPHERPOW
        CAT3_SHORT
        CAT3_FAST
        CAT3_SHORT_CIPHERPOW
        CAT3_FAST_CIPHERPOW
        CAT5_SHORT
        CAT5_FAST
        CAT5_SHORT_CIPHERPOW
        CAT5_FAST_CIPHERPOW
)

add_subdirectory(lib/sha3)
add_subdirectory(lib/aes)

if (BUILD_KATS)
    set(kats_incs ${CMAKE_SOURCE_DIR}/src)
    set(kats_libs)
    # searching for libcrypto (for KATs only)
    find_path(crypto_inc NAMES openssl/conf.h)
    find_library(crypto NAMES crypto)
    if (crypto_inc AND crypto)
        message(STATUS "Found libcrypto: I=${crypto_inc} L=${crypto}")
        set(kats_incs ${kats_incs} ${crypto_inc})
        set(kats_libs ${kats_libs} ${crypto})
    else ()
        message(FATAL_ERROR "Libcrypto not found (required for NIST's KATs): I=${crypto_inc} L=${crypto}")
    endif ()
endif (BUILD_KATS)


if (BUILD_TESTING)
set(test_incs)
set(gtest_libs)
set(benchmark_libs)
# searching for libgtest
find_path(gtest_inc NAMES gtest/gtest.h)
find_library(gtest NAMES gtest)
find_library(gtest_main REQUIRED NAMES gtest_main)
if (gtest_inc AND gtest AND gtest_main)
    message(STATUS "Found gtest: I=${gtest_inc} L=${gtest},${gtest_main}")
    set(test_incs ${test_incs} ${gtest_inc})
    set(gtest_libs ${gtest_libs} ${gtest} ${gtest_main} pthread)
else()
    message(FATAL_ERROR "Libgtest not found (required if ENABLE_TESTING is on): I=${gtest_inc} L=${gtest},${gtest_main}")
endif()
# searching for libbenchmark
find_path(benchmark_inc NAMES benchmark/benchmark.h)
find_library(benchmark NAMES benchmark)
if (benchmark_inc AND benchmark)
    message(STATUS "Found benchmark: I=${benchmark_inc} L=${benchmark}")
    set(test_incs ${test_incs} ${benchmark_inc})
    set(benchmark_libs ${benchmark_libs} ${benchmark} pthread)
else()
    message(FATAL_ERROR "Libbenchmark not found (required if ENABLE_TESTING is on): I=${benchmark_inc} L=${benchmark}")
endif()
endif (BUILD_TESTING)


set(TESTLIB_SRCS
        test/testlib/testlib.cpp
        test/testlib/testlib.h
        test/testlib/bit_matrix_layout.cpp
        test/testlib/bit_matrix_layout.h
        test/testlib/vole_testlib.cpp
        test/testlib/vole_testlib.h
        test/testlib/ggm_testlib.cpp
)

set(VOLE_SRCS
        src/commons.c
        src/vole_private.h
        src/sdith_prng.h
        src/sdith_prng.c
        src/gf256.c
        src/gf192.c
        src/matrix_vector_products_f2.c
        src/matrix_transpose_f2.c
        src/ggm.c
        src/ggm.h
        src/vole_expansion.c
        src/piop_circuit.c
        src/gf128.c
        src/rsd.c
        src/ct_utils.c
        src/sdith_ct_utils.h
        src/sdith_prng_private.h
        src/commons.h
        src/sdith_signature.c
        src/sdith_signature_parameters.c
        src/vole_to_piop.c
        src/vole_parameters.c
        src/sdith_arithmetic.h
        src/sdith_algebra.h
        src/sdith_vole_to_piop.h
        src/sdith_rsd.h
        src/sdith_piop_circuits.h
        src/vole_parameters.h
        src/vole_generation.h
        src/sdith_signature.h
)
set(VOLE_SRCS_AVX2
        src/ct_utils_avx2.c
        src/gf128_avx2.c
        src/gf192_avx2.c
        src/gf256_avx2.c
        src/matrix_vector_products_f2_avx2.c
        src/sdith_prng_avx2.c
        src/vole_parameters_avx2.c
)
# -maes: sdith_prng_avx2.c fuses aes128 row generation with the gf128 reduction,
# so it needs the AES-NI intrinsics as well (same set as lib/aes AVX2 sources).
set_source_files_properties(${VOLE_SRCS_AVX2} PROPERTIES COMPILE_FLAGS "-mpclmul -msse2 -mavx2 -maes")

# Add the AVX2 sources only on x86 Linux, and only when the user did not ask
# for a reference-only build. USE_REFERENCE_CODE_ONLY builds the portable C
# path alone and defines ONLY_REF_IMPLEMENTATION so the runtime dispatch also
# selects the _ref path instead of AVX2.
if (X86_LINUX AND NOT USE_REFERENCE_CODE_ONLY)
    add_library(vole STATIC ${VOLE_SRCS} ${VOLE_SRCS_AVX2})
else ()
    add_library(vole STATIC ${VOLE_SRCS})
endif ()
if (USE_REFERENCE_CODE_ONLY)
    target_compile_definitions(vole PRIVATE ONLY_REF_IMPLEMENTATION)
endif ()
target_link_libraries(vole sha3 aes m)


if (BUILD_TESTING)
add_library(vole_testlib STATIC ${TESTLIB_SRCS})
target_include_directories(vole_testlib PUBLIC src)

add_executable(bench test/bench.cpp)
target_link_libraries(bench vole_testlib vole ${benchmark_libs})
target_include_directories(bench PRIVATE ${test_incs})

add_executable(mini_kat test/mini_kat.cpp)
target_link_libraries(mini_kat vole_testlib vole)
target_include_directories(mini_kat PRIVATE ${test_incs})

add_executable(bench_gf256 test/bench_gf256.cpp)
target_link_libraries(bench_gf256 vole_testlib vole ${benchmark_libs})
target_include_directories(bench_gf256 PRIVATE ${test_incs})

add_executable(bench_gf192 test/bench_gf192.cpp)
target_link_libraries(bench_gf192 vole_testlib vole ${benchmark_libs})
target_include_directories(bench_gf192 PRIVATE ${test_incs})

add_executable(bench_mvpf2 test/bench_mvpf2.cpp)
target_link_libraries(bench_mvpf2 vole_testlib vole ${benchmark_libs})
target_include_directories(bench_mvpf2 PRIVATE ${test_incs})

add_executable(bench_aes test/bench_aes.cpp)
target_link_libraries(bench_aes vole_testlib vole ${benchmark_libs})
target_include_directories(bench_aes PRIVATE ${test_incs})

add_executable(bench_leaf_seed_4x test/bench_leaf_seed_4x.cpp)
target_link_libraries(bench_leaf_seed_4x vole_testlib vole ${benchmark_libs})
target_include_directories(bench_leaf_seed_4x PRIVATE ${test_incs})

add_executable(bench_sdith test/bench_sdith.c)
target_link_libraries(bench_sdith vole)
target_compile_definitions(bench_sdith PRIVATE CAT1B)
target_include_directories(bench_sdith PRIVATE ${test_incs} src)

foreach (category ${PARAMS_CATEGORIES})
    add_executable(bench_signature_${category} test/bench_signature.cpp)
    target_link_libraries(bench_signature_${category} vole_testlib vole)
    target_compile_definitions(bench_signature_${category} PRIVATE TARGET_CATEGORY=${category})
    target_include_directories(bench_signature_${category} PRIVATE ${test_incs} src)
    add_test(bench_signature_${category} bench_signature_${category})
endforeach()

add_executable(bench_pow test/bench_pow.cpp)
target_link_libraries(bench_pow vole_testlib vole ${benchmark_libs})
target_include_directories(bench_pow PRIVATE ${test_incs})

add_executable(pow_histogram test/pow_histograms.cpp)
target_link_libraries(pow_histogram vole_testlib vole)
target_include_directories(pow_histogram PRIVATE ${test_incs})

add_executable(kats_properties test/kats_properties.cpp)
target_link_libraries(kats_properties vole_testlib vole)
target_include_directories(kats_properties PRIVATE ${test_incs})

add_executable(unittest
	test/unittest.cpp
        test/commons_test.cpp
        test/matrix_transpose_test.cpp
        test/gf256_test.cpp
        test/gf192_test.cpp
        test/gf128_test.cpp
        test/ggm_test.cpp
        test/ggm_helpers_test.cpp
        test/parameters_test.cpp
        test/mvpf2_test.cpp
        test/midsize_vole_test.cpp
        test/vole_conversions_test.cpp
        test/vole_stages_test.cpp
        test/vole_circuits_test.cpp
        test/piop_circuit_test.cpp
        test/ct_utils_test.cpp
        test/rsd_test.cpp
        test/rsd_sampler_dist_test.cpp
        test/signature_test.cpp
        test/prng_test.cpp
        test/aes_lowlevel_test.cpp
        test/leaf_seed_4x_test.cpp
        test/algebra_test.cpp)

target_link_libraries(unittest vole_testlib vole ${gtest_libs})
target_include_directories(unittest PRIVATE ${test_incs})

enable_testing()
add_test(unittest unittest)
add_test(mini_kat mini_kat)

# --- B4: stress soak, one executable + ctest per parameter set ---
# STRESS_ITERS defaults to a quick smoke; bump -DSTRESS_ITERS for a real soak.
set(STRESS_ITERS 3 CACHE STRING "Iterations per stress ctest run")
foreach(sset CAT1_SHORT CAT1B CAT3A CAT3B CAT5A CAT5B)
    add_executable(stress_${sset} test/stress_test_single.c)
    target_link_libraries(stress_${sset} vole)
    target_include_directories(stress_${sset} PRIVATE src)
    if(NOT sset STREQUAL "CAT1_SHORT")  # CAT1_SHORT is the #else default (no define)
        target_compile_definitions(stress_${sset} PRIVATE ${sset})
    endif()
    add_test(NAME stress_${sset} COMMAND stress_${sset} ${STRESS_ITERS})
endforeach()

# --- B6: constant-time test, one executable + ctest per parameter set. ---
# Timing mode runs everywhere; valgrind/ctgrind taint-tracking is opt-in (-DWITH_VALGRIND=ON).
option(WITH_VALGRIND "Build the constant-time test with valgrind/memcheck taint tracking" OFF)
if(WITH_VALGRIND)
    find_program(VALGRIND_EXE valgrind)
endif()
foreach(cset CAT1_SHORT CAT1B CAT3A CAT3B CAT5A CAT5B)
    add_executable(test_ct_${cset} test/test_constant_time.c)
    target_link_libraries(test_ct_${cset} vole m)
    target_include_directories(test_ct_${cset} PRIVATE src)
    if(NOT cset STREQUAL "CAT1_SHORT")  # CAT1_SHORT is the #else default (no define)
        target_compile_definitions(test_ct_${cset} PRIVATE ${cset})
    endif()
    add_test(NAME ct_timing_${cset} COMMAND test_ct_${cset} timing 20)
    if(WITH_VALGRIND)
        target_compile_definitions(test_ct_${cset} PRIVATE WITH_VALGRIND)
        if(VALGRIND_EXE)
            add_test(NAME ct_valgrind_${cset}
                     COMMAND ${VALGRIND_EXE} --tool=memcheck --track-origins=yes
                             --error-exitcode=1 $<TARGET_FILE:test_ct_${cset}> valgrind)
        endif()
    endif()
endforeach()

# Keygen-only constant-time gate: poisons sk_seed, runs sdith_keygen under
# valgrind, and fails on any secret-dependent branch/access except the whitelisted
# sampler rejection loop (test/ct_keygen.supp). Meaningful on the avx table only.
if(WITH_VALGRIND AND VALGRIND_EXE)
    foreach(cset CAT1_SHORT CAT1B CAT3A CAT3B CAT5A CAT5B)
        add_executable(ct_keygen_${cset} test/ct_keygen.c)
        target_link_libraries(ct_keygen_${cset} vole m)
        target_include_directories(ct_keygen_${cset} PRIVATE src)
        target_compile_definitions(ct_keygen_${cset} PRIVATE WITH_VALGRIND)
        if(NOT cset STREQUAL "CAT1_SHORT")  # CAT1_SHORT is the #else default (no define)
            target_compile_definitions(ct_keygen_${cset} PRIVATE ${cset})
        endif()
        add_test(NAME ct_keygen_valgrind_${cset}
                 COMMAND ${VALGRIND_EXE} --tool=memcheck --track-origins=yes
                         --error-exitcode=1
                         --suppressions=${CMAKE_SOURCE_DIR}/test/ct_keygen.supp
                         $<TARGET_FILE:ct_keygen_${cset}>)
    endforeach()
endif()

# --- B5: libFuzzer harnesses (opt-in, Clang only; gcc CI path unaffected) ---
option(BUILD_FUZZERS "Build libFuzzer harnesses (requires Clang)" OFF)
if(BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "BUILD_FUZZERS requires Clang (-fsanitize=fuzzer)")
    endif()
    # One fuzzer per (harness x parameter set); CATxy tokens match stress_test_single.c
    # (CAT1_SHORT is the #else default, so it gets no -D define).
    foreach(fz fuzz_verify fuzz_sign_mutate)
        foreach(fset CAT1_SHORT CAT1B CAT3A CAT3B CAT5A CAT5B)
            set(ftgt ${fz}_${fset})
            add_executable(${ftgt} test/${fz}.cpp)
            target_link_libraries(${ftgt} vole)
            target_include_directories(${ftgt} PRIVATE src)
            if(NOT fset STREQUAL "CAT1_SHORT")
                target_compile_definitions(${ftgt} PRIVATE ${fset})
            endif()
            target_compile_options(${ftgt} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
            target_link_options(${ftgt} PRIVATE -fsanitize=fuzzer,address,undefined)
        endforeach()
    endforeach()
    # ctest smoke covers cat1-short only; the full per-set campaign is driven manually.
    add_test(NAME fuzz_verify_smoke COMMAND fuzz_verify_CAT1_SHORT -runs=20000 -max_total_time=30)
    add_test(NAME fuzz_sign_mutate_smoke COMMAND fuzz_sign_mutate_CAT1_SHORT -runs=200 -max_total_time=30)
    # leaf-seed 4x is a low-level check (no parameter set), so it is a single target.
    add_executable(fuzz_leaf_seed_4x test/fuzz_leaf_seed_4x.cpp)
    target_link_libraries(fuzz_leaf_seed_4x vole)
    target_include_directories(fuzz_leaf_seed_4x PRIVATE src)
    target_compile_options(fuzz_leaf_seed_4x PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_leaf_seed_4x PRIVATE -fsanitize=fuzzer,address,undefined)
    # ctest smoke covers cat1-short only; the full per-set campaign is driven manually.
    add_test(NAME fuzz_leaf_seed_4x_smoke COMMAND fuzz_leaf_seed_4x -runs=200000 -max_total_time=30)
endif()
endif (BUILD_TESTING)

if (BUILD_KATS)
    # NIST's KAT generators, one executable per parameter set.  kat/sdith_cat1_short is
    # the only copy of PQCgenKAT_sign.c, rng.c and sign.c: every set compiles those same
    # files against its own api.h, generated into the build tree by kat_api_gen.  api.h
    # is generated rather than committed because sign.c abort()s when its CRYPTO_*BYTES
    # disagree with the library, which happens every time the parameters are retuned.
    set(KAT_TEMPLATE_DIR ${CMAKE_SOURCE_DIR}/kat/sdith_cat1_short)
    set(KAT_TEMPLATE_SRCS PQCgenKAT_sign.c rng.c rng.h sign.c)

    add_executable(kat_api_gen kat/kat_api_gen.c)
    target_link_libraries(kat_api_gen vole)
    target_include_directories(kat_api_gen PRIVATE src)

    foreach (category ${PARAMS_CATEGORIES})
        # One materialised folder per set: sign.c does #include "api.h", which the
        # preprocessor resolves next to sign.c itself before it ever looks at -I, so the
        # sources have to sit beside the api.h they belong to.  The generator also writes
        # its .req/.rsp into its own directory, and utils/check_full_kats and
        # test/kat_differential.py look the binaries up by this path.
        set(katdir ${CMAKE_BINARY_DIR}/kats_folder/SDITH_${category})
        file(MAKE_DIRECTORY ${katdir})

        set(katsrcs)
        foreach (f ${KAT_TEMPLATE_SRCS})
            add_custom_command(
                    OUTPUT ${katdir}/${f}
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${KAT_TEMPLATE_DIR}/${f} ${katdir}/${f}
                    DEPENDS ${KAT_TEMPLATE_DIR}/${f}
                    VERBATIM
            )
            set(katsrcs ${katsrcs} ${katdir}/${f})
        endforeach ()
        add_custom_command(
                OUTPUT ${katdir}/api.h
                COMMAND kat_api_gen ${KAT_TEMPLATE_DIR}/api.h ${category} ${katdir}/api.h
                DEPENDS kat_api_gen ${KAT_TEMPLATE_DIR}/api.h
                COMMENT "Generating api.h for SDITH_${category}"
                VERBATIM
        )

        set_source_files_properties(${katdir}/PQCgenKAT_sign.c PROPERTIES COMPILE_FLAGS "-Wno-unused-result")
        set_source_files_properties(${katdir}/rng.c PROPERTIES COMPILE_FLAGS "-Wno-unused-but-set-variable")
        add_executable(PQCGenKat_${category} ${katsrcs} ${katdir}/api.h)
        target_include_directories(PQCGenKat_${category} PRIVATE ${katdir} ${kats_incs})
        target_link_libraries(PQCGenKat_${category} vole ${kats_libs} m)
        set_target_properties(PQCGenKat_${category} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${katdir})
    endforeach ()
endif (BUILD_KATS)
