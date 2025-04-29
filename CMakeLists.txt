cmake_minimum_required(VERSION 3.12)
project(sha3 VERSION 1.0.0 LANGUAGES C)
find_package(Threads REQUIRED)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Include directories
# (project include + third-party Keccak headers)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/KeccakCodePackage/lib/low/KeccakP-1600-times8/AVX512
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/KeccakCodePackage/lib/low/KeccakP-1600-times8/AVX512/u12
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/KeccakCodePackage/lib/low/KeccakP-1600/AVX512/C
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/KeccakCodePackage/lib/low/KeccakP-1600/AVX512/C/u12
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/KeccakCodePackage/lib/common
)

# Library source files
set(SHA3_SOURCES
    src/sha3.c
    src/sha3_avx2.c
    src/sha3_avx512_single.c
    src/sha3_parallel.c
    third_party/KeccakCodePackage/lib/low/KeccakP-1600/AVX512/C/KeccakP-1600-AVX512.c
    src/sha3_avx512_times8.c
    third_party/KeccakCodePackage/lib/low/KeccakP-1600-times8/AVX512/KeccakP-1600-times8-SIMD512.c
    src/keccak.c
    src/keccak_avx2.c
    src/keccak_avx512.c
    src/shake.c
    src/hash_function.c
)

## Create library (static by default)
add_library(sha3 ${SHA3_SOURCES})
## Link threads for parallel hashing
target_link_libraries(sha3 PUBLIC Threads::Threads)
  # Suppress GCC unused-variable errors in third-party Keccak code
  set_source_files_properties(
    third_party/KeccakCodePackage/lib/low/KeccakP-1600-times8/AVX512/KeccakP-1600-times8-SIMD512.c
    PROPERTIES COMPILE_FLAGS "-Wno-error=unused-variable"
  )
  set_source_files_properties(
    third_party/KeccakCodePackage/lib/low/KeccakP-1600/AVX512/C/KeccakP-1600-AVX512.c
    PROPERTIES COMPILE_FLAGS "-Wno-error=unused-variable"
  )

# Set warning levels
# Set warning levels
target_compile_options(sha3 PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)
## Performance optimizations: enable aggressive compile flags for SHA-3
target_compile_options(sha3 PRIVATE
    -O3
    -march=native
    -funroll-loops
)

# Install headers
install(FILES include/sha3.h DESTINATION include)

# Install library
## Enable link-time optimization if supported (LTO)
set_target_properties(sha3 PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)

install(TARGETS sha3
        EXPORT sha3Targets
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin)

# Generate and install package files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/sha3ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/sha3Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/sha3Config.cmake"
    @ONLY
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/sha3Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/sha3ConfigVersion.cmake"
    DESTINATION lib/cmake/sha3
)

# Install exported targets for CMake
install(
    EXPORT sha3Targets
    FILE sha3Targets.cmake
    DESTINATION lib/cmake/sha3
)

# Install license file
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE DESTINATION .)

# Enable testing and examples
option(SHA3_BUILD_TESTS "Build tests for SHA3 library" ON)
option(SHA3_BUILD_EXAMPLES "Build examples for SHA3 library" ON)

# Optional: tests
if(SHA3_BUILD_TESTS)
    # Enable testing
    enable_testing()
    
    # Add test executable
    add_executable(test_sha3 tests/test_sha3.c)
    target_link_libraries(test_sha3 sha3)
    set_target_properties(test_sha3 PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON)
    
    # Add test
    add_test(NAME test_sha3 COMMAND test_sha3)
endif()

# Optional: examples
if(SHA3_BUILD_EXAMPLES)
    # Simple hash example (SHA3-256)
    add_executable(sha3_hash_example examples/hash_example.c)
    target_link_libraries(sha3_hash_example sha3)

    # SHAKE example (SHAKE128)
    add_executable(sha3_shake_example examples/shake_example.c)
    target_link_libraries(sha3_shake_example sha3)

    # Benchmark example: measure SHA3-256 hashes per second (single-threaded)
    add_executable(sha3_benchmark examples/sha3_benchmark.c)
    target_link_libraries(sha3_benchmark PRIVATE sha3 Threads::Threads)
    # Build examples with performance flags
    target_compile_options(sha3_benchmark PRIVATE -O3 -march=native -funroll-loops)
    
    # Parallel benchmark: measure throughput of sha3_hash_parallel across threads
    add_executable(sha3_parallel_benchmark examples/sha3_parallel_benchmark.c)
    target_link_libraries(sha3_parallel_benchmark PRIVATE sha3 Threads::Threads)
    target_compile_options(sha3_parallel_benchmark PRIVATE -O3 -march=native -funroll-loops)

    set_target_properties(
        sha3_hash_example sha3_shake_example sha3_benchmark sha3_parallel_benchmark
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    # Enable link-time optimization for examples
    set_target_properties(
        sha3_hash_example sha3_shake_example sha3_benchmark
        PROPERTIES INTERPROCEDURAL_OPTIMIZATION ON
    )
endif()