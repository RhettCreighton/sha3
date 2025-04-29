# SHA3 Library – AI Assistant Guide

This file provides essential context and coding guidelines for AI assistants working on the SHA3 library.

## Project Structure
- include/           Public headers (sha3.h)
- src/               Core C implementation and SIMD-optimized modules
- examples/          Usage and benchmark programs
- tests/             Unit tests with NIST vectors and API validation
- third_party/       External KeccakP-1600 SIMD implementations (CC0)
- cmake/             CMake package configuration templates
- LICENSE            Apache License 2.0
- README.md          Developer and user guide
- CMakeLists.txt     Top-level build configuration

## Coding & Style Guidelines
- Language: ISO C99 (no GNU extensions in headers; intrinsics allowed in .c files)
- All source headers and code must start with: `/* SPDX-License-Identifier: Apache-2.0 */`
- Public API functions prefixed with `sha3_`; internal helpers as `static`
- No global or static mutable state; thread-safe design
- Maintain concise, focused patches: use `apply_patch` for edits
- Avoid inline comments except for SPDX, file/module headers, and brief clarifications
- Follow existing indentation and brace style (spaces, 4-column indent)

## Build & Test Workflow
```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
ctest --output-on-failure
``` 

Verify examples compile and run:
```bash
./bin/sha3_hash_example
./bin/sha3_shake_example
./bin/sha3_benchmark
```

## Integration Patterns
- **CMake Submodule**:
  ```cmake
  add_subdirectory(path/to/sha3)
  target_link_libraries(myapp PRIVATE sha3::sha3)
  ```
- **FetchContent**:
  ```cmake
  include(FetchContent)
  FetchContent_Declare(
    sha3
    GIT_REPOSITORY https://github.com/yourorg/sha3.git
    GIT_TAG        v<version>  # e.g. v1.0.0
  )
  FetchContent_MakeAvailable(sha3)
  target_link_libraries(myapp PRIVATE sha3::sha3)
  ```

## AI Assistant Instructions
- Focus on root-cause fixes and minimal diffs
- Run builds and tests locally to verify changes
- Preserve existing API and behavior unless asked to break compatibility
+ Ask clarifying questions if the intent or structure is unclear

### Technical Deep Dive

At the heart of this library is the Keccak-f[1600] cryptographic permutation—a 1600-bit state organized as a 5×5 array of 64-bit lanes—and a sponge construction that alternates between absorbing input into the "rate" portion of the state and applying 24 rounds of Theta, Rho, Pi, Chi, and Iota steps.  The scalar C implementation unrolls all loops for maximum compiler optimizations and follows FIPS-202 padding and domain separation rules directly in-place, minimizing memory copies.

To exploit SIMD on modern x86-64 CPUs, we provide multi-lane kernels: an AVX2-based 4-way core and an AVX-512F 8-way core (from the XKCP code package) that process four or eight independent hash states in parallel.  These kernels broadcast the padded 64-byte input into each lane, execute the permutation on all lanes simultaneously using 256/512-bit vector registers, and then extract the first 32 bytes of output per state as valid SHA3-256 digests.  For SHA3-512 we similarly offer single-state vectorized hot-paths and times-8 multi-buffer kernels.

The library also contains specialized single-state AVX2 and AVX-512F functions (sha3_hash_<type>_64B_avx2 or _avx512) that fuse padding, absorption, permutation, and squeeze for fixed 64-byte inputs, reducing overhead for hot-paths in high-performance applications.  Runtime CPU feature detection via `__builtin_cpu_supports()` dispatches automatically to the best available implementation, falling back to the portable C path if neither AVX2 nor AVX-512F are available.

All contexts (`sha3_ctx`) are stack-allocated and contain no global or static mutable state, ensuring thread safety.  The incremental API supports streaming large messages with repeated calls to `sha3_update()`, while the one-shot APIs optimize the common case of hashing a known buffer in a single call.