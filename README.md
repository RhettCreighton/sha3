# SHA3 Library

A C implementation of the SHA-3 family of hash functions, including SHAKE extendable output functions.

## Features

- Complete implementation of SHA3-224, SHA3-256, SHA3-384, and SHA3-512
- Support for SHAKE128 and SHAKE256 extendable output functions
- Simple API with initialization, update, and finalization functions
- One-shot hashing function for convenience
- Thread-safe implementation
- No external dependencies
- Comprehensive test suite

## Usage

### One-Shot Hashing

```c
#include "sha3.h"
#include <stdio.h>

int main() {
    uint8_t digest[SHA3_256_DIGEST_SIZE];
    const char *data = "Hello, SHA-3!";
    
    sha3_hash(SHA3_256, data, strlen(data), digest, SHA3_256_DIGEST_SIZE);
    
    printf("SHA3-256 digest: ");
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    return 0;
}
```

### Incremental Hashing

```c
#include "sha3.h"
#include <stdio.h>

int main() {
    sha3_ctx ctx;
    uint8_t digest[SHA3_256_DIGEST_SIZE];
    
    sha3_init(&ctx, SHA3_256);
    sha3_update(&ctx, "Hello, ", 7);
    sha3_update(&ctx, "SHA-3!", 6);
    sha3_final(&ctx, digest, SHA3_256_DIGEST_SIZE);
    
    printf("SHA3-256 digest: ");
    for (int i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    return 0;
}
```

### SHAKE Functions

```c
#include "sha3.h"
#include <stdio.h>

int main() {
    uint8_t output[64]; // Variable-length output
    const char *data = "Hello, SHAKE!";
    
    shake_xof(SHAKE_256, data, strlen(data), output, sizeof(output));
    
    printf("SHAKE-256 output (64 bytes): ");
    for (int i = 0; i < sizeof(output); i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
    
    return 0;
}
```

## Examples

After building, example executables are available in `build/bin/`:

 - `sha3_hash_example`             — One-shot SHA3-256 (and SHA3-512) hashing.
 - `sha3_shake_example`            — SHAKE128/256 extendable-output demonstration.
 - `sha3_benchmark`               — Micro-benchmark tool for single-threaded throughput.
 - `sha3_parallel_benchmark`      — Parallel distinct 64B hashing across all cores.

### Parallel Distinct-Block Benchmark

To hash *distinct* 64-byte messages in parallel:
```bash
./bin/sha3_parallel_benchmark
```
This demo uses the public API:
```c
sha3_hash_parallel(SHA3_256, in, out, n);
```
which dispatches to the AVX-512F 8-way multi-buffer kernel when available.

Run an example:

    ./bin/sha3_hash_example

## Building

```bash
mkdir build && cd build
cmake ..
make
```

## Testing

```bash
ctest
```

or

```bash
./bin/test_sha3
```

## Benchmarking

After building, use the `sha3_benchmark` executable to measure single-threaded performance of various optimized kernels:

```bash
./bin/sha3_benchmark
```

This runs 1-second throughput tests for:
- Scalar SHA3-256 and SHA3-512
- Single-state AVX2 and AVX-512F kernels (64-byte input)
- 4-way (AVX2) and 8-way (AVX-512F) multi-lane kernels

## Performance Results

The following single-threaded benchmark results were obtained on our test machine
with `-O3 -march=native -funroll-loops` and link-time optimization enabled.

| Kernel                             | Throughput (hashes/sec) |
|------------------------------------|------------------------:|
| SHA3-256 (scalar)                  |      1,685,413          |
| AVX2 4-way SHA3-256                |      7,367,596          |
| AVX-512F 8-way SHA3-256            |     24,807,856          |
| AVX-512F single-state SHA3-256     |      1,654,062          |
| SHA3-512 (scalar)                  |      1,665,397          |
| AVX2 single-state SHA3-512         |      1,820,481          |
| AVX-512F single-state SHA3-512     |      1,676,651          |
| AVX-512F 8-way SHA3-512            |     11,341,912          |

Run `./bin/sha3_benchmark` to measure performance on your hardware.

### Multicore AVX-512F 8-way SHA3-256 Throughput

To instantly measure and aggregate 8-way AVX-512F SHA3-256 throughput across all cores (expect ~170 MH/s on a 16-core AVX-512F CPU), use:

```bash
n=$(nproc); \
for i in $(seq 1 $n); do \
  ./bin/sha3_benchmark > bench$i.log 2>&1 & \
done; wait; \
grep -A2 'AVX-512F 8-way SHA3-256 Benchmark - 1 second test' bench*.log | grep 'Hash rate' | awk -F':' '{sum+=$2} END {printf "Aggregate AVX-512F 8-way SHA3-256 throughput: %.0f hashes/sec (%.1f MH/s)\n", sum, sum/1e6}'; \
rm bench*.log
```

## Runtime Dispatch & CPU Feature Detection

By default, the library uses runtime CPU feature detection (GCC/Clang only) to select optimized implementations for SHA3-256 and SHA3-512 when hashing 64-byte inputs:

- If the CPU supports AVX-512F at runtime, the single-state AVX-512F kernel (`sha3_hash_<type>_64B_avx512`) is used.
- Else if the CPU supports AVX2, the single-state AVX2 kernel (`sha3_hash_<type>_64B_avx2`) is used.
- Otherwise, the portable C implementation is used.

This detection relies on `__builtin_cpu_supports("avx512f")` and `__builtin_cpu_supports("avx2")` in `<immintrin.h>`. To enable these optimizations, compile with `-mavx512f` and/or `-mavx2`. On non-GNU compilers or platforms without these built-in checks, the library falls back to the generic C path.

If you need explicit control over specialized kernels (e.g., multi-buffer or multi-lane processing), you can call the optimized functions directly:

```c
// Direct AVX2 single-state SHA3-256 for 64-byte input
sha3_hash_256_64B_avx2(data, 64, digest, SHA3_256_DIGEST_SIZE);

// AVX-512F 8-way SHA3-512 (times-8 SIMD) for 64-byte inputs
sha3_hash_512_64B_avx512_times8(data, 64, digests, SHA3_512_DIGEST_SIZE * 8);
```

To enable compile-time flags, for example with CMake:

```bash
cmake -DCMAKE_C_FLAGS="-mavx2 -mavx512f -O3 -march=native" -DCMAKE_BUILD_TYPE=Release ..
```

## Using the Optimized API in Your Application

### One-Shot Hashing with Runtime Dispatch

Build and link with AVX2/AVX-512F support to enable runtime CPU feature detection. Then simply call:
```c
#include "sha3.h"

uint8_t digest[SHA3_256_DIGEST_SIZE];
// data_len may be any length; if data_len == 64, auto-dispatch uses best single-state kernel
sha3_hash(SHA3_256, data, data_len, digest, SHA3_256_DIGEST_SIZE);
```

### Direct Calls to Specialized Kernels

For maximum per-core throughput when hashing fixed 64-byte blocks, use the 8-way AVX-512F kernel:
```c
#include "sha3.h"

uint8_t digest[SHA3_256_DIGEST_SIZE];
// Processes 8 hashes in parallel on one core (returns digest of lane 0)
sha3_hash_256_64B_avx512_times8(block64, 64, digest, SHA3_256_DIGEST_SIZE);
```

### Multithreading for Full CPU Utilization

Spawn one thread per core, each looping over the one-shot API to fully saturate the CPU:
```c
#include <unistd.h>  // for sysconf
#include <pthread.h>
#include "sha3.h"

void* worker(void* _) {
    uint8_t block[64] = { /* your 64-byte message */ };
    uint8_t digest[SHA3_256_DIGEST_SIZE];
    while (1) {
        sha3_hash(SHA3_256, block, 64, digest, SHA3_256_DIGEST_SIZE);
    }
    return NULL;
}

int main() {
    int n = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[n];
    for (int i = 0; i < n; i++) {
        pthread_create(&threads[i], NULL, worker, NULL);
    }
    pthread_join(threads[0], NULL);
    return 0;
}
```

## Integration

You can integrate this library into your own CMake-based project in a reproducible way by pinning to a specific tag or commit SHA. Choose one of the following methods:

### 1. Git Submodule

Add the SHA3 repo as a submodule and check out a tagged release (or exact commit):
```bash
git submodule add https://github.com/RhettCreighton/sha3.git external/sha3
cd external/sha3
git checkout v1.0.0    # or replace with a full 40-char commit SHA
cd -
```

In your top-level `CMakeLists.txt`, add:
```cmake
add_subdirectory(external/sha3)
target_link_libraries(myapp PRIVATE sha3::sha3)
```

### 2. CMake FetchContent

Let CMake automatically clone and configure the exact release for you:
```cmake
include(FetchContent)
FetchContent_Declare(
  sha3
  GIT_REPOSITORY https://github.com/RhettCreighton/sha3.git
  GIT_TAG        v1.0.0    # pins to the v1.0.0 tag or commit
)
FetchContent_MakeAvailable(sha3)

target_link_libraries(myapp PRIVATE sha3::sha3)
```

Both approaches ensure that your build always uses the exact source version you have tested.

## License

This library is licensed under the Apache License, Version 2.0.
See the accompanying LICENSE file for details.

## Third-Party Code and Licensing

This project incorporates optimized Keccak-f[1600] kernels from the eXtended Keccak Code Package (XKCP) by the Keccak Team:
  - Assembly AVX2, AVX-512 and C SIMD512 implementations in `third_party/KeccakCodePackage/lib/low/KeccakP-1600...`
  - Supporting headers under `third_party/KeccakCodePackage/lib/common`

All third-party files are used under their open-source license (primarily CC0 / public domain). Please refer to `third_party/KeccakCodePackage/LICENSE` and the file-level headers for full license terms.