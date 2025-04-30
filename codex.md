# SHA3 Library – High-Performance Usage Guide

This guide focuses on building and using the SHA3 library for maximum parallel throughput on fixed-size messages.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DSHA3_BUILD_EXAMPLES=ON \
      -DCMAKE_C_FLAGS="-O3 -march=native -funroll-loops" ..
make -j$(nproc)
```

## API – Parallel Pad-and-Hash

Include the header:
```c
#include "sha3.h"
```

Hash N messages of constant length `msg_len` (≤ block size) in one call:
```c
int rc = sha3_hash_parallel_len(
    SHA3_256,   // hash type
    data,       // input buffer: N * msg_len bytes
    msg_len,    // constant message length
    out,        // output buffer: N * digest_size bytes
    N           // number of messages
);
```
This function performs padding and hashing entirely within the timed region, dispatching to SIMD-optimized AVX2/AVX-512F kernels.

For exactly 64-byte messages, use the convenience wrapper:
```c
sha3_hash_parallel(SHA3_256, data, out, N);
```

## Example Usage

```c
#include "sha3.h"

// Prepare N messages of length 64 bytes
uint8_t data[N][64];  // input data
uint8_t out[N][SHA3_256_DIGEST_SIZE];

// Fill data...

// Run parallel pad-and-hash
sha3_hash_parallel(SHA3_256, data, out, N);

// Now out[i] contains SHA3-256 digest of data[i]
```

## Benchmark

```bash
build/bin/sha3_parallel_benchmark 1000000 64
```

```text
sha3_hash_parallel_len: 1000000 messages of 64 bytes in 0.009 s
Throughput: 113391284 msgs/s (6920.9 MiB/s) on 16 threads
```

## License

Apache-2.0