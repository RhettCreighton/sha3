# SHA3 Library – High-Performance Parallel SHA3-256

This library provides a parallel, SIMD-accelerated implementation of SHA3-256 optimized for fixed-size messages.

## XKCP AVX-512 Submodule

This library integrates the 8×-lane AVX-512 Keccak-f[1600] kernel from the XKCP project.
The sources are provided as the `vendor/XKCP` Git submodule. To initialize and update it:

```bash
git submodule update --init --recursive
```

Verify that the directory
`vendor/XKCP/lib/low/KeccakP-1600-times8/AVX512/`
contains the files:
- `KeccakP-1600-times8-SIMD512.c`
- `KeccakP-1600-times8-SnP.h`

CMake will automatically include the common headers from
`vendor/XKCP/lib/common` and compile the AVX-512 kernel.

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DSHA3_BUILD_EXAMPLES=ON \
      -DCMAKE_C_FLAGS="-O3 -march=native -funroll-loops" ..
make -j$(nproc)
```

## API

Include the public header:
```c
#include "sha3.h"
```

Hash N messages of constant length `msg_len` (≤ block size):
```c
int rc = sha3_hash_parallel_len(
    SHA3_256,   // hash type
    data,       // input buffer: N * msg_len bytes
    msg_len,    // constant message length
    out,        // output buffer: N * digest_size bytes
    N           // number of messages
);
```
For exactly 64-byte messages:
```c
sha3_hash_parallel(SHA3_256, data, out, N);
```

## Benchmark

Measure pad-and-hash throughput for 1 000 000 messages of 64 bytes:
```bash
build/bin/sha3_parallel_benchmark 1000000 64
```
Example output:
```
sha3_hash_parallel_len: 1000000 messages of 64 bytes in 0.009 s
Throughput: 113391284 msgs/s (6920.9 MiB/s) on 16 threads
```

## License

Apache-2.0