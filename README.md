# SHA3 Library – High-Performance Parallel SHA3-256

This library provides a parallel, SIMD-accelerated implementation of SHA3-256 optimized for fixed-size messages.

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