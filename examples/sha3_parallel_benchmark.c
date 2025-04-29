/* SPDX-License-Identifier: Apache-2.0 */
/*
 * @file sha3_parallel_benchmark.c
 * @brief Benchmark parallel SHA3 hashing over multiple threads
 * Requires POSIX.1b clock_gettime and pthreads
 */
#define _POSIX_C_SOURCE 199309L
#include "sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1) nproc = 1;
    /* Number of messages per thread; total messages = per_thread * nproc */
    size_t per_thread = 500000;
    size_t n = per_thread * nproc;
    if (argc > 1) {
        n = strtoull(argv[1], NULL, 0);
    }
    /* Use 64-byte messages to leverage multi-buffer vector kernels */
    size_t len = 64;
    size_t digest = sha3_get_digest_size(SHA3_256);
    uint8_t *in = malloc(n * len);
    uint8_t *out = malloc(n * digest);
    if (!in || !out) {
        fprintf(stderr, "Allocation failure\n");
        return 1;
    }
    /* initialize input with repeating pattern */
    for (size_t i = 0; i < n * len; ++i) {
        in[i] = (uint8_t)(i & 0xFF);
    }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    /* Parallel hash of n messages of length 64 bytes */
    if (sha3_hash_parallel(SHA3_256, in, out, n) != 0) {
        fprintf(stderr, "sha3_hash_parallel failed\n");
        return 1;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    double msgs_per_sec = n / elapsed;
    double mb_per_sec = msgs_per_sec * len / (1024.0 * 1024.0);
    printf("sha3_hash_parallel: %zu messages of %zu bytes in %.3f s\n", n, len, elapsed);
    printf("Throughput: %.0f msgs/s (%.1f MiB/s) on %d threads\n", msgs_per_sec, mb_per_sec, nproc);
    free(in);
    free(out);
    return 0;
}