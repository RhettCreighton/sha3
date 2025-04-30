/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
/*
 * @file sha3_parallel.c
 * @brief Parallel SHA3 hashing across multiple threads
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "sha3.h"
// For multi-buffer AVX-512 8-way sponge (disabled due to missing third-party code)
// #ifdef __GNUC__
// #include "KeccakP-1600-times8-SnP.h"
// #endif
/* Declarations for specialized one-shot 64-byte hash functions */
extern int sha3_hash_256_64B_avx512_times8(const void *data, size_t len, void *digest, size_t digest_size);
extern int sha3_hash_256_64B_avx2(const void *data, size_t len, void *digest, size_t digest_size);
extern int sha3_hash_512_64B_avx512_times8(const void *data, size_t len, void *digest, size_t digest_size);
extern int sha3_hash_512_64B_avx2(const void *data, size_t len, void *digest, size_t digest_size);

typedef struct {
    sha3_hash_type type;
    const uint8_t *data;
    uint8_t *output;
    size_t len;          /* input message length */
    size_t digest_size;
    size_t start;
    size_t end;
} sha3_parallel_arg;

static void *sha3_parallel_thread(void *arg) {
    sha3_parallel_arg *a = (sha3_parallel_arg *)arg;
    const uint8_t *data = a->data;
    uint8_t *output = a->output;
    size_t len = a->len;
    size_t digest = a->digest_size;
    size_t start = a->start;
    size_t end = a->end;
/* Prefetch distance in blocks to hide memory latency */
#define PF_DIST 32
#ifdef __GNUC__
    int have_avx512 = __builtin_cpu_supports("avx512f");
    int have_avx2   = __builtin_cpu_supports("avx2");
#else
    int have_avx512 = 0;
    int have_avx2   = 0;
#endif
    /* Fast multi-buffer 8-way path for 64-byte messages with AVX-512 */
#ifdef __GNUC__
    if (have_avx512 && (a->type == SHA3_256 || a->type == SHA3_512) && len == 64) {
        size_t BS = (a->type == SHA3_256 ? SHA3_256_BLOCK_SIZE : SHA3_512_BLOCK_SIZE);
        size_t i = start;
        while (i + 8 <= end) {
            if (i + PF_DIST < end) __builtin_prefetch(data + (i + PF_DIST) * len, 0, 3);
            uint8_t buf0[SHA3_MAX_BLOCK_SIZE], buf1[SHA3_MAX_BLOCK_SIZE], buf2[SHA3_MAX_BLOCK_SIZE], buf3[SHA3_MAX_BLOCK_SIZE];
            uint8_t buf4[SHA3_MAX_BLOCK_SIZE], buf5[SHA3_MAX_BLOCK_SIZE], buf6[SHA3_MAX_BLOCK_SIZE], buf7[SHA3_MAX_BLOCK_SIZE];
            uint64_t s0[25] = {0}, s1[25] = {0}, s2[25] = {0}, s3[25] = {0};
            uint64_t s4[25] = {0}, s5[25] = {0}, s6[25] = {0}, s7[25] = {0};
            const uint8_t *src = data + i * len;
            uint8_t *bufs[8] = {buf0, buf1, buf2, buf3, buf4, buf5, buf6, buf7};
            for (int j = 0; j < 8; ++j) {
                uint8_t *b = bufs[j];
                memcpy(b, src + j * len, len);
                b[len] = 0x06;
                memset(b + len + 1, 0, BS - (len + 1));
                b[BS - 1] ^= 0x80;
            }
            const uint64_t *lanes0 = (const uint64_t *)buf0;
            const uint64_t *lanes1 = (const uint64_t *)buf1;
            const uint64_t *lanes2 = (const uint64_t *)buf2;
            const uint64_t *lanes3 = (const uint64_t *)buf3;
            const uint64_t *lanes4 = (const uint64_t *)buf4;
            const uint64_t *lanes5 = (const uint64_t *)buf5;
            const uint64_t *lanes6 = (const uint64_t *)buf6;
            const uint64_t *lanes7 = (const uint64_t *)buf7;
            for (int k = 0; k < (int)(BS / 8); ++k) {
                s0[k] = lanes0[k]; s1[k] = lanes1[k]; s2[k] = lanes2[k]; s3[k] = lanes3[k];
                s4[k] = lanes4[k]; s5[k] = lanes5[k]; s6[k] = lanes6[k]; s7[k] = lanes7[k];
            }
            extern void keccak_permutation8_avx512(uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *);
            keccak_permutation8_avx512(s0, s1, s2, s3, s4, s5, s6, s7);
            uint8_t *dst = output + i * digest;
            uint64_t *out0 = (uint64_t *)(dst + 0 * digest);
            uint64_t *out1 = (uint64_t *)(dst + 1 * digest);
            uint64_t *out2 = (uint64_t *)(dst + 2 * digest);
            uint64_t *out3 = (uint64_t *)(dst + 3 * digest);
            uint64_t *out4 = (uint64_t *)(dst + 4 * digest);
            uint64_t *out5 = (uint64_t *)(dst + 5 * digest);
            uint64_t *out6 = (uint64_t *)(dst + 6 * digest);
            uint64_t *out7 = (uint64_t *)(dst + 7 * digest);
            for (int k = 0; k < (int)(digest / 8); ++k) {
                out0[k] = s0[k]; out1[k] = s1[k]; out2[k] = s2[k]; out3[k] = s3[k];
                out4[k] = s4[k]; out5[k] = s5[k]; out6[k] = s6[k]; out7[k] = s7[k];
            }
            i += 8;
        }
        for (; i < end; ++i) {
            const void *msg = data + i * len;
            void *dig = output + i * digest;
            sha3_hash(a->type, msg, len, dig, digest);
        }
        return NULL;
    }
#endif
    /* Fast multi-buffer 4-way path for 64-byte messages with AVX2 */
    if (have_avx2 && (a->type == SHA3_256 || a->type == SHA3_512) && len == 64) {
#ifdef __GNUC__
        size_t BS = (a->type == SHA3_256 ? SHA3_256_BLOCK_SIZE : SHA3_512_BLOCK_SIZE);
        size_t i = start;
        while (i + 4 <= end) {
            /* Prefetch block PF_DIST ahead */
            if (i + PF_DIST < end) __builtin_prefetch(data + (i + PF_DIST) * len, 0, 3);
            uint8_t buf0[SHA3_MAX_BLOCK_SIZE];
            uint8_t buf1[SHA3_MAX_BLOCK_SIZE];
            uint8_t buf2[SHA3_MAX_BLOCK_SIZE];
            uint8_t buf3[SHA3_MAX_BLOCK_SIZE];
            uint64_t s0[25] = {0}, s1[25] = {0}, s2[25] = {0}, s3[25] = {0};
            /* pad and load each buffer */
            uint8_t *bs[4] = {buf0, buf1, buf2, buf3};
            for (int j = 0; j < 4; ++j) {
                uint8_t *b = bs[j];
                memcpy(b, data + (i+j)*len, len);
                b[len] = 0x06;
                memset(b + len + 1, 0, BS - (len + 1));
                b[BS - 1] ^= 0x80;
            }
            /* map lanes to state words */
            const uint64_t *lanes0 = (const uint64_t *)buf0;
            const uint64_t *lanes1 = (const uint64_t *)buf1;
            const uint64_t *lanes2 = (const uint64_t *)buf2;
            const uint64_t *lanes3 = (const uint64_t *)buf3;
            for (int k = 0; k < (int)(BS/8); ++k) {
                s0[k] = lanes0[k];
                s1[k] = lanes1[k];
                s2[k] = lanes2[k];
                s3[k] = lanes3[k];
            }
            extern void keccak_permutation4_avx2(uint64_t *, uint64_t *, uint64_t *, uint64_t *);
            keccak_permutation4_avx2(s0, s1, s2, s3);
            /* extract digests */
            uint64_t *o0 = (uint64_t *)(output + (i+0)*digest);
            uint64_t *o1 = (uint64_t *)(output + (i+1)*digest);
            uint64_t *o2 = (uint64_t *)(output + (i+2)*digest);
            uint64_t *o3 = (uint64_t *)(output + (i+3)*digest);
            for (int k = 0; k < (int)(digest/8); ++k) {
                o0[k] = s0[k];
                o1[k] = s1[k];
                o2[k] = s2[k];
                o3[k] = s3[k];
            }
            i += 4;
        }
        /* leftover */
        for (size_t i = start + ((end - start)/4)*4; i < end; ++i) {
            const void *msg = data + i*len;
            void *dig = output + i*digest;
            sha3_hash(a->type, msg, len, dig, digest);
        }
        return NULL;
#endif
    }
    /* Generic per-message path */
    for (size_t i = start; i < end; ++i) {
        /* Prefetch PF_DIST blocks ahead */
        if (i + PF_DIST < end) __builtin_prefetch(data + (i + PF_DIST) * len, 0, 3);
        const void *msg = data + i*len;
        void *dig = output + i*digest;
        sha3_hash(a->type, msg, len, dig, digest);
    }
    return NULL;
}

int sha3_hash_parallel_len(sha3_hash_type type,
                           const void *data,
                           size_t len,
                           void *output,
                           size_t n) {
    if (!data || !output) return -1;
    if (n == 0) return 0;
    size_t digest_size = sha3_get_digest_size(type);
    if (digest_size == 0) return -1;
    /* Determine number of threads */
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    int nthreads = (nproc > 0 ? (int)nproc : 1);
    if ((size_t)nthreads > n) nthreads = (int)n;

    pthread_t *threads = malloc(sizeof(pthread_t) * nthreads);
    if (!threads) return -1;
    sha3_parallel_arg *args = malloc(sizeof(sha3_parallel_arg) * nthreads);
    if (!args) {
        free(threads);
        return -1;
    }

    /* Partition work across threads */
    size_t base = n / nthreads;
    size_t rem = n % nthreads;
    size_t offset = 0;
    for (int t = 0; t < nthreads; ++t) {
        size_t count = base + (t < (int)rem ? 1 : 0);
        args[t].type = type;
        args[t].data = (const uint8_t *)data;
        args[t].output = (uint8_t *)output;
        args[t].len = len;
        args[t].digest_size = digest_size;
        args[t].start = offset;
        args[t].end = offset + count;
        offset += count;
        if (pthread_create(&threads[t], NULL, sha3_parallel_thread, &args[t]) != 0) {
            /* Cleanup on failure */
            for (int j = 0; j < t; ++j) pthread_join(threads[j], NULL);
            free(args);
            free(threads);
            return -1;
        }
    }

    /* Join threads */
    for (int t = 0; t < nthreads; ++t) {
        pthread_join(threads[t], NULL);
    }
    free(args);
    free(threads);
    return 0;
}
/**
 * @brief Compute multiple SHA3 hashes in parallel for fixed-length (64-byte) messages.
 *
 * Simple wrapper around sha3_hash_parallel_len using len=64 to leverage
 * 8-way AVX-512F or 4-way AVX2 multi-buffer kernels on SHA3_256/SHA3_512.
 */
int sha3_hash_parallel(sha3_hash_type type,
                       const void *data,
                       void *output,
                       size_t n) {
    return sha3_hash_parallel_len(type, data, 64, output, n);
}

/* Helper struct and thread entry for sha3_hash_parallel_same */
typedef struct {
    sha3_hash_type type;
    const uint8_t *msg;
    uint8_t *output;
    size_t len;
    size_t digest_size;
    size_t start;
    size_t end;
} sha3_parallel_same_arg;

static void *sha3_parallel_same_thread(void *arg) {
    sha3_parallel_same_arg *a = arg;
    sha3_hash_type type = a->type;
    const void *msg = a->msg;
    size_t len = a->len;
    size_t ds = a->digest_size;
    uint8_t *out = a->output;
#ifdef __GNUC__
    int have_avx512 = __builtin_cpu_supports("avx512f");
    int have_avx2   = __builtin_cpu_supports("avx2");
#else
    int have_avx512 = 0, have_avx2 = 0;
#endif
    for (size_t i = a->start; i < a->end; ++i) {
        void *dig = out + i * ds;
        if (have_avx512 && type == SHA3_256 && len == 64 && ds >= SHA3_256_DIGEST_SIZE) {
            sha3_hash_256_64B_avx512_times8(msg, len, dig, ds);
        } else if (have_avx2 && type == SHA3_256 && len == 64 && ds >= SHA3_256_DIGEST_SIZE) {
            sha3_hash_256_64B_avx2(msg, len, dig, ds);
        } else if (have_avx512 && type == SHA3_512 && len == 64 && ds >= SHA3_512_DIGEST_SIZE) {
            sha3_hash_512_64B_avx512_times8(msg, len, dig, ds);
        } else if (have_avx2 && type == SHA3_512 && len == 64 && ds >= SHA3_512_DIGEST_SIZE) {
            sha3_hash_512_64B_avx2(msg, len, dig, ds);
        } else {
            sha3_hash(type, msg, len, dig, ds);
        }
    }
    return NULL;
}

int sha3_hash_parallel_same(sha3_hash_type type,
                            const void *msg,
                            size_t len,
                            void *output,
                            size_t n) {
    if (!msg || !output) return -1;
    if (n == 0) return 0;
    size_t ds = sha3_get_digest_size(type);
    if (ds == 0) return -1;
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    int nthreads = (nproc > 0 ? (int)nproc : 1);
    if ((size_t)nthreads > n) nthreads = (int)n;

    pthread_t *threads = malloc(sizeof(pthread_t) * nthreads);
    if (!threads) return -1;
    sha3_parallel_same_arg *args = malloc(sizeof(sha3_parallel_same_arg) * nthreads);
    if (!args) { free(threads); return -1; }

    size_t base = n / nthreads;
    size_t rem = n % nthreads;
    size_t offset = 0;
    for (int t = 0; t < nthreads; ++t) {
        size_t count = base + (t < (int)rem ? 1 : 0);
        args[t].type = type;
        args[t].msg = (const uint8_t *)msg;
        args[t].output = (uint8_t *)output;
        args[t].len = len;
        args[t].digest_size = ds;
        args[t].start = offset;
        args[t].end = offset + count;
        offset += count;
        pthread_create(&threads[t], NULL, sha3_parallel_same_thread, &args[t]);
    }
    for (int t = 0; t < nthreads; ++t) pthread_join(threads[t], NULL);
    free(args);
    free(threads);
    return 0;
}