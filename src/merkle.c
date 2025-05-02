/* SPDX-License-Identifier: Apache-2.0 */
/*
 * @file merkle.c
 * @brief 4-ary Merkle tree construction using SHA3-256 with persistent thread pool
 *
 * This implementation spins up a pool of worker threads once, then uses two-phase
 * pthread_barrier sync per tree level. Each worker applies the internal 8-way AVX-512
 * Keccak-f[1600] permutation on batched 136-byte blocks for maximum throughput.
 */
#define _POSIX_C_SOURCE 200112L  /* for posix_memalign, sysconf */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#ifdef __GNUC__
#include "KeccakP-1600-times8-SnP.h"
#endif
#include "sha3.h"

// Context data shared by all worker threads
typedef struct {
    size_t rate;           // SHA3 sponge rate in bytes
    size_t leaf_size;      // Digest size in bytes
    size_t branch;         // Number of children hashed per node
    const uint8_t *cur;    // Input array of current level nodes
    uint8_t *buf1, *buf2;  // Buffers for output nodes (ping-pong)
    uint8_t *next;         // Current output buffer
    size_t parents;        // Number of nodes at this level
    int nthreads;          // Number of worker threads
    int done;              // Flag signaling workers to exit
    pthread_barrier_t barrier; // Barrier for two-phase sync per level
} merkle_ctx_t;

// Argument for each worker thread
typedef struct {
    merkle_ctx_t *ctx;
    int tid;
} worker_arg_t;

// Worker thread: waits for packing, hashes its slice, then signals completion
// Worker thread: hashes nodes directly from cur[], packing and padding on-the-fly
static void *merkle_worker(void *arg) {
    worker_arg_t *a = arg;
    merkle_ctx_t *c = a->ctx;
    for (;;) {
        // Phase 1: wait for main thread to set c->cur and c->parents
        pthread_barrier_wait(&c->barrier);
        if (c->done) break;
        size_t P = c->parents;
        size_t R = c->rate;
        size_t D = c->leaf_size;
        const uint8_t *cur = c->cur;
        uint8_t *out = c->next;
        // AVX-512 x8 multi-buffer: pack+pad per lane
        for (size_t i = (size_t)a->tid * 8; i + 8 <= P; i += c->nthreads * 8) {
            KeccakP1600times8_SIMD512_states st;
            KeccakP1600times8_InitializeAll(&st);
            for (int lane = 0; lane < 8; lane++) {
                const uint8_t *src = cur + (i + lane) * D;
                KeccakP1600times8_OverwriteBytes(&st, lane, src,      0, (unsigned)D);
                KeccakP1600times8_OverwriteBytes(&st, lane, (uint8_t[]){0x06}, (unsigned)D, 1);
                KeccakP1600times8_OverwriteWithZeroes(&st, lane, (unsigned)(D + 1));
                KeccakP1600times8_OverwriteBytes(&st, lane, (uint8_t[]){0x80}, (unsigned)(R - 1), 1);
            }
            KeccakP1600times8_PermuteAll_24rounds(&st);
            for (int lane = 0; lane < 8; lane++) {
                KeccakP1600times8_ExtractBytes(&st, lane, out + (i + lane) * D, 0, (unsigned)D);
            }
        }
        // Scalar fallback for tail
        for (size_t i = (P/8)*8; i < P; i++) {
            uint8_t tmp[136];
            const uint8_t *src = cur + i * D;
            memcpy(tmp, src, D);
            tmp[D] = 0x06;
            memset(tmp + D + 1, 0, R - D - 1);
            tmp[R - 1] ^= 0x80;
            sha3_hash(SHA3_256, tmp, R, out + i * D, D);
        }
        // Phase 2: signal completion
        pthread_barrier_wait(&c->barrier);
    }
    return NULL;
}

/**
 * @brief Build a 4-ary Merkle tree from 32-byte leaves using SHA3-256.
 *
 * This function spawns a pool of worker threads once, then for each level:
 *  1) Packs up to 'branch' (rate/leaf_size) child digests into padded blocks
 *  2) Phase 1 barrier: signal workers to hash those blocks
 *  3) Phase 2 barrier: wait for workers to finish
 * and proceeds until a single root remains.
 *
 * @param leaves     Input leaves array (num_leaves × 32 bytes)
 * @param num_leaves Number of leaves
 * @param root       Output buffer (32 bytes) for the Merkle root
 * @return 0 on success, -1 on error
 */
int sha3_merkle_tree4_32(const uint8_t *leaves, size_t num_leaves, uint8_t *root) {
    if (!leaves || !root || num_leaves == 0) return -1;
    merkle_ctx_t ctx;
    ctx.leaf_size = SHA3_256_DIGEST_SIZE;
    ctx.rate      = sha3_get_block_size(SHA3_256);
    ctx.branch    = ctx.rate / ctx.leaf_size;
    ctx.done      = 0;
    ctx.nthreads  = (int)(sysconf(_SC_NPROCESSORS_ONLN) > 0 ?
                       sysconf(_SC_NPROCESSORS_ONLN) : 1);
    pthread_barrier_init(&ctx.barrier, NULL, ctx.nthreads + 1);
    size_t maxp = (num_leaves + ctx.branch - 1) / ctx.branch;
    // Allocate buffers for highest-level node count
    if (posix_memalign((void**)&ctx.buf1, 64, maxp * ctx.leaf_size) != 0 ||
        posix_memalign((void**)&ctx.buf2, 64, maxp * ctx.leaf_size) != 0) {
        free(ctx.buf1); free(ctx.buf2);
        return -1;
    }
    ctx.next = ctx.buf1;
    // Launch persistent workers
    pthread_t threads[ctx.nthreads];
    worker_arg_t args[ctx.nthreads];
    for (int t = 0; t < ctx.nthreads; t++) {
        args[t].ctx = &ctx;
        args[t].tid = t;
        pthread_create(&threads[t], NULL, merkle_worker, &args[t]);
    }
    const uint8_t *cur = leaves;
    uint8_t *swap_buf = ctx.buf2;
    size_t N = num_leaves;
    while (N > 1) {
        ctx.parents = (N + ctx.branch - 1) / ctx.branch;
        ctx.cur     = cur;
        // Phase 1: signal workers to hash this level
        pthread_barrier_wait(&ctx.barrier);
        // Phase 2: wait for workers to finish
        pthread_barrier_wait(&ctx.barrier);
        // Advance to next level
        N   = ctx.parents;
        cur = ctx.next;
        ctx.next = swap_buf;
        swap_buf = (uint8_t*)cur;
    }
    // Copy final root
    memcpy(root, cur, ctx.leaf_size);
    // Shutdown workers
    ctx.done = 1;
    pthread_barrier_wait(&ctx.barrier);
    for (int t = 0; t < ctx.nthreads; t++) pthread_join(threads[t], NULL);
    pthread_barrier_destroy(&ctx.barrier);
    free(ctx.buf1); free(ctx.buf2);
    return 0;
}