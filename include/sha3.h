/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
/**
 * @file sha3.h
 * @brief Implementation of SHA-3 hash functions with support for integration with other protocols
 *
 * This library implements the SHA-3 family (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256)
 * of hash functions, designed to provide a modern cryptographic hash function interface.
 */

#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Hash function types supported by this library */
typedef enum {
    SHA3_224 = 0,    /**< SHA3-224 hash function */
    SHA3_256 = 1,    /**< SHA3-256 hash function */
    SHA3_384 = 2,    /**< SHA3-384 hash function */
    SHA3_512 = 3,    /**< SHA3-512 hash function */
    SHAKE_128 = 4,   /**< SHAKE128 extendable output function */
    SHAKE_256 = 5    /**< SHAKE256 extendable output function */
} sha3_hash_type;

/** Output size of each hash function in bytes */
#define SHA3_224_DIGEST_SIZE 28
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_512_DIGEST_SIZE 64

/** Maximum digest size among all supported hash functions */
#define SHA3_MAX_DIGEST_SIZE 64

/** Block size (rate) of each hash function in bytes */
#define SHA3_224_BLOCK_SIZE 144
#define SHA3_256_BLOCK_SIZE 136
#define SHA3_384_BLOCK_SIZE 104
#define SHA3_512_BLOCK_SIZE 72
#define SHAKE_128_BLOCK_SIZE 168
#define SHAKE_256_BLOCK_SIZE 136

/** Maximum block size among all supported hash functions */
#define SHA3_MAX_BLOCK_SIZE 168

/**
 * @struct sha3_ctx
 * @brief Context structure for SHA-3 hash functions
 * 
 * This structure contains the state for a hashing operation.
 * It is designed to be opaque to users, with internal fields
 * depending on the specific hash variant.
 */
typedef struct __attribute__((aligned(64))) {
    sha3_hash_type type;          /**< Type of hash function */
    uint64_t state[25];           /**< State for SHA3 (Keccak-f[1600]) */
    uint8_t buffer[200];          /**< Buffer for SHA3 input */
    size_t buffer_pos;            /**< Current position in buffer */
    size_t rate;                  /**< Rate in bytes (200 - capacity/8) */
    uint8_t domain_suffix;        /**< Domain separation suffix */
} sha3_ctx;

/**
 * @brief Initialize the hash context for a specific hash algorithm
 *
 * @param ctx Pointer to the hash context to initialize
 * @param type Type of hash function to use
 * @return 0 on success, -1 on error
 */
int sha3_init(sha3_ctx *ctx, sha3_hash_type type);

/**
 * @brief Update the hash context with new data
 *
 * @param ctx Pointer to the hash context
 * @param data Pointer to the data to hash
 * @param len Length of the data in bytes
 * @return 0 on success, -1 on error
 */
int sha3_update(sha3_ctx *ctx, const void *data, size_t len);

/**
 * @brief Finalize the hash and get the digest
 *
 * @param ctx Pointer to the hash context
 * @param digest Pointer to buffer to receive the digest
 * @param digest_size Size of the digest buffer in bytes
 * @return Number of bytes written to digest on success, -1 on error
 */
int sha3_final(sha3_ctx *ctx, void *digest, size_t digest_size);

/**
 * @brief Compute hash in one operation
 *
 * If compiled with GCC/Clang on x86-64, hashing exactly 64-byte inputs for
 * SHA3-256 or SHA3-512 triggers runtime CPU feature detection via
 * __builtin_cpu_supports():
 *   - AVX-512F support selects sha3_hash_<type>_64B_avx512
 *   - AVX2 support selects sha3_hash_<type>_64B_avx2
 * Otherwise, falls back to the portable C implementation.
 *
 * @param type Type of hash function to use
 * @param data Pointer to the data to hash
 * @param len Length of the data in bytes
 * @param digest Pointer to buffer to receive the digest
 * @param digest_size Size of the digest buffer in bytes
 * @return Number of bytes written to digest on success, -1 on error
 */
int sha3_hash(sha3_hash_type type, const void *data, size_t len, void *digest, size_t digest_size);

/**
 * @brief Get the digest size for a hash type
 *
 * @param type Type of hash function
 * @return Size of the digest in bytes, or 0 if unknown
 */
size_t sha3_get_digest_size(sha3_hash_type type);

/**
 * @brief Get the block size for a hash type
 *
 * @param type Type of hash function
 * @return Size of the block in bytes, or 0 if unknown
 */
size_t sha3_get_block_size(sha3_hash_type type);

/**
 * @brief Library information
 *
 * @return Version string for the library
 */
const char* sha3_version(void);

/**
 * @brief Generate arbitrary-length output using SHAKE
 *
 * @param type SHAKE type (SHAKE_128 or SHAKE_256)
 * @param data Input data
 * @param len Length of input data in bytes
 * @param output Buffer to receive output
 * @param output_len Desired output length in bytes
 * @return Number of bytes written to output on success, -1 on error
 */
int shake_xof(sha3_hash_type type, const void *data, size_t len, void *output, size_t output_len);

#ifdef __GNUC__
/**
 * @brief Specialized AVX2-optimized SHA3-256 for 64-byte input batches
 * @param data Pointer to 64-byte input
 * @param len Input length (must be 64)
 * @param digest Pointer to output buffer
 * @param digest_size Size of digest buffer (>= SHA3_256_DIGEST_SIZE)
 * @return Number of bytes written to digest on success, -1 on error
 */
int sha3_hash_256_64B_avx2(const void *data, size_t len, void *digest, size_t digest_size);
/**
 * @brief AVX2 4-way SHA3-512 for 64-byte inputs (specialized hot path)
 */
int sha3_hash_512_64B_avx2(const void *data, size_t len, void *digest, size_t digest_size);
#endif
//# AVX-512F specialized path for 64B SHA3-256
#ifdef __GNUC__
/**
 * @brief Specialized AVX-512F single-state SHA3-256 for 64-byte input batches
 * @param data Pointer to 64-byte input
 * @param len Input length (must be 64)
 * @param digest Pointer to output buffer
 * @param digest_size Size of digest buffer (>= SHA3_256_DIGEST_SIZE)
 * @return Number of bytes written to digest on success, -1 on error
 */
int sha3_hash_256_64B_avx512(const void *data, size_t len, void *digest, size_t digest_size);
/**
 * @brief AVX-512F single-state SHA3-512 for 64-byte inputs
 */
int sha3_hash_512_64B_avx512(const void *data, size_t len, void *digest, size_t digest_size);
/**
 * @brief AVX-512F 8-way SHA3-256 for 64-byte input batches (times-8 kernel)
 */
int sha3_hash_256_64B_avx512_times8(const void *data, size_t len, void *digest, size_t digest_size);
/**
 * @brief AVX-512F 8-way SHA3-512 for 64-byte inputs (times-8 SIMD512)
 */
int sha3_hash_512_64B_avx512_times8(const void *data, size_t len, void *digest, size_t digest_size);
#endif

/*
 * HashFunction interface for pluggable hash functions
 */

/**
 * @struct sha3_hash_function
 * @brief Interface for pluggable hash functions
 * 
 * This structure provides a generic interface for hash functions
 * that can be used with other libraries.
 */
typedef struct sha3_hash_function {
    /** Initialize the hash context */
    int (*init)(void *ctx);
    
    /** Update the hash context with new data */
    int (*update)(void *ctx, const void *data, size_t len);
    
    /** Finalize the hash and get the digest */
    int (*final)(void *ctx, void *digest, size_t digest_size);
    
    /** Size of the hash context structure */
    size_t ctx_size;
    
    /** Size of the digest output */
    size_t digest_size;
    
    /** Human-readable name of the hash function */
    const char *name;
} sha3_hash_function;

/**
 * @brief Get a hash function instance by type
 *
 * @param type Type of hash function
 * @return Pointer to hash function instance, or NULL if unsupported
 */
const sha3_hash_function* sha3_get_hash_function(sha3_hash_type type);

/**
 * @brief Create a new hash function instance with default values
 * 
 * @param name Human-readable name of the hash function
 * @param ctx_size Size of the hash context structure
 * @param digest_size Size of the digest output
 * @param init Initialize function
 * @param update Update function
 * @param final Finalize function
 * @return Pointer to newly allocated hash function instance, or NULL on error
 */
sha3_hash_function* sha3_create_hash_function(
    const char *name,
    size_t ctx_size,
    size_t digest_size,
    int (*init)(void *ctx),
    int (*update)(void *ctx, const void *data, size_t len),
    int (*final)(void *ctx, void *digest, size_t digest_size)
);

/**
 * @brief Free a hash function instance created with sha3_create_hash_function
 * 
 * @param hash_func Pointer to hash function instance to free
 */
void sha3_free_hash_function(sha3_hash_function *hash_func);

#ifdef __cplusplus
}
#endif

#endif /* SHA3_H */
  
// blank line to ensure newline at end-of-file
