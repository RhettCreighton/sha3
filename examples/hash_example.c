/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#include "sha3.h"
#include <stdio.h>
#include <string.h>

/* Utility function to print a digest as hex */
static void print_digest(const char *label, const uint8_t *digest, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

int main() {
    uint8_t digest[SHA3_MAX_DIGEST_SIZE];
    sha3_ctx ctx;
    const char *data = "Hello, SHA-3!";
    const size_t data_len = strlen(data);
    
    printf("SHA-3 Hash Example\n");
    printf("------------------\n");
    printf("Input data: \"%s\"\n\n", data);
    
    /* SHA3-224 one-shot */
    sha3_hash(SHA3_224, data, data_len, digest, SHA3_224_DIGEST_SIZE);
    print_digest("SHA3-224", digest, SHA3_224_DIGEST_SIZE);
    
    /* SHA3-256 one-shot */
    sha3_hash(SHA3_256, data, data_len, digest, SHA3_256_DIGEST_SIZE);
    print_digest("SHA3-256", digest, SHA3_256_DIGEST_SIZE);
    
    /* SHA3-384 one-shot */
    sha3_hash(SHA3_384, data, data_len, digest, SHA3_384_DIGEST_SIZE);
    print_digest("SHA3-384", digest, SHA3_384_DIGEST_SIZE);
    
    /* SHA3-512 one-shot */
    sha3_hash(SHA3_512, data, data_len, digest, SHA3_512_DIGEST_SIZE);
    print_digest("SHA3-512", digest, SHA3_512_DIGEST_SIZE);
    
    printf("\nIncremental Hashing Example\n");
    printf("--------------------------\n");
    
    /* SHA3-256 incremental */
    sha3_init(&ctx, SHA3_256);
    sha3_update(&ctx, "Hello, ", 7);
    sha3_update(&ctx, "SHA-3!", 6);
    sha3_final(&ctx, digest, SHA3_256_DIGEST_SIZE);
    print_digest("SHA3-256 (incremental)", digest, SHA3_256_DIGEST_SIZE);
    
    /* Library information */
    printf("\nLibrary version: %s\n", sha3_version());
    
    return 0;
}