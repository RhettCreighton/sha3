/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Rhett Creighton */
#include "sha3.h"
#include <stdio.h>
#include <string.h>

/* Utility function to print a digest as hex */
static void print_output(const char *label, const uint8_t *output, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
}

int main() {
    uint8_t output[128]; /* Variable-length output */
    const char *data = "Hello, SHAKE!";
    const size_t data_len = strlen(data);
    
    printf("SHAKE Example (Extendable Output Function)\n");
    printf("------------------------------------------\n");
    printf("Input data: \"%s\"\n\n", data);
    
    /* SHAKE128 with different output lengths */
    shake_xof(SHAKE_128, data, data_len, output, 32);
    print_output("SHAKE128", output, 32);
    
    shake_xof(SHAKE_128, data, data_len, output, 64);
    print_output("SHAKE128", output, 64);
    
    /* SHAKE256 with different output lengths */
    shake_xof(SHAKE_256, data, data_len, output, 32);
    print_output("SHAKE256", output, 32);
    
    shake_xof(SHAKE_256, data, data_len, output, 64);
    print_output("SHAKE256", output, 64);
    
    /* Longer output example */
    shake_xof(SHAKE_256, data, data_len, output, 128);
    print_output("SHAKE256", output, 128);
    
    printf("\nNote: SHAKE functions can generate output of arbitrary length\n");
    
    return 0;
}