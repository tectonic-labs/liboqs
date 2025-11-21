/* keccak256.h - Keccak256 hash implementation header */
#ifndef KECCAK256_H
#define KECCAK256_H

#include <stdint.h>
#include <stddef.h>

#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords 24

/**
 * Keccak256 Algorithm context.
 */
typedef struct SHA3_CTX
{
    /* 1600 bits algorithm hashing state */
    uint64_t hash[sha3_max_permutation_size];
    /* 1536-bit buffer for leftovers */
    uint64_t message[sha3_max_rate_in_qwords];
    /* count of bytes in the message[] buffer */
    unsigned rest;
} SHA3_CTX;

/* methods for calculating the hash function */
void keccak_init(SHA3_CTX *ctx);
void keccak_update(SHA3_CTX *ctx, const unsigned char *msg, uint16_t size);
void keccak_final(SHA3_CTX *ctx, unsigned char* result);

#endif /* KECCAK256_H */


