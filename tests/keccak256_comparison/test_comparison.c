/* test_comparison.c - Test to compare two Keccak256 implementations */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Include both implementations */
#include "keccak256.h"
#include "sha3.h"

/* Helper function to print hex */
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Helper function to compare two byte arrays */
int compare_hashes(const unsigned char *hash1, const unsigned char *hash2, size_t len) {
    return memcmp(hash1, hash2, len) == 0;
}

/* Test function that hashes input with both implementations */
int test_keccak256(const unsigned char *input, size_t input_len, const char *test_name) {
    unsigned char result1[32];
    unsigned char result2[32];
    
    printf("\n=== Test: %s ===\n", test_name);
    printf("Input length: %zu bytes\n", input_len);
    
    /* Test with keccak256.c (keccak_final) */
    SHA3_CTX ctx1;
    keccak_init(&ctx1);
    keccak_update(&ctx1, input, (uint16_t)input_len);
    keccak_final(&ctx1, result1);
    
    /* Test with sha3.c (rhash_keccak_final) */
    sha3_ctx ctx2;
    rhash_keccak_256_init(&ctx2);
    rhash_keccak_update(&ctx2, input, input_len);
    rhash_keccak_final(&ctx2, result2);
    
    /* Print results */
    print_hex("keccak256.c output", result1, 32);
    print_hex("sha3.c output     ", result2, 32);
    
    /* Compare */
    if (compare_hashes(result1, result2, 32)) {
        printf("✓ PASS: Both implementations produce the same output\n");
        return 1;
    } else {
        printf("✗ FAIL: Outputs differ!\n");
        return 0;
    }
}


/* 
Test cases:

1. Empty string
2. Short string ("abc")
3. Longer sentence
4. Binary data (zeros)
5. Binary data (0xFF)
6. Sequential bytes (0-255)
7. Large input (1000 bytes, multiple blocks)
8. Known test vector ("abc") validation
*/

int main() {
    int passed = 0;
    int total = 0;
    
    printf("========================================\n");
    printf("Keccak256 Implementation Comparison Test\n");
    printf("========================================\n");
    
    /* Test 1: Empty string */
    {
        const unsigned char input[] = "";
        total++;
        if (test_keccak256(input, 0, "Empty string")) passed++;
    }
    
    /* Test 2: Simple short string */
    {
        const unsigned char input[] = "abc";
        total++;
        if (test_keccak256(input, strlen((const char *)input), "Short string 'abc'")) passed++;
    }
    
    /* Test 3: Longer string */
    {
        const unsigned char input[] = "The quick brown fox jumps over the lazy dog";
        total++;
        if (test_keccak256(input, strlen((const char *)input), "Fox and dog sentence")) passed++;
    }
    
    /* Test 4: All zeros */
    {
        unsigned char input[64];
        memset(input, 0, sizeof(input));
        total++;
        if (test_keccak256(input, sizeof(input), "64 bytes of zeros")) passed++;
    }
    
    /* Test 5: All 0xFF */
    {
        unsigned char input[64];
        memset(input, 0xFF, sizeof(input));
        total++;
        if (test_keccak256(input, sizeof(input), "64 bytes of 0xFF")) passed++;
    }
    
    /* Test 6: Sequential bytes */
    {
        unsigned char input[256];
        for (int i = 0; i < 256; i++) {
            input[i] = (unsigned char)i;
        }
        total++;
        if (test_keccak256(input, sizeof(input), "Sequential bytes 0-255")) passed++;
    }
    
    /* Test 7: Large input (multiple blocks) */
    {
        unsigned char input[1000];
        for (int i = 0; i < 1000; i++) {
            input[i] = (unsigned char)(i % 256);
        }
        total++;
        if (test_keccak256(input, sizeof(input), "1000 bytes cycling pattern")) passed++;
    }
    
    /* Test 8: Known test vector - "abc" should give a specific hash */
    {
        const unsigned char input[] = "abc";
        const unsigned char expected[32] = {
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f,
            0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8, 0xd6, 0x67,
            0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36,
            0xec, 0x44, 0xf5, 0x8f, 0xa1, 0x2d, 0x6c, 0x45
        };
        
        unsigned char result1[32];
        unsigned char result2[32];
        
        printf("\n=== Test: Known test vector for 'abc' ===\n");
        
        SHA3_CTX ctx1;
        keccak_init(&ctx1);
        keccak_update(&ctx1, input, strlen((const char *)input));
        keccak_final(&ctx1, result1);
        
        sha3_ctx ctx2;
        rhash_keccak_256_init(&ctx2);
        rhash_keccak_update(&ctx2, input, strlen((const char *)input));
        rhash_keccak_final(&ctx2, result2);
        
        print_hex("Expected         ", expected, 32);
        print_hex("keccak256.c      ", result1, 32);
        print_hex("sha3.c           ", result2, 32);
        
        int match1 = compare_hashes(result1, expected, 32);
        int match2 = compare_hashes(result2, expected, 32);
        
        total++;
        if (match1 && match2 && compare_hashes(result1, result2, 32)) {
            printf("✓ PASS: Both match known test vector\n");
            passed++;
        } else {
            printf("✗ FAIL: ");
            if (!match1) printf("keccak256.c doesn't match expected. ");
            if (!match2) printf("sha3.c doesn't match expected. ");
            if (!compare_hashes(result1, result2, 32)) printf("Implementations differ. ");
            printf("\n");
        }
    }
    
    /* Summary */
    printf("\n========================================\n");
    printf("Test Summary: %d/%d tests passed\n", passed, total);
    printf("========================================\n");
    
    if (passed == total) {
        printf("✓ All tests PASSED! The implementations are compatible.\n");
        return 0;
    } else {
        printf("✗ Some tests FAILED! The implementations may not be compatible.\n");
        return 1;
    }
}

