// SPDX-License-Identifier: MIT

#if defined(_WIN32)
#pragma warning(disable : 4244 4293)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>
#include <oqs/rand_nist.h>

#include "system_info.c"
#include "test_helpers.h"

// Add extern declarations for direct access to implementations.
// This is used to test different optimizations do not lead to different
// keypairs being generated from the same seed.
// Falcon 512
#if defined(OQS_ENABLE_SIG_falcon_512)
// Declare CLEAN implementation functions
extern int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_with_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES 897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES 1281

#if defined(OQS_ENABLE_SIG_falcon_512_avx2)
// Declare AVX2 implementation functions
extern int PQCLEAN_FALCON512_AVX2_crypto_sign_keypair_with_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
#define PQCLEAN_FALCON512_AVX2_CRYPTO_PUBLICKEYBYTES 897
#define PQCLEAN_FALCON512_AVX2_CRYPTO_SECRETKEYBYTES 1281
#endif
#endif

// FAlcon padded 512
#if defined(OQS_ENABLE_SIG_falcon_padded_512)
// Declare CLEAN implementation functions
extern int PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair_with_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES 897
#define PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES 1281

#if defined(OQS_ENABLE_SIG_falcon_padded_512_avx2)
// Declare AVX2 implementation functions
extern int PQCLEAN_FALCONPADDED512_AVX2_crypto_sign_keypair_with_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
#define PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_PUBLICKEYBYTES 897
#define PQCLEAN_FALCONPADDED512_AVX2_CRYPTO_SECRETKEYBYTES 1281
#endif
#endif

static OQS_STATUS test_keypair_with_seed_twice(const char *method_name) {
	OQS_SIG *sig = NULL;
	uint8_t *public_key1 = NULL;
	uint8_t *secret_key1 = NULL;
	uint8_t *public_key2 = NULL;
	uint8_t *secret_key2 = NULL;
	uint8_t seed[48];
	OQS_STATUS rc;
	OQS_KAT_PRNG *prng = NULL;
	uint8_t entropy_input[48];

	// Initialize
	sig = OQS_SIG_new(method_name);
	if (sig == NULL) {
		fprintf(stderr, "[test_keypair_seeded_twice] %s was not enabled at compile-time.\n", method_name);
		return OQS_ERROR;
	}

	// Check if keypair_with_seed is available
	if (sig->keypair_with_seed == NULL) {
		fprintf(stderr, "[test_keypair_seeded_twice] %s does not support keypair_with_seed.\n", method_name);
		OQS_SIG_free(sig);
		return OQS_ERROR;
	}

	// Setup KAT PRNG (same as kat_sig.c)
	prng = OQS_KAT_PRNG_new(method_name);
	if (prng == NULL) {
		fprintf(stderr, "[test_keypair_seeded_twice] Failed to create KAT PRNG.\n");
		OQS_SIG_free(sig);
		return OQS_ERROR;
	}

	// Initialize entropy input (same as kat_sig.c)
	for (uint8_t i = 0; i < 48; i++) {
		entropy_input[i] = i;
	}
	OQS_KAT_PRNG_seed(prng, entropy_input, NULL);

	// Allocate memory for first keypair
	public_key1 = OQS_MEM_malloc(sig->length_public_key);
	secret_key1 = OQS_MEM_malloc(sig->length_secret_key);
	if ((public_key1 == NULL) || (secret_key1 == NULL)) {
		fprintf(stderr, "[test_keypair_seeded_twice] OQS_MEM_malloc failed for first keypair\n");
		goto err;
	}

	// Allocate memory for second keypair
	public_key2 = OQS_MEM_malloc(sig->length_public_key);
	secret_key2 = OQS_MEM_malloc(sig->length_secret_key);
	if ((public_key2 == NULL) || (secret_key2 == NULL)) {
		fprintf(stderr, "[test_keypair_seeded_twice] OQS_MEM_malloc failed for second keypair\n");
		goto err;
	}

	// Generate a deterministic seed using KAT PRNG
	OQS_randombytes(seed, 48);

	printf("================================================================================\n");
	printf("Testing %s keypair_with_seed determinism\n", method_name);
	printf("Version source: %s\n", sig->alg_version);
	printf("================================================================================\n");
	printf("Generated seed (48 bytes):\n");
	for (size_t i = 0; i < 48; i++) {
		printf("%02x", seed[i]);
	}
	printf("\n\n");

	// First keypair generation
	printf("Generating first keypair with seed...\n");
	rc = OQS_SIG_keypair_with_seed(sig, public_key1, secret_key1, seed);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "[test_keypair_seeded_twice] First OQS_SIG_keypair_with_seed failed\n");
		goto err;
	}
	printf("First keypair generated successfully.\n\n");

	// Second keypair generation with the same seed
	printf("Generating second keypair with same seed...\n");
	rc = OQS_SIG_keypair_with_seed(sig, public_key2, secret_key2, seed);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "[test_keypair_seeded_twice] Second OQS_SIG_keypair_with_seed failed\n");
		goto err;
	}
	printf("Second keypair generated successfully.\n\n");

	// Compare public keys
	printf("Comparing public keys...\n");
	if (memcmp(public_key1, public_key2, sig->length_public_key) == 0) {
		printf("✓ Public keys match!\n");
	} else {
		fprintf(stderr, "✗ Public keys do NOT match!\n");
		goto err;
	}

	// Compare secret keys
	printf("Comparing secret keys...\n");
	if (memcmp(secret_key1, secret_key2, sig->length_secret_key) == 0) {
		printf("✓ Secret keys match!\n");
	} else {
		fprintf(stderr, "✗ Secret keys do NOT match!\n");
		goto err;
	}

	printf("\n================================================================================\n");
	printf("SUCCESS: Both keypairs are identical - keypair_with_seed is deterministic!\n");
	printf("================================================================================\n");

	// Cleanup
	OQS_MEM_secure_free(secret_key1, sig->length_secret_key);
	OQS_MEM_secure_free(secret_key2, sig->length_secret_key);
	OQS_MEM_insecure_free(public_key1);
	OQS_MEM_insecure_free(public_key2);
	OQS_KAT_PRNG_free(prng);
	OQS_SIG_free(sig);
	return OQS_SUCCESS;

err:
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key1, sig->length_secret_key);
		OQS_MEM_secure_free(secret_key2, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key1);
	OQS_MEM_insecure_free(public_key2);
	OQS_KAT_PRNG_free(prng);
	OQS_SIG_free(sig);
	return OQS_ERROR;
}

static OQS_STATUS test_other_algorithms_return_error(void) {
	// Test a few algorithms that don't support keypair_with_seed
	const char *test_algorithms[] = {
		"ML-DSA-44",
		"ML-DSA-65", 
		"SPHINCS+-SHA2-128f-simple",
		NULL  // Sentinel
	};
	
	uint8_t dummy_seed[48] = {0};  // Dummy seed
	uint8_t dummy_pk[2048];  // Large enough for any algorithm
	uint8_t dummy_sk[4096];  // Large enough for any algorithm
	
	printf("\n================================================================================\n");
	printf("Testing that other algorithms return error for keypair_with_seed\n");
	printf("================================================================================\n");
	
	for (size_t i = 0; test_algorithms[i] != NULL; i++) {
		const char *alg_name = test_algorithms[i];
		OQS_SIG *sig = OQS_SIG_new(alg_name);
		
		if (sig == NULL) {
			printf("[test_other_algorithms] %s not enabled, skipping...\n", alg_name);
			continue;
		}
		
		printf("Testing %s...\n", alg_name);
		
		// Allocate proper sizes
		uint8_t *pk = OQS_MEM_malloc(sig->length_public_key);
		uint8_t *sk = OQS_MEM_malloc(sig->length_secret_key);
		
		if (pk == NULL || sk == NULL) {
			fprintf(stderr, "[test_other_algorithms] Memory allocation failed for %s\n", alg_name);
			OQS_SIG_free(sig);
			continue;
		}
		
		// Test that keypair_with_seed returns error
		OQS_STATUS rc = OQS_SIG_keypair_with_seed(sig, pk, sk, dummy_seed);
		
		if (rc == OQS_ERROR) {
			printf("  ✓ %s correctly returns OQS_ERROR (as expected)\n", alg_name);
		} else {
			fprintf(stderr, "  ✗ %s returned OQS_SUCCESS (expected OQS_ERROR!)\n", alg_name);
			OQS_MEM_insecure_free(pk);
			OQS_MEM_secure_free(sk, sig->length_secret_key);
			OQS_SIG_free(sig);
			return OQS_ERROR;
		}
		
		OQS_MEM_insecure_free(pk);
		OQS_MEM_secure_free(sk, sig->length_secret_key);
		OQS_SIG_free(sig);
	}
	
	printf("\n================================================================================\n");
	printf("SUCCESS: All other algorithms correctly return error for keypair_with_seed\n");
	printf("================================================================================\n");
	
	return OQS_SUCCESS;
}

static OQS_STATUS test_clean_vs_avx2_keypair_consistency(const char *method_name) {
#if !defined(OQS_ENABLE_SIG_falcon_512)
	printf("[test_clean_vs_avx2] Falcon-512 not enabled, skipping...\n");
	return OQS_SUCCESS;
#elif !defined(OQS_ENABLE_SIG_falcon_512_avx2)
	printf("[test_clean_vs_avx2] Falcon-512 AVX2 not enabled, skipping...\n");
	return OQS_SUCCESS;
#else
	uint8_t seed[48];
	uint8_t pk_clean[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
	uint8_t sk_clean[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
	uint8_t pk_avx2[PQCLEAN_FALCON512_AVX2_CRYPTO_PUBLICKEYBYTES];
	uint8_t sk_avx2[PQCLEAN_FALCON512_AVX2_CRYPTO_SECRETKEYBYTES];
	OQS_KAT_PRNG *prng = NULL;
	uint8_t entropy_input[48];
	int rc_clean, rc_avx2;

	// Setup KAT PRNG for deterministic seed generation
	prng = OQS_KAT_PRNG_new(method_name);
	if (prng == NULL) {
		fprintf(stderr, "[test_clean_vs_avx2] Failed to create KAT PRNG.\n");
		return OQS_ERROR;
	}

	// Initialize entropy input
	for (uint8_t i = 0; i < 48; i++) {
		entropy_input[i] = i;
	}
	OQS_KAT_PRNG_seed(prng, entropy_input, NULL);

	// Generate a deterministic seed
	OQS_randombytes(seed, 48);

	printf("\n================================================================================\n");
	printf("Testing CLEAN vs AVX2 keypair consistency for %s\n", method_name);
	printf("================================================================================\n");
	printf("Using seed (48 bytes):\n");
	for (size_t i = 0; i < 48; i++) {
		printf("%02x", seed[i]);
	}
	printf("\n\n");

	// Generate keypair using CLEAN implementation
	printf("Generating keypair with CLEAN implementation...\n");
	rc_clean = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_with_seed(pk_clean, sk_clean, seed);
	if (rc_clean != 0) {
		fprintf(stderr, "[test_clean_vs_avx2] CLEAN keypair generation failed (returned %d)\n", rc_clean);
		OQS_KAT_PRNG_free(prng);
		return OQS_ERROR;
	}
	printf("CLEAN keypair generated successfully.\n\n");

	// Generate keypair using AVX2 implementation
	printf("Generating keypair with AVX2 implementation...\n");
	rc_avx2 = PQCLEAN_FALCON512_AVX2_crypto_sign_keypair_with_seed(pk_avx2, sk_avx2, seed);
	if (rc_avx2 != 0) {
		fprintf(stderr, "[test_clean_vs_avx2] AVX2 keypair generation failed (returned %d)\n", rc_avx2);
		OQS_KAT_PRNG_free(prng);
		return OQS_ERROR;
	}
	printf("AVX2 keypair generated successfully.\n\n");

	// Compare public keys
	printf("Comparing public keys...\n");
	if (memcmp(pk_clean, pk_avx2, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES) == 0) {
		printf("✓ Public keys match!\n");
	} else {
		fprintf(stderr, "✗ Public keys do NOT match!\n");
		printf("CLEAN public key (first 32 bytes):\n");
		for (size_t i = 0; i < 32 && i < PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES; i++) {
			printf("%02x", pk_clean[i]);
		}
		printf("\nAVX2 public key (first 32 bytes):\n");
		for (size_t i = 0; i < 32 && i < PQCLEAN_FALCON512_AVX2_CRYPTO_PUBLICKEYBYTES; i++) {
			printf("%02x", pk_avx2[i]);
		}
		printf("\n");
		OQS_KAT_PRNG_free(prng);
		return OQS_ERROR;
	}

	// Compare secret keys
	printf("Comparing secret keys...\n");
	if (memcmp(sk_clean, sk_avx2, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES) == 0) {
		printf("✓ Secret keys match!\n");
	} else {
		fprintf(stderr, "✗ Secret keys do NOT match!\n");
		printf("CLEAN secret key (first 32 bytes):\n");
		for (size_t i = 0; i < 32 && i < PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES; i++) {
			printf("%02x", sk_clean[i]);
		}
		printf("\nAVX2 secret key (first 32 bytes):\n");
		for (size_t i = 0; i < 32 && i < PQCLEAN_FALCON512_AVX2_CRYPTO_SECRETKEYBYTES; i++) {
			printf("%02x", sk_avx2[i]);
		}
		printf("\n");
		OQS_KAT_PRNG_free(prng);
		return OQS_ERROR;
	}

	printf("\n================================================================================\n");
	printf("SUCCESS: CLEAN and AVX2 implementations produce identical keypairs!\n");
	printf("================================================================================\n");

	OQS_KAT_PRNG_free(prng);
	return OQS_SUCCESS;
#endif
}

int main(void) {
	OQS_init();

	print_system_info();

	// List of algorithms to test
	const char *falcon_algorithms[] = {
		"Falcon-512",
		"Falcon-padded-512",
		NULL  // Sentinel
	};

	OQS_STATUS overall_result = OQS_SUCCESS;

	// Test each Falcon variant (Falcon-512 and Falcon-padded-512)
	for (size_t i = 0; falcon_algorithms[i] != NULL; i++) {
		const char *alg_name = falcon_algorithms[i];
		
		printf("\n\n");
		printf("################################################################################\n");
		printf("## Testing algorithm: %s\n", alg_name);
		printf("################################################################################\n\n");

		// Test keypair_with_seed twice
		OQS_STATUS rc1 = test_keypair_with_seed_twice(alg_name);
		if (rc1 != OQS_SUCCESS) {
			overall_result = OQS_ERROR;
			fprintf(stderr, "FAILED: %s keypair_with_seed determinism test\n", alg_name);
		}

		// Test CLEAN vs AVX2 consistency
		OQS_STATUS rc2 = test_clean_vs_avx2_keypair_consistency(alg_name);
		if (rc2 != OQS_SUCCESS) {
			overall_result = OQS_ERROR;
			fprintf(stderr, "FAILED: %s CLEAN vs AVX2 consistency test\n", alg_name);
		}
	}

	// Test other algorithms (should return error)
	OQS_STATUS rc_other = test_other_algorithms_return_error();
	if (rc_other != OQS_SUCCESS) {
		overall_result = OQS_ERROR;
	}

	printf("\n\n");
	printf("################################################################################\n");
	if (overall_result == OQS_SUCCESS) {
		printf("## ALL TESTS PASSED\n");
	} else {
		printf("## SOME TESTS FAILED\n");
	}
	printf("################################################################################\n");

	OQS_destroy();
	return (overall_result == OQS_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}