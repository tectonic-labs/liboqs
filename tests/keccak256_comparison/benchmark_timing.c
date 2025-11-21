/* benchmark_timing.c - Performance comparison of two Keccak256 implementations */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

/* Include both implementations */
#include "keccak256.h"
#include "sha3.h"

/* Statistics tracking */
typedef struct {
    size_t data_size;
    int iterations;
    double time_keccak256;
    double time_sha3;
    double speedup_ratio;  /* > 1.0 means sha3 faster, < 1.0 means keccak256 faster */
    int winner;  /* 0 = tie, 1 = keccak256, 2 = sha3 */
} benchmark_result;

#define MAX_BENCHMARKS 20
static benchmark_result results[MAX_BENCHMARKS];
static int num_results = 0;

/* High-resolution timing */
static double get_time_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Benchmark function for keccak256.c implementation */
static double benchmark_keccak256(const unsigned char *data, size_t len, int iterations) {
    unsigned char result[32];
    double start, end;
    
    start = get_time_seconds();
    for (int i = 0; i < iterations; i++) {
        SHA3_CTX ctx;
        keccak_init(&ctx);
        
        /* keccak_update only accepts uint16_t, so we need to chunk large inputs */
        size_t remaining = len;
        const unsigned char *ptr = data;
        while (remaining > 0) {
            size_t chunk_size = remaining > 65535 ? 65535 : remaining;
            keccak_update(&ctx, ptr, (uint16_t)chunk_size);
            ptr += chunk_size;
            remaining -= chunk_size;
        }
        
        keccak_final(&ctx, result);
    }
    end = get_time_seconds();
    
    return end - start;
}

/* Benchmark function for sha3.c implementation */
static double benchmark_sha3(const unsigned char *data, size_t len, int iterations) {
    unsigned char result[32];
    double start, end;
    
    start = get_time_seconds();
    for (int i = 0; i < iterations; i++) {
        sha3_ctx ctx;
        rhash_keccak_256_init(&ctx);
        rhash_keccak_update(&ctx, data, len);
        rhash_keccak_final(&ctx, result);
    }
    end = get_time_seconds();
    
    return end - start;
}

/* Run benchmark for a given size */
static void run_benchmark(size_t data_size, int iterations) {
    unsigned char *data = malloc(data_size);
    if (!data) {
        fprintf(stderr, "Failed to allocate memory for benchmark\n");
        return;
    }
    
    /* Fill with pseudo-random data */
    for (size_t i = 0; i < data_size; i++) {
        data[i] = (unsigned char)(i * 7919 % 256);
    }
    
    printf("\n=== Benchmark: %zu bytes, %d iterations ===\n", data_size, iterations);
    
    /* Benchmark keccak256.c */
    double time1 = benchmark_keccak256(data, data_size, iterations);
    double throughput1 = (data_size * iterations) / (time1 * 1024.0 * 1024.0);
    
    /* Benchmark sha3.c */
    double time2 = benchmark_sha3(data, data_size, iterations);
    double throughput2 = (data_size * iterations) / (time2 * 1024.0 * 1024.0);
    
    /* Results */
    printf("keccak256.c: %.6f seconds (%.2f MB/s)\n", time1, throughput1);
    printf("sha3.c:      %.6f seconds (%.2f MB/s)\n", time2, throughput2);
    
    /* Comparison */
    double ratio = time1 / time2;
    int winner;
    
    if (ratio > 1.05) {
        printf("Result: sha3.c is %.2fx faster\n", ratio);
        winner = 2;
    } else if (ratio < 0.95) {
        printf("Result: keccak256.c is %.2fx faster\n", 1.0 / ratio);
        winner = 1;
    } else {
        printf("Result: Both implementations have similar performance\n");
        winner = 0;
    }
    
    /* Store results for summary */
    if (num_results < MAX_BENCHMARKS) {
        results[num_results].data_size = data_size;
        results[num_results].iterations = iterations;
        results[num_results].time_keccak256 = time1;
        results[num_results].time_sha3 = time2;
        results[num_results].speedup_ratio = ratio;
        results[num_results].winner = winner;
        num_results++;
    }
    
    free(data);
}

/* Warmup to stabilize CPU frequency */
static void warmup(void) {
    unsigned char data[1024];
    unsigned char result[32];
    
    for (int i = 0; i < 1000; i++) {
        SHA3_CTX ctx;
        keccak_init(&ctx);
        keccak_update(&ctx, data, sizeof(data));
        keccak_final(&ctx, result);
    }
}

int main() {
    printf("========================================\n");
    printf("Keccak256 Performance Comparison\n");
    printf("========================================\n");
    
    printf("\nWarming up CPU...\n");
    warmup();
    
    /* Small messages - more iterations */
    run_benchmark(16, 100000);      /* 16 bytes */
    run_benchmark(64, 100000);      /* 64 bytes */
    run_benchmark(256, 50000);      /* 256 bytes */
    
    /* Medium messages */
    run_benchmark(1024, 10000);     /* 1 KB */
    run_benchmark(4096, 5000);      /* 4 KB */
    
    /* Large messages */
    run_benchmark(16384, 1000);     /* 16 KB */
    run_benchmark(65536, 500);      /* 64 KB */
    run_benchmark(1048576, 100);    /* 1 MB */
    
    /* Single block (exactly rate size for Keccak256) */
    printf("\n=== Special Case: Single Block (136 bytes) ===\n");
    run_benchmark(136, 50000);
    
    /* Multiple blocks */
    printf("\n=== Special Case: Multiple Blocks (272 bytes) ===\n");
    run_benchmark(272, 50000);
    
    printf("\n========================================\n");
    printf("Summary Statistics\n");
    printf("========================================\n");
    
    /* Calculate statistics */
    int keccak256_wins = 0;
    int sha3_wins = 0;
    int ties = 0;
    double keccak256_speedup_sum = 0.0;
    double sha3_speedup_sum = 0.0;
    
    for (int i = 0; i < num_results; i++) {
        if (results[i].winner == 1) {
            keccak256_wins++;
            keccak256_speedup_sum += (1.0 / results[i].speedup_ratio);
        } else if (results[i].winner == 2) {
            sha3_wins++;
            sha3_speedup_sum += results[i].speedup_ratio;
        } else {
            ties++;
        }
    }
    
    printf("\nTotal benchmarks: %d\n", num_results);
    printf("  keccak256.c wins: %d\n", keccak256_wins);
    printf("  sha3.c wins:      %d\n", sha3_wins);
    printf("  Ties:             %d\n", ties);
    
    if (keccak256_wins > 0) {
        double mean_speedup = keccak256_speedup_sum / keccak256_wins;
        printf("\nkeccak256.c average speedup (when faster): %.2fx\n", mean_speedup);
    }
    
    if (sha3_wins > 0) {
        double mean_speedup = sha3_speedup_sum / sha3_wins;
        printf("sha3.c average speedup (when faster):      %.2fx\n", mean_speedup);
    }
    
    /* Overall winner */
    printf("\n");
    if (sha3_wins > keccak256_wins) {
        printf("🏆 Overall: sha3.c is faster in most cases (%d/%d tests)\n", 
               sha3_wins, num_results);
    } else if (keccak256_wins > sha3_wins) {
        printf("🏆 Overall: keccak256.c is faster in most cases (%d/%d tests)\n", 
               keccak256_wins, num_results);
    } else {
        printf("🤝 Overall: Both implementations are equally competitive\n");
    }
    
    printf("\n========================================\n");
    printf("Benchmark Complete\n");
    printf("========================================\n");
    
    printf("\nNote: Performance may vary based on:\n");
    printf("  - CPU frequency scaling\n");
    printf("  - System load\n");
    printf("  - Compiler optimizations\n");
    printf("  - Cache effects\n");
    
    return 0;
}

