# Keccak256 Implementation Comparison Test

This directory contains a test suite to compare two different Keccak256 implementations:

1. **keccak256.c** - A compact implementation from Ethfalcon C reference code https://github.com/zhenfeizhang/falcon-go/blob/main/c/keccak256.c
2. **sha3.c** - The RHash library implementation (https://github.com/rhash/RHash)

## Purpose

The two implementations above are functionally equivalent. The purpose of these tests is twofold:
1. Correctness: verify that both implementations produce identical outputs for the same inputs;
2. Benchmarks: run benchmarks to assess which implementation is faster.

## Building and Running

### Using Make

```bash
make            # Build the test
make run        # Build and run the correctness tests
make benchmark  # Build and run benchmarks
make clean      # Clean build artifacts
```

### Benchmark results

```
========================================
Keccak256 Performance Comparison
========================================

Warming up CPU...

=== Benchmark: 16 bytes, 100000 iterations ===
keccak256.c: 0.237102 seconds (6.44 MB/s)
sha3.c:      0.039659 seconds (38.48 MB/s)
Result: sha3.c is 5.98x faster

=== Benchmark: 64 bytes, 100000 iterations ===
keccak256.c: 0.267137 seconds (22.85 MB/s)
sha3.c:      0.044558 seconds (136.98 MB/s)
Result: sha3.c is 6.00x faster

=== Benchmark: 256 bytes, 50000 iterations ===
keccak256.c: 0.253298 seconds (48.19 MB/s)
sha3.c:      0.047068 seconds (259.35 MB/s)
Result: sha3.c is 5.38x faster

=== Benchmark: 1024 bytes, 10000 iterations ===
keccak256.c: 0.202313 seconds (48.27 MB/s)
sha3.c:      0.029780 seconds (327.93 MB/s)
Result: sha3.c is 6.79x faster

=== Benchmark: 4096 bytes, 5000 iterations ===
keccak256.c: 0.329351 seconds (59.30 MB/s)
sha3.c:      0.050855 seconds (384.06 MB/s)
Result: sha3.c is 6.48x faster

=== Benchmark: 16384 bytes, 1000 iterations ===
keccak256.c: 0.308710 seconds (50.61 MB/s)
sha3.c:      0.048134 seconds (324.61 MB/s)
Result: sha3.c is 6.41x faster

=== Benchmark: 65536 bytes, 500 iterations ===
keccak256.c: 0.537247 seconds (58.17 MB/s)
sha3.c:      0.085512 seconds (365.45 MB/s)
Result: sha3.c is 6.28x faster

=== Benchmark: 1048576 bytes, 100 iterations ===
keccak256.c: 1.715346 seconds (58.30 MB/s)
sha3.c:      0.282479 seconds (354.01 MB/s)
Result: sha3.c is 6.07x faster

=== Special Case: Single Block (136 bytes) ===

=== Benchmark: 136 bytes, 50000 iterations ===
keccak256.c: 0.243221 seconds (26.66 MB/s)
sha3.c:      0.044385 seconds (146.11 MB/s)
Result: sha3.c is 5.48x faster

=== Special Case: Multiple Blocks (272 bytes) ===

=== Benchmark: 272 bytes, 50000 iterations ===
keccak256.c: 0.358635 seconds (36.16 MB/s)
sha3.c:      0.052071 seconds (249.08 MB/s)
Result: sha3.c is 6.89x faster

========================================
Summary Statistics
========================================

Total benchmarks: 10
  keccak256.c wins: 0
  sha3.c wins:      10
  Ties:             0
sha3.c average speedup (when faster):      6.18x

🏆 Overall: sha3.c is faster in most cases (10/10 tests)

========================================
Benchmark Complete
========================================

Note: Performance may vary based on:
  - CPU frequency scaling
  - System load
  - Compiler optimizations
  - Cache effects
```


