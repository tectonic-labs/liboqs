# Makefile for Keccak256 comparison test

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -DUSE_KECCAK
LDFLAGS =

# Source files
SOURCES = test_comparison.c keccak256.c sha3.c
BENCHMARK_SOURCES = benchmark_timing.c keccak256.c sha3.c
HEADERS = keccak256.h sha3.h byte_order.h ustd.h
OBJECTS = $(SOURCES:.c=.o)
BENCHMARK_OBJECTS = $(BENCHMARK_SOURCES:.c=.o)

# Target executables
TARGET = test_keccak256_comparison
BENCHMARK = benchmark_keccak256

.PHONY: all clean run benchmark

all: $(TARGET) $(BENCHMARK)

$(TARGET): test_comparison.o keccak256.o sha3.o
	$(CC) $(CFLAGS) -o $@ test_comparison.o keccak256.o sha3.o $(LDFLAGS)

$(BENCHMARK): benchmark_timing.o keccak256.o sha3.o
	$(CC) $(CFLAGS) -o $@ benchmark_timing.o keccak256.o sha3.o $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

benchmark: $(BENCHMARK)
	./$(BENCHMARK)

clean:
	rm -f test_comparison.o benchmark_timing.o keccak256.o sha3.o $(TARGET) $(BENCHMARK)

# Individual object dependencies
test_comparison.o: test_comparison.c keccak256.h sha3.h
keccak256.o: keccak256.c keccak256.h
sha3.o: sha3.c sha3.h byte_order.h ustd.h

