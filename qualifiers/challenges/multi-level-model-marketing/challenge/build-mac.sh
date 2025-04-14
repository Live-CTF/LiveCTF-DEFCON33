#!/bin/bash

set -e

# Build for macOS
mkdir -p build

# Compile with clang, omitting the -no-pie flag since it's not supported on macOS
clang src/mlmm.c -O0 -fno-stack-protector -Wall -o build/mlmm

echo "Build complete! Binary is at build/mlmm"
echo "Run with: ./build/mlmm"