#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    # from ldd
    "/lib/x86_64-linux-gnu/libstdc++.so.6"
    "/lib/x86_64-linux-gnu/libgcc_s.so.1"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib/x86_64-linux-gnu/libm.so.6"
    "/lib64/ld-linux-x86-64.so.2"
)

# Build binaries
cmake -S src -B build
cmake --build build

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
