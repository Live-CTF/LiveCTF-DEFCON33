#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib64/ld-linux-x86-64.so.2"
)

# Build binaries
gcc -g -o build/challenge -fno-stack-protector -O0 src/challenge.c

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
