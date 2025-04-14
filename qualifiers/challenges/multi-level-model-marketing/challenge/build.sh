#!/bin/bash

set -e

HANDOUT_FILES=(
    "./build/challenge"
    "/lib/x86_64-linux-gnu/libc.so.6"
    "/lib64/ld-linux-x86-64.so.2"
    "src/requirements.txt"
    "src/sentiment.py"
)

# Build binaries
mkdir -p build
mkdir -p handout
gcc src/mlmm.c -O0 -fno-stack-protector -no-pie -Wall -o build/challenge

# Copy required files to handout
for f in ${HANDOUT_FILES[@]}; do
    cp $f handout/
done
