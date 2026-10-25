#!/bin/sh
# Native test of sota_core: python3 (cryptography) makes the vectors, gcc runs them.
set -e
cd "$(dirname "$0")"
python3 gen_vectors.py
cc -std=c99 -Wall -Wextra -O2 -o /tmp/sota_core_test test_sota_core.c ../src/sota_core.c ../src/monocypher.c ../src/monocypher-ed25519.c
/tmp/sota_core_test
