#!/bin/bash
# Build and run the interpreter tests on the PC, with address and undefined-behaviour checks.
set -e
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
rules/h2rules.py rules/examples/demo.c -o "$T/demo.bpf"
gcc -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -o "$T/t" tests/bpf_host_test.c common/h2_bpf.c
"$T/t" "$T/demo.bpf"
