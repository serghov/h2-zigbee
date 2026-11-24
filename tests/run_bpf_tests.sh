#!/bin/bash
# Build and run the interpreter tests on the PC, with address and undefined-behaviour checks.
set -e -o pipefail
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
rules/h2rules.py rules/examples/demo.c -o "$T/demo.bpf" >/dev/null
rules/h2rules.py tests/rules_calls.c -o "$T/calls.bpf"
gcc -O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -o "$T/t" tests/bpf_host_test.c common/h2_bpf.c
"$T/t" "$T/demo.bpf" "$T/calls.bpf"
# Structured fuzzing with an independent model of permitted memory (see the file's header).
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Icommon -Dmemcpy=h2_traced_memcpy -c -o "$T/bpf_traced.o" common/h2_bpf.c
gcc -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -Icommon -o "$T/oracle" tests/bpf_oracle_fuzz.c "$T/bpf_traced.o"
"$T/oracle" "${H2_ORACLE_COUNT:-500000}" "${H2_FUZZ_SEED:-1}" | tail -4
# The same on a 32-bit build (pointer width of the switch), if this machine can build one.
F32="-m32 -O1 -ffreestanding -fno-builtin -nostdlib -static -DFREESTANDING -Itests/shim32 -Icommon"
if gcc $F32 -Dmemcpy=h2_traced_memcpy -c -o "$T/bpf32.o" common/h2_bpf.c 2>/dev/null \
   && gcc $F32 -o "$T/oracle32" tests/bpf_oracle_fuzz.c "$T/bpf32.o" 2>/dev/null; then
  "$T/oracle32" | tail -1
else
  echo "32-bit build not available here; skipped"
fi
