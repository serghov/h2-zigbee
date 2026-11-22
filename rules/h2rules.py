#!/usr/bin/env python3
"""Compile an H2 rule program (C) to the bytecode blob the firmware loads.

usage: h2rules.py rules.c [-o rules.bpf]

The blob is the raw .text section: eBPF instructions, entry at offset 0.
Programs with relocations (global variables, string literals, calls to non-inlined
functions) are rejected, because the firmware's interpreter has no loader for them.
"""
import argparse, os, subprocess, sys, tempfile

def run(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r.stdout

def compile_rules(src, out):
    with tempfile.TemporaryDirectory() as tmp:
        obj = os.path.join(tmp, "rules.o")
        run("clang", "-target", "bpf", "-mcpu=v4", "-O2", "-Wall", "-Wno-unused-variable",
            "-fno-jump-tables", "-c", src, "-o", obj)
        relocs = [l for l in run("llvm-readelf", "-r", obj).splitlines() if l.startswith("0")]
        if relocs:
            sys.exit("rule program needs relocations, which the firmware cannot resolve.\n"
                     "Avoid global variables, string literals, constant arrays and functions that are\n"
                     "not 'static inline' (use var_get/var_set for state):\n" + "\n".join(relocs))
        syms = run("llvm-readelf", "-s", obj)
        entry = [l.split() for l in syms.splitlines() if l.rstrip().endswith(" on_event")]
        if not entry or int(entry[0][1], 16) != 0:
            sys.exit("on_event() must exist and be the first function in the file")
        run("llvm-objcopy", "-O", "binary", "--only-section=.text", obj, out)
    size = os.path.getsize(out)
    if size == 0 or size % 8:
        sys.exit(f"unexpected code size {size}")
    return size

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    out = a.output or os.path.splitext(a.source)[0] + ".bpf"
    n = compile_rules(a.source, out)
    print(f"{out}: {n} bytes, {n // 8} instructions")
