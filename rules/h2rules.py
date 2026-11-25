#!/usr/bin/env python3
"""Compile an H2 rule program (C) to the bytecode blob the firmware loads.

usage: h2rules.py rules.c [-o rules.bpf]

The blob is the program image the firmware loads: the eBPF instructions (entry at offset
0), and, if the file uses constant tables or strings, a header in front and the constant
data behind (see common/h2_bpf.h). Functions of the file may call each other. Writable
global variables are rejected: state lives in var_get/var_set.
"""
import argparse, os, struct, subprocess, sys, tempfile

MAX_BYTES = 8192      # H2_RULES_MAX_BYTES in common/h2_rules.h

def run(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r.stdout

# ---- minimal ELF64 reader (little-endian object files from clang -target bpf) ----------

SHT_PROGBITS, SHT_SYMTAB, SHT_NOBITS, SHT_REL = 1, 2, 8, 9
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
R_BPF_64_64, R_BPF_64_32 = 1, 10

def read_elf(path):
    b = open(path, "rb").read()
    if b[:6] != b"\x7fELF\x02\x01":
        sys.exit("unexpected object file format")
    shoff, = struct.unpack_from("<Q", b, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", b, 0x3A)
    secs = []
    for i in range(shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", b, shoff + i * shentsize)
        secs.append(dict(name=name, type=typ, flags=flags, off=off, size=size, link=link,
                         info=info, align=align or 1, entsize=entsize,
                         data=b"" if typ == SHT_NOBITS else b[off:off + size]))
    strtab = secs[shstrndx]["data"]
    def cstr(tab, o):
        return tab[o:tab.index(b"\0", o)].decode()
    for sec in secs:
        sec["name"] = cstr(strtab, sec["name"])
    syms = []
    for sec in secs:
        if sec["type"] == SHT_SYMTAB:
            names = secs[sec["link"]]["data"]
            for o in range(0, sec["size"], 24):
                n, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", sec["data"], o)
                syms.append(dict(name=cstr(names, n), shndx=shndx, value=value, type=info & 15))
    return secs, syms

FRAME_SIZE, MAX_DEPTH = 128, 6      # H2_BPF_FRAME_SIZE, H2_BPF_MAX_DEPTH in common/h2_bpf.h

def check_limits(text):
    """Catch at build time what would otherwise only fault on the device: a function that
    uses more stack than one call gets, recursion, and calls nested too deeply.
    The stack check sees direct accesses below the frame pointer and the usual way of
    taking a local buffer's address; it is a help, not a proof."""
    n = len(text) // 8
    def insn(i):
        op = text[i * 8]; regs = text[i * 8 + 1]
        off, imm = struct.unpack_from("<hi", text, i * 8 + 2)
        return op, regs & 15, regs >> 4, off, imm
    starts = {0}
    for i in range(n):
        op, dst, src, off, imm = insn(i)
        if op == 0x85 and src == 1:
            starts.add(i + 1 + imm)
    starts = sorted(x for x in starts if 0 <= x < n)
    def func_of(i):
        return max(x for x in starts if x <= i)
    calls = {f: set() for f in starts}
    deepest = {f: 0 for f in starts}
    i = 0
    while i < n:
        op, dst, src, off, imm = insn(i)
        f = func_of(i)
        cls = op & 7
        if op == 0x85 and src == 1 and 0 <= i + 1 + imm < n:
            calls[f].add(i + 1 + imm)
        if cls in (1, 2, 3) and off < 0:                       # load/store relative to r10
            base_reg = src if cls == 1 else dst
            if base_reg == 10:
                deepest[f] = max(deepest[f], -off)
        if op == 0x07 and imm < 0 and i > 0:                   # rX = r10; rX += -N
            pop, pdst, psrc, _, _ = insn(i - 1)
            if pop == 0xBF and psrc == 10 and pdst == dst:
                deepest[f] = max(deepest[f], -imm)
        i += 2 if op == 0x18 else 1
    for f, used in deepest.items():
        if used > FRAME_SIZE:
            sys.exit(f"the function at instruction {f} uses {used} bytes of stack; a call gets {FRAME_SIZE}.\n"
                     "Use smaller local buffers.")
    def depth(f, path):
        if f in path:
            sys.exit(f"the function at instruction {f} calls itself (directly or through others); "
                     "the firmware does not allow recursion deeper than a few levels, so it is refused here.")
        return 1 + max((depth(g, path | {f}) for g in calls[f]), default=0)
    d = depth(0, frozenset())
    if d > MAX_DEPTH:
        sys.exit(f"calls are nested {d} deep; the firmware allows {MAX_DEPTH} (on_event counts as one).")

def compile_rules(src, out):
    with tempfile.TemporaryDirectory() as tmp:
        obj = os.path.join(tmp, "rules.o")
        run("clang", "-target", "bpf", "-mcpu=v4", "-Oz", "-Wall", "-Wno-unused-variable",
            "-Wno-unused-function", "-fno-jump-tables", "-c", src, "-o", obj)
        secs, syms = read_elf(obj)

    text_idx = next((i for i, x in enumerate(secs) if x["name"] == ".text"), None)
    if text_idx is None or not secs[text_idx]["size"]:
        sys.exit("no code in the rule file")
    text = bytearray(secs[text_idx]["data"])
    if len(text) % 8:
        sys.exit(f"unexpected code size {len(text)}")
    entry = [x for x in syms if x["name"] == "on_event" and x["shndx"] == text_idx]
    if not entry or entry[0]["value"] != 0:
        sys.exit("on_event() must exist and be the first function in the file")

    # Constant data: every read-only data section, laid out one after another.
    data = bytearray()
    base = {}
    for i, sec in enumerate(secs):
        if not (sec["flags"] & SHF_ALLOC) or (sec["flags"] & SHF_EXECINSTR) or not sec["size"]:
            continue
        if (sec["flags"] & SHF_WRITE) or sec["type"] == SHT_NOBITS:
            sys.exit(f"the rule file has writable global data (section {sec['name']}), which the\n"
                     "firmware does not provide. Use 'static const' for tables and var_get/var_set\n"
                     "for state.")
        if sec["type"] != SHT_PROGBITS:
            continue
        while len(data) % sec["align"]:
            data.append(0)
        base[i] = len(data)
        data += sec["data"]

    # Relocations in the code: addresses of constant data, and calls the compiler left open.
    for sec in secs:
        if sec["type"] != SHT_REL:
            continue
        if sec["info"] in base and sec["size"]:
            # The constant data itself contains addresses (a table of strings or of
            # function pointers). Nothing fixes those up when the program is loaded.
            sys.exit(f"constant data in section {secs[sec['info']]['name']} contains pointers (for example a\n"
                     "table of strings, 'const char *names[]'), which the firmware cannot resolve.\n"
                     "Use a table of values or of fixed-size character arrays ('const char names[][8]').")
        if sec["info"] != text_idx:
            continue
        for o in range(0, sec["size"], 16):
            r_off, r_info = struct.unpack_from("<QQ", sec["data"], o)
            sym, rtype = syms[r_info >> 32], r_info & 0xFFFFFFFF
            insn = r_off // 8
            imm, = struct.unpack_from("<i", text, r_off + 4)
            if rtype == R_BPF_64_64 and sym["shndx"] in base and text[r_off] == 0x18:
                target = base[sym["shndx"]] + sym["value"] + imm
                if not 0 <= target < len(data):
                    sys.exit(f"instruction {insn}: constant data reference out of range")
                text[r_off + 1] = (text[r_off + 1] & 0x0F) | (2 << 4)   # source 2: data offset
                struct.pack_into("<i", text, r_off + 4, target)
                struct.pack_into("<i", text, r_off + 12, 0)
            elif rtype == R_BPF_64_32 and sym["shndx"] == text_idx and text[r_off] == 0x85:
                target = sym["value"] // 8 + imm + 1
                struct.pack_into("<i", text, r_off + 4, target - (insn + 1))
            else:
                sys.exit(f"instruction {insn}: reference to '{sym['name'] or secs[sym['shndx']]['name'] if sym['shndx'] < len(secs) else sym['name']}' "
                         "cannot be resolved (only constant data and the file's own functions can be referenced)")

    check_limits(text)

    if data:
        while len(data) % 8:              # the firmware takes images in whole 8-byte units
            data.append(0)
        image = bytes([0x00, 1]) + struct.pack("<HH", len(text) // 8, len(data)) + b"\0\0" + bytes(text) + bytes(data)
    else:
        image = bytes(text)               # bare instructions, as before
    if len(image) > MAX_BYTES:
        sys.exit(f"program is {len(image)} bytes; the firmware accepts at most {MAX_BYTES}")
    open(out, "wb").write(image)
    return len(image), len(text) // 8, len(data)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    out = a.output or os.path.splitext(a.source)[0] + ".bpf"
    size, insns, data = compile_rules(a.source, out)
    print(f"{out}: {size} bytes, {insns} instructions" + (f", {data} bytes of constant data" if data else ""))
