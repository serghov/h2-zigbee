// H2 rule programs: a port of rules/h2rules.py (the version with function calls and constant
// data), done on the ELF object in JS. Keep it step-for-step equal to the script, messages
// included; bench/h2-ref-test.mjs compares the two byte for byte.
//
// Image: the eBPF instructions (entry at offset 0) and, if the file uses constant tables or
// strings, an 8-byte header in front and the constant data behind (common/h2_bpf.h).

export const H2_FLAGS = ["-mcpu=v4", "-Oz", "-Wall", "-Wno-unused-variable", "-Wno-unused-function",
  "-fno-jump-tables"];
export const H2_MAX_BYTES = 8192;               // H2_RULES_MAX_BYTES in common/h2_rules.h
const FRAME_SIZE = 128, MAX_DEPTH = 6;          // H2_BPF_FRAME_SIZE, H2_BPF_MAX_DEPTH in common/h2_bpf.h

const SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_NOBITS = 8, SHT_REL = 9;
const SHF_WRITE = 1, SHF_ALLOC = 2, SHF_EXECINSTR = 4;
const R_BPF_64_64 = 1, R_BPF_64_32 = 10;

class H2Error extends Error {}
const fail = (msg) => { throw new H2Error(msg); };

// ---- minimal ELF64 reader (little-endian object files from clang -target bpf) ----------
function readElf(b) {
  const magic = [0x7f, 0x45, 0x4c, 0x46, 2, 1];
  if (b.length < 64 || magic.some((v, i) => b[i] !== v)) fail("unexpected object file format");
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u64 = (o) => Number(dv.getBigUint64(o, true));
  const shoff = u64(0x28);
  const shentsize = dv.getUint16(0x3a, true), shnum = dv.getUint16(0x3c, true), shstrndx = dv.getUint16(0x3e, true);
  const secs = [];
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize;
    const type = dv.getUint32(o + 4, true), off = u64(o + 24), size = u64(o + 32);
    secs.push({
      name: dv.getUint32(o, true), type, flags: u64(o + 8), off, size,
      link: dv.getUint32(o + 40, true), info: dv.getUint32(o + 44, true), align: u64(o + 48) || 1,
      entsize: u64(o + 56), data: type === SHT_NOBITS ? new Uint8Array(0) : b.subarray(off, off + size),
    });
  }
  const cstr = (tab, o) => { let e = o; while (tab[e]) e++; return new TextDecoder().decode(tab.subarray(o, e)); };
  const strtab = secs[shstrndx].data;
  for (const sec of secs) sec.name = cstr(strtab, sec.name);
  const syms = [];
  for (const sec of secs) {
    if (sec.type !== SHT_SYMTAB) continue;
    const names = secs[sec.link].data;
    const sd = new DataView(sec.data.buffer, sec.data.byteOffset, sec.data.byteLength);
    for (let o = 0; o < sec.size; o += 24)
      syms.push({ name: cstr(names, sd.getUint32(o, true)), shndx: sd.getUint16(o + 6, true),
        value: Number(sd.getBigUint64(o + 8, true)), type: sd.getUint8(o + 4) & 15 });
  }
  return { secs, syms };
}

// Catch at build time what would otherwise only fault on the device: a function that uses
// more stack than one call gets, recursion, and calls nested too deeply. The stack check
// sees direct accesses below the frame pointer and the usual way of taking a local buffer's
// address; it is a help, not a proof.
function checkLimits(text) {
  const n = text.length / 8;
  const tv = new DataView(text.buffer, text.byteOffset, text.byteLength);
  const insn = (i) => {
    const regs = text[i * 8 + 1];
    return [text[i * 8], regs & 15, regs >> 4, tv.getInt16(i * 8 + 2, true), tv.getInt32(i * 8 + 4, true)];
  };
  let starts = new Set([0]);
  for (let i = 0; i < n; i++) {
    const [op, , src, , imm] = insn(i);
    if (op === 0x85 && src === 1) starts.add(i + 1 + imm);
  }
  starts = [...starts].filter((x) => x >= 0 && x < n).sort((a, b) => a - b);
  const funcOf = (i) => { let f = 0; for (const x of starts) if (x <= i) f = x; return f; };
  const calls = new Map(starts.map((f) => [f, new Set()]));
  const deepest = new Map(starts.map((f) => [f, 0]));
  let i = 0;
  while (i < n) {
    const [op, dst, src, off, imm] = insn(i);
    const f = funcOf(i);
    const cls = op & 7;
    if (op === 0x85 && src === 1 && i + 1 + imm >= 0 && i + 1 + imm < n) calls.get(f).add(i + 1 + imm);
    if ((cls === 1 || cls === 2 || cls === 3) && off < 0) {        // load/store relative to r10
      const baseReg = cls === 1 ? src : dst;
      if (baseReg === 10) deepest.set(f, Math.max(deepest.get(f), -off));
    }
    if (op === 0x07 && imm < 0 && i > 0) {                           // rX = r10; rX += -N
      const [pop, pdst, psrc] = insn(i - 1);
      if (pop === 0xbf && psrc === 10 && pdst === dst) deepest.set(f, Math.max(deepest.get(f), -imm));
    }
    i += op === 0x18 ? 2 : 1;
  }
  for (const [f, used] of deepest)
    if (used > FRAME_SIZE)
      fail(`the function at instruction ${f} uses ${used} bytes of stack; a call gets ${FRAME_SIZE}.\n` +
        "Use smaller local buffers.");
  const depth = (f, path) => {
    if (path.has(f))
      fail(`the function at instruction ${f} calls itself (directly or through others); ` +
        "the firmware does not allow recursion deeper than a few levels, so it is refused here.");
    const inner = new Set(path).add(f);
    let d = 0;
    for (const g of [...calls.get(f)].sort((a, b) => a - b)) d = Math.max(d, depth(g, inner));
    return 1 + d;
  };
  const d = depth(0, new Set());
  if (d > MAX_DEPTH) fail(`calls are nested ${d} deep; the firmware allows ${MAX_DEPTH} (on_event counts as one).`);
}

function link(obj) {
  const { secs, syms } = readElf(obj);

  const textIdx = secs.findIndex((x) => x.name === ".text");
  if (textIdx < 0 || !secs[textIdx].size) fail("no code in the rule file");
  const text = secs[textIdx].data.slice();
  if (text.length % 8) fail(`unexpected code size ${text.length}`);
  const entry = syms.filter((x) => x.name === "on_event" && x.shndx === textIdx);
  if (!entry.length || entry[0].value !== 0) fail("on_event() must exist and be the first function in the file");

  // Constant data: every read-only data section, laid out one after another.
  const data = [];
  const base = new Map();
  secs.forEach((sec, i) => {
    if (!(sec.flags & SHF_ALLOC) || (sec.flags & SHF_EXECINSTR) || !sec.size) return;
    if ((sec.flags & SHF_WRITE) || sec.type === SHT_NOBITS)
      fail(`the rule file has writable global data (section ${sec.name}), which the\n` +
        "firmware does not provide. Use 'static const' for tables and var_get/var_set\nfor state.");
    if (sec.type !== SHT_PROGBITS) return;
    while (data.length % sec.align) data.push(0);
    base.set(i, data.length);
    data.push(...sec.data);
  });

  // Relocations in the code: addresses of constant data, and calls the compiler left open.
  const tv = new DataView(text.buffer, text.byteOffset, text.byteLength);
  for (const sec of secs) {
    if (sec.type !== SHT_REL) continue;
    if (base.has(sec.info) && sec.size)
      // The constant data itself contains addresses (a table of strings or of function
      // pointers). Nothing fixes those up when the program is loaded.
      fail(`constant data in section ${secs[sec.info].name} contains pointers (for example a\n` +
        "table of strings, 'const char *names[]'), which the firmware cannot resolve.\n" +
        "Use a table of values or of fixed-size character arrays ('const char names[][8]').");
    if (sec.info !== textIdx) continue;
    const rd = new DataView(sec.data.buffer, sec.data.byteOffset, sec.data.byteLength);
    for (let o = 0; o < sec.size; o += 16) {
      const rOff = Number(rd.getBigUint64(o, true));
      const rInfo = rd.getBigUint64(o + 8, true);
      const sym = syms[Number(rInfo >> 32n)], rtype = Number(rInfo & 0xffffffffn);
      const at = Math.floor(rOff / 8);
      const imm = tv.getInt32(rOff + 4, true);
      if (rtype === R_BPF_64_64 && base.has(sym.shndx) && text[rOff] === 0x18) {
        const target = base.get(sym.shndx) + sym.value + imm;
        if (!(target >= 0 && target < data.length)) fail(`instruction ${at}: constant data reference out of range`);
        text[rOff + 1] = (text[rOff + 1] & 0x0f) | (2 << 4);         // source 2: data offset
        tv.setInt32(rOff + 4, target, true);
        tv.setInt32(rOff + 12, 0, true);
      } else if (rtype === R_BPF_64_32 && sym.shndx === textIdx && text[rOff] === 0x85) {
        const target = Math.floor(sym.value / 8) + imm + 1;
        tv.setInt32(rOff + 4, target - (at + 1), true);
      } else {
        const name = sym.shndx < secs.length ? (sym.name || secs[sym.shndx].name) : sym.name;
        fail(`instruction ${at}: reference to '${name}' cannot be resolved ` +
          "(only constant data and the file's own functions can be referenced)");
      }
    }
  }

  checkLimits(text);

  let image;
  if (data.length) {
    while (data.length % 8) data.push(0);                // the firmware takes whole 8-byte units
    image = new Uint8Array(8 + text.length + data.length);
    const hv = new DataView(image.buffer);
    image[0] = 0x00; image[1] = 1;
    hv.setUint16(2, text.length / 8, true);
    hv.setUint16(4, data.length, true);
    image.set(text, 8);
    image.set(data, 8 + text.length);
  } else {
    image = text;                                        // bare instructions, as before
  }
  if (image.length > H2_MAX_BYTES) fail(`program is ${image.length} bytes; the firmware accepts at most ${H2_MAX_BYTES}`);
  return { image, insns: text.length / 8, dataBytes: data.length };
}

// Returns { ok, blob, insns, dataBytes, problems: [string] }
export function checkH2(objBytes) {
  try {
    const { image, insns, dataBytes } = link(objBytes);
    return { ok: true, blob: image, insns, dataBytes, problems: [] };
  } catch (e) {
    if (e instanceof H2Error) return { ok: false, problems: [e.message] };
    throw e;
  }
}
