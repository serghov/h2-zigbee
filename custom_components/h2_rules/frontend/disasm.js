// Disassembler for rule program images (common/h2_bpf.h): eBPF instructions, optionally
// with an 8-byte header in front and constant data behind. For reading a program that was
// read back from a switch when its source is not at hand.

const ALU = ["+=", "-=", "*=", "/=", "|=", "&=", "<<=", ">>=", null, "%=", "^=", "=", "s>>=", null];
const JMP = { 1: "==", 2: ">", 3: ">=", 4: "&", 5: "!=", 6: "s>", 7: "s>=", 10: "<", 11: "<=", 12: "s<", 13: "s<=" };
const SIZE = { 0x00: "u32", 0x08: "u16", 0x10: "u8", 0x18: "u64" };
const SSIZE = { 0x00: "s32", 0x08: "s16", 0x10: "s8" };

// Helper names from the text of rules/h2_rules.h: H2_FN(id, ret, name, args...)
export function helperNames(header) {
  const names = {};
  for (const m of (header || "").matchAll(/H2_FN\(\s*(\d+)\s*,\s*[\w ]+?\s*,\s*(\w+)\s*,/g)) names[+m[1]] = m[2];
  return names;
}

export function parseImage(image) {
  const dv = new DataView(image.buffer, image.byteOffset, image.byteLength);
  let code = image, data = new Uint8Array(0);
  if (image.length >= 8 && image[0] === 0x00 && image[1] === 0x01) {
    const insns = dv.getUint16(2, true), dataLen = dv.getUint16(4, true);
    if (8 + insns * 8 + dataLen <= image.length) {
      code = image.subarray(8, 8 + insns * 8);
      data = image.subarray(8 + insns * 8, 8 + insns * 8 + dataLen);
    }
  }
  return { code, data };
}

const off = (v) => (v < 0 ? ` - ${-v}` : ` + ${v}`);
const hex = (v) => (v < 0 ? "-0x" + (-v).toString(16) : "0x" + v.toString(16));
const num = (v) => (Math.abs(v) > 255 ? hex(v) : String(v));

// -> text listing. helpers: {id: name}
export function disassemble(image, helpers = {}) {
  const { code, data } = parseImage(image);
  const dv = new DataView(code.buffer, code.byteOffset, code.byteLength);
  const n = code.length >> 3;
  const insn = (pc) => ({
    op: code[pc * 8], dst: code[pc * 8 + 1] & 15, src: code[pc * 8 + 1] >> 4,
    off: dv.getInt16(pc * 8 + 2, true), imm: dv.getInt32(pc * 8 + 4, true),
  });

  // First pass: jump targets and the starts of the program's own functions.
  const labels = new Set(), funcs = new Map([[0, "on_event"]]);
  for (let pc = 0; pc < n; pc++) {
    const i = insn(pc), cls = i.op & 7;
    if (i.op === 0x18) { pc++; continue; }
    if (cls === 5 || cls === 6) {
      const o = i.op >> 4;
      if (i.op === 0x85) { if (i.src === 1) funcs.set(pc + 1 + i.imm, null); }
      else if (i.op === 0x06) labels.add(pc + 1 + i.imm);
      else if (o !== 9) labels.add(pc + 1 + i.off);
    }
  }
  let k = 1;
  for (const pc of [...funcs.keys()].sort((a, b) => a - b)) if (funcs.get(pc) === null) funcs.set(pc, `fn${k++}`);
  const target = (pc) => (funcs.has(pc) ? funcs.get(pc) : `L${pc}`);

  const lines = [];
  const reg = (r, w) => (w ? "w" : "r") + r;
  for (let pc = 0; pc < n; pc++) {
    const i = insn(pc), cls = i.op & 7;
    if (funcs.has(pc)) lines.push(`${pc ? "\n" : ""}${funcs.get(pc)}:`);
    else if (labels.has(pc)) lines.push(`L${pc}:`);
    let text;
    if (i.op === 0x18) {
      const hi = pc + 1 < n ? insn(pc + 1).imm : 0;
      if (i.src === 2) text = `r${i.dst} = &data[${i.imm}]` + constantNote(data, i.imm);
      else text = `r${i.dst} = ${hex(i.imm >>> 0)}${hi ? ` (high word ${hex(hi >>> 0)})` : ""} ll`;
      lines.push(row(pc, text));
      pc++;
      continue;
    }
    if (cls === 4 || cls === 7) {
      const w = cls === 4, o = i.op >> 4, d = reg(i.dst, w);
      const s = i.op & 8 ? reg(i.src, w) : num(i.imm);
      if (o === 8) text = `${d} = -${d}`;
      else if (o === 13) text = `${d} = ${i.op & 8 ? "be" : cls === 7 ? "bswap" : "le"}${i.imm} ${d}`;
      else if (o === 11 && (i.op & 8) && i.off) text = `${d} = (s${i.off})${s}`;
      else if ((o === 3 || o === 9) && i.off === 1) text = `${d} s${ALU[o]} ${s}`;
      else text = ALU[o] ? `${d} ${ALU[o]} ${s}` : `?? opcode ${hex(i.op)}`;
    } else if (cls === 1) {
      const sx = (i.op & 0xe0) === 0x80;
      text = `r${i.dst} = *(${(sx ? SSIZE : SIZE)[i.op & 0x18] || "?"} *)(r${i.src}${off(i.off)})`;
    } else if (cls === 3) {
      text = `*(${SIZE[i.op & 0x18]} *)(r${i.dst}${off(i.off)}) = r${i.src}`;
    } else if (cls === 2) {
      text = `*(${SIZE[i.op & 0x18]} *)(r${i.dst}${off(i.off)}) = ${num(i.imm)}`;
    } else if (cls === 5 || cls === 6) {
      const o = i.op >> 4, w = cls === 6;
      if (i.op === 0x95) text = "exit";
      else if (i.op === 0x85) text = i.src === 1 ? `call ${target(pc + 1 + i.imm)}` : `call ${helpers[i.imm] || "helper_" + i.imm}`;
      else if (i.op === 0x05) text = `goto ${target(pc + 1 + i.off)}`;
      else if (i.op === 0x06) text = `goto ${target(pc + 1 + i.imm)}`;
      else if (JMP[o]) text = `if ${reg(i.dst, w)} ${JMP[o]} ${i.op & 8 ? reg(i.src, w) : num(i.imm)} goto ${target(pc + 1 + i.off)}`;
      else text = `?? opcode ${hex(i.op)}`;
    } else {
      text = `?? opcode ${hex(i.op)}`;
    }
    lines.push(row(pc, text));
  }
  if (data.length) {
    lines.push("", `data: ${data.length} bytes of constants`);
    for (let o = 0; o < data.length; o += 16) {
      const part = data.subarray(o, o + 16);
      lines.push(`  ${String(o).padStart(4)}: ${Array.from(part, (b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48)} ${Array.from(part, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("")}`);
    }
  }
  return lines.join("\n");
}

const row = (pc, text) => `${String(pc).padStart(5)}:  ${text}`;

function constantNote(data, at) {
  const part = data.subarray(at, at + 8);
  return part.length ? `        # ${Array.from(part, (b) => b.toString(16).padStart(2, "0")).join(" ")}${data.length > at + 8 ? " ..." : ""}` : "";
}
