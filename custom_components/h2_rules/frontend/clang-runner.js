// Runs clang.wasm (WASI) against an in-memory filesystem.
// Works in a Web Worker and in Node (used by bench/).
import {
  WASI, File, OpenFile, ConsoleStdout, PreopenDirectory, Directory,
} from "./vendor/browser_wasi_shim/index.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

// sysroot bundle: { "lib/clang/include/stddef.h": "...", "include/linux/bpf.h": "...", ... }
// -> nested Map<string, Inode>, built once and shared (read-only) by every run.
export function buildTree(bundle) {
  const root = new Map();
  for (const [path, text] of Object.entries(bundle)) {
    const parts = path.split("/");
    let dir = root;
    for (const p of parts.slice(0, -1)) {
      if (!dir.has(p)) dir.set(p, new Directory(new Map()));
      dir = dir.get(p).contents;
    }
    dir.set(parts.at(-1), new File(typeof text === "string" ? enc.encode(text) : text));
  }
  return root;
}

export const BASE_FLAGS = [
  "--target=bpfel", "-resource-dir=/lib/clang", "-nostdlibinc", "-isystem", "/include",
  "-D__TARGET_ARCH_x86", "-fno-color-diagnostics", "-fmessage-length=0",
];

// sysTree: result of buildTree(); files: { "main.c": "..." } placed in /work
// Returns { code, stdout, stderr, files: {name: Uint8Array}, ms: {instantiate, run} }
export async function runClang(module, sysTree, args, files) {
  const work = new Map();
  for (const [name, data] of Object.entries(files))
    work.set(name, new File(typeof data === "string" ? enc.encode(data) : data));
  const root = new Map(sysTree);
  root.set("work", new Directory(work));
  root.set("tmp", new Directory(new Map()));

  let stdout = "", stderr = "";
  const fds = [
    new OpenFile(new File([])),
    ConsoleStdout.lineBuffered((l) => (stdout += l + "\n")),
    ConsoleStdout.lineBuffered((l) => (stderr += l + "\n")),
    new PreopenDirectory("/", root),
  ];
  const wasi = new WASI(["clang", ...args], ["TMPDIR=/tmp", "PWD=/work"], fds, { debug: false });
  const t0 = performance.now();
  const inst = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
  const t1 = performance.now();
  let code;
  try {
    code = wasi.start(inst);
  } catch (e) {
    // abort()/unreachable or out-of-memory traps end up here
    code = -1;
    stderr += `\n[clang.wasm trapped: ${e}]\n`;
  }
  const t2 = performance.now();

  const out = {};
  for (const [name, inode] of root.get("work").contents)
    if (!(name in files) && inode instanceof File) out[name] = inode.data.slice();
  const memBytes = inst.exports.memory.buffer.byteLength;
  return { code, stdout, stderr, files: out, memBytes, ms: { instantiate: t1 - t0, run: t2 - t1 } };
}

export const decode = (u8) => dec.decode(u8);
