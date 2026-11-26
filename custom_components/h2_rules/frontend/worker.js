// Web Worker: owns the compiled clang.wasm module and runs compilations off the UI thread.
// One job: C source of a rule program -> the image the firmware takes (what rules/h2rules.py
// does), plus the assembly listing for reading.
import { buildTree, runClang, BASE_FLAGS, decode } from "./clang-runner.js";
import { H2_FLAGS, checkH2 } from "./h2.js";

let module, sysTree;
const post = (type, data) => self.postMessage({ type, ...data });

function withProgress(stream, total) {
  let loaded = 0;
  return stream.pipeThrough(new TransformStream({
    transform(chunk, ctrl) {
      loaded += chunk.length;
      post("progress", { loaded, total });
      ctrl.enqueue(chunk);
    },
  }));
}

async function init() {
  const t0 = performance.now();
  const manifest = await fetch("manifest.json").then((r) => r.json()).catch(() => ({}));
  const res = await fetch("clang.wasm");
  if (!res.ok) {
    throw new Error(res.status === 404
      ? "the compiler (clang.wasm) is not installed next to the panel; see the README"
      : `clang.wasm: HTTP ${res.status}`);
  }
  const wasm = withProgress(res.body, manifest["clang.wasm"] || 0);
  // Streaming compile overlaps download and compilation.
  const modP = WebAssembly.compileStreaming(new Response(wasm, { headers: { "content-type": "application/wasm" } }));
  const sysP = fetch("sysroot.json").then((r) => r.json()).then(buildTree);
  [module, sysTree] = await Promise.all([modP, sysP]);
  post("ready", { ms: performance.now() - t0 });
}

async function compile({ id, source }) {
  const flags = [...BASE_FLAGS, ...H2_FLAGS];
  const files = { "main.c": source };
  const obj = await runClang(module, sysTree, [...flags, "-c", "/work/main.c", "-o", "/work/main.o"], files);
  let asm = null, h2 = null;
  if (obj.code === 0) {
    h2 = checkH2(obj.files["main.o"]);
    asm = await runClang(module, sysTree, [...flags, "-S", "/work/main.c", "-o", "/work/main.s"], files);
  }
  post("result", {
    id, h2, code: obj.code, log: obj.stderr + obj.stdout,
    asm: asm && asm.files["main.s"] ? decode(asm.files["main.s"]) : null,
    ms: Math.round(obj.ms.run),
  });
}

self.onmessage = async ({ data }) => {
  try {
    if (data.type === "compile") await compile(data);
  } catch (e) {
    post("error", { id: data.id, message: String(e && e.stack || e) });
  }
};

init().catch((e) => post("error", { message: "Could not load the compiler: " + (e.message || e) }));
