# The in-browser compiler

The Home Assistant panel compiles rule programs in the browser with clang built for
WebAssembly: clang 22.1 with only the C front end and the BPF backend, as a `wasm32-wasip1`
program run in a Web Worker through a WASI shim. No server takes part in compiling.

`clang.wasm` is about 47 MB (11.6 MB brotli-compressed, which is what a browser downloads,
once) and is **not kept in git**. Get it from the release page of this repository, or build
it, and put it next to the panel:

    custom_components/h2_rules/frontend/clang.wasm        (and clang.wasm.br / clang.wasm.gz)

`tools/build_panel.py --compiler <dir>` copies the three files from a build's `web/`
directory and updates `manifest.json`.

## Building it

`build.sh` builds a native `llvm-tblgen`/`clang-tblgen`, then clang for WASI, then runs
`wasm-opt -Oz`. About 10 minutes on 24 cores and 4.5 GB of RAM for the link. It needs:

- LLVM sources: YoWASP/llvm-project at 97196c8 (LLVM 22.1.0 plus their WASI portability
  patch), sparse checkout of `llvm/ clang/ cmake/ third-party/`, in `llvm-src/`
- wasi-sdk 29 and binaryen 125, unpacked next to it
- `patches/0001-wasi-close-stale-errno.patch`, applied by the script: without it a failed
  `#include` lookup made clang trap instead of exiting with an error

Configuration: `LLVM_TARGETS_TO_BUILD=BPF`, default triple `bpfel`, MinSizeRel, ThinLTO,
stripped; assertions, threads, the static analyzer and plugins off.

## The other vendored pieces of the panel

- `custom_components/h2_rules/frontend/vendor/editor.js`: CodeMirror 6, bundled from
  `editor/` here (`cd editor && npm ci && npm run build`; versions pinned in `package.json`).
- `custom_components/h2_rules/frontend/vendor/browser_wasi_shim/`: bjorn3/browser_wasi_shim
  0.4.2 (MIT / Apache-2.0), with `fs_mem.js` patched to grow files geometrically.
- `custom_components/h2_rules/frontend/clang-headers.json`: clang's own freestanding C
  headers (`stddef.h`, `stdint.h`, ...), taken from the compiler build
  (Apache-2.0 with LLVM exceptions).
