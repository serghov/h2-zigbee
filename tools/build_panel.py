#!/usr/bin/env python3
"""Rebuild the generated files of the Home Assistant panel (custom_components/h2_rules/frontend).

  sysroot.json        headers the in-browser compiler sees: clang's own C headers
                      (clang-headers.json, taken once from the compiler build) and the rule
                      API: rules/h2_rules.h and rules/lib/*.h
  examples/           rules/examples/*.c and their index
  manifest.json       size of clang.wasm, for the download progress bar

Run it after changing anything in rules/. With --compiler <dir> it also copies clang.wasm
(and clang.wasm.br / .gz if present) from a wasi-clang-web build; the compiler is not kept
in git (see compiler/README.md).

usage: build_panel.py [--compiler /path/to/wasi-clang-web/web]
"""
import json, pathlib, shutil, sys

root = pathlib.Path(__file__).resolve().parent.parent
front = root / "custom_components/h2_rules/frontend"
rules = root / "rules"

bundle = dict(json.loads((front / "clang-headers.json").read_text()))
# Laid out as in rules/, with the program compiled as /work/main.c standing in for
# rules/examples/x.c:  "../h2_rules.h" -> /h2_rules.h,  "../lib/sync.h" -> /lib/sync.h.
# Also reachable as <h2_rules.h> and <lib/sync.h> through /include.
h2 = (rules / "h2_rules.h").read_text()
bundle["h2_rules.h"] = h2
bundle["include/h2_rules.h"] = h2
for f in sorted((rules / "lib").glob("*.h")):
    bundle["lib/" + f.name] = f.read_text()
    bundle["include/lib/" + f.name] = f.read_text()
(front / "sysroot.json").write_text(json.dumps(bundle, separators=(",", ":")))

ex = front / "examples"
shutil.rmtree(ex, ignore_errors=True)
ex.mkdir()
names = []
for f in sorted((rules / "examples").glob("*.c")):
    shutil.copy(f, ex / f.name)
    names.append(f.name)
(ex / "index.json").write_text(json.dumps(names))

if "--compiler" in sys.argv:
    src = pathlib.Path(sys.argv[sys.argv.index("--compiler") + 1])
    for name in ("clang.wasm", "clang.wasm.br", "clang.wasm.gz"):
        if (src / name).is_file():
            shutil.copy(src / name, front / name)
wasm = front / "clang.wasm"
(front / "manifest.json").write_text(json.dumps({"clang.wasm": wasm.stat().st_size if wasm.is_file() else 0}))
print(f"sysroot.json: {len(bundle)} files; examples: {len(names)}; clang.wasm: "
      + (f"{wasm.stat().st_size:,} bytes" if wasm.is_file() else "NOT PRESENT (the panel cannot compile without it)"))
