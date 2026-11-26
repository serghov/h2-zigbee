// Home Assistant sidebar panel for H2 switch rule programs.
//
// Loaded by panel_custom inside an iframe (embed_iframe), so this document is ours: the
// element fills it. Home Assistant sets .hass on the element; everything that touches a
// switch goes through it (zha.js), and sources are kept by the integration (store.py).
import { createEditor } from "./vendor/editor.js";
import { H2_MAX_BYTES } from "./h2.js";
import { Switch, listSwitches, crc16, toHex, RESULTS, FAULTS } from "./zha.js";
import { disassemble, helperNames } from "./disasm.js";

const BASE = new URL(".", import.meta.url);
const LAST_KEY = "h2-rules-last-switch";
const hex4 = (v) => v.toString(16).padStart(4, "0");
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

const STYLE = `
:root {
  --bg: #f6f7f9; --panel: #ffffff; --panel-2: #eef0f3; --border: #d9dde3;
  --text: #1b1f24; --muted: #5d6673; --accent: #2b6cd4; --accent-text: #ffffff;
  --ok: #1d7a46; --err: #c0362c; --warn: #9a6400;
  --c-comment: #6a737d; --c-kw: #cf222e; --c-fn: #8250df; --c-const: #0550ae; --c-str: #0a3069; --c-type: #953800; --c-pp: #cf222e;
  --line-active: rgba(43,108,212,.06); --selection: rgba(43,108,212,.2);
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
:root[data-theme="dark"] {
  --bg: #0f1419; --panel: #161b22; --panel-2: #1f262f; --border: #2d3540;
  --text: #e3e7ec; --muted: #8b95a3; --accent: #4c8dff; --accent-text: #0b0f14;
  --ok: #4cc283; --err: #ff6b5e; --warn: #e3b341;
  --c-comment: #7d8794; --c-kw: #ff7b72; --c-fn: #d2a8ff; --c-const: #79c0ff; --c-str: #a5d6ff; --c-type: #ffa657; --c-pp: #ff7b72;
  --line-active: rgba(76,141,255,.08); --selection: rgba(76,141,255,.3);
  color-scheme: dark;
}
* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body { background: var(--bg); color: var(--text); font: 15px/1.4 var(--sans); }
h2-rules-panel { display: grid; height: 100%; grid-template-rows: auto auto minmax(0, 1fr) auto;
  grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); grid-template-areas: "bar bar" "state state" "src out" "foot foot"; }
.bar { grid-area: bar; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 10px 16px;
  background: var(--panel); border-bottom: 1px solid var(--border); }
.bar .spacer { flex: 1 1 0; }
.menu-btn { display: none; }
select, button { font: inherit; color: inherit; border: 1px solid var(--border); border-radius: 8px;
  background: var(--panel); padding: 7px 12px; min-height: 38px; }
select { max-width: 100%; }
button { cursor: pointer; }
button:disabled { opacity: .5; cursor: default; }
button.primary { background: var(--accent); color: var(--accent-text); border-color: var(--accent); font-weight: 600; }
.state { grid-area: state; padding: 8px 16px; background: var(--panel-2); border-bottom: 1px solid var(--border);
  font-size: 13.5px; color: var(--muted); display: flex; flex-wrap: wrap; gap: 4px 18px; }
.state b { color: var(--text); font-weight: 600; }
.state .ok { color: var(--ok); } .state .err { color: var(--err); } .state .warn { color: var(--warn); }
.src { grid-area: src; min-height: 0; border-right: 1px solid var(--border); background: var(--panel); font-size: 13.5px; }
.out { grid-area: out; min-height: 0; display: grid; grid-template-rows: auto minmax(0, 1fr); background: var(--panel); }
.tabs { display: flex; gap: 2px; padding: 6px 10px 0; border-bottom: 1px solid var(--border); }
.tabs button { border: none; border-bottom: 2px solid transparent; border-radius: 0; background: none; color: var(--muted); padding: 6px 10px; min-height: 34px; }
.tabs button[aria-selected="true"] { color: var(--text); border-bottom-color: var(--accent); }
.tabs .src-tab { display: none; }
pre { margin: 0; padding: 12px 16px; overflow: auto; height: 100%; font: 12.5px/1.5 var(--mono); white-space: pre; tab-size: 8; }
pre.wrap { white-space: pre-wrap; }
pre .e { color: var(--err); font-weight: 600; } pre .w { color: var(--warn); font-weight: 600; } pre .dim { color: var(--muted); }
.foot { grid-area: foot; padding: 6px 16px; font-size: 13px; color: var(--muted); background: var(--panel);
  border-top: 1px solid var(--border); display: flex; gap: 12px; align-items: center; min-height: 34px; }
.foot .msg.ok { color: var(--ok); } .foot .msg.err { color: var(--err); }
.progress { flex: 0 0 140px; height: 4px; border-radius: 2px; background: var(--panel-2); overflow: hidden; visibility: hidden; }
.progress.on { visibility: visible; }
.progress i { display: block; height: 100%; width: 0; background: var(--accent); transition: width .15s; }
.more { position: relative; }
.more .list { position: absolute; right: 0; top: calc(100% + 4px); z-index: 20; min-width: 230px; display: none; flex-direction: column;
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 4px; box-shadow: 0 6px 24px rgba(0,0,0,.18); }
.more.open .list { display: flex; }
.more .list button { border: none; text-align: left; border-radius: 6px; }
.more .list button:hover { background: var(--panel-2); }
@media (max-width: 760px) {
  h2-rules-panel { grid-template-columns: minmax(0, 1fr); grid-template-rows: auto auto auto minmax(0, 1fr) auto;
    grid-template-areas: "bar" "state" "tabs" "main" "foot"; }
  .out { display: contents; }
  .tabs { grid-area: tabs; background: var(--panel); }
  .out pre { grid-area: main; background: var(--panel); }
  .src { grid-area: main; border-right: none; display: none; }
  h2-rules-panel[data-tab="src"] .src { display: block; }
  h2-rules-panel[data-tab="src"] .out pre { display: none; }
  .tabs .src-tab { display: block; }
  .menu-btn { display: inline-block; }
  .bar { padding: 8px 10px; }
  .bar select { flex: 1 1 calc(100% - 60px); min-width: 0; }
  .more .list { max-width: calc(100vw - 20px); }
  .bar .spacer { display: none; }
  .bar [data-act="compile"] { margin-left: auto; }
  .state { padding: 6px 12px; }
}
`;

const TEMPLATE = `
<div class="bar">
  <button class="menu-btn" data-act="menu" aria-label="Home Assistant menu">☰</button>
  <select data-id="switch" aria-label="Switch"></select>
  <span class="spacer"></span>
  <button data-act="compile" disabled>Compile</button>
  <button data-act="upload" class="primary" disabled>Load onto switch</button>
  <span class="more">
    <button data-act="more" aria-haspopup="true">More</button>
    <span class="list">
      <button data-act="save">Save source</button>
      <button data-act="readback">Read program from switch</button>
      <button data-act="saveimage">Save that program as a file</button>
      <button data-act="example">Start from an example…</button>
      <button data-act="erase">Remove the program from the switch</button>
      <button data-act="refresh">Refresh switch state</button>
    </span>
  </span>
</div>
<div class="state" data-id="state">Looking for switches…</div>
<div class="src" data-id="src"></div>
<div class="out">
  <div class="tabs" role="tablist">
    <button role="tab" class="src-tab" data-tab="src">Source</button>
    <button role="tab" data-tab="log">Messages</button>
    <button role="tab" data-tab="asm">Assembly</button>
    <button role="tab" data-tab="dev">On the switch</button>
  </div>
  <pre data-id="pane" class="wrap"></pre>
</div>
<div class="foot"><span class="msg" data-id="msg">Loading the compiler…</span><span class="spacer" style="flex:1"></span><span class="progress" data-id="progress"><i></i></span></div>
`;

class H2RulesPanel extends HTMLElement {
  connectedCallback() {
    if (this._built) return;
    this._built = true;
    const style = document.createElement("style");
    style.textContent = STYLE;
    document.head.append(style);
    this.innerHTML = TEMPLATE;
    this.$ = (id) => this.querySelector(`[data-id="${id}"]`);
    this.panes = { log: "Nothing compiled yet.", asm: "", dev: "Use More → Read program from switch to see what the switch is running." };
    this.tab = matchMedia("(max-width: 760px)").matches ? "src" : "log";
    this.sw = null;             // zha.Switch for the selected switch
    this.status = null;         // its last status()
    this.saved = { source: null, meta: {} };
    this.compiled = null;       // { source, image } of the last good compile
    this.dirty = false;         // editor differs from the saved source
    this.busy = false;
    this.seq = 0;
    this.pending = new Map();

    this.editor = createEditor(this.$("src"), {
      onChange: () => { if (!this._loading) { this.dirty = true; this.renderState(); } },
      onRun: () => this.act("compile"),
      wrap: matchMedia("(max-width: 760px)").matches,
    });
    this.addEventListener("click", (e) => {
      const b = e.target.closest("button");
      if (!b) { this.querySelector(".more").classList.remove("open"); return; }
      if (b.dataset.tab) return this.setTab(b.dataset.tab);
      if (b.dataset.act === "more") return this.querySelector(".more").classList.toggle("open");
      this.querySelector(".more").classList.remove("open");
      if (b.dataset.act) this.act(b.dataset.act);
    });
    this.$("switch").addEventListener("change", (e) => this.selectSwitch(e.target.value));
    this.setTab(this.tab);
    this.startWorker();
    fetch(new URL("sysroot.json", BASE)).then((r) => r.json())
      .then((s) => { this.helpers = helperNames(s["h2_rules.h"]); }).catch(() => { this.helpers = {}; });
    if (this._hass) this.start();
  }

  set hass(hass) {
    const first = !this._hass;
    this._hass = hass;
    document.documentElement.dataset.theme = hass.themes && hass.themes.darkMode ? "dark" : "light";
    if (this.sw) this.sw.hass = hass;
    if (first && this._built) this.start();
  }
  set narrow(v) { this._narrow = v; }
  set panel(v) { this._panel = v; }

  // ---------- compiler ----------
  startWorker() {
    this.worker = new Worker(new URL("worker.js", BASE), { type: "module" });
    this.worker.onmessage = ({ data: m }) => {
      if (m.type === "progress") {
        this.progress(m.loaded, m.total);
        this.say(`Downloading the compiler: ${(m.loaded / 1048576).toFixed(1)}${m.total ? " of " + (m.total / 1048576).toFixed(1) : ""} MB`);
      } else if (m.type === "ready") {
        this.ready = true;
        this.progress(0, 0);
        this.say(`Compiler ready (${(m.ms / 1000).toFixed(1)} s)`, "ok");
        this.renderButtons();
      } else if (m.type === "result" || m.type === "error") {
        const done = this.pending.get(m.id);
        this.pending.delete(m.id);
        if (done) done(m);
        else if (m.type === "error") { this.say(m.message.split("\n")[0], "err"); this.panes.log = esc(m.message); this.renderPane(); }
      }
    };
  }
  compileSource(source) {
    return new Promise((resolve) => {
      const id = ++this.seq;
      this.pending.set(id, resolve);
      this.worker.postMessage({ type: "compile", id, source });
    });
  }

  // Compile what is in the editor. Returns the image or null; fills the Messages pane.
  async compile() {
    const source = this.editor.value;
    this.say("Compiling…");
    const m = await this.compileSource(source);
    if (m.type === "error") {
      this.panes.log = esc(m.message); this.setTab("log");
      this.say("The compiler failed", "err");
      return null;
    }
    const h2 = m.h2;
    let log = m.log;
    if (h2 && !h2.ok) log += `${log ? "\n" : ""}error: ${h2.problems.join("\nerror: ")}\n`;
    this.editor.setDiagnostics(diagnostics(m.log));
    const ok = m.code === 0 && h2 && h2.ok;
    if (ok) {
      log += `${log ? "\n" : ""}${h2.blob.length} bytes, ${h2.insns} instructions` +
        (h2.dataBytes ? `, ${h2.dataBytes} bytes of constant data` : "") +
        ` (${Math.round((100 * h2.blob.length) / H2_MAX_BYTES)} % of the ${H2_MAX_BYTES} the firmware takes), checksum ${hex4(crc16(h2.blob))}\n`;
    }
    this.panes.log = esc(log || "No messages.")
      .replace(/\berror:/g, '<span class="e">error:</span>').replace(/\bwarning:/g, '<span class="w">warning:</span>');
    this.panes.asm = ok && m.asm ? esc(m.asm) : "";
    if (!ok) {
      this.compiled = null;
      this.setTab("log");
      this.say(m.code === 0 ? "The rule checks failed" : "Compilation failed", "err");
      return null;
    }
    this.compiled = { source, image: h2.blob };
    if (this.tab !== "src") this.setTab(/warning:/.test(m.log) ? "log" : this.tab);
    else this.renderPane();
    this.say(`Compiled in ${m.ms} ms: ${h2.blob.length} bytes`, "ok");
    this.renderState();
    return h2.blob;
  }

  // ---------- switches ----------
  async start() {
    if (this._started) return;
    this._started = true;
    try {
      this.switches = await listSwitches(this._hass);
    } catch (e) {
      this.$("state").innerHTML = `<span class="err">Could not list ZHA devices: ${esc(e.message || e.code || e)}</span>`;
      return;
    }
    const sel = this.$("switch");
    sel.innerHTML = "";
    const ours = this.switches.filter((s) => s.ours);
    if (!ours.length) {
      this.$("state").innerHTML = this.switches.length
        ? "No switch runs the h2-zigbee firmware yet. Flash one first (see the README)."
        : "ZHA knows no H2 switch.";
      return;
    }
    for (const s of ours) sel.add(new Option(s.name + (s.available ? "" : " (unavailable)"), s.ieee));
    let last = null;
    try { last = localStorage.getItem(LAST_KEY); } catch {}
    sel.value = ours.some((s) => s.ieee === last) ? last : ours[0].ieee;
    await this.selectSwitch(sel.value);
  }

  async selectSwitch(ieee) {
    if (this.dirty && !confirm("The source has changes that are not saved. Leave them?")) {
      this.$("switch").value = this.sw.ieee;
      return;
    }
    try { localStorage.setItem(LAST_KEY, ieee); } catch {}
    this.sw = new Switch(this._hass, ieee);
    this.info = this.switches.find((s) => s.ieee === ieee);
    this.status = null; this.compiled = null; this.devImage = null;
    this.panes.dev = "Use More → Read program from switch to see what the switch is running.";
    this.$("state").textContent = "Reading the switch…";
    try {
      this.saved = await this._hass.callWS({ type: "h2_rules/source/get", ieee });
    } catch (e) {
      this.saved = { source: null, meta: {} };
      this.say("Could not read the saved source: " + (e.message || e.code), "err");
    }
    if (this.saved.source !== null) this.setSource(this.saved.source);
    else await this.loadExample("switch_demo.c", false);
    this.dirty = false;
    await this.refresh();
  }

  async refresh() {
    if (!this.sw) return;
    const sw = this.sw;
    try {
      const st = await sw.status();
      if (sw !== this.sw) return;
      this.status = st; this.statusError = null;
    } catch (e) {
      if (sw !== this.sw) return;
      this.status = null; this.statusError = e.message || String(e);
    }
    this.renderState();
    this.renderButtons();
  }

  setSource(text) {
    this._loading = true;
    try { this.editor.value = text; } finally { this._loading = false; }
    this.editor.setDiagnostics([]);
  }

  async loadExample(name, ask = true) {
    if (ask && this.dirty && !confirm("Replace the source in the editor with the example?")) return;
    const text = await (await fetch(new URL("examples/" + name, BASE))).text();
    this.setSource(text);
    this.dirty = ask;
    this.compiled = null;
    this.renderState();
  }

  // ---------- actions ----------
  async act(what) {
    if (what === "menu") {
      // Narrow screens: Home Assistant hides its sidebar; this opens it.
      // The event has to start inside Home Assistant's page: from the iframe that holds us.
      const ev = new CustomEvent("hass-toggle-menu", { bubbles: true, composed: true });
      try { (window.frameElement || this).dispatchEvent(ev); } catch { this.dispatchEvent(ev); }
      return;
    }
    if (this.busy) return;
    this.busy = true;
    this.renderButtons();
    try {
      await this[`do_${what}`]();
    } catch (e) {
      this.say(e.message || String(e), "err");
    } finally {
      this.busy = false;
      this.progress(0, 0);
      this.renderButtons();
    }
  }

  async do_compile() { await this.compile(); }

  async do_save() {
    const source = this.editor.value;
    const r = await this._hass.callWS({ type: "h2_rules/source/save", ieee: this.sw.ieee, source,
      meta: { name: this.info.name, saved: new Date().toISOString() } });
    this.saved = { ...this.saved, source, meta: r.meta };
    this.dirty = false;
    this.say("Source saved in Home Assistant", "ok");
    this.renderState();
  }

  async do_upload() {
    const source = this.editor.value;
    const image = this.compiled && this.compiled.source === source ? this.compiled.image : await this.compile();
    if (!image) return;
    this.say("Loading onto the switch…");
    let st;
    try {
      st = await this.sw.upload(image, (done, total) => this.progress(done, total));
    } catch (e) {
      if (e.status) this.status = e.status;
      this.renderState();
      throw new Error("The switch did not take the program: " + e.message);
    }
    this.status = st;
    const now = new Date().toISOString();
    const r = await this._hass.callWS({ type: "h2_rules/source/save", ieee: this.sw.ieee, source, image: toHex(image),
      meta: { name: this.info.name, saved: now, uploaded: now, crc: crc16(image), length: image.length } });
    this.saved = { source, meta: r.meta, image: toHex(image) };
    this.dirty = false;
    this.say(`Running on the switch: ${image.length} bytes, checksum ${hex4(crc16(image))}. Source saved.`, "ok");
    this.renderState();
  }

  async do_readback() {
    this.say("Reading the program from the switch…");
    const image = await this.sw.download((done, total) => this.progress(done, total));
    this.devImage = image;
    this.panes.dev = `<span class="dim"># read from ${esc(this.info.name)}: ${image.length} bytes, checksum ${hex4(crc16(image))}\n` +
      `# names of the program's own functions and variables are not stored on the switch\n\n</span>` +
      esc(disassemble(image, this.helpers || {}));
    this.setTab("dev");
    this.say(`Read ${image.length} bytes from the switch`, "ok");
  }

  async do_saveimage() {
    if (!this.devImage) await this.do_readback();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([this.devImage], { type: "application/octet-stream" }));
    a.download = `${this.sw.ieee.replace(/:/g, "-")}.bpf`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  async do_example() {
    const names = await (await fetch(new URL("examples/index.json", BASE))).json();
    const pick = prompt("Example to start from:\n\n" + names.map((n, i) => `${i + 1}  ${n}`).join("\n") + "\n\nNumber:");
    const n = names[Number(pick) - 1];
    if (n) await this.loadExample(n);
  }

  async do_erase() {
    if (!confirm(`Remove the rule program from ${this.info.name}? Its buttons go back to the firmware's own behaviour. The saved source stays.`)) return;
    this.status = await this.sw.erase();
    this.say("The switch has no rule program now", "ok");
    this.renderState();
  }

  async do_refresh() { await this.refresh(); this.say("Switch state read", "ok"); }

  // ---------- rendering ----------
  setTab(tab) {
    this.tab = tab;
    this.dataset.tab = tab;
    for (const b of this.querySelectorAll(".tabs [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
    this.renderPane();
  }
  renderPane() {
    if (this.tab === "src") return;
    const pane = this.$("pane");
    pane.classList.toggle("wrap", this.tab === "log");
    pane.innerHTML = this.panes[this.tab] || '<span class="dim">Compile to see the assembly.</span>';
  }
  renderButtons() {
    const q = (a) => this.querySelector(`[data-act="${a}"]`);
    q("compile").disabled = !this.ready || this.busy;
    q("upload").disabled = !this.ready || this.busy || !this.sw || !this.status;
    for (const a of ["save", "readback", "saveimage", "erase", "refresh"]) q(a).disabled = this.busy || !this.sw;
  }
  renderState() {
    const st = this.status, parts = [];
    if (!this.sw) return;
    if (!st) {
      this.$("state").innerHTML = `<span class="err">${esc(this.statusError || "The switch state is not known.")}</span>`;
      return;
    }
    if (st.program) parts.push(`On the switch: <b>${st.program.length} bytes</b>, checksum ${hex4(st.program.crc)}${st.running ? "" : ', <span class="warn">not running</span>'}`);
    else parts.push("On the switch: <b>no rule program</b>");
    if (st.safeMode) parts.push('<span class="err">The switch is in safe mode: programs do not run</span>');
    const meta = this.saved.meta || {};
    if (st.program) {
      if (this.compiled && this.compiled.source === this.editor.value) {
        parts.push(crc16(this.compiled.image) === st.program.crc
          ? '<span class="ok">Same as the source in the editor</span>'
          : '<span class="warn">The editor compiles to a different program</span>');
      } else if (meta.crc === st.program.crc && meta.length === st.program.length) {
        parts.push(this.dirty ? '<span class="warn">Source changed since it was loaded</span>' : '<span class="ok">Loaded from the saved source</span>');
      } else if (this.saved.source !== null) {
        parts.push('<span class="warn">Not the program last loaded from here</span>');
      } else {
        parts.push('<span class="warn">No saved source for it</span>');
      }
    }
    if (this.dirty) parts.push("Source not saved");
    if (st.faults && st.faults.count) parts.push(`<span class="err">${st.faults.count} fault${st.faults.count > 1 ? "s" : ""}; last: ${esc(FAULTS[st.faults.code] || "code " + st.faults.code)} at instruction ${st.faults.at}</span>`);
    if (st.lastResult) parts.push(`<span class="warn">Last load: ${esc(RESULTS[st.lastResult] || st.lastResult)}</span>`);
    if (st.storeBytes) parts.push(`Settings store: ${st.storeBytes.toLocaleString()} of 18,000 bytes`);
    if (st.dropped) parts.push(`${st.dropped} messages or events dropped by limits`);
    this.$("state").innerHTML = parts.map((p) => `<span>${p}</span>`).join("");
  }
  say(text, cls = "") { const m = this.$("msg"); m.textContent = text; m.className = "msg " + cls; }
  progress(done, total) {
    const p = this.$("progress");
    p.classList.toggle("on", total > 0);
    p.firstElementChild.style.width = total ? Math.min(100, (100 * done) / total) + "%" : "0";
  }
}

// clang diagnostics -> editor markers. A problem inside a header is shown on the line of
// the source that included it.
function diagnostics(text) {
  const out = [];
  let includeLine = null;
  for (const l of (text || "").split("\n")) {
    let m = l.match(/^In file included from \/work\/main\.c:(\d+):/);
    if (m) { includeLine = +m[1]; continue; }
    m = l.match(/^(\/[^:]+):(\d+):(\d+): (fatal error|error|warning|note): (.*)$/);
    if (!m) continue;
    const [, file, line, col, kind, message] = m;
    const severity = kind === "warning" ? "warning" : kind === "note" ? "info" : "error";
    if (file === "/work/main.c") { out.push({ line: +line, col: +col, severity, message }); includeLine = null; }
    else if (includeLine) out.push({ line: includeLine, col: 1, severity, message: `${file}:${line}:${col}: ${message}` });
  }
  return out;
}

customElements.define("h2-rules-panel", H2RulesPanel);
