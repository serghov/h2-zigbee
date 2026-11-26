// CodeMirror 6 setup for the eBPF compiler page. Bundled by esbuild into web/vendor/editor.js.
// Colors come from the page's CSS custom properties, so the editor follows its light/dark theme.
import {
  EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection,
  highlightSpecialChars, dropCursor, rectangularSelection, crosshairCursor, ViewPlugin, Decoration,
  MatchDecorator,
} from "@codemirror/view";
import { EditorState, Prec, Compartment } from "@codemirror/state";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import {
  indentOnInput, bracketMatching, syntaxHighlighting, HighlightStyle, indentUnit, foldGutter, foldKeymap,
} from "@codemirror/language";
import { closeBrackets, closeBracketsKeymap } from "@codemirror/autocomplete";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { lintGutter, lintKeymap, setDiagnostics } from "@codemirror/lint";
import { cpp } from "@codemirror/lang-cpp";
import { tags as t } from "@lezer/highlight";

const highlight = HighlightStyle.define([
  { tag: [t.keyword, t.definitionKeyword, t.modifier, t.controlKeyword, t.operatorKeyword], color: "var(--c-kw)" },
  { tag: [t.typeName, t.standard(t.typeName)], color: "var(--c-type)" },
  { tag: [t.string, t.special(t.string), t.character], color: "var(--c-str)" },
  { tag: [t.number, t.bool, t.null], color: "var(--c-const)" },
  { tag: t.escape, color: "var(--c-const)" },
  { tag: [t.lineComment, t.blockComment], color: "var(--c-comment)", fontStyle: "italic" },
  { tag: t.processingInstruction, color: "var(--c-pp)" },
  { tag: t.meta, color: "var(--c-const)" },   // #define values
  { tag: t.special(t.name), color: "var(--c-const)" },
  { tag: [t.function(t.variableName), t.function(t.propertyName)], color: "var(--c-fn)" },
  { tag: t.function(t.definition(t.variableName)), color: "var(--c-fn)", fontWeight: "600" },
]);

// Macro constants used in code (H2_EV_SINGLE, GROUP, XDP_PASS, ...) parse as plain
// identifiers; give ALL_CAPS words the constant colour.
const constMatcher = new MatchDecorator({
  regexp: /\b[A-Z][A-Z0-9_]{2,}\b/g,
  decoration: Decoration.mark({ class: "cm-const" }),
});
const constants = ViewPlugin.define((view) => ({
  decorations: constMatcher.createDeco(view),
  update(u) { this.decorations = constMatcher.updateDeco(u, this.decorations); },
}), { decorations: (v) => v.decorations });

const theme = EditorView.theme({
  "&": { height: "100%", backgroundColor: "var(--panel)", color: "var(--text)", fontSize: "inherit" },
  "&.cm-focused": { outline: "none" },
  ".cm-scroller": { fontFamily: "var(--mono)", lineHeight: "1.5", overflow: "auto" },
  ".cm-content": { padding: "12px 0", caretColor: "var(--accent)" },
  ".cm-line": { padding: "0 16px 0 8px" },
  ".cm-gutters": { backgroundColor: "var(--panel)", color: "var(--muted)", border: "none" },
  ".cm-lineNumbers .cm-gutterElement": { padding: "0 4px 0 12px", minWidth: "2.5em" },
  ".cm-activeLine": { backgroundColor: "var(--line-active)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--line-active)", color: "var(--text)" },
  "&.cm-focused .cm-cursor": { borderLeftColor: "var(--accent)" },
  "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, ::selection":
    { backgroundColor: "var(--selection)" },
  ".cm-matchingBracket": { backgroundColor: "var(--selection)", outline: "1px solid var(--border)" },
  ".cm-selectionMatch": { backgroundColor: "var(--line-active)" },
  ".cm-const": { color: "var(--c-const)" },
  ".cm-tooltip": { backgroundColor: "var(--panel-2)", color: "var(--text)", border: "1px solid var(--border)", borderRadius: "6px" },
  ".cm-diagnostic": { fontFamily: "var(--mono)", fontSize: "12.5px", whiteSpace: "pre-wrap" },
  ".cm-panels": { backgroundColor: "var(--panel-2)", color: "var(--text)" },
  ".cm-panels input, .cm-panels button": { fontSize: "14px" },
  ".cm-foldGutter .cm-gutterElement": { padding: "0 4px", color: "var(--muted)" },
});

/**
 * createEditor(parent, { doc, onChange(text), onRun(), wrap })
 *  -> { value (get/set), setDiagnostics([{ line, col, severity, message }]), setWrap(bool), focus() }
 * line/col are 1-based (clang's numbering). severity: "error" | "warning" | "info".
 */
export function createEditor(parent, { doc = "", onChange, onRun, wrap = false } = {}) {
  const wrapping = new Compartment();
  const view = new EditorView({
    parent,
    state: EditorState.create({
      doc,
      extensions: [
        lineNumbers(), foldGutter(), lintGutter(), highlightActiveLineGutter(), highlightSpecialChars(),
        history(), drawSelection(), dropCursor(), indentOnInput(), bracketMatching(), closeBrackets(),
        rectangularSelection(), crosshairCursor(), highlightActiveLine(), highlightSelectionMatches(),
        EditorState.allowMultipleSelections.of(true), indentUnit.of("    "), EditorState.tabSize.of(4),
        cpp(), syntaxHighlighting(highlight), constants, theme,
        wrapping.of(wrap ? EditorView.lineWrapping : []),
        EditorView.contentAttributes.of({ autocorrect: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "C source" }),
        Prec.highest(keymap.of([{ key: "Mod-Enter", run: () => { onRun && onRun(); return true; } }])),
        keymap.of([...closeBracketsKeymap, ...defaultKeymap, ...searchKeymap, ...historyKeymap,
          ...foldKeymap, ...lintKeymap, indentWithTab]),
        EditorView.updateListener.of((u) => { if (u.docChanged && onChange) onChange(u.state.doc.toString()); }),
      ],
    }),
  });

  return {
    view,
    get value() { return view.state.doc.toString(); },
    set value(text) {
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text }, selection: { anchor: 0 },
        scrollIntoView: true });
      view.dispatch(setDiagnostics(view.state, []));
    },
    setDiagnostics(list) {
      const doc = view.state.doc;
      const diags = [];
      for (const d of list) {
        if (d.line < 1 || d.line > doc.lines) continue;
        const line = doc.line(d.line);
        const from = Math.min(line.from + Math.max(0, d.col - 1), line.to);
        // underline the word at the column (at least one character)
        const word = /^[A-Za-z0-9_]+/.exec(line.text.slice(from - line.from));
        const to = Math.min(line.to, from + Math.max(1, word ? word[0].length : 1));
        diags.push({ from, to: Math.max(to, from), severity: d.severity, message: d.message });
      }
      view.dispatch(setDiagnostics(view.state, diags));
    },
    setWrap(on) { view.dispatch({ effects: wrapping.reconfigure(on ? EditorView.lineWrapping : []) }); },
    focus() { view.focus(); },
  };
}
