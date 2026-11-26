/* ============================================================
   CORSAIR USERSCRIPT CODE EDITOR
   ------------------------------------------------------------
   Zero-CDN, CSP-safe JavaScript & ==UserScript== code editor
   with real-time syntax highlighting, line numbers, error line
   markers, smart indentation, find & replace, metadata helpers,
   and live syntax validation.
   ============================================================ */
const CorsairUserscriptEditor = (() => {
  'use strict';

  const JS_KEYWORDS = new Set([
    'async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue',
    'debugger', 'default', 'delete', 'do', 'else', 'export', 'extends', 'false',
    'finally', 'for', 'from', 'function', 'if', 'import', 'in', 'instanceof',
    'let', 'new', 'null', 'of', 'return', 'static', 'super', 'switch', 'this',
    'throw', 'true', 'try', 'typeof', 'undefined', 'var', 'void', 'while', 'with', 'yield'
  ]);

  const GM_GLOBALS = new Set([
    'GM', 'GM_info', 'unsafeWindow', 'GM_getValue', 'GM_setValue', 'GM_deleteValue',
    'GM_listValues', 'GM_getValues', 'GM_setValues', 'GM_deleteValues',
    'GM_addValueChangeListener', 'GM_removeValueChangeListener',
    'GM_xmlhttpRequest', 'GM_getResourceText', 'GM_getResourceURL',
    'GM_openInTab', 'GM_download', 'GM_notification', 'GM_setClipboard',
    'GM_addStyle', 'GM_addElement', 'GM_log', 'GM_registerMenuCommand',
    'GM_unregisterMenuCommand', 'window', 'document', 'console', 'Promise', 'fetch'
  ]);

  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  /**
   * Tokenize JavaScript + Userscript metadata into safe highlighted HTML.
   * Always produces the exact same character/line layout as the raw text.
   */
  function highlightCode(source) {
    const src = String(source || '');
    const len = src.length;
    let i = 0;
    let out = '';
    let inHeader = false;

    while (i < len) {
      const ch = src[i];
      const next = src[i + 1];

      // Line comment or Userscript metadata line
      if (ch === '/' && next === '/') {
        let end = src.indexOf('\n', i);
        if (end < 0) end = len;
        const line = src.slice(i, end);
        if (/^\/\/\s*==UserScript==\s*$/.test(line)) {
          inHeader = true;
          out += '<span class="tok-meta-bound">' + escHtml(line) + '</span>';
        } else if (/^\/\/\s*==\/UserScript==\s*$/.test(line)) {
          inHeader = false;
          out += '<span class="tok-meta-bound">' + escHtml(line) + '</span>';
        } else if (inHeader) {
          const dm = /^(\/\/\s*)(@[\w:\-.]+)([\s\S]*)$/.exec(line);
          if (dm) {
            out += '<span class="tok-comment">' + escHtml(dm[1]) + '</span>'
              + '<span class="tok-meta-key">' + escHtml(dm[2]) + '</span>'
              + '<span class="tok-meta-val">' + escHtml(dm[3]) + '</span>';
          } else {
            out += '<span class="tok-comment">' + escHtml(line) + '</span>';
          }
        } else {
          out += '<span class="tok-comment">' + escHtml(line) + '</span>';
        }
        i = end;
        continue;
      }

      // Block comment
      if (ch === '/' && next === '*') {
        let end = src.indexOf('*/', i + 2);
        end = end < 0 ? len : end + 2;
        out += '<span class="tok-comment">' + escHtml(src.slice(i, end)) + '</span>';
        i = end;
        continue;
      }

      // Strings & template literals
      if (ch === '"' || ch === "'" || ch === '`') {
        const quote = ch;
        let j = i + 1;
        while (j < len) {
          if (src[j] === '\\') { j += 2; continue; }
          if (src[j] === quote) { j++; break; }
          if (quote !== '`' && src[j] === '\n') break;
          j++;
        }
        out += '<span class="tok-string">' + escHtml(src.slice(i, j)) + '</span>';
        i = j;
        continue;
      }

      // Numbers
      if ((ch >= '0' && ch <= '9') || (ch === '.' && next >= '0' && next <= '9')) {
        let j = i;
        if (ch === '0' && (next === 'x' || next === 'X' || next === 'b' || next === 'B' || next === 'o' || next === 'O')) {
          j += 2;
          while (j < len && /[0-9a-fA-F_]/.test(src[j])) j++;
        } else {
          while (j < len && /[0-9._eE+-]/.test(src[j])) {
            if ((src[j] === '+' || src[j] === '-') && src[j - 1] !== 'e' && src[j - 1] !== 'E') break;
            j++;
          }
        }
        out += '<span class="tok-number">' + escHtml(src.slice(i, j)) + '</span>';
        i = j;
        continue;
      }

      // Identifiers / keywords / GM globals
      if (/[a-zA-Z_$]/.test(ch)) {
        let j = i + 1;
        while (j < len && /[a-zA-Z0-9_$]/.test(src[j])) j++;
        const word = src.slice(i, j);
        if (JS_KEYWORDS.has(word)) {
          out += '<span class="tok-kw">' + word + '</span>';
        } else if (GM_GLOBALS.has(word)) {
          out += '<span class="tok-gm">' + word + '</span>';
        } else if (src[j] === '(') {
          out += '<span class="tok-fn">' + word + '</span>';
        } else {
          out += word;
        }
        i = j;
        continue;
      }

      out += escHtml(ch);
      i++;
    }

    // Trailing newline ensures the highlight layer matches textarea scrollHeight
    return out + '\n';
  }

  /** Insert a full Tampermonkey ==UserScript== header template if missing (preserving existing code). */
  function insertTemplate(code, opts = {}) {
    const src = String(code || '');
    if (/\/\/\s*==UserScript==[\s\S]*?\/\/\s*==\/UserScript==/.test(src)) return src;
    const name = opts.name || 'My Userscript';
    const match = opts.match || 'https://*/*';
    const header = [
      '// ==UserScript==',
      `// @name         ${name}`,
      '// @namespace    corsair-unbound',
      '// @version      1.0.0',
      '// @description  Custom userscript for Corsair Unbound',
      '// @author       You',
      `// @match        ${match}`,
      '// @grant        GM_getValue',
      '// @grant        GM_setValue',
      '// @grant        GM_addStyle',
      '// @run-at       document-idle',
      '// ==/UserScript==',
      ''
    ].join('\n');
    return header + (src.trim() ? '\n' + src : '\n(function () {\n  \'use strict\';\n\n})();\n');
  }

    /** Insert a metadata directive right before `// ==/UserScript==` (or prepend header). */
  function insertDirective(code, directiveLine) {
    const src = String(code || '');
    const endMarker = /\/\/\s*==\/UserScript==/;
    const m = endMarker.exec(src);
    if (m) {
      const idx = m.index;
      const prefix = src.slice(0, idx);
      const needsNl = prefix.length > 0 && !prefix.endsWith('\n');
      return prefix + (needsNl ? '\n' : '') + directiveLine + '\n' + src.slice(idx);
    }
    return [
      '// ==UserScript==',
      '// @name         New Script',
      '// @namespace    corsair-unbound',
      '// @version      1.0.0',
      directiveLine,
      '// ==/UserScript==',
      '',
      src
    ].join('\n');
  }

  /** Find all match ranges `{ start, end }` in text. */
  function findMatches(text, query, opts = {}) {
    if (!query) return [];
    const src = String(text || '');
    const results = [];
    if (opts.regex) {
      let re;
      try { re = new RegExp(query, opts.caseSensitive ? 'g' : 'gi'); }
      catch { return []; }
      let m;
      while ((m = re.exec(src)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        results.push({ start: m.index, end: m.index + m[0].length });
        if (results.length >= 2000) break;
      }
      return results;
    }
    const hay = opts.caseSensitive ? src : src.toLowerCase();
    const needle = opts.caseSensitive ? query : query.toLowerCase();
    let pos = 0;
    while (pos <= hay.length) {
      const idx = hay.indexOf(needle, pos);
      if (idx < 0) break;
      results.push({ start: idx, end: idx + needle.length });
      pos = idx + needle.length;
      if (results.length >= 2000) break;
    }
    return results;
  }

  /** Compute 1-based { line, col } for a cursor index. */
  function cursorLineCol(text, index) {
    const before = String(text || '').slice(0, Math.max(0, index));
    const lines = before.split('\n');
    return { line: lines.length, col: lines[lines.length - 1].length + 1 };
  }

  /** Toggle `// ` comments on all lines covered by [start, end]. */
  function toggleLineComments(text, start, end) {
    const lineStart = text.lastIndexOf('\n', start - 1) + 1;
    let lineEnd = text.indexOf('\n', end);
    if (lineEnd < 0) lineEnd = text.length;
    const block = text.slice(lineStart, lineEnd);
    const lines = block.split('\n');
    const allCommented = lines.every(l => /^\s*\/\//.test(l) || l.trim() === '');
    const updated = lines.map(l => {
      if (l.trim() === '') return l;
      if (allCommented) return l.replace(/^(\s*)\/\/\s?/, '$1');
      return '// ' + l;
    }).join('\n');
    const nextText = text.slice(0, lineStart) + updated + text.slice(lineEnd);
    return { text: nextText, start: lineStart, end: lineStart + updated.length };
  }

  /** Indent or dedent lines covered by [start, end]. */
  function indentSelection(text, start, end, dedent = false) {
    const lineStart = text.lastIndexOf('\n', start - 1) + 1;
    let lineEnd = text.indexOf('\n', end);
    if (lineEnd < 0) lineEnd = text.length;
    const block = text.slice(lineStart, lineEnd);
    const lines = block.split('\n');
    const updated = lines.map(l => {
      if (dedent) return l.replace(/^(?: {1,2}|\t)/, '');
      return '  ' + l;
    }).join('\n');
    const nextText = text.slice(0, lineStart) + updated + text.slice(lineEnd);
    return { text: nextText, start: lineStart, end: lineStart + updated.length };
  }

  return {
    highlightCode,
    insertTemplate,
    insertDirective,
    findMatches,
    cursorLineCol,
    toggleLineComments,
    indentSelection
  };
})();

globalThis.CorsairUserscriptEditor = CorsairUserscriptEditor;
