/* ============================================================
   CORSAIR USERSCRIPTS ENGINE
   ------------------------------------------------------------
   Tampermonkey-class userscript manager built on the official
   chrome.userScripts API (Chrome 120+).

   - Full ==UserScript== metadata parser (with BOM/CRLF, IDN,
     localized keys, unsupported/unknown directive diagnostics)
   - Converts @match / @include / @exclude / @exclude-match into
     Chrome registration rules + runtime URL filter (.tld, regex)
   - Pre-registration syntax validator with exact line/column
     attribution (user script vs @require vs runtime)
   - Caches & validates @require / @resource dependencies
   - Full GM_* and GM.* API suite with cross-tab value-change
     sync (onUserScriptConnect), full XHR lifecycle, @connect
     enforcement, and strict per-script capability checks
   - Registers scripts with chrome.userScripts (CSP-proof)
   - Preserves backward compatibility with legacy migration &
     backup/restore storage formats.
   ============================================================ */
const CorsairUserScripts = (() => {
  'use strict';

  const INDEX_KEY = 'cus:index';
  const REC_PREFIX = 'cus:rec:';
  const VALS_PREFIX = 'cus:vals:';
  const MIGRATED_KEY = 'cus:legacyMigrated';
  const REG_PREFIX = 'cu-';
  const FETCH_TIMEOUT_MS = 20000;
  const BROAD_MATCH = '*://*/*';

  /* ---------- tiny async mutex ---------- */
  let _chain = Promise.resolve();
  function withLock(fn) {
    const run = _chain.then(() => fn());
    _chain = run.catch(() => {});
    return run;
  }

  function stripBom(str) {
    const s = String(str == null ? '' : str);
    return s.charCodeAt(0) === 0xFEFF ? s.slice(1) : s;
  }

  function safeJson(val) {
    return JSON.stringify(val)
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
  }

  /* ============================================================
     COMPATIBILITY MATRIX (Tampermonkey <-> Chrome MV3)
     ============================================================ */
  const UNSUPPORTED_DIRECTIVES = {
    webrequest: 'Chrome MV3 userScripts cannot intercept/modify network requests dynamically via @webRequest.',
    'run-in': 'Container/incognito per-context targeting (@run-in) is controlled by Chrome extension incognito mode.',
    unwrap: 'Chrome MV3 userScripts wrap execution for GM APIs and runtime URL filtering; @unwrap is ignored when grants or runtime filters are active.'
  };

  const UNSUPPORTED_GRANTS = {
    gm_cookie: 'Direct cross-site cookie jar access (GM_cookie) is not exposed to userscripts for security isolation.',
    'gm.cookie': 'Direct cross-site cookie jar access (GM.cookie) is not exposed to userscripts for security isolation.',
    gm_webrequest: 'Dynamic blocking webRequest is unavailable in Chrome Manifest V3.',
    'window.close': 'Chrome prevents scripts from closing tabs not opened by the script itself.',
    'window.focus': 'Programmatic window focusing is restricted by Chrome security policy.'
  };

  function getCompatibilityMatrix() {
    return {
      storage: [
        { api: 'GM_getValue / GM.getValue', status: 'supported', notes: 'Synchronous cache preloaded before script runs; async Promise for GM.*' },
        { api: 'GM_setValue / GM.setValue', status: 'supported', notes: 'Per-script isolated storage in chrome.storage.local' },
        { api: 'GM_deleteValue / GM.deleteValue', status: 'supported', notes: 'Deletes key and triggers local + cross-tab listeners' },
        { api: 'GM_listValues / GM.listValues', status: 'supported', notes: 'Returns array of stored keys' },
        { api: 'GM_getValues / GM.getValues', status: 'supported', notes: 'Batch read supporting array, defaults map, or all values' },
        { api: 'GM_setValues / GM.setValues', status: 'supported', notes: 'Atomic batch write to storage' },
        { api: 'GM_deleteValues / GM.deleteValues', status: 'supported', notes: 'Atomic batch delete from storage' },
        { api: 'GM_addValueChangeListener / GM_removeValueChangeListener', status: 'supported', notes: 'Local and cross-tab/frame sync via chrome.runtime.onUserScriptConnect' }
      ],
      networking: [
        { api: 'GM_xmlhttpRequest / GM.xmlHttpRequest', status: 'supported', notes: 'Cross-origin via extension background; Promise + .abort(); @connect enforced; private IPs blocked unless explicitly listed' }
      ],
      resources: [
        { api: 'GM_getResourceText / GM.getResourceText', status: 'supported', notes: 'Cached at install/save time from @resource' },
        { api: 'GM_getResourceURL / GM.getResourceUrl', status: 'supported', notes: 'Returns data: URL cached from @resource' },
        { api: '@require', status: 'supported', notes: 'Cached over HTTPS/data:/localhost, validated before registration' }
      ],
      browser: [
        { api: 'GM_openInTab / GM.openInTab', status: 'supported', notes: 'Opens http(s)/about:blank tab; returns handle with close() & onclose' },
        { api: 'GM_download / GM.download', status: 'supported', notes: 'Uses chrome.downloads with dangerous executable extension guard' },
        { api: 'GM_notification / GM.notification', status: 'supported', notes: 'Uses chrome.notifications with onclick/ondone callbacks' },
        { api: 'GM_setClipboard / GM.setClipboard', status: 'supported', notes: 'Supports text/plain and text/html with Clipboard API + fallback' },
        { api: 'GM_addStyle / GM.addStyle', status: 'supported', notes: 'Injects <style> element into head/documentElement' },
        { api: 'GM_addElement / GM.addElement', status: 'supported', notes: 'Creates and appends DOM elements' },
        { api: 'GM_registerMenuCommand / GM_unregisterMenuCommand', status: 'supported', notes: 'Rendered securely in the Corsair toolbar popup' },
        { api: 'GM_log / GM.log', status: 'supported', notes: 'Logs to page console' },
        { api: 'GM_info / GM.info', status: 'supported', notes: 'Tampermonkey-compatible script metadata and runtime info' },
        { api: 'unsafeWindow', status: 'partial', notes: 'Direct page window in MAIN world (@inject-into page); isolated window in USER_SCRIPT world due to Chrome MV3 world isolation' },
        { api: 'window.onurlchange', status: 'supported', notes: 'SPA navigation listener hooking History API, popstate, and hashchange' },
        { api: 'GM_getTab / GM_saveTab / GM_getTabs', status: 'supported', notes: 'Per-tab session objects persisted in chrome.storage.session and cleaned up on tab close' },
        { api: 'GM_cookie / GM_webRequest', status: 'unsupported', notes: 'Restricted by Chrome MV3 security architecture or not exposed to userscripts' }
      ]
    };
  }

  /* ============================================================
     METADATA PARSER
     ============================================================ */
  const HEADER_RE = /\/\/\s*==UserScript==([\s\S]*?)\/\/\s*==\/UserScript==/;

  function emptyMeta() {
    return {
      name: '', namespace: '', version: '', description: '', author: '',
      homepage: '', website: '', source: '', icon: '', updateURL: '', downloadURL: '', supportURL: '',
      license: '', copyright: '', runAt: 'document-idle', injectInto: 'auto', sandbox: '',
      noframes: false, topLevelAwait: false, unwrap: false,
      match: [], include: [], exclude: [], excludeMatch: [],
      grant: [], require: [], resource: [], connect: [], tags: [], antifeature: [],
      localized: {},
      unsupported: [],
      unknown: [],
      warnings: []
    };
  }

  function parseMetadata(code) {
    const meta = emptyMeta();
    const src = stripBom(code);
    const m = HEADER_RE.exec(src);
    if (!m) return { meta, hasHeader: false, headerText: '', headerStartLine: 0, headerEndLine: 0 };

    const beforeHeader = src.slice(0, m.index);
    const headerStartLine = beforeHeader.split(/\r\n|\r|\n/).length;
    const headerEndLine = headerStartLine + m[0].split(/\r\n|\r|\n/).length - 1;

    const seenSingle = new Set();
    const setSingle = (field, val, directiveName) => {
      if (seenSingle.has(field)) {
        meta.warnings.push(`Duplicate @${directiveName} directive; keeping latest value.`);
      }
      seenSingle.add(field);
      meta[field] = val;
    };

    for (const rawLine of m[1].split(/\r\n|\r|\n/)) {
      const cleaned = stripBom(rawLine);
      const lm = /^\s*\/\/\s*@([\w:\-.]+)(?:[ \t]+(.*?))?\s*$/.exec(cleaned);
      if (!lm) continue;
      const rawKey = lm[1];
      const key = rawKey.toLowerCase();
      const val = (lm[2] || '').trim();

      if (key.includes(':')) {            // @name:fa, @description:de ...
        meta.localized[key] = val;
        continue;
      }

      switch (key) {
        case 'name': setSingle('name', val, 'name'); break;
        case 'namespace': setSingle('namespace', val, 'namespace'); break;
        case 'version': setSingle('version', val, 'version'); break;
        case 'description': setSingle('description', val, 'description'); break;
        case 'author': setSingle('author', val, 'author'); break;
        case 'homepage': case 'homepageurl':
          if (!meta.homepage) meta.homepage = val;
          break;
        case 'website':
          meta.website = val;
          if (!meta.homepage) meta.homepage = val;
          break;
        case 'source':
          meta.source = val;
          if (!meta.homepage) meta.homepage = val;
          break;
        case 'icon': case 'iconurl': case 'defaulticon': case 'icon64': case 'icon64url':
          if (!meta.icon) meta.icon = val;
          break;
        case 'updateurl': setSingle('updateURL', val, 'updateURL'); break;
        case 'downloadurl': case 'installurl': setSingle('downloadURL', val, 'downloadURL'); break;
        case 'supporturl': setSingle('supportURL', val, 'supportURL'); break;
        case 'license': setSingle('license', val, 'license'); break;
        case 'copyright': setSingle('copyright', val, 'copyright'); break;
        case 'match': if (val) meta.match.push(val); break;
        case 'include':
          if (val) {
            meta.include.push(val);
            if (isRegexLiteral(val)) {
              const [s, fl] = regexLiteralToPair(val);
              try { new RegExp(s, fl); } catch { meta.warnings.push(`Invalid regex in @include: ${val}`); }
            }
          }
          break;
        case 'exclude':
          if (val) {
            meta.exclude.push(val);
            if (isRegexLiteral(val)) {
              const [s, fl] = regexLiteralToPair(val);
              try { new RegExp(s, fl); } catch { meta.warnings.push(`Invalid regex in @exclude: ${val}`); }
            }
          }
          break;
        case 'exclude-match': if (val) meta.excludeMatch.push(val); break;
        case 'grant':
          if (val) {
            meta.grant.push(val);
            const lk = val.toLowerCase();
            if (UNSUPPORTED_GRANTS[lk]) {
              meta.unsupported.push({ directive: '@grant', value: val, reason: UNSUPPORTED_GRANTS[lk] });
            }
          }
          break;
        case 'require': if (val) meta.require.push(val); break;
        case 'connect': if (val) meta.connect.push(val); break;
        case 'tag': if (val) meta.tags.push(val); break;
        case 'antifeature': if (val) meta.antifeature.push(val); break;
        case 'resource': {
          const rm = /^(\S+)\s+(\S+)(?:\s+.*)?$/.exec(val);
          if (rm) meta.resource.push({ name: rm[1], url: rm[2] });
          else if (val) meta.warnings.push(`Malformed @resource directive: ${val}`);
          break;
        }
        case 'noframes': meta.noframes = true; break;
        case 'top-level-await': meta.topLevelAwait = true; break;
        case 'unwrap':
          meta.unwrap = true;
          meta.unsupported.push({ directive: '@unwrap', value: val, reason: UNSUPPORTED_DIRECTIVES.unwrap });
          break;
        case 'sandbox':
          meta.sandbox = val.toLowerCase();
          if (meta.sandbox === 'raw') {
            meta.unsupported.push({ directive: '@sandbox', value: val, reason: 'Chrome MV3 maps raw sandbox to MAIN world (@inject-into page); GM bridge APIs are unavailable in MAIN world.' });
          }
          break;
        case 'run-at': {
          const v = val.toLowerCase();
          if (['document-start', 'document-body', 'document-end', 'document-idle', 'context-menu'].includes(v)) {
            meta.runAt = v === 'context-menu' ? 'document-idle' : v;
          } else if (val) {
            meta.warnings.push(`Unknown @run-at value "${val}"; defaulting to document-idle.`);
          }
          break;
        }
        case 'inject-into': {
          const v = val.toLowerCase();
          if (['page', 'content', 'auto'].includes(v)) meta.injectInto = v;
          else if (val) meta.warnings.push(`Unknown @inject-into value "${val}"; defaulting to auto.`);
          break;
        }
        default:
          if (UNSUPPORTED_DIRECTIVES[key]) {
            meta.unsupported.push({ directive: '@' + rawKey, value: val, reason: UNSUPPORTED_DIRECTIVES[key] });
          } else {
            meta.unknown.push({ key: rawKey, value: val });
          }
          break;
      }
    }

    meta.grant = Array.from(new Set(meta.grant));
    if (meta.grant.some(g => g.toLowerCase() === 'none') && meta.grant.length > 1) {
      meta.warnings.push('@grant none is combined with other @grant directives; explicit grants take precedence.');
    }
    return { meta, hasHeader: true, headerText: m[0], headerStartLine, headerEndLine };
  }

  function chooseWorld(meta, code) {
    if (meta.injectInto === 'page') return 'MAIN';
    if (meta.injectInto === 'content') return 'USER_SCRIPT';
    if (meta.sandbox === 'raw') return 'MAIN';
    if (meta.sandbox === 'javascript' || meta.sandbox === 'dom') return 'USER_SCRIPT';
    return needsBridge(meta, code) ? 'USER_SCRIPT' : 'MAIN';
  }

  /* ============================================================
     MATCH PATTERNS
     ============================================================ */
  const SCHEMES = new Set(['*', 'http', 'https', 'file', 'ftp', 'ws', 'wss']);
  const HOST_RE = /^(\*|(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*)(?::(\d+|\*))?$/;

  /** Normalize internationalized domain names (IDN -> punycode ASCII) for Chrome match patterns. */
  function normalizeIdnHost(rawHost) {
    const h = String(rawHost || '').trim();
    if (!h || h === '*') return h;
    // Preserve wildcard prefix and optional port
    const hasWild = h.startsWith('*.');
    const rest = hasWild ? h.slice(2) : h;
    const portMatch = /^(.*?)(?::(\d+|\*))?$/.exec(rest);
    if (!portMatch) return h.toLowerCase();
    let domain = portMatch[1];
    const port = portMatch[2] ? ':' + portMatch[2] : '';
    if (!/^[\x00-\x7f]*$/.test(domain)) {
      try {
        domain = new URL('https://' + domain).hostname;
      } catch {
        return h.toLowerCase();
      }
    } else {
      domain = domain.toLowerCase();
    }
    return (hasWild ? '*.' : '') + domain + port;
  }

  /** Convert a Tampermonkey-style @match into a valid Chrome match pattern, or null. */
  function toChromeMatch(pattern) {
    let p = String(pattern == null ? '' : pattern).trim();
    if (!p) return null;
    if (p === '<all_urls>') return p;
    p = p.replace(/^http\*:\/\//i, '*://');

    const m = /^([a-z*]+):\/\/([^/]*)(\/.*)?$/i.exec(p);
    if (!m) return null;

    const scheme = m[1].toLowerCase();
    if (!SCHEMES.has(scheme)) return null;

    const rawHost = m[2];
    const path = m[3] === undefined ? '/*' : m[3];

    if (scheme === 'file') {
      if (rawHost !== '') return null;
      return `file://${path}`;
    }

    // Tampermonkey magic .tld cannot be expressed in Chrome match patterns
    if (/\.tld(?::(?:\d+|\*))?$/i.test(rawHost)) return null;

    const host = normalizeIdnHost(rawHost);
    if (!HOST_RE.test(host)) return null;
    return `${scheme}://${host}${path}`;
  }

  function escapeRegex(s) {
    return String(s).replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }

  /** Glob (* and ?) to regex source, supporting Tampermonkey `.tld` magic TLD. */
  function globToRegexSource(glob) {
    const raw = String(glob);
    // Support Tampermonkey's .tld magic suffix in host position
    const TLD_RE = '(?:[a-z0-9-]{2,}(?:\\.[a-z]{2,3})?)';
    const placeholder = '__CU_MAGIC_TLD__';
    const withTld = raw.replace(/\.tld(?=[/:*?]|$)/gi, '.' + placeholder);
    let out = '';
    for (const ch of withTld) {
      if (ch === '*') out += '.*';
      else if (ch === '?') out += '.';
      else out += escapeRegex(ch);
    }
    out = out.replace(new RegExp(escapeRegex(placeholder), 'g'), TLD_RE);
    return `^${out}$`;
  }

  /** Chrome-style match pattern to regex source (used only for the runtime filter). */
  function matchToRegexSource(chromePattern) {
    if (chromePattern === '<all_urls>') return '^(?:https?|wss?|ftp|file):\\/\\/.*$';
    const m = /^([^:]+):\/\/([^/]*)(\/.*)$/.exec(chromePattern);
    if (!m) return globToRegexSource(chromePattern);
    const scheme = m[1] === '*' ? 'https?' : escapeRegex(m[1]);

    let hostRe = '';
    if (m[1] === 'file') {
      hostRe = '';
    } else {
      const hm = HOST_RE.exec(m[2]);
      if (!hm) return globToRegexSource(chromePattern);
      const h = hm[1];
      const port = hm[2];
      if (h === '*') hostRe = '[^/:]*';
      else if (h.startsWith('*.')) hostRe = `(?:[^/:]*\\.)?${escapeRegex(h.slice(2))}`;
      else hostRe = escapeRegex(h);
      if (!port || port === '*') hostRe += '(?::\\d+)?';
      else hostRe += `:${port}`;
    }
    const pathRe = m[3].split('*').map(escapeRegex).join('.*');
    return `^${scheme}:\\/\\/${hostRe}${pathRe}$`;
  }

  const isRegexLiteral = (s) => /^\/.+\/[a-z]*$/.test(s);

  function regexLiteralToPair(s) {
    const i = s.lastIndexOf('/');
    return [s.slice(1, i), s.slice(i + 1)];
  }

  const unique = (arr) => Array.from(new Set(arr));

  /**
   * Turn parsed metadata into a registration plan.
   * Returns { noMatch, matches, excludeMatches, includeGlobs, excludeGlobs, runtime }
   * `runtime` is non-null when URL filtering must also happen inside the page.
   */
  function buildPlan(meta) {
    const plan = {
      noMatch: false,
      matches: [],
      excludeMatches: [],
      includeGlobs: [],
      excludeGlobs: [],
      runtime: null
    };

    const matchRaw = meta.match || [];
    const includeRaw = meta.include || [];
    const excludeRaw = meta.exclude || [];
    const excludeMatchRaw = meta.excludeMatch || [];

    if (!matchRaw.length && !includeRaw.length) {
      plan.noMatch = true;
      return plan;
    }

    const includeRegex = includeRaw.filter(isRegexLiteral);
    const includeGlob = includeRaw.filter(s => !isRegexLiteral(s));
    const excludeRegex = excludeRaw.filter(isRegexLiteral);
    const excludeGlob = excludeRaw.filter(s => !isRegexLiteral(s));
    const hasMagicTld = (arr) => arr.some(s => /\.tld(?=[/:*?]|$)/i.test(String(s || '')));

    const matchConv = matchRaw.map(toChromeMatch);
    const allMatchOk = matchConv.every(Boolean);

    let needRuntime = false;

    if (matchRaw.length && !includeRaw.length && allMatchOk) {
      plan.matches = unique(matchConv);
    } else if (!matchRaw.length && includeGlob.length && !includeRegex.length && !hasMagicTld(includeGlob)) {
      plan.matches = [BROAD_MATCH];
      if (includeGlob.some(g => /^file:/i.test(g))) plan.matches.push('file:///*');
      plan.includeGlobs = unique(includeGlob);
    } else {
      plan.matches = [BROAD_MATCH];
      if ([...matchRaw, ...includeRaw].some(g => /^file:/i.test(g))) plan.matches.push('file:///*');
      needRuntime = true;
    }

    const excludeMatchConv = excludeMatchRaw.map(toChromeMatch);
    if (excludeMatchConv.every(Boolean)) plan.excludeMatches = unique(excludeMatchConv);
    else needRuntime = true;

    if (excludeRegex.length || hasMagicTld(excludeGlob)) needRuntime = true;
    else plan.excludeGlobs = unique(excludeGlob);

    if (needRuntime) {
      const inc = [];
      matchRaw.forEach((raw, i) => {
        inc.push([matchConv[i] ? matchToRegexSource(matchConv[i]) : globToRegexSource(raw), matchConv[i] ? '' : 'i']);
      });
      includeRaw.forEach(raw => {
        if (isRegexLiteral(raw)) inc.push(regexLiteralToPair(raw));
        else inc.push([globToRegexSource(raw), 'i']);
      });
      const exc = [];
      excludeRaw.forEach(raw => {
        if (isRegexLiteral(raw)) exc.push(regexLiteralToPair(raw));
        else exc.push([globToRegexSource(raw), 'i']);
      });
      excludeMatchRaw.forEach((raw, i) => {
        exc.push([excludeMatchConv[i] ? matchToRegexSource(excludeMatchConv[i]) : globToRegexSource(raw), excludeMatchConv[i] ? '' : 'i']);
      });
      plan.runtime = { i: inc, e: exc };
    }

    return plan;
  }

  /* ============================================================
     CSP-SAFE STATIC SYNTAX & METADATA DIAGNOSTICS (ADVISORY ONLY)
     ------------------------------------------------------------
     NEVER uses dynamic code evaluation (which throw
     EvalError under Manifest V3 CSP script-src 'self' and would
     break script registration in Chrome). Also NEVER blocks a
     user's script from registering or running.
     ============================================================ */
  function looksLikeHtml(text) {
    const t = stripBom(text).trimStart().slice(0, 200).toLowerCase();
    return t.startsWith('<!doctype html') || t.startsWith('<html') || t.startsWith('<?xml');
  }

  /**
   * Pure-JS lexical checker: detects unterminated strings/comments,
   * mismatched brackets, and uncommented prose lines inside/above
   * the ==UserScript== header (such as the Redgifs "Unexpected
   * identifier 'Video'" bug) without ever invoking eval/Function.
   */
  function validateCodeSnippet(code) {
    const clean = stripBom(code);
    const len = clean.length;
    const stack = [];
    let line = 1;
    let col = 1;
    let inHeader = false;
    let headerClosed = false;

    const lines = clean.split(/\r\n|\r|\n/);
    for (let li = 0; li < lines.length; li++) {
      const l = lines[li];
      if (/^\s*\/\/\s*==UserScript==\s*$/.test(l)) { inHeader = true; continue; }
      if (/^\s*\/\/\s*==\/UserScript==\s*$/.test(l)) { inHeader = false; headerClosed = true; continue; }
      if (inHeader && l.trim() && !/^\s*\/\//.test(l)) {
        return {
          ok: false,
          error: 'Uncommented line inside ==UserScript== header: ' + l.trim().slice(0, 60),
          line: li + 1,
          column: 1
        };
      }
    }

    const pairs = { '(': ')', '[': ']', '{': '}' };
    const closers = { ')': '(', ']': '[', '}': '{' };

    let i = 0;
    while (i < len) {
      const ch = clean[i];
      const next = clean[i + 1];

      if (ch === '\n') { line++; col = 1; i++; continue; }
      if (ch === '\r') {
        line++; col = 1;
        i += (next === '\n' ? 2 : 1);
        continue;
      }

      // Line comment
      if (ch === '/' && next === '/') {
        while (i < len && clean[i] !== '\n' && clean[i] !== '\r') { i++; col++; }
        continue;
      }

      // Block comment
      if (ch === '/' && next === '*') {
        const startLine = line, startCol = col;
        i += 2; col += 2;
        let closed = false;
        while (i < len) {
          if (clean[i] === '*' && clean[i + 1] === '/') { i += 2; col += 2; closed = true; break; }
          if (clean[i] === '\n') { line++; col = 1; i++; }
          else { i++; col++; }
        }
        if (!closed) return { ok: false, error: 'Unterminated block comment /*', line: startLine, column: startCol };
        continue;
      }

      // Strings & template literals
      if (ch === '"' || ch === "'" || ch === '`') {
        const quote = ch;
        const startLine = line, startCol = col;
        i++; col++;
        let closed = false;
        while (i < len) {
          const c = clean[i];
          if (c === '\\') { i += 2; col += 2; continue; }
          if (c === quote) { i++; col++; closed = true; break; }
          if (quote !== '`' && (c === '\n' || c === '\r')) break;
          if (c === '\n') { line++; col = 1; i++; }
          else { i++; col++; }
        }
        if (!closed) return { ok: false, error: 'Unterminated string literal', line: startLine, column: startCol };
        continue;
      }

      if (pairs[ch]) {
        stack.push({ ch, line, col });
      } else if (closers[ch]) {
        if (!stack.length || stack[stack.length - 1].ch !== closers[ch]) {
          return { ok: false, error: `Unexpected token '${ch}'`, line, column: col };
        }
        stack.pop();
      }
      i++; col++;
    }

    if (stack.length) {
      const top = stack[stack.length - 1];
      return { ok: false, error: `Unclosed '${top.ch}'`, line: top.line, column: top.col };
    }
    return { ok: true, error: '', line: null, column: null };
  }

  /**
   * Advisory validation for editor diagnostics (NEVER blocks registration).
   */
  function validateScript(record) {
    const meta = (record && record.meta) || parseMetadata(record && record.code).meta;
    const scriptName = meta.name || 'Untitled script';

    const reqs = (record && record.requires) || {};
    for (const rawUrl of (meta.require || [])) {
      const resolved = resolveUrl(rawUrl, record && record.sourceUrl);
      const text = reqs[resolved];
      if (typeof text !== 'string') continue;
      if (looksLikeHtml(text)) {
        const error = 'Downloaded @require appears to be HTML instead of JavaScript';
        return {
          ok: false, source: 'require', requireUrl: rawUrl, line: 1, column: 1, error,
          formatted: `Warning in @require ${rawUrl} (line 1): ${error}`
        };
      }
      const res = validateCodeSnippet(text);
      if (!res.ok) {
        return {
          ok: false, source: 'require', requireUrl: rawUrl, line: res.line, column: res.column, error: res.error,
          formatted: `Syntax warning in @require ${rawUrl}${res.line ? ` (line ${res.line})` : ''}: ${res.error}`
        };
      }
    }

    const userRes = validateCodeSnippet(record && record.code);
    if (!userRes.ok) {
      return {
        ok: false, source: 'user-script', requireUrl: '', line: userRes.line, column: userRes.column, error: userRes.error,
        formatted: `Syntax warning in "${scriptName}"${userRes.line ? ` (line ${userRes.line})` : ''}: ${userRes.error}`
      };
    }

    return { ok: true, source: null, requireUrl: '', line: null, column: null, error: '', formatted: '' };
  }

  /* ============================================================
     GM_* RUNTIME (runs inside the page / user-script world)
     ------------------------------------------------------------
     This function is serialised with toString() and injected, so it
     must stay fully self-contained: no references to module scope.
     ============================================================ */
  function gmRuntime(ctx) {
    'use strict';
    const hasBridge = !!(ctx.bridge && typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage);
    const send = (op, data) => {
      if (!hasBridge) return Promise.reject(new Error('This GM_* function needs the sandbox world (remove @inject-into page).'));
      return chrome.runtime.sendMessage({ __cu: 1, id: ctx.id, op: op, data: data });
    };
    if (ctx.wantsBridge && !hasBridge) {
      console.warn('[Corsair Userscripts] "' + ctx.name + '" uses GM_* functions that need the sandbox world; they are disabled in page mode.');
    }

    const clone = (v) => {
      if (v === undefined) return undefined;
      try { return JSON.parse(JSON.stringify(v)); } catch (e) { return v; }
    };
    const bytesToB64 = (buf) => {
      const b = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
      return btoa(s);
    };
    const b64ToBytes = (b64) => {
      const s = atob(b64);
      const b = new Uint8Array(s.length);
      for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
      return b;
    };
    const impl = {};
    const activeXhrs = new Set();

    /* ---------- values (synchronous cache, async persistence, cross-tab sync) ---------- */
    let values = {};
    const listeners = new Map();
    let listenerSeq = 1;
    let valPort = null;
    const ready = (ctx.needValues && hasBridge)
      ? send('vals:get').then((r) => { values = (r && r.values) || {}; }).catch(() => {})
      : Promise.resolve();
    const has = (k) => Object.prototype.hasOwnProperty.call(values, k);
    const fire = (k, o, n, remote) => {
      listeners.forEach((l) => {
        if (l.key === k) { try { l.cb(k, o, n, !!remote); } catch (e) { console.error(e); } }
      });
    };
    const ensureValPort = () => {
      if (valPort || !hasBridge || !chrome.runtime || typeof chrome.runtime.connect !== 'function') return;
      try {
        valPort = chrome.runtime.connect({ name: 'cu-vals:' + ctx.id });
        valPort.onMessage.addListener((msg) => {
          if (!msg || msg.type !== 'val-change') return;
          const k = String(msg.k);
          const oldVal = has(k) ? clone(values[k]) : undefined;
          if (msg.deleted) {
            delete values[k];
            fire(k, oldVal, undefined, true);
          } else {
            values[k] = clone(msg.v);
            fire(k, oldVal, clone(values[k]), true);
          }
        });
        valPort.onDisconnect.addListener(() => { valPort = null; });
      } catch (e) {}
    };
    impl.getvalue = (k, d) => (has(k) ? clone(values[k]) : d);
    impl.setvalue = (k, v) => {
      const o = has(k) ? clone(values[k]) : undefined;
      values[k] = clone(v);
      fire(k, o, clone(values[k]), false);
      send('vals:set', { k: k, v: values[k] }).catch(() => {});
    };
    impl.deletevalue = (k) => {
      if (!has(k)) return;
      const o = clone(values[k]);
      delete values[k];
      fire(k, o, undefined, false);
      send('vals:del', { k: k }).catch(() => {});
    };
    impl.listvalues = () => Object.keys(values);
    impl.getvalues = (keys) => {
      const out = {};
      if (Array.isArray(keys)) keys.forEach((k) => { if (has(k)) out[k] = clone(values[k]); });
      else if (keys && typeof keys === 'object') Object.keys(keys).forEach((k) => { out[k] = impl.getvalue(k, keys[k]); });
      else Object.keys(values).forEach((k) => { out[k] = clone(values[k]); });
      return out;
    };
    impl.setvalues = (obj) => {
      const entries = {};
      Object.keys(obj || {}).forEach((k) => {
        const o = has(k) ? clone(values[k]) : undefined;
        values[k] = clone(obj[k]);
        entries[k] = values[k];
        fire(k, o, clone(values[k]), false);
      });
      if (Object.keys(entries).length) send('vals:setBatch', { entries: entries }).catch(() => {});
    };
    impl.deletevalues = (keys) => {
      const removed = [];
      (keys || []).forEach((k) => {
        if (!has(k)) return;
        const o = clone(values[k]);
        delete values[k];
        removed.push(k);
        fire(k, o, undefined, false);
      });
      if (removed.length) send('vals:delBatch', { keys: removed }).catch(() => {});
    };
    impl.addvaluechangelistener = (key, cb) => {
      const id = listenerSeq++;
      listeners.set(id, { key: String(key), cb: cb });
      ensureValPort();
      return id;
    };
    impl.removevaluechangelistener = (id) => { listeners.delete(id); };

    /* ---------- GM_xmlhttpRequest (cross-origin, performed by the extension) ---------- */
    impl.xmlhttprequest = (d) => {
      d = d || {};
      const reqId = 'x' + Math.random().toString(36).slice(2) + Date.now().toString(36);
      let finished = false;
      const call = (name, arg) => {
        const f = d[name];
        if (typeof f === 'function') { try { f.call(d, arg); } catch (e) { console.error(e); } }
      };
      const fail = (kind, message, url) => {
        activeXhrs.delete(reqId);
        const e = {
          readyState: 4, status: 0, statusText: '', responseText: '', response: null,
          responseHeaders: '', finalUrl: url || d.url, context: d.context, error: message
        };
        if (kind === 'timeout') call('ontimeout', e);
        else if (kind === 'abort') call('onabort', e);
        else call('onerror', e);
        call('onloadend', e);
      };
      activeXhrs.add(reqId);
      (async () => {
        let url;
        try { url = new URL(d.url, location.href).href; }
        catch (e) { finished = true; fail('error', 'Invalid URL', d.url); return; }

        const headers = Object.assign({}, d.headers || {});
        if (d.user) headers['Authorization'] = 'Basic ' + btoa(d.user + ':' + (d.password || ''));
        const req = {
          reqId: reqId, url: url, method: String(d.method || 'GET').toUpperCase(), headers: headers,
          anonymous: !!d.anonymous, timeout: d.timeout | 0, redirect: d.redirect || 'follow',
          responseType: d.responseType || '', nocache: !!d.nocache, overrideMimeType: d.overrideMimeType || ''
        };
        const data = d.data;
        if (data !== undefined && data !== null) {
          if (typeof data === 'string' && !d.binary) {
            req.body = data;
          } else if (typeof data === 'string' && d.binary) {
            const bytes = new Uint8Array(data.length);
            for (let i = 0; i < data.length; i++) bytes[i] = data.charCodeAt(i) & 0xff;
            req.bodyB64 = bytesToB64(bytes.buffer);
          } else {
            try {
              const wrapped = new Response(data);
              const ct = wrapped.headers.get('content-type');
              req.bodyB64 = bytesToB64(await wrapped.arrayBuffer());
              const hasCT = Object.keys(headers).some((h) => h.toLowerCase() === 'content-type');
              if (ct && !hasCT) headers['Content-Type'] = ct;
            } catch (e) { finished = true; fail('error', 'Unsupported request body', url); return; }
          }
        }

        call('onloadstart', { readyState: 1, status: 0, statusText: '', responseHeaders: '', finalUrl: url, context: d.context });

        let r;
        try { r = await send('xhr', req); }
        catch (e) { r = { ok: false, kind: 'error', error: String((e && e.message) || e) }; }
        if (finished) return;
        finished = true;
        activeXhrs.delete(reqId);

        if (!r || !r.ok) { fail(r && r.kind, (r && r.error) || 'Network error', url); return; }

        const raw = r.res;
        const rt = req.responseType;
        const mime = req.overrideMimeType ? req.overrideMimeType.split(';')[0].trim() : (raw.mime || '');
        let response;
        let responseText = '';
        let responseXML = null;
        if (rt === 'arraybuffer') {
          response = b64ToBytes(raw.b64).buffer;
        } else if (rt === 'blob') {
          response = new Blob([b64ToBytes(raw.b64)], { type: mime });
        } else {
          responseText = raw.text || '';
          if (rt === 'json') {
            try { response = JSON.parse(responseText); } catch (e) { response = null; }
          } else if (rt === 'document' && typeof DOMParser !== 'undefined') {
            try {
              const docType = /xml/i.test(mime) ? 'application/xml' : 'text/html';
              responseXML = new DOMParser().parseFromString(responseText, docType);
              response = responseXML;
            } catch (e) { response = null; }
          } else {
            response = responseText;
            if (/xml/i.test(mime) && typeof DOMParser !== 'undefined') {
              try { responseXML = new DOMParser().parseFromString(responseText, 'application/xml'); } catch (e) {}
            }
          }
        }
        const size = raw.byteLength != null ? raw.byteLength : (raw.text ? raw.text.length : 0);
        const base = {
          status: raw.status, statusText: raw.statusText, responseHeaders: raw.responseHeaders,
          finalUrl: raw.finalUrl, context: d.context
        };
        call('onreadystatechange', Object.assign({ readyState: 2, response: null, responseText: '', responseXML: null }, base));
        call('onreadystatechange', Object.assign({ readyState: 3, response: response, responseText: responseText, responseXML: responseXML }, base));
        const res = Object.assign({ readyState: 4, response: response, responseText: responseText, responseXML: responseXML }, base);
        call('onprogress', Object.assign({ lengthComputable: true, loaded: size, total: size }, res));
        call('onreadystatechange', res);
        call('onload', res);
        call('onloadend', res);
      })();
      return {
        abort: () => {
          if (finished) return;
          finished = true;
          activeXhrs.delete(reqId);
          send('xhr-abort', { reqId: reqId }).catch(() => {});
          fail('abort', 'Aborted', d.url);
        }
      };
    };
    impl.xmlhttprequestp = (d) => {
      let ctl;
      const p = new Promise((resolve, reject) => {
        d = d || {};
        const wrap = (name, fn) => {
          const orig = d[name];
          return function (r) { if (typeof orig === 'function') orig.call(d, r); fn(r); };
        };
        ctl = impl.xmlhttprequest(Object.assign({}, d, {
          onload: wrap('onload', resolve),
          onerror: wrap('onerror', reject),
          ontimeout: wrap('ontimeout', reject),
          onabort: wrap('onabort', reject)
        }));
      });
      p.abort = ctl.abort;
      return p;
    };

    try {
      if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
        window.addEventListener('pagehide', () => {
          activeXhrs.forEach((reqId) => { send('xhr-abort', { reqId: reqId }).catch(() => {}); });
          activeXhrs.clear();
        });
      }
    } catch (e) {}

    /* ---------- per-tab session objects (GM_getTab / GM_saveTab / GM_getTabs) ---------- */
    impl.gettab = (cb) => {
      const p = send('tab:get').then((r) => (r && r.tab && typeof r.tab === 'object') ? r.tab : {}).catch(() => ({}));
      if (typeof cb === 'function') p.then((t) => { try { cb(t); } catch (e) { console.error(e); } });
      return p;
    };
    impl.savetab = (obj, cb) => {
      const clean = (obj && typeof obj === 'object') ? clone(obj) : {};
      const p = send('tab:save', { tab: clean }).then(() => undefined).catch(() => undefined);
      if (typeof cb === 'function') p.then(() => { try { cb(); } catch (e) { console.error(e); } });
      return p;
    };
    impl.gettabs = (cb) => {
      const p = send('tab:list').then((r) => (r && r.tabs && typeof r.tabs === 'object') ? r.tabs : {}).catch(() => ({}));
      if (typeof cb === 'function') p.then((tabs) => { try { cb(tabs); } catch (e) { console.error(e); } });
      return p;
    };

        /* ---------- notifications, tabs, downloads ---------- */
    impl.notification = (a, b, c, e) => {
      let o = {};
      if (a && typeof a === 'object') o = Object.assign({}, a);
      else { o.text = a; o.title = b; o.image = c; o.onclick = e; }
      return send('notify', {
        title: String(o.title || ''), text: String(o.text || ''),
        image: o.image ? String(o.image) : '', timeout: o.timeout | 0, silent: !!o.silent
      }).then((r) => {
        if (typeof o.ondone === 'function') { try { o.ondone(false); } catch (err) {} }
        return r;
      }).catch(() => {});
    };
    impl.opentab = (url, opts) => {
      const o = (typeof opts === 'boolean') ? { active: !opts } : (opts || {});
      const tab = {
        closed: false,
        onclose: null,
        tabId: null,
        close: () => {
          if (tab.tabId != null && !tab.closed) {
            tab.closed = true;
            send('tab-close', { tabId: tab.tabId }).catch(() => {});
            if (typeof tab.onclose === 'function') { try { tab.onclose(); } catch (e) {} }
          }
        }
      };
      let abs = url;
      try { abs = new URL(url, location.href).href; } catch (e) {}
      send('open-tab', {
        url: abs,
        active: o.active !== false && !o.background && !o.loadInBackground,
        insert: o.insert !== false,
        setParent: !!o.setParent
      }).then((r) => { if (r && r.tabId != null) tab.tabId = r.tabId; }).catch(() => {});
      return tab;
    };
    impl.download = (a, b) => {
      const o = (a && typeof a === 'object') ? a : { url: a, name: b };
      const cb = (n, arg) => { if (typeof o[n] === 'function') { try { o[n](arg); } catch (e) { console.error(e); } } };
      let abs = o.url;
      try { abs = new URL(o.url, location.href).href; } catch (e) {}
      let dlId = null;
      send('download', { url: abs, name: o.name || '', saveAs: !!o.saveAs, headers: o.headers || null })
        .then((r) => {
          if (r && r.ok) { dlId = r.downloadId; cb('onload', { downloadId: dlId }); }
          else { cb('onerror', { error: (r && r.error) || 'not_succeeded', details: r && r.error }); }
        })
        .catch((e) => cb('onerror', { error: 'not_succeeded', details: String(e && e.message) }));
      return {
        abort: () => { if (dlId != null) send('download-cancel', { downloadId: dlId }).catch(() => {}); }
      };
    };

    /* ---------- local helpers (no bridge needed) ---------- */
    impl.log = function () { console.log.apply(console, arguments); };
    impl.addstyle = (css) => {
      const s = document.createElement('style');
      s.textContent = String(css);
      (document.head || document.documentElement).appendChild(s);
      return s;
    };
    impl.addelement = (a, b, c) => {
      let parent, tag, attrs;
      if (typeof a === 'string') { tag = a; attrs = b || {}; parent = document.head || document.documentElement; }
      else { parent = a; tag = b; attrs = c || {}; }
      const el = document.createElement(tag);
      Object.keys(attrs).forEach((k) => {
        if (k === 'textContent') el.textContent = attrs[k];
        else el.setAttribute(k, attrs[k]);
      });
      parent.appendChild(el);
      return el;
    };
    impl.setclipboard = (text, info, cb) => {
      const s = String(text);
      const mime = (typeof info === 'string' && info.includes('/')) ? info : (info && info.mimetype) || 'text/plain';
      const done = () => { if (typeof cb === 'function') { try { cb(); } catch (e) {} } };
      const fallback = () => {
        const ta = document.createElement('textarea');
        ta.value = s;
        ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
        (document.body || document.documentElement).appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        ta.remove();
        done();
      };
      try {
        if (mime === 'text/html' && navigator.clipboard && navigator.clipboard.write && typeof ClipboardItem !== 'undefined') {
          const item = new ClipboardItem({ 'text/html': new Blob([s], { type: 'text/html' }), 'text/plain': new Blob([s], { type: 'text/plain' }) });
          navigator.clipboard.write([item]).then(done, fallback);
          return;
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(s).then(done, fallback);
          return;
        }
      } catch (e) {}
      fallback();
    };
    impl.getresourcetext = (name) => {
      const r = ctx.resources && ctx.resources[name];
      return r && typeof r.text === 'string' ? r.text : null;
    };
    impl.getresourceurl = (name) => {
      const r = ctx.resources && ctx.resources[name];
      return r ? r.dataUrl : null;
    };

    /* ---------- SPA navigation helper (window.onurlchange) ---------- */
    if (ctx.urlChange && typeof window !== 'undefined' && typeof history !== 'undefined') {
      try {
        let lastUrl = location.href;
        const notifyUrl = () => {
          const cur = location.href;
          if (cur === lastUrl) return;
          lastUrl = cur;
          const ev = { url: cur };
          if (typeof window.onurlchange === 'function') { try { window.onurlchange(ev); } catch (e) { console.error(e); } }
          try { window.dispatchEvent(new CustomEvent('urlchange', { detail: ev })); } catch (e) {}
        };
        const wrapHist = (fnName) => {
          const orig = history[fnName];
          if (typeof orig !== 'function') return;
          history[fnName] = function () {
            const ret = orig.apply(this, arguments);
            notifyUrl();
            return ret;
          };
        };
        wrapHist('pushState');
        wrapHist('replaceState');
        window.addEventListener('popstate', notifyUrl);
        window.addEventListener('hashchange', notifyUrl);
      } catch (e) {}
    }

    /* ---------- menu commands ---------- */
    const commands = new Map();
    let cmdSeq = 1;
    let announceQueued = false;
    let syncBound = false;
    const isTop = (() => { try { return window.top === window; } catch (e) { return false; } })();
    const menuToken = (() => {
      try {
        const a = new Uint8Array(16);
        crypto.getRandomValues(a);
        return Array.from(a, (b) => (b < 16 ? '0' : '') + b.toString(16)).join('');
      } catch (e) { return ''; }
    })();
    const runEvent = (id) => 'corsair-gm-run-' + menuToken + '-' + id;
    const announce = () => {
      if (!isTop || !menuToken) return;
      const list = [];
      commands.forEach((c, id) => list.push({ id: id, name: c.name, accessKey: c.accessKey || '' }));
      try {
        if (hasBridge) {
          const p = send('menu:set', { token: menuToken, commands: list });
          if (p && typeof p.catch === 'function') p.catch(() => {});
        } else {
          document.dispatchEvent(new CustomEvent('corsair-gm-menu', {
            detail: JSON.stringify({ id: ctx.id, token: menuToken, commands: list })
          }));
        }
      } catch (e) {}
    };
    const queueAnnounce = () => {
      if (!hasBridge) return;
      if (announceQueued) return;
      announceQueued = true;
      setTimeout(() => { announceQueued = false; announce(); }, 0);
    };
    impl.registermenucommand = (name, fn, optOrKey) => {
      const id = cmdSeq++;
      const accessKey = typeof optOrKey === 'string' ? optOrKey.slice(0, 1) : (optOrKey && typeof optOrKey.accessKey === 'string' ? optOrKey.accessKey.slice(0, 1) : '');
      const listener = () => { try { if (typeof fn === 'function') fn(); } catch (e) { console.error(e); } };
      commands.set(id, { name: String(name), fn: fn, listener: listener, accessKey: accessKey });
      if (isTop && menuToken) {
        try { document.addEventListener(runEvent(id), listener); } catch (e) {}
        if (!syncBound) {
          syncBound = true;
          try { document.addEventListener('corsair-gm-menu-sync', announce); } catch (e) {}
        }
        queueAnnounce();
      }
      return id;
    };
    impl.unregistermenucommand = (id) => {
      const c = commands.get(id);
      if (c) { try { document.removeEventListener(runEvent(id), c.listener); } catch (e) {} }
      commands.delete(id);
      queueAnnounce();
    };

    const reportError = (e) => {
      const msg = (e && e.message) ? (e.name ? e.name + ': ' + e.message : e.message) : String(e);
      console.error('[Corsair Userscripts] ' + ctx.name + ':', e);
      if (hasBridge) {
        send('error:report', { error: msg.slice(0, 400) }).catch(() => {});
      }
    };

    return { impl: impl, ready: ready, reportError: reportError };
  }

  /** Grants that need the extension bridge (and therefore the isolated user-script world). */
  const BRIDGE_KEYS = new Set([
    'getvalue', 'setvalue', 'deletevalue', 'listvalues', 'getvalues', 'setvalues', 'deletevalues',
    'addvaluechangelistener', 'removevaluechangelistener',
    'xmlhttprequest', 'notification', 'opentab', 'download', 'gettab', 'savetab', 'gettabs'
  ]);
  const VALUE_KEYS = new Set([
    'getvalue', 'setvalue', 'deletevalue', 'listvalues', 'getvalues', 'setvalues', 'deletevalues',
    'addvaluechangelistener', 'removevaluechangelistener'
  ]);

  // [normalised key, GM_ name, GM. name]
  const GM_API = [
    ['getvalue', 'GM_getValue', 'getValue'], ['setvalue', 'GM_setValue', 'setValue'],
    ['deletevalue', 'GM_deleteValue', 'deleteValue'], ['listvalues', 'GM_listValues', 'listValues'],
    ['getvalues', 'GM_getValues', 'getValues'], ['setvalues', 'GM_setValues', 'setValues'],
    ['deletevalues', 'GM_deleteValues', 'deleteValues'],
    ['addvaluechangelistener', 'GM_addValueChangeListener', 'addValueChangeListener'],
    ['removevaluechangelistener', 'GM_removeValueChangeListener', 'removeValueChangeListener'],
    ['xmlhttprequest', 'GM_xmlhttpRequest', 'xmlHttpRequest'],
    ['notification', 'GM_notification', 'notification'], ['opentab', 'GM_openInTab', 'openInTab'],
    ['download', 'GM_download', 'download'], ['setclipboard', 'GM_setClipboard', 'setClipboard'],
    ['addstyle', 'GM_addStyle', 'addStyle'], ['addelement', 'GM_addElement', 'addElement'],
    ['log', 'GM_log', 'log'],
    ['registermenucommand', 'GM_registerMenuCommand', 'registerMenuCommand'],
    ['unregistermenucommand', 'GM_unregisterMenuCommand', 'unregisterMenuCommand'],
    ['getresourcetext', 'GM_getResourceText', 'getResourceText'],
    ['getresourceurl', 'GM_getResourceURL', 'getResourceUrl'],
    ['gettab', 'GM_getTab', 'getTab'],
    ['savetab', 'GM_saveTab', 'saveTab'],
    ['gettabs', 'GM_getTabs', 'getTabs']
  ];

  // Maps bridge ops to the required GM grant keys
  const OP_REQUIRED_GRANTS = {
    'vals:get': ['getvalue', 'getvalues', 'listvalues', 'setvalue', 'setvalues', 'deletevalue', 'deletevalues', 'addvaluechangelistener'],
    'vals:set': ['setvalue', 'setvalues'],
    'vals:setBatch': ['setvalues', 'setvalue'],
    'vals:del': ['deletevalue', 'deletevalues'],
    'vals:delBatch': ['deletevalues', 'deletevalue'],
    'xhr': ['xmlhttprequest'],
    'xhr-abort': ['xmlhttprequest'],
    'notify': ['notification'],
    'open-tab': ['opentab'],
    'tab-close': ['opentab'],
    'download': ['download'],
    'download-cancel': ['download'],
    'menu:set': ['registermenucommand', 'unregistermenucommand']
  };

  function detectAutoGrants(code) {
    const src = stripBom(code);
    const out = new Set();
    for (const [key, gmName, dotName] of GM_API) {
      if (src.includes(gmName) || src.includes('GM.' + dotName)) out.add(key);
    }
    return out;
  }

  function grantedKeys(meta, code) {
    const raw = (meta && meta.grant) || [];
    const out = new Set();
    for (const g of raw) {
      const m = /^GM[._](\w+)$/i.exec(g);
      if (m) out.add(m[1].toLowerCase());
    }
    // If the user omitted @grant completely (didn't write @grant none), auto-detect GM_* usage
    if (!raw.length && typeof code === 'string' && code) {
      for (const k of detectAutoGrants(code)) out.add(k);
    }
    return out;
  }

  function hasUrlChangeGrant(meta) {
    return (meta.grant || []).some(g => g.toLowerCase() === 'window.onurlchange');
  }

  /** True when the script uses GM_* functions that need the extension bridge. */
  function needsBridge(meta, code) {
    for (const k of grantedKeys(meta, code)) if (BRIDGE_KEYS.has(k)) return true;
    return false;
  }

  /* ============================================================
     SOURCE BUILDER
     ============================================================ */
  function runAtToChrome(runAt) {
    if (runAt === 'document-start' || runAt === 'document-body') return 'document_start';
    if (runAt === 'document-end') return 'document_end';
    return 'document_idle';
  }

  function safeSourceName(name) {
    return String(name || 'script').replace(/[^\w.\-]+/g, '_').slice(0, 60) || 'script';
  }

  function extensionVersion() {
    try { return chrome.runtime.getManifest().version; } catch { return ''; }
  }

  /**
   * Build the code string injected for a script plus exact line mapping metadata.
   * User code and @require libraries share one async function scope,
   * so `return` and top-level `await` both work in userscripts.
   */
  /**
   * Ensure the ==UserScript== metadata block (and any pasted plain-text title
   * lines before ==UserScript==) can never cause a V8 SyntaxError during execution,
   * while preserving exact 1-to-1 line numbering for stack traces.
   */
  function sanitizeExecutableCode(rawCode) {
    const clean = stripBom(rawCode);
    const lines = clean.split(/\r\n|\r|\n/);
    let headerStart = -1;
    let headerEnd = -1;
    for (let i = 0; i < lines.length; i++) {
      if (headerStart < 0 && /^\s*\/\/\s*==UserScript==\s*$/.test(lines[i])) headerStart = i;
      else if (headerStart >= 0 && /^\s*\/\/\s*==\/UserScript==\s*$/.test(lines[i])) { headerEnd = i; break; }
    }

    if (headerStart >= 0) {
      const end = headerEnd >= 0 ? headerEnd : lines.length - 1;
      // Everything from line 0 through ==/UserScript== is header/preamble, never executable JS.
      // Commenting non-// lines preserves exact 1-to-1 line numbers while preventing SyntaxErrors
      // from pasted titles, descriptions (even with parentheses/punctuation), or wrapped metadata.
      for (let i = 0; i <= end; i++) {
        if (lines[i].trim() && !/^\s*\/\//.test(lines[i])) {
          lines[i] = '// ' + lines[i];
        }
      }
    }
    return lines.join('\n');
  }
  function buildSourceWithMap(record, plan) {
    const meta = record.meta || emptyMeta();
    const parsed = parseMetadata(record.code);
    const info = {
      script: {
        name: meta.name, namespace: meta.namespace, version: meta.version,
        description: meta.description, author: meta.author, grant: meta.grant,
        'run-at': meta.runAt, noframes: meta.noframes, matches: meta.match,
        includes: meta.include, excludes: meta.exclude, excludeMatches: meta.excludeMatch,
        connects: meta.connect, uuid: record.id,
        resources: (meta.resource || []).map(r => ({ name: r.name, url: r.url }))
      },
      scriptMetaStr: parsed.headerText || '',
      scriptHandler: 'Corsair Unbound',
      version: extensionVersion(),
      injectInto: chooseWorld(meta, record.code) === 'MAIN' ? 'page' : 'content',
      scriptWillUpdate: Boolean(meta.updateURL || meta.downloadURL)
    };

    const parts = [];
    parts.push('(async function(){');

    if (plan.runtime) {
      parts.push(
        'const __f=' + safeJson(plan.runtime) + ';' +
        'const __h=location.href,__n=__h.replace(/#.*$/,"");' +
        'const __t=(l)=>l.some(([s,fl])=>{try{const r=new RegExp(s,fl);return r.test(__h)||r.test(__n)}catch(e){return false}});' +
        'if(!__t(__f.i)||__t(__f.e))return;'
      );
    }

    if (meta.runAt === 'document-body') {
      parts.push(
        'if(!document.body){await new Promise(function(res){var done=false,fin=function(){if(done)return;done=true;try{o.disconnect()}catch(e){}document.removeEventListener("DOMContentLoaded",fin);res()};var o=new MutationObserver(function(){if(document.body)fin()});o.observe(document.documentElement||document,{childList:true,subtree:true});if(document.readyState==="interactive"||document.readyState==="complete"){fin()}else{document.addEventListener("DOMContentLoaded",fin,{once:true})}})}'
      );
    }

    const world = chooseWorld(meta, record.code);
    const keys = grantedKeys(meta, record.code);
    const resources = {};
    for (const [name, r] of Object.entries(record.resources || {})) {
      resources[name] = { text: typeof r.text === 'string' ? r.text : null, dataUrl: r.dataUrl || '' };
    }
    const needValues = Array.from(keys).some(k => VALUE_KEYS.has(k));
    const ctx = {
      id: record.id,
      name: meta.name || 'Untitled script',
      bridge: world === 'USER_SCRIPT',
      wantsBridge: needsBridge(meta),
      needValues,
      urlChange: hasUrlChangeGrant(meta),
      resources
    };

    // GM_* names are passed as PARAMETERS of the inner function (not const),
    // so userscripts may freely redeclare them with `var` or `function`.
    let prelude =
      'const __info=' + safeJson(info) + ';' +
      'const __gm=(' + gmRuntime.toString() + ')(' + safeJson(ctx) + ');' +
      (needValues ? 'await __gm.ready;' : '') +
      'const __GM={info:__info};';
    const paramNames = ['GM_info', 'unsafeWindow', 'GM'];
    const paramArgs = ['__info', 'window', '__GM'];
    for (const [key, gmName, dotName] of GM_API) {
      if (!keys.has(key)) continue;
      paramNames.push(gmName);
      paramArgs.push('__gm.impl.' + key);
      if (key === 'xmlhttprequest') prelude += '__GM.' + dotName + '=__gm.impl.xmlhttprequestp;';
      else prelude += '__GM.' + dotName + '=function(){var a=arguments;return Promise.resolve().then(function(){return __gm.impl.' + key + '.apply(null,a)})};';
    }
    prelude += 'try{await (async function(' + paramNames.join(',') + '){';
    parts.push(prelude);

    let currentLine = parts.join('').split('\n').length;
    const requireRanges = [];

    // @require libraries first, then the user's own code
    const reqs = record.requires || {};
    for (const url of (meta.require || [])) {
      const text = reqs[resolveUrl(url, record.sourceUrl)];
      if (typeof text === 'string') {
        const cleanReq = stripBom(text);
        const startLine = currentLine + 2;
        const reqLines = cleanReq.split(/\r\n|\r|\n/).length;
        requireRanges.push({ url, startLine, endLine: startLine + reqLines - 1 });
        parts.push('\n;/* @require ' + url.replace(/\*\//g, '* /') + ' */\n' + cleanReq + '\n;');
        currentLine = parts.join('').split('\n').length;
      } else {
        parts.push('console.warn("[Corsair Userscripts] @require not cached: ' + url.replace(/["\\\n\r]/g, '') + '");');
      }
    }

    const userStartLine = currentLine + 1;
    const cleanCode = sanitizeExecutableCode(record.code || '');
    parts.push('\n' + cleanCode + '\n');
    parts.push('}).call(window,' + paramArgs.join(',') + ');}catch(__e){__gm.reportError(__e);}');
    parts.push('})().catch(function(e){console.error("[Corsair Userscripts] ' + safeSourceName(meta.name) + ':",e)});');
    parts.push('\n//# sourceURL=corsair-userscript/' + safeSourceName(meta.name) + '.user.js');

    return {
      code: parts.join(''),
      userStartLine,
      requireRanges
    };
  }

  function buildSource(record, plan) {
    return buildSourceWithMap(record, plan).code;
  }

  /* ============================================================
     URL + FETCH HELPERS
     ============================================================ */
  function resolveUrl(url, base) {
    const u = String(url || '').trim();
    if (!u) return '';
    try {
      if (u.startsWith('//')) return new URL('https:' + u).href;
      return new URL(u, base || undefined).href;
    } catch { return ''; }
  }

  /* SECURITY: a plain-http @require / import can be rewritten by anyone on the network path, and the
     downloaded code then runs in every page the script matches. Only https: and data: are accepted;
     http: is allowed solely for a developer's own loopback server. */
  function isFetchableUrl(u) {
    const s = String(u || '').trim();
    if (/^data:/i.test(s)) return true;
    let p;
    try { p = new URL(s); } catch { return false; }
    return p.protocol === 'https:' || p.protocol === 'http:';
  }

  async function fetchWithTimeout(url, asBuffer) {
    const ctrl = new AbortController();
    const to = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const r = await fetch(url, { signal: ctrl.signal, cache: 'no-store', credentials: 'omit' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      if (asBuffer) {
        const mime = (r.headers.get('content-type') || '').split(';')[0].trim();
        return { buffer: await r.arrayBuffer(), mime };
      }
      return await r.text();
    } finally {
      clearTimeout(to);
    }
  }

  function bytesToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    const CHUNK = 0x8000;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
    }
    return btoa(bin);
  }

  async function fetchText(url) {
    return fetchWithTimeout(url, false);
  }

  async function fetchDependencies(record, previous, forceRefresh = false) {
    const warnings = [];
    const meta = record.meta;
    const prevReq = (!forceRefresh && previous && previous.requires) || {};
    const prevRes = (!forceRefresh && previous && previous.resources) || {};

    record.requires = {};
    for (const raw of (meta.require || [])) {
      const url = resolveUrl(raw, record.sourceUrl);
      if (!url || !isFetchableUrl(url)) { warnings.push(`@require skipped (unsupported URL): ${raw}`); continue; }
      if (typeof prevReq[url] === 'string') { record.requires[url] = prevReq[url]; continue; }
      try {
        const text = await fetchText(url);
        if (looksLikeHtml(text)) {
          warnings.push(`@require rejected (HTML response instead of JS): ${raw}`);
          continue;
        }
        record.requires[url] = text;
      } catch (e) { warnings.push(`@require failed: ${raw} (${e && e.message})`); }
    }

    record.resources = {};
    for (const r of (meta.resource || [])) {
      const url = resolveUrl(r.url, record.sourceUrl);
      if (!url || !isFetchableUrl(url)) { warnings.push(`@resource skipped (unsupported URL): ${r.name}`); continue; }
      if (prevRes[r.name] && prevRes[r.name].url === url) { record.resources[r.name] = prevRes[r.name]; continue; }
      try {
        const { buffer, mime } = await fetchWithTimeout(url, true);
        const isText = /^text\/|json|javascript|xml|svg/i.test(mime || '');
        record.resources[r.name] = {
          url, mime: mime || 'application/octet-stream',
          text: isText ? new TextDecoder().decode(buffer) : null,
          dataUrl: `data:${mime || 'application/octet-stream'};base64,${bytesToBase64(buffer)}`
        };
      } catch (e) { warnings.push(`@resource failed: ${r.name} (${e && e.message})`); }
    }
    return warnings;
  }

  /* ============================================================
     STORAGE
     ============================================================ */
  function newId() {
    const rnd = (globalThis.crypto && crypto.randomUUID) ? crypto.randomUUID().replace(/-/g, '').slice(0, 16)
      : Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
    return REG_PREFIX + rnd;
  }

  async function readIndex() {
    const r = await chrome.storage.local.get(INDEX_KEY);
    return Array.isArray(r[INDEX_KEY]) ? r[INDEX_KEY].filter(id => typeof id === 'string' && id) : [];
  }

  async function writeIndex(ids) {
    await chrome.storage.local.set({ [INDEX_KEY]: unique(ids) });
  }

  async function readRecord(id) {
    const k = REC_PREFIX + id;
    const r = await chrome.storage.local.get(k);
    const rec = r[k];
    return rec && typeof rec === 'object' && !Array.isArray(rec) ? rec : null;
  }

  async function writeRecord(rec) {
    await chrome.storage.local.set({ [REC_PREFIX + rec.id]: rec });
  }

  async function readAll() {
    const ids = await readIndex();
    if (!ids.length) return [];
    const keys = ids.map(id => REC_PREFIX + id);
    const r = await chrome.storage.local.get(keys);
    return ids.map(id => r[REC_PREFIX + id]).filter(rec => rec && typeof rec === 'object' && typeof rec.code === 'string');
  }

  function summarize(rec) {
    const meta = rec.meta || emptyMeta();
    const plan = buildPlan(meta);
    const code = String(rec.code || '');
    return {
      id: rec.id,
      name: meta.name || 'Untitled script',
      namespace: meta.namespace,
      version: meta.version,
      description: meta.description,
      author: meta.author,
      homepage: meta.homepage || '',
      supportURL: meta.supportURL || '',
      license: meta.license || '',
      icon: meta.icon,
      enabled: rec.enabled !== false,
      matches: [...meta.match, ...meta.include],
      excludes: [...meta.exclude, ...meta.excludeMatch],
      grant: meta.grant || [],
      connect: meta.connect || [],
      require: meta.require || [],
      resource: (meta.resource || []).map(r => ({ name: r.name, url: r.url })),
      tags: meta.tags || [],
      unsupported: meta.unsupported || [],
      metaWarnings: meta.warnings || [],
      runAt: meta.runAt,
      world: chooseWorld(meta, rec.code),
      noframes: Boolean(meta.noframes),
      runEverywhere: Boolean(rec.runEverywhere),
      noMatch: rec.runEverywhere ? false : plan.noMatch,
      lines: code.split('\n').length,
      bytes: code.length,
      sourceUrl: rec.sourceUrl || '',
      updateURL: meta.updateURL,
      downloadURL: meta.downloadURL,
      userModified: Boolean(rec.userModified),
      lastError: rec.lastError || '',
      lastErrorAt: rec.lastErrorAt || 0,
      migratedFrom: rec.migratedFrom || '',
      createdAt: rec.createdAt || 0,
      updatedAt: rec.updatedAt || 0
    };
  }

  /* ============================================================
     AVAILABILITY
     ============================================================ */
  function chromeMajor() {
    try {
      const m = /Chrome\/(\d+)/.exec(navigator.userAgent || '');
      return m ? parseInt(m[1], 10) : 0;
    } catch { return 0; }
  }

  async function checkAvailability() {
    const major = chromeMajor();
    const extId = (() => { try { return chrome.runtime && chrome.runtime.id ? chrome.runtime.id : ''; } catch { return ''; } })();
    const detailsUrl = extId ? `chrome://extensions/?id=${extId}` : 'chrome://extensions/';
    const needsAllowToggle = !major || major >= 138;
    const requirement = needsAllowToggle ? 'allow-user-scripts' : 'developer-mode';
    const setupInstructions = needsAllowToggle
      ? `Open ${detailsUrl} and turn ON "Allow User Scripts" for Corsair Unbound.`
      : 'Open chrome://extensions/ and turn ON "Developer mode" in the top-right corner.';
    if (major && major < 120) {
      return {
        ok: false, code: 'old-chrome', chrome: major, requirement: 'upgrade-chrome',
        executeSupported: false, detailsUrl, setupInstructions: 'Update Chrome to version 120 or newer.',
        message: 'Chrome 120 or newer is required for userscripts.'
      };
    }
    if (!chrome.userScripts) {
      return {
        ok: false, code: 'disabled', chrome: major, requirement,
        executeSupported: false, detailsUrl, setupInstructions,
        message: needsAllowToggle
          ? 'Enable "Allow User Scripts" in extension details (Chrome 138+).'
          : 'Enable "Developer mode" on chrome://extensions (Chrome 120-137).'
      };
    }
    try {
      await chrome.userScripts.getScripts();
      const executeSupported = typeof chrome.userScripts.execute === 'function';
      return { ok: true, chrome: major, requirement, executeSupported, detailsUrl, setupInstructions };
    } catch (e) {
      return {
        ok: false, code: 'disabled', chrome: major, requirement,
        executeSupported: false, detailsUrl, setupInstructions,
        message: (e && e.message) || (needsAllowToggle
          ? 'Enable "Allow User Scripts" in extension details.'
          : 'Enable "Developer mode" on chrome://extensions.')
      };
    }
  }

  /* ============================================================
     REGISTRATION
     ============================================================ */
  function buildRegistration(rec) {
    const meta = rec.meta || emptyMeta();
    const plan = rec.runEverywhere
      ? { noMatch: false, matches: ['<all_urls>'], excludeMatches: [], includeGlobs: [], excludeGlobs: [], runtime: null }
      : buildPlan(meta);
    if (plan.noMatch) return { plan, registration: null };

    const registration = {
      id: rec.id,
      matches: plan.matches,
      allFrames: rec.runEverywhere ? true : !meta.noframes,
      runAt: runAtToChrome(meta.runAt),
      world: chooseWorld(meta, rec.code),
      js: [{ code: buildSource(rec, plan) }]
    };
    if (plan.excludeMatches.length) registration.excludeMatches = plan.excludeMatches;
    if (plan.includeGlobs.length) registration.includeGlobs = plan.includeGlobs;
    if (plan.excludeGlobs.length) registration.excludeGlobs = plan.excludeGlobs;
    return { plan, registration };
  }

  async function configureWorld() {
    try {
      await chrome.userScripts.configureWorld({
        csp: "script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'self'",
        messaging: true
      });
    } catch {
      try { await chrome.userScripts.configureWorld({ messaging: true }); } catch {}
    }
  }

  function signature(registration) {
    return JSON.stringify(registration);
  }

  async function syncRegistrations() {
    const avail = await checkAvailability();
    if (!avail.ok) return { ok: false, availability: avail, registered: 0, errors: [] };

    await configureWorld();

    const records = await readAll();
    const desired = new Map();
    const errors = [];

    for (const rec of records) {
      if (rec.enabled === false) continue;

      // Never block user scripts from registering; always attempt registration.

      try {
        const { registration } = buildRegistration(rec);
        if (registration) desired.set(rec.id, { rec, registration });
      } catch (e) {
        errors.push({ id: rec.id, error: (e && e.message) || String(e) });
      }
    }

    let existing = [];
    try { existing = await chrome.userScripts.getScripts(); } catch {}
    const existingById = new Map(existing.map(s => [s.id, s]));

    // Remove registrations that should no longer exist (ours only)
    const staleIds = existing
      .map(s => s.id)
      .filter(id => id.startsWith(REG_PREFIX) && !desired.has(id));
    if (staleIds.length) {
      try { await chrome.userScripts.unregister({ ids: staleIds }); } catch {}
    }

    let registered = 0;
    for (const [id, { rec, registration }] of desired) {
      const sig = signature(registration);
      const present = existingById.has(id);
      if (present && rec.regSig === sig && !rec.lastError) { registered++; continue; }

      let err = '';
      try {
        if (present) {
          try { await chrome.userScripts.update([registration]); }
          catch {
            await chrome.userScripts.unregister({ ids: [id] });
            await chrome.userScripts.register([registration]);
          }
        } else {
          await chrome.userScripts.register([registration]);
        }
      } catch (e1) {
        // Fallback: broad match + in-page filtering for patterns Chrome rejects
        try {
          const plan = buildPlan(rec.meta);
          const fallbackPlan = { ...plan, matches: [BROAD_MATCH], includeGlobs: [], runtime: runtimeForAll(rec.meta) };
          const reg2 = { ...registration, matches: [BROAD_MATCH], js: [{ code: buildSource(rec, fallbackPlan) }] };
          delete reg2.includeGlobs;
          try { await chrome.userScripts.unregister({ ids: [id] }); } catch {}
          await chrome.userScripts.register([reg2]);
        } catch (e2) {
          err = (e2 && e2.message) || (e1 && e1.message) || 'registration failed';
        }
      }

      const nextErr = err;
      if (!err) registered++;
      if ((rec.lastError || '') !== nextErr || rec.regSig !== (err ? '' : sig)) {
        rec.lastError = nextErr;
        rec.lastErrorAt = nextErr ? Date.now() : 0;
        rec.regSig = err ? '' : sig;
        try { await writeRecord(rec); } catch {}
      }
      if (err) errors.push({ id, error: err });
    }

    return { ok: true, availability: avail, registered, errors };
  }

  /** Runtime filter that evaluates every rule inside the page (used for fallbacks). */
  function runtimeForAll(meta) {
    const inc = [];
    for (const raw of (meta.match || [])) {
      const c = toChromeMatch(raw);
      inc.push(c ? [matchToRegexSource(c), ''] : [globToRegexSource(raw), 'i']);
    }
    for (const raw of (meta.include || [])) {
      inc.push(isRegexLiteral(raw) ? regexLiteralToPair(raw) : [globToRegexSource(raw), 'i']);
    }
    const exc = [];
    for (const raw of (meta.exclude || [])) {
      exc.push(isRegexLiteral(raw) ? regexLiteralToPair(raw) : [globToRegexSource(raw), 'i']);
    }
    for (const raw of (meta.excludeMatch || [])) {
      const c = toChromeMatch(raw);
      exc.push(c ? [matchToRegexSource(c), ''] : [globToRegexSource(raw), 'i']);
    }
    return { i: inc, e: exc };
  }

  let _lastSyncOk = false;
  let _lastSyncAt = 0;

  function sync() {
    return withLock(async () => {
      invalidateRuntimeCaches();
      const res = await syncRegistrations();
      _lastSyncOk = Boolean(res && res.ok);
      _lastSyncAt = Date.now();
      return res;
    });
  }

  /**
   * Lightweight reconciliation for service worker wakeups, permission toggles,
   * and navigation events: ensures enabled scripts are actually registered in
   * Chrome without unregistering unrelated scripts or repeating unnecessary work.
   */
  async function ensureSynced(opts = {}) {
    const force = Boolean(opts && opts.force);
    const now = Date.now();
    // If previously failed (e.g. Allow User Scripts was off), retry at most every 4s
    if (!force && !_lastSyncOk && (now - _lastSyncAt) < 4000) {
      return { ok: false, skipped: true, reason: 'cooldown' };
    }
    if (!force && _lastSyncOk && (now - _lastSyncAt) < 15000) {
      // Fast check: verify Chrome still holds registrations for enabled scripts
      try {
        if (chrome.userScripts && typeof chrome.userScripts.getScripts === 'function') {
          const [existing, ids] = await Promise.all([
            chrome.userScripts.getScripts(),
            readIndex()
          ]);
          const existingIds = new Set(existing.map(s => s.id));
          if (ids.length === 0 || existingIds.size > 0) {
            return { ok: true, skipped: true, registered: existingIds.size };
          }
        }
      } catch {}
    }
    return sync();
  }

  /* ============================================================
     CRUD, DUPLICATE, UPDATES & DEPENDENCY REFRESH
     ============================================================ */
  async function list() {
    const records = await readAll();
    return records.map(summarize).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  }

  async function get(id) {
    const rec = await readRecord(id);
    if (!rec) return null;
    return { ...summarize(rec), code: rec.code || '' };
  }

  function findByIdentity(records, meta, hasName, sourceUrl) {
    if (sourceUrl) {
      const bySource = records.find(r => r.sourceUrl && r.sourceUrl === sourceUrl);
      if (bySource) return bySource;
    }
    if (!hasName) return null;
    return records.find(r => r.meta && r.meta.name === meta.name && (r.meta.namespace || '') === (meta.namespace || '')) || null;
  }

  /**
   * Create or update a script.
   * input: { id?, code, enabled?, sourceUrl?, isRemoteUpdate? }
   */
  async function save(input) {
    const code = String(input && input.code != null ? input.code : '');
    const { meta } = parseMetadata(code);
    const hasName = Boolean(meta.name);
    if (!meta.name) meta.name = 'Untitled script';

    let previous = null;
    let id = input && input.id ? String(input.id) : '';
    if (id) previous = await readRecord(id);
    if (!previous && !id && input && input.sourceUrl) {
      previous = findByIdentity(await readAll(), meta, hasName, input.sourceUrl);
      if (previous) id = previous.id;
    }
    if (!id) id = newId();

    const now = Date.now();
    const isRemote = Boolean(input && input.isRemoteUpdate);
    const userModified = isRemote
      ? false
      : Boolean(previous && previous.sourceUrl && previous.code !== code) || Boolean(previous && previous.userModified && previous.code !== code);

    const rec = {
      id,
      code,
      meta,
      enabled: input && input.enabled !== undefined ? Boolean(input.enabled) : (previous ? previous.enabled !== false : true),
      createdAt: previous ? previous.createdAt || now : now,
      updatedAt: now,
      sourceUrl: (input && input.sourceUrl) || (previous && previous.sourceUrl) || '',
      migratedFrom: (previous && previous.migratedFrom) || '',
      userModified,
      runEverywhere: input && input.runEverywhere !== undefined ? Boolean(input.runEverywhere) : Boolean(previous && previous.runEverywhere),
      regSig: '',
      lastError: '',
      lastErrorAt: 0
    };

    const warnings = await fetchDependencies(rec, previous);
    const syntax = validateScript(rec);

    await withLock(async () => {
      await writeRecord(rec);
      const ids = await readIndex();
      if (!ids.includes(id)) { ids.push(id); await writeIndex(ids); }
    });

    const syncRes = await sync();
    const fresh = await readRecord(id);
    return {
      ok: true,
      script: summarize(fresh || rec),
      warnings,
      syntax: syntax.ok ? null : syntax,
      sync: { ok: syncRes.ok, availability: syncRes.availability, errors: syncRes.errors }
    };
  }

  async function duplicate(id) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    let code = String(rec.code || '');
    if (/^\s*\/\/\s*@name\s+.+$/m.test(code)) {
      code = code.replace(/^(\s*\/\/\s*@name\s+)(.+)$/m, (_, prefix, name) => `${prefix}${name.trim()} (Copy)`);
    } else {
      const name = (rec.meta && rec.meta.name ? rec.meta.name : 'Untitled script') + ' (Copy)';
      code = `// ==UserScript==\n// @name         ${name}\n// ==/UserScript==\n${code}`;
    }
    return save({ code, enabled: false });
  }

  async function refreshDependencies(id) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    rec.meta = parseMetadata(rec.code).meta;
    if (!rec.meta.name) rec.meta.name = 'Untitled script';
    const warnings = await fetchDependencies(rec, rec, true);
    rec.regSig = '';
    rec.updatedAt = Date.now();
    await withLock(() => writeRecord(rec));
    const syncRes = await sync();
    const fresh = await readRecord(id);
    return { ok: true, script: summarize(fresh || rec), warnings, sync: { ok: syncRes.ok, availability: syncRes.availability, errors: syncRes.errors } };
  }

  async function updateFromRemote(id, force = false) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    const url = (rec.meta && (rec.meta.downloadURL || rec.meta.updateURL)) || rec.sourceUrl;
    if (!url || !isFetchableUrl(url)) return { ok: false, error: 'no-update-url' };
    if (rec.userModified && !force) {
      return { ok: false, error: 'local-modifications', message: 'Script has local edits; pass force=true to overwrite.' };
    }
    let code;
    try { code = await fetchText(url); }
    catch (e) { return { ok: false, error: `Download failed: ${e && e.message}` }; }
    if (code === rec.code) return { ok: true, updated: false, script: summarize(rec) };
    const res = await save({ id: rec.id, code, sourceUrl: rec.sourceUrl || url, isRemoteUpdate: true });
    return { ...res, updated: true };
  }

  /** Check all URL-backed scripts for remote updates (skips locally modified scripts). */
  async function checkAllUpdates() {
    const records = await readAll();
    let checked = 0;
    let updated = 0;
    let skippedModified = 0;
    const errors = [];
    for (const rec of records) {
      const url = (rec.meta && (rec.meta.downloadURL || rec.meta.updateURL)) || rec.sourceUrl;
      if (!url || !isFetchableUrl(url)) continue;
      checked++;
      if (rec.userModified) { skippedModified++; continue; }
      const r = await updateFromRemote(rec.id, false);
      if (r.ok && r.updated) updated++;
      else if (!r.ok && r.error !== 'no-update-url') errors.push({ id: rec.id, name: rec.meta && rec.meta.name, error: r.error });
    }
    return { ok: true, checked, updated, skippedModified, errors };
  }

  async function getValues(id) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    return { ok: true, values: await readVals(id) };
  }

  async function clearValues(id) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    await withValsLock(id, () => chrome.storage.local.remove(VALS_PREFIX + id));
    return { ok: true };
  }

    async function setRunEverywhere(id, enabled) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    rec.runEverywhere = Boolean(enabled);
    rec.regSig = '';
    rec.updatedAt = Date.now();
    await withLock(() => writeRecord(rec));
    const syncRes = await sync();
    return { ok: true, script: summarize(rec), sync: { ok: syncRes.ok, availability: syncRes.availability, errors: syncRes.errors } };
  }

  async function addMatchRule(id, pattern) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    const p = String(pattern || '').trim();
    if (!p) return { ok: false, error: 'empty-pattern' };
    let code = String(rec.code || '');
    const line = `// @match        ${p}`;
    const endRe = /\/\/\s*==\/UserScript==/;
    if (endRe.test(code)) {
      code = code.replace(endRe, m => line + '\n' + m);
    } else {
      code = `// ==UserScript==\n// @name         ${(rec.meta && rec.meta.name) || 'Script'}\n${line}\n// ==/UserScript==\n\n${code}`;
    }
    return save({ id: rec.id, code, enabled: true });
  }

  /**
   * Inject and run ANY script immediately on a specific tab (or active tab),
   * regardless of @match / @include rules.
   */
  async function executeNow(id, tabId) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    let targetTabId = Number(tabId);
    if (!Number.isInteger(targetTabId)) {
      try {
        const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        if (tabs && tabs[0] && Number.isInteger(tabs[0].id)) targetTabId = tabs[0].id;
      } catch {}
    }
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'no-active-tab' };

    const meta = rec.meta || emptyMeta();
    const world = chooseWorld(meta, rec.code);
    const plan = { noMatch: false, matches: ['<all_urls>'], excludeMatches: [], includeGlobs: [], excludeGlobs: [], runtime: null };
    const code = buildSource(rec, plan);

    await configureWorld();

    // Chrome 135+: chrome.userScripts.execute() injects inline code directly into any tab
    if (chrome.userScripts && typeof chrome.userScripts.execute === 'function') {
      try {
        await chrome.userScripts.execute({
          target: { tabId: targetTabId, allFrames: !meta.noframes },
          world,
          js: [{ code }]
        });
        return { ok: true, method: 'userScripts.execute', tabId: targetTabId };
      } catch (e) {
        return { ok: false, error: (e && e.message) || 'execute-failed' };
      }
    }

    // Fallback for Chrome 120-134: inject via blob script element in MAIN world
    if (chrome.scripting && typeof chrome.scripting.executeScript === 'function') {
      try {
        await chrome.scripting.executeScript({
          target: { tabId: targetTabId, allFrames: !meta.noframes },
          world: 'MAIN',
          func: (src) => {
            const s = document.createElement('script');
            s.textContent = src;
            (document.head || document.documentElement).appendChild(s);
            s.remove();
          },
          args: [code]
        });
        return { ok: true, method: 'scripting.executeScript', tabId: targetTabId };
      } catch (e) {
        return { ok: false, error: (e && e.message) || 'execute-failed' };
      }
    }
    return { ok: false, error: 'execute-unavailable' };
  }

  /**
   * One-time, tab-targeted preview execution for AI Script Studio.
   * NEVER permanently registers the script or executes on other tabs.
   * Prefers Chrome 135+ chrome.userScripts.execute() in USER_SCRIPT world.
   */

  const _recentAutoInject = new Map();
  let _availCache = { at: 0, value: null };
  let _enabledCache = { at: 0, records: null };

  function invalidateRuntimeCaches() {
    _availCache = { at: 0, value: null };
    _enabledCache = { at: 0, records: null };
  }

  async function getCachedAvailability() {
    const now = Date.now();
    if (_availCache.value && (now - _availCache.at) < 5000) return _availCache.value;
    const val = await checkAvailability();
    _availCache = { at: now, value: val };
    return val;
  }

  async function getCachedEnabledRecords() {
    const now = Date.now();
    if (_enabledCache.records && (now - _enabledCache.at) < 10000) return _enabledCache.records;
    const all = await readAll();
    const enabled = all.filter(r => r && r.enabled !== false);
    _enabledCache = { at: now, records: enabled };
    return enabled;
  }

  /**
   * Automatic navigation-driven fallback injection when Chrome's userScripts API
   * is unavailable (e.g. Chrome 138+ Allow User Scripts toggle is OFF).
   * Uses short-lived availability & enabled-record caches so per-frame navigation
   * overhead stays sub-millisecond. When chrome.userScripts IS available, does
   * nothing (native registration handles it) so scripts are NEVER double-injected.
   */
  async function autoInjectForNavigation({ tabId, frameId = 0, url = '', stage = 'idle' } = {}) {
    if (!Number.isInteger(tabId) || !/^https?:\/\//i.test(url)) return { ok: true, skipped: true };
    const avail = await getCachedAvailability();
    if (avail.ok) {
      if (frameId === 0) await ensureSynced();
      return { ok: true, skipped: true, reason: 'native-userScripts-active' };
    }
    if (!chrome.scripting || typeof chrome.scripting.executeScript !== 'function') {
      return { ok: false, skipped: true, reason: 'scripting-unavailable' };
    }

    const records = await getCachedEnabledRecords();
    const now = Date.now();
    // Prune stale dedup entries (> 30s)
    for (const [k, ts] of _recentAutoInject.entries()) {
      if (now - ts > 30000) _recentAutoInject.delete(k);
    }

    let injected = 0;
    for (const rec of records) {
      if (rec.enabled === false) continue;
      const meta = rec.meta || emptyMeta();
      if (frameId !== 0 && meta.noframes && !rec.runEverywhere) continue;
      const runAt = meta.runAt || 'document-idle';
      const wantsStart = (runAt === 'document-start' || runAt === 'document-body');
      if (stage === 'start' && !wantsStart) continue;
      if (stage !== 'start' && wantsStart) continue;

      if (!rec.runEverywhere && !urlMatchesMeta(meta, url)) continue;

      const dedupKey = `${tabId}:${frameId}:${rec.id}:${url}`;
      if (_recentAutoInject.has(dedupKey)) continue;
      _recentAutoInject.set(dedupKey, now);

      const plan = { noMatch: false, matches: ['<all_urls>'], excludeMatches: [], includeGlobs: [], excludeGlobs: [], runtime: null };
      const code = buildSource(rec, plan);
      try {
        await chrome.scripting.executeScript({
          target: { tabId, frameIds: [frameId] },
          world: 'MAIN',
          func: (src) => {
            const s = document.createElement('script');
            s.textContent = src;
            (document.head || document.documentElement).appendChild(s);
            s.remove();
          },
          args: [code]
        });
        injected++;
      } catch {}
    }
    return { ok: true, method: 'scripting-auto-fallback', injected };
  }

  async function executePreview(opts = {}) {
    const rawCode = String(opts.code || '');
    if (!rawCode.trim()) return { ok: false, error: 'empty-code', method: 'none' };
    const targetTabId = Number(opts.tabId);
    if (!Number.isInteger(targetTabId)) return { ok: false, error: 'invalid-tab-id', method: 'none' };

    const avail = await checkAvailability();
    const { meta } = parseMetadata(rawCode);
    const requestedWorld = opts.world === 'MAIN' ? 'MAIN' : 'USER_SCRIPT';
    const previewRec = {
      id: 'cus_preview_' + Date.now().toString(36),
      code: rawCode,
      meta,
      enabled: false,
      requires: {},
      resources: {}
    };
    const plan = { noMatch: false, matches: ['<all_urls>'], excludeMatches: [], includeGlobs: [], excludeGlobs: [], runtime: null };
    const wrappedCode = buildSource(previewRec, plan);

    if (avail.ok && avail.executeSupported && chrome.userScripts && typeof chrome.userScripts.execute === 'function') {
      await configureWorld();
      try {
        const results = await chrome.userScripts.execute({
          target: { tabId: targetTabId, allFrames: Boolean(opts.allFrames) && !meta.noframes },
          world: requestedWorld,
          js: [{ code: wrappedCode }]
        });
        return {
          ok: true,
          method: 'userScripts.execute',
          world: requestedWorld,
          tabId: targetTabId,
          frameCount: Array.isArray(results) ? results.length : 1,
          registered: false
        };
      } catch (e) {
        return {
          ok: false,
          method: 'userScripts.execute',
          world: requestedWorld,
          tabId: targetTabId,
          error: (e && e.message) || 'preview-execute-failed',
          registered: false
        };
      }
    }

    return {
      ok: false,
      method: 'unsupported',
      world: requestedWorld,
      tabId: targetTabId,
      availability: avail,
      error: !avail.ok
        ? (avail.message || 'User Scripts permission is disabled.')
        : 'One-time live preview requires Chrome 135+ (chrome.userScripts.execute). Static validation completed; save and reload the tab to test on Chrome 120-134.',
      registered: false
    };
  }

    async function remove(id) {
    await withLock(async () => {
      const ids = (await readIndex()).filter(x => x !== id);
      await writeIndex(ids);
      await chrome.storage.local.remove([REC_PREFIX + id, VALS_PREFIX + id]);
    });
    await sync();
    return { ok: true };
  }

  async function setEnabled(id, enabled) {
    const rec = await readRecord(id);
    if (!rec) return { ok: false, error: 'not-found' };
    rec.enabled = Boolean(enabled);
    rec.regSig = '';
    await withLock(() => writeRecord(rec));
    const syncRes = await sync();
    return { ok: true, sync: { ok: syncRes.ok, availability: syncRes.availability, errors: syncRes.errors } };
  }

  async function importFromUrl(url) {
    const u = String(url || '').trim();
    if (!/^https?:\/\//i.test(u) || !isFetchableUrl(u)) return { ok: false, error: 'Only https:// URLs can be imported (http:// is allowed only for localhost)' };
    let code;
    try { code = await fetchText(u); }
    catch (e) { return { ok: false, error: `Download failed: ${e && e.message}` }; }
    return save({ code, sourceUrl: u, isRemoteUpdate: true });
  }

  /* ============================================================
     GM BRIDGE (extension side)
     Messages arrive from user-script worlds via
     chrome.runtime.onUserScriptMessage (wired up in background.js).
     Cross-tab value-change ports arrive via onUserScriptConnect.
     ============================================================ */
  const _valChains = new Map();
  const _xhrControllers = new Map(); // reqId -> { ctrl, scriptId }
  const _openedTabs = new Map();     // tabId -> scriptId
  const _valPorts = new Map();       // scriptId -> Set<Port>

  function handleGmConnect(port) {
    if (!port || typeof port.name !== 'string' || !port.name.startsWith('cu-vals:')) return false;
    const scriptId = port.name.slice('cu-vals:'.length);
    if (!scriptId.startsWith(REG_PREFIX)) {
      try { port.disconnect(); } catch {}
      return false;
    }
    let set = _valPorts.get(scriptId);
    if (!set) { set = new Set(); _valPorts.set(scriptId, set); }
    set.add(port);
    if (port.onDisconnect && typeof port.onDisconnect.addListener === 'function') {
      port.onDisconnect.addListener(() => {
        const s = _valPorts.get(scriptId);
        if (s) { s.delete(port); if (!s.size) _valPorts.delete(scriptId); }
      });
    }
    return true;
  }

  function broadcastValueChange(scriptId, key, val, deleted, senderTabId, senderFrameId) {
    const set = _valPorts.get(scriptId);
    if (!set || !set.size) return;
    for (const port of set) {
      try {
        const pt = port.sender && port.sender.tab && port.sender.tab.id;
        const pf = (port.sender && port.sender.frameId) || 0;
        if (senderTabId != null && pt === senderTabId && pf === (senderFrameId || 0)) continue;
        port.postMessage({ type: 'val-change', k: key, v: val, deleted: Boolean(deleted) });
      } catch {}
    }
  }

  function withValsLock(id, fn) {
    const prev = _valChains.get(id) || Promise.resolve();
    const run = prev.then(() => fn());
    const tail = run.catch(() => {});
    _valChains.set(id, tail);
    tail.then(() => { if (_valChains.get(id) === tail) _valChains.delete(id); });
    return run;
  }

  async function readVals(id) {
    const k = VALS_PREFIX + id;
    const r = await chrome.storage.local.get(k);
    return r[k] && typeof r[k] === 'object' ? r[k] : {};
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function isHttpUrl(u) {
    try { const p = new URL(String(u)).protocol; return p === 'http:' || p === 'https:'; } catch { return false; }
  }

  /* ============================================================
     TOOLBAR-POPUP MENU (replaces the floating in-page button)
     ============================================================ */
  /** Would this script run on `url`? Mirrors buildPlan() / the registration + runtime filters. */
  function urlMatchesMeta(meta, url) {
    const u = String(url || '');
    const plan = buildPlan(meta || emptyMeta());
    if (plan.noMatch) return false;
    const allowFile = plan.matches.some(m => m.startsWith('file:'));
    if (!/^https?:\/\//i.test(u) && !(allowFile && /^file:\/\//i.test(u))) return false;
    const norm = u.replace(/#.*$/, '');
    const test = (src, flags) => {
      try { const r = new RegExp(src, flags || ''); return r.test(u) || r.test(norm); } catch { return false; }
    };
    if (!plan.matches.some(m => test(matchToRegexSource(m)))) return false;
    if (plan.includeGlobs.length && !plan.includeGlobs.some(g => test(globToRegexSource(g), 'i'))) return false;
    if (plan.excludeMatches.some(m => test(matchToRegexSource(m)))) return false;
    if (plan.excludeGlobs.some(g => test(globToRegexSource(g), 'i'))) return false;
    if (plan.runtime) {
      const any = (list) => list.some(([src, fl]) => test(src, fl));
      if (!any(plan.runtime.i) || any(plan.runtime.e)) return false;
    }
    return true;
  }

  const MENU_PREFIX = 'gmMenu:';
  let _menuChain = Promise.resolve();
  function withMenuLock(fn) {
    const run = _menuChain.then(fn, fn);
    _menuChain = run.catch(() => {});
    return run;
  }
  const hasSessionStore = () => typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session;

  async function menuRead(tabId) {
    if (!hasSessionStore()) return {};
    const k = MENU_PREFIX + tabId;
    const r = await chrome.storage.session.get(k);
    return r[k] && typeof r[k] === 'object' && !Array.isArray(r[k]) ? r[k] : {};
  }

  function cleanMenuPayload(token, commands) {
    if (typeof token !== 'string' || !/^[a-f0-9]{32}$/.test(token)) return null;
    if (!Array.isArray(commands)) return null;
    const list = [];
    for (const c of commands.slice(0, 30)) {
      const id = Number(c && c.id);
      if (!Number.isInteger(id) || id < 1 || id > 100000) continue;
      const name = String(c && c.name != null ? c.name : '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 100);
      if (!name) continue;
      const accessKey = typeof (c && c.accessKey) === 'string' ? c.accessKey.replace(/[\u0000-\u001f]/g, '').slice(0, 1) : '';
      list.push({ id, name, accessKey });
    }
    return { token, commands: list };
  }

  async function menuSet(tabId, scriptId, token, commands) {
    if (!Number.isInteger(tabId) || !hasSessionStore()) return { ok: false, error: 'no-tab' };
    const clean = cleanMenuPayload(token, commands);
    if (!clean) return { ok: false, error: 'bad-menu' };
    return withMenuLock(async () => {
      const cur = await menuRead(tabId);
      if (clean.commands.length) cur[scriptId] = { token: clean.token, commands: clean.commands };
      else delete cur[scriptId];
      await chrome.storage.session.set({ [MENU_PREFIX + tabId]: cur });
      return { ok: true };
    });
  }

  async function clearTabMenu(tabId) {
    if (!Number.isInteger(tabId) || !hasSessionStore()) return;
    return withMenuLock(() => chrome.storage.session.remove(MENU_PREFIX + tabId)).catch(() => {});
  }

  /** Remove any GM_saveTab state stored for a closed tab. */
  async function clearTabData(tabId) {
    if (!Number.isInteger(tabId) || !hasSessionStore()) return;
    try {
      const ids = await readIndex();
      const keyStr = String(tabId);
      for (const id of ids) {
        const k = 'cuTabs:' + id;
        const r = await chrome.storage.session.get(k);
        const map = r[k];
        if (map && typeof map === 'object' && Object.prototype.hasOwnProperty.call(map, keyStr)) {
          delete map[keyStr];
          await chrome.storage.session.set({ [k]: map });
        }
      }
    } catch {}
  }

  /** Validate an announcement from a script that runs in the PAGE world (no bridge). */
  async function announceFromPage(sender, payload) {
    const tabId = sender && sender.tab && sender.tab.id;
    if (!Number.isInteger(tabId) || (sender.frameId || 0) !== 0) return { ok: false, error: 'top-frame-only' };
    const id = payload && payload.id;
    if (typeof id !== 'string' || !id.startsWith(REG_PREFIX)) return { ok: false, error: 'bad-id' };
    const rec = await readRecord(id);
    if (!rec || rec.enabled === false) return { ok: false, error: 'unknown-script' };
    const meta = rec.meta || emptyMeta();
    // Sandbox-world scripts announce ONLY through the private bridge. Accepting a DOM announcement
    // for them would let any web page overwrite their entry.
    if (chooseWorld(meta) === 'USER_SCRIPT') return { ok: false, error: 'bridge-script' };
    if (!urlMatchesMeta(meta, (sender.tab && sender.tab.url) || sender.url || '')) return { ok: false, error: 'not-for-this-page' };
    return menuSet(tabId, id, payload.token, payload.commands);
  }

  /** What the popup shows: every script that applies to this tab + its menu commands. */
  async function getTabMenu(tabId) {
    if (!Number.isInteger(tabId)) return { ok: false, error: 'bad-tab' };
    let tab;
    try { tab = await chrome.tabs.get(tabId); } catch { return { ok: false, error: 'no-tab' }; }
    const url = (tab && tab.url) || '';
    if (!/^https?:\/\//i.test(url)) return { ok: true, url, scripts: [] };

    // Drop the old list and ask the running scripts to announce again, so what we show is current.
    await clearTabMenu(tabId);
    let pageAnnouncements = [];
    try {
      const out = await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        world: 'ISOLATED',
        func: () => {
          const found = [];
          const onMenu = (ev) => {
            try { if (typeof ev.detail === 'string' && ev.detail.length <= 8000) found.push(ev.detail); } catch (e) {}
          };
          document.addEventListener('corsair-gm-menu', onMenu);
          try { document.dispatchEvent(new CustomEvent('corsair-gm-menu-sync')); } catch (e) {}
          document.removeEventListener('corsair-gm-menu', onMenu);
          return found.slice(0, 60);
        }
      });
      pageAnnouncements = Array.isArray(out) && out[0] && Array.isArray(out[0].result) ? out[0].result : [];
    } catch {}
    for (const raw of pageAnnouncements) {
      let payload = null;
      try { payload = JSON.parse(raw); } catch {}
      if (payload && typeof payload === 'object') {
        try { await announceFromPage({ tab: { id: tabId, url }, frameId: 0 }, payload); } catch {}
      }
    }
    await new Promise(r => setTimeout(r, 250));   // let sandbox-world scripts answer over the bridge

    const store = await menuRead(tabId);
    const scripts = [];
    const otherScripts = [];
    for (const rec of await readAll()) {
      if (!rec) continue;
      const meta = rec.meta || emptyMeta();
      const matchesHere = Boolean(rec.runEverywhere) || urlMatchesMeta(meta, url);
      const enabled = rec.enabled !== false;
      if (!matchesHere) {
        otherScripts.push({ id: rec.id, name: meta.name || 'Script', version: meta.version || '', enabled });
        continue;
      }
      const entry = enabled && Object.prototype.hasOwnProperty.call(store, rec.id) ? store[rec.id] : null;
      scripts.push({
        id: rec.id,
        name: meta.name || 'Script',
        version: meta.version || '',
        enabled,
        runEverywhere: Boolean(rec.runEverywhere),
        world: chooseWorld(meta, rec.code),
        runAt: meta.runAt || 'document-idle',
        lastError: rec.lastError || '',
        commands: entry && Array.isArray(entry.commands) ? entry.commands.map(c => ({ id: c.id, name: c.name, accessKey: c.accessKey || '' })) : []
      });
    }
    return { ok: true, url, scripts, otherScripts };
  }

  async function runMenuCommand(tabId, scriptId, commandId) {
    const cid = Number(commandId);
    if (!Number.isInteger(tabId) || !Number.isInteger(cid) || cid < 1) return { ok: false, error: 'bad-request' };
    const store = await menuRead(tabId);
    const key = String(scriptId);
    const entry = Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null;
    if (!entry || !Array.isArray(entry.commands) || !entry.commands.some(c => c.id === cid)) {
      return { ok: false, error: 'command-not-found' };
    }
    if (typeof entry.token !== 'string' || !/^[a-f0-9]{32}$/.test(entry.token)) return { ok: false, error: 'bad-token' };
    try {
      await chrome.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        world: 'ISOLATED',
        func: (name) => { document.dispatchEvent(new CustomEvent(name)); },
        args: ['corsair-gm-run-' + entry.token + '-' + cid]
      });
    } catch (e) { return { ok: false, error: (e && e.message) || 'could-not-reach-tab' }; }
    return { ok: true };
  }

  /* ---------- GM_xmlhttpRequest access control ---------- */
  function isPrivateHost(host) {
    const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!h) return true;
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan') || h.endsWith('.home.arpa')) return true;
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    if (v4) {
      const [a, b] = [Number(v4[1]), Number(v4[2])];
      return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
             (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
    }
    if (h.includes(':')) {
      if (h === '::' || h === '::1') return true;
      if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;
      if (/^fe[89ab][0-9a-f]:/.test(h)) return true;
      if (/^::ffff:/.test(h)) return true;
      return false;
    }
    if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true;
    return false;
  }

  function hostInList(host, entry) {
    let e = String(entry || '').trim().toLowerCase().replace(/^\*\./, '');
    if (!e) return false;
    return host === e || host.endsWith('.' + e);
  }

  function connectDecision(urlStr, connectList, pageUrl) {
    let host;
    try { host = new URL(urlStr).hostname.toLowerCase().replace(/\.$/, ''); } catch { return { allow: false, anonymous: true, deny: 'bad-url' }; }
    let pageHost = '';
    try { pageHost = new URL(String(pageUrl || '')).hostname.toLowerCase(); } catch {}
    const list = (Array.isArray(connectList) ? connectList : []).map(s => String(s || '').trim().toLowerCase()).filter(Boolean);

    const explicit = list.some(e => e !== '*' && e !== 'self' && hostInList(host, e));
    const wildcard = list.includes('*');
    const selfOk = Boolean(pageHost) && (host === pageHost || host.endsWith('.' + pageHost) || pageHost.endsWith('.' + host));

    if (isPrivateHost(host)) {
      if (explicit || (pageHost && host === pageHost)) return { allow: true, anonymous: false, deny: '' };
      return { allow: false, anonymous: true, deny: 'blocked-private-address' };
    }
    if (explicit || wildcard || selfOk) return { allow: true, anonymous: false, deny: '' };
    return { allow: true, anonymous: true, deny: '' };
  }

  async function gmXhr(req, ctx) {
    if (!isHttpUrl(req && req.url)) return { ok: false, kind: 'error', error: 'unsupported-url' };
    const decision = connectDecision(req.url, ctx && ctx.connect, ctx && ctx.pageUrl);
    if (decision.deny) return { ok: false, kind: 'error', error: decision.deny };
    if (decision.anonymous) req = { ...req, anonymous: true };
    const ctrl = new AbortController();
    _xhrControllers.set(req.reqId, { ctrl, scriptId: (ctx && ctx.scriptId) || '' });
    let timedOut = false;
    let timer = null;
    if (req.timeout > 0) timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, req.timeout);
    try {
      const init = {
        method: req.method || 'GET',
        headers: req.headers || {},
        credentials: req.anonymous ? 'omit' : 'include',
        redirect: req.redirect === 'manual' || req.redirect === 'error' ? req.redirect : 'follow',
        cache: req.nocache ? 'reload' : 'no-store',
        signal: ctrl.signal
      };
      if (init.method !== 'GET' && init.method !== 'HEAD') {
        if (req.bodyB64) init.body = base64ToBytes(req.bodyB64);
        else if (typeof req.body === 'string') init.body = req.body;
      }
      const r = await fetch(req.url, init);
      if (r.url && r.url !== req.url) {
        const again = connectDecision(r.url, ctx && ctx.connect, ctx && ctx.pageUrl);
        if (again.deny) return { ok: false, kind: 'error', error: again.deny };
      }
      const responseHeaders = Array.from(r.headers.entries()).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n';
      const mime = (r.headers.get('content-type') || '').split(';')[0].trim();
      const res = { status: r.status, statusText: r.statusText, responseHeaders, finalUrl: r.url || req.url, mime };
      if (req.responseType === 'arraybuffer' || req.responseType === 'blob') {
        const buf = await r.arrayBuffer();
        res.byteLength = buf.byteLength;
        res.b64 = bytesToBase64(buf);
      } else {
        const txt = await r.text();
        res.text = txt;
        res.byteLength = txt.length;
      }
      return { ok: true, res };
    } catch (e) {
      if (timedOut) return { ok: false, kind: 'timeout', error: 'Timeout' };
      if (ctrl.__userAbort) return { ok: false, kind: 'abort', error: 'Aborted' };
      return { ok: false, kind: 'error', error: (e && e.message) || 'Network error' };
    } finally {
      if (timer) clearTimeout(timer);
      _xhrControllers.delete(req.reqId);
    }
  }

  function safeDownloadName(name) {
    return String(name || '')
      .replace(/[\\/]+/g, '/')
      .split('/')
      .filter(seg => seg && seg !== '.' && seg !== '..')
      .join('/')
      .replace(/[<>:"|?*\x00-\x1f]/g, '_')
      .slice(0, 200);
  }

  function isOpGranted(meta, op) {
    const reqGrants = OP_REQUIRED_GRANTS[op];
    if (!reqGrants) return true;
    const rawGrants = (meta && Array.isArray(meta.grant)) ? meta.grant : [];
    // Legacy compatibility: if no @grant directives were declared at all, allow
    // (in production, grant-less scripts run in MAIN world without bridge access).
    if (!rawGrants.length) return true;
    const keys = grantedKeys(meta);
    return reqGrants.some(k => keys.has(k));
  }

  /** Handle one message from a user script. Returns the response object. */
  async function handleGmMessage(msg, sender) {
    if (!msg || msg.__cu !== 1 || typeof msg.id !== 'string' || !msg.id.startsWith(REG_PREFIX)) {
      return { ok: false, error: 'bad-message' };
    }
    const id = msg.id;
    const data = msg.data || {};

    // Only scripts that really exist and are enabled may use the bridge.
    const known = await readRecord(id);
    if (!known || known.enabled === false) return { ok: false, error: 'unknown-script' };

    // Unrestricted GM bridge for enabled installed scripts

    const senderTabId = sender && sender.tab && sender.tab.id;
    const senderFrameId = (sender && sender.frameId) || 0;

    switch (msg.op) {
      case 'vals:get':
        return { ok: true, values: await readVals(id) };

      case 'vals:set':
        return withValsLock(id, async () => {
          const vals = await readVals(id);
          const k = String(data.k);
          vals[k] = data.v;
          await chrome.storage.local.set({ [VALS_PREFIX + id]: vals });
          broadcastValueChange(id, k, data.v, false, senderTabId, senderFrameId);
          return { ok: true };
        });

      case 'vals:setBatch':
        return withValsLock(id, async () => {
          const vals = await readVals(id);
          const entries = (data.entries && typeof data.entries === 'object') ? data.entries : {};
          for (const [k, v] of Object.entries(entries)) {
            vals[String(k)] = v;
            broadcastValueChange(id, String(k), v, false, senderTabId, senderFrameId);
          }
          await chrome.storage.local.set({ [VALS_PREFIX + id]: vals });
          return { ok: true };
        });

      case 'vals:del':
        return withValsLock(id, async () => {
          const vals = await readVals(id);
          const k = String(data.k);
          delete vals[k];
          await chrome.storage.local.set({ [VALS_PREFIX + id]: vals });
          broadcastValueChange(id, k, undefined, true, senderTabId, senderFrameId);
          return { ok: true };
        });

      case 'vals:delBatch':
        return withValsLock(id, async () => {
          const vals = await readVals(id);
          const keys = Array.isArray(data.keys) ? data.keys : [];
          for (const rawK of keys) {
            const k = String(rawK);
            delete vals[k];
            broadcastValueChange(id, k, undefined, true, senderTabId, senderFrameId);
          }
          await chrome.storage.local.set({ [VALS_PREFIX + id]: vals });
          return { ok: true };
        });

      case 'xhr': {
        let pageUrl = '';
        try { pageUrl = (sender && (sender.tab && sender.tab.url)) || (sender && sender.url) || ''; } catch {}
        return gmXhr(data, { connect: known.meta && known.meta.connect, pageUrl, scriptId: id });
      }

      case 'menu:set': {
        if (!sender || !sender.tab || (sender.frameId || 0) !== 0) return { ok: false, error: 'top-frame-only' };
        return menuSet(sender.tab.id, id, data.token, data.commands);
      }

      case 'error:report': {
        const errText = String(data.error || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 400);
        if (errText) {
          known.lastError = errText;
          known.lastErrorAt = Date.now();
          try { await withLock(() => writeRecord(known)); } catch {}
        }
        return { ok: true };
      }

      case 'xhr-abort': {
        const entry = _xhrControllers.get(data.reqId);
        if (entry && entry.scriptId === id) {
          entry.ctrl.__userAbort = true;
          entry.ctrl.abort();
        }
        return { ok: true };
      }

      case 'notify': {
        const nid = 'gm-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        await chrome.notifications.create(nid, {
          type: 'basic',
          iconUrl: data.image || chrome.runtime.getURL('icons/icon128.png'),
          title: data.title || 'Userscript',
          message: data.text || ' ',
          silent: Boolean(data.silent)
        });
        if (data.timeout > 0) setTimeout(() => { try { chrome.notifications.clear(nid); } catch {} }, data.timeout);
        return { ok: true, id: nid };
      }

      case 'open-tab': {
        let proto = '';
        try { proto = new URL(String(data.url || '')).protocol; } catch {}
        if (!['http:', 'https:'].includes(proto) && String(data.url || '').trim().toLowerCase() !== 'about:blank') return { ok: false, error: 'unsupported-url' };
        const opts = { url: String(data.url || ''), active: data.active !== false };
        if (sender && sender.tab && sender.tab.id != null) {
          opts.openerTabId = sender.tab.id;
          if (data.insert !== false && typeof sender.tab.index === 'number') opts.index = sender.tab.index + 1;
        }
        const tab = await chrome.tabs.create(opts);
        if (tab && tab.id != null) _openedTabs.set(tab.id, id);
        return { ok: true, tabId: tab && tab.id };
      }

      case 'tab:get': {
        if (!Number.isInteger(senderTabId) || !hasSessionStore()) return { ok: true, tab: {} };
        const k = 'cuTabs:' + id;
        const r = await chrome.storage.session.get(k);
        const map = (r[k] && typeof r[k] === 'object') ? r[k] : {};
        return { ok: true, tab: map[String(senderTabId)] || {} };
      }

      case 'tab:save': {
        if (!Number.isInteger(senderTabId) || !hasSessionStore()) return { ok: false, error: 'no-tab' };
        const k = 'cuTabs:' + id;
        return withValsLock('tab:' + id, async () => {
          const r = await chrome.storage.session.get(k);
          const map = (r[k] && typeof r[k] === 'object') ? r[k] : {};
          map[String(senderTabId)] = (data.tab && typeof data.tab === 'object') ? data.tab : {};
          await chrome.storage.session.set({ [k]: map });
          return { ok: true };
        });
      }

      case 'tab:list': {
        if (!hasSessionStore()) return { ok: true, tabs: {} };
        const k = 'cuTabs:' + id;
        const r = await chrome.storage.session.get(k);
        const map = (r[k] && typeof r[k] === 'object') ? r[k] : {};
        return { ok: true, tabs: map };
      }

            case 'tab-close': {
        if (_openedTabs.get(data.tabId) === id) {
          _openedTabs.delete(data.tabId);
          try { await chrome.tabs.remove(data.tabId); } catch {}
        }
        return { ok: true };
      }

      case 'download': {
        if (!isHttpUrl(data.url)) return { ok: false, error: 'unsupported-url' };
        // No arbitrary file-type restriction on user-initiated script downloads
        try {
          const opts = { url: String(data.url || ''), saveAs: Boolean(data.saveAs) };
          const name = safeDownloadName(data.name);
          if (name) opts.filename = name;
          const downloadId = await chrome.downloads.download(opts);
          return { ok: true, downloadId };
        } catch (e) {
          return { ok: false, error: (e && e.message) || 'download failed' };
        }
      }

      case 'download-cancel': {
        if (Number.isInteger(data.downloadId) && chrome.downloads && typeof chrome.downloads.cancel === 'function') {
          try { await chrome.downloads.cancel(data.downloadId); } catch {}
        }
        return { ok: true };
      }

      default:
        return { ok: false, error: 'unknown-op' };
    }
  }

  /* ============================================================
     LEGACY MIGRATION (customDomainScripts -> userscripts)
     ============================================================ */
  function legacyToUserscript(host, entry) {
    const header = [
      '// ==UserScript==',
      `// @name         ${host} (migrated)`,
      '// @namespace    corsair-unbound/migrated',
      '// @version      1.0',
      `// @description  Migrated from the old per-domain custom script for ${host}`,
      `// @match        *://${host}/*`,
      `// @match        *://*.${host}/*`,
      '// @grant        none',
      '// @run-at       document-end',
      '// ==/UserScript=='
    ].join('\n');
    return `${header}\n\n${String((entry && entry.code) || '')}\n`;
  }

  /** Convert a legacy { host: {code, enabled} } map into userscripts. Skips hosts already converted. */
  async function importLegacy(legacy) {
    let migrated = 0;
    const existing = await readAll();
    for (const [host, entry] of Object.entries(legacy || {})) {
      if (!entry || typeof entry.code !== 'string' || !entry.code.trim()) continue;
      if (existing.some(r => r.migratedFrom === host)) continue;
      const code = legacyToUserscript(host, entry);
      const { meta } = parseMetadata(code);
      const now = Date.now();
      const rec = {
        id: newId(), code, meta,
        enabled: entry.enabled !== false,
        createdAt: entry.createdAt || now, updatedAt: now,
        sourceUrl: '', migratedFrom: host, regSig: '', lastError: '', lastErrorAt: 0,
        requires: {}, resources: {}
      };
      await withLock(async () => {
        await writeRecord(rec);
        const ids = await readIndex();
        ids.push(rec.id);
        await writeIndex(ids);
      });
      migrated++;
    }
    if (migrated) await sync();
    return migrated;
  }

  async function migrateLegacy() {
    const flag = await chrome.storage.local.get(MIGRATED_KEY);
    if (flag[MIGRATED_KEY]) return { ok: true, migrated: 0, skipped: true };

    let legacy = {};
    try {
      if (typeof CorsairStorage !== 'undefined') legacy = await CorsairStorage.get('customDomainScripts', {});
      else legacy = (await chrome.storage.local.get('customDomainScripts')).customDomainScripts || {};
    } catch { legacy = {}; }

    const migrated = await importLegacy(legacy);
    await chrome.storage.local.set({ [MIGRATED_KEY]: true });
    return { ok: true, migrated };
  }

  /* ============================================================
     BACKUP / RESTORE
     ============================================================ */
  async function exportForBackup() {
    const records = await readAll();
    const values = {};
    for (const r of records) {
      const v = await readVals(r.id);
      if (Object.keys(v).length) values[r.id] = v;
    }
    return {
      version: 1,
      scripts: records.map(r => ({
        id: r.id,
        code: String(r.code || ''),
        enabled: r.enabled !== false,
        runEverywhere: Boolean(r.runEverywhere),
        sourceUrl: r.sourceUrl || '',
        migratedFrom: r.migratedFrom || '',
        createdAt: r.createdAt || 0,
        updatedAt: r.updatedAt || 0,
        requires: r.requires || {},
        resources: r.resources || {}
      })),
      values
    };
  }

  function validateBackupBlock(data) {
    if (data == null) return { ok: true, scripts: [], values: {} };
    if (typeof data !== 'object' || Array.isArray(data)) return { ok: false, error: 'invalid-userscripts: must be an object' };
    if (!Array.isArray(data.scripts)) return { ok: false, error: 'invalid-userscripts: scripts must be an array' };
    const scripts = [];
    for (const s of data.scripts) {
      if (!s || typeof s !== 'object' || typeof s.code !== 'string') continue;
      scripts.push({
        id: typeof s.id === 'string' && /^cu-[a-z0-9]{6,40}$/i.test(s.id) ? s.id : '',
        code: s.code,
        enabled: s.enabled !== false,
        runEverywhere: Boolean(s.runEverywhere),
        sourceUrl: typeof s.sourceUrl === 'string' ? s.sourceUrl : '',
        migratedFrom: typeof s.migratedFrom === 'string' ? s.migratedFrom : '',
        createdAt: Number(s.createdAt) || 0,
        updatedAt: Number(s.updatedAt) || 0,
        requires: s.requires && typeof s.requires === 'object' && !Array.isArray(s.requires) ? s.requires : {},
        resources: s.resources && typeof s.resources === 'object' && !Array.isArray(s.resources) ? s.resources : {}
      });
    }
    const values = {};
    if (data.values && typeof data.values === 'object' && !Array.isArray(data.values)) {
      for (const [id, v] of Object.entries(data.values)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) values[id] = v;
      }
    }
    return { ok: true, scripts, values };
  }

  async function restoreFromBackup(data) {
    const val = validateBackupBlock(data);
    if (!val.ok) return { ok: false, error: val.error, restored: 0 };

    const now = Date.now();
    const incoming = [];
    const idMap = new Map();
    for (const s of val.scripts) {
      const id = s.id || newId();
      idMap.set(s.id, id);
      const { meta } = parseMetadata(s.code);
      if (!meta.name) meta.name = 'Untitled script';
      incoming.push({
        id, code: s.code, meta, enabled: s.enabled,
        runEverywhere: Boolean(s.runEverywhere),
        createdAt: s.createdAt || now, updatedAt: s.updatedAt || now,
        sourceUrl: s.sourceUrl, migratedFrom: s.migratedFrom,
        requires: s.requires, resources: s.resources,
        regSig: '', lastError: '', lastErrorAt: 0
      });
    }

    await withLock(async () => {
      const oldIds = await readIndex();
      const removeKeys = [];
      for (const id of oldIds) removeKeys.push(REC_PREFIX + id, VALS_PREFIX + id);
      if (removeKeys.length) await chrome.storage.local.remove(removeKeys);

      const batch = {};
      for (const rec of incoming) batch[REC_PREFIX + rec.id] = rec;
      for (const [oldId, v] of Object.entries(val.values)) {
        const id = idMap.get(oldId) || oldId;
        if (incoming.some(r => r.id === id)) batch[VALS_PREFIX + id] = v;
      }
      batch[INDEX_KEY] = incoming.map(r => r.id);
      batch[MIGRATED_KEY] = true;
      await chrome.storage.local.set(batch);
    });

    for (const rec of incoming) {
      const needsReq = (rec.meta.require || []).some(u => typeof rec.requires[resolveUrl(u, rec.sourceUrl)] !== 'string');
      const needsRes = (rec.meta.resource || []).some(r => !rec.resources[r.name]);
      if (needsReq || needsRes) {
        try {
          await fetchDependencies(rec, rec);
          await withLock(() => writeRecord(rec));
        } catch {}
      }
    }

    await sync();
    return { ok: true, restored: incoming.length };
  }

  let _initPromise = null;
  function init() {
    if (!_initPromise) {
      _initPromise = (async () => {
        try { await migrateLegacy(); } catch (e) { console.warn('[Corsair Userscripts] migration failed:', e && e.message); }
        try {
          const r = await sync();
          if (!r || !r.ok) _initPromise = null;
          return r;
        } catch (e) {
          _initPromise = null;
          console.warn('[Corsair Userscripts] sync failed:', e && e.message);
        }
      })();
    }
    return _initPromise;
  }

  return {
    parseMetadata,
    toChromeMatch,
    globToRegexSource,
    matchToRegexSource,
    buildPlan,
    buildSource,
    buildSourceWithMap,
    sanitizeExecutableCode,
    validateScript,
    validateCodeSnippet,
    getCompatibilityMatrix,
    chooseWorld,
    needsBridge,
    needsGM: needsBridge,
    handleGmMessage,
    handleGmConnect,
    gmRuntime,
    legacyToUserscript,
    checkAvailability,
    syncRegistrations,
    sync,
    ensureSynced,
    list,
    get,
    save,
    duplicate,
    refreshDependencies,
    updateFromRemote,
    checkAllUpdates,
    getValues,
    clearValues,
    clearTabData,
    setRunEverywhere,
    addMatchRule,
    executeNow,
    executePreview,
    autoInjectForNavigation,
    detectAutoGrants,
    remove,
    setEnabled,
    importFromUrl,
    connectDecision,
    isPrivateHost,
    urlMatchesMeta,
    announceFromPage,
    getTabMenu,
    runMenuCommand,
    clearTabMenu,
    migrateLegacy,
    importLegacy,
    exportForBackup,
    validateBackupBlock,
    restoreFromBackup,
    init
  };
})();

globalThis.CorsairUserScripts = CorsairUserScripts;
