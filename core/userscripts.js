/* ============================================================
   CORSAIR USERSCRIPTS ENGINE
   ------------------------------------------------------------
   Tampermonkey-style userscript manager built on the official
   chrome.userScripts API (Chrome 120+).

   - Parses the standard ==UserScript== metadata block
   - Converts @match / @include / @exclude into registration rules
     (with a runtime URL filter for anything Chrome cannot express)
   - Caches @require / @resource dependencies
   - Registers scripts with chrome.userScripts (CSP-proof)
   - Migrates the legacy one-script-per-domain store

   There is deliberately NO code linting or size limit here:
   whatever the user installs is what runs.
   ============================================================ */
const CorsairUserScripts = (() => {
  'use strict';

  const INDEX_KEY = 'cus:index';
  const REC_PREFIX = 'cus:rec:';
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

  /* ============================================================
     METADATA PARSER
     ============================================================ */
  const HEADER_RE = /\/\/\s*==UserScript==([\s\S]*?)\/\/\s*==\/UserScript==/;

  function emptyMeta() {
    return {
      name: '', namespace: '', version: '', description: '', author: '',
      homepage: '', icon: '', updateURL: '', downloadURL: '', supportURL: '',
      license: '', runAt: 'document-idle', injectInto: 'auto',
      noframes: false, topLevelAwait: false,
      match: [], include: [], exclude: [], excludeMatch: [],
      grant: [], require: [], resource: [], connect: [], tags: [],
      localized: {}
    };
  }

  function parseMetadata(code) {
    const meta = emptyMeta();
    const src = String(code == null ? '' : code);
    const m = HEADER_RE.exec(src);
    if (!m) return { meta, hasHeader: false, headerText: '' };

    for (const rawLine of m[1].split(/\r?\n/)) {
      const lm = /^\s*\/\/\s*@([\w:\-]+)(?:\s+(.*?))?\s*$/.exec(rawLine);
      if (!lm) continue;
      const key = lm[1].toLowerCase();
      const val = (lm[2] || '').trim();

      if (key.includes(':')) {            // @name:fa, @description:de ...
        meta.localized[key] = val;
        continue;
      }

      switch (key) {
        case 'name': meta.name = val; break;
        case 'namespace': meta.namespace = val; break;
        case 'version': meta.version = val; break;
        case 'description': meta.description = val; break;
        case 'author': meta.author = val; break;
        case 'homepage': case 'homepageurl': case 'website': case 'source':
          if (!meta.homepage) meta.homepage = val; break;
        case 'icon': case 'iconurl': case 'defaulticon':
          if (!meta.icon) meta.icon = val; break;
        case 'updateurl': meta.updateURL = val; break;
        case 'downloadurl': case 'installurl': meta.downloadURL = val; break;
        case 'supporturl': meta.supportURL = val; break;
        case 'license': meta.license = val; break;
        case 'match': if (val) meta.match.push(val); break;
        case 'include': if (val) meta.include.push(val); break;
        case 'exclude': if (val) meta.exclude.push(val); break;
        case 'exclude-match': if (val) meta.excludeMatch.push(val); break;
        case 'grant': if (val) meta.grant.push(val); break;
        case 'require': if (val) meta.require.push(val); break;
        case 'connect': if (val) meta.connect.push(val); break;
        case 'tag': if (val) meta.tags.push(val); break;
        case 'resource': {
          const rm = /^(\S+)\s+(\S+)$/.exec(val);
          if (rm) meta.resource.push({ name: rm[1], url: rm[2] });
          break;
        }
        case 'noframes': meta.noframes = true; break;
        case 'top-level-await': meta.topLevelAwait = true; break;
        case 'run-at': {
          const v = val.toLowerCase();
          if (['document-start', 'document-body', 'document-end', 'document-idle', 'context-menu'].includes(v)) {
            meta.runAt = v === 'context-menu' ? 'document-idle' : v;
          }
          break;
        }
        case 'inject-into': {
          const v = val.toLowerCase();
          if (['page', 'content', 'auto'].includes(v)) meta.injectInto = v;
          break;
        }
        default: break;
      }
    }

    meta.grant = Array.from(new Set(meta.grant));
    return { meta, hasHeader: true, headerText: m[0] };
  }

  function chooseWorld(meta) {
    if (meta.injectInto === 'page') return 'MAIN';
    if (meta.injectInto === 'content') return 'USER_SCRIPT';
    return needsBridge(meta) ? 'USER_SCRIPT' : 'MAIN';
  }

  /* ============================================================
     MATCH PATTERNS
     ============================================================ */
  const SCHEMES = new Set(['*', 'http', 'https', 'file', 'ftp', 'ws', 'wss']);
  const HOST_RE = /^(\*|(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*)(?::(\d+|\*))?$/;

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

    let host = m[2].toLowerCase();
    const path = m[3] === undefined ? '/*' : m[3];

    if (scheme === 'file') {
      if (host !== '') return null;
      return `file://${path}`;
    }
    if (!HOST_RE.test(host)) return null;
    return `${scheme}://${host}${path}`;
  }

  function escapeRegex(s) {
    return String(s).replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }

  /** Glob (* and ?) to regex source. */
  function globToRegexSource(glob) {
    let out = '';
    for (const ch of String(glob)) {
      if (ch === '*') out += '.*';
      else if (ch === '?') out += '.';
      else out += escapeRegex(ch);
    }
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

    const matchConv = matchRaw.map(toChromeMatch);
    const allMatchOk = matchConv.every(Boolean);

    let needRuntime = false;

    if (matchRaw.length && !includeRaw.length && allMatchOk) {
      plan.matches = unique(matchConv);
    } else if (!matchRaw.length && includeGlob.length && !includeRegex.length) {
      plan.matches = [BROAD_MATCH];
      if (includeGlob.some(g => /^file:/i.test(g))) plan.matches.push('file:///*');
      plan.includeGlobs = unique(includeGlob);
    } else {
      plan.matches = [BROAD_MATCH];
      if (includeRaw.some(g => /^file:/i.test(g))) plan.matches.push('file:///*');
      needRuntime = true;
    }

    const excludeMatchConv = excludeMatchRaw.map(toChromeMatch);
    if (excludeMatchConv.every(Boolean)) plan.excludeMatches = unique(excludeMatchConv);
    else needRuntime = true;

    if (excludeRegex.length) needRuntime = true;
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

    /* ---------- values (synchronous cache, async persistence) ---------- */
    let values = {};
    const listeners = new Map();
    let listenerSeq = 1;
    const ready = (ctx.needValues && hasBridge)
      ? send('vals:get').then((r) => { values = (r && r.values) || {}; }).catch(() => {})
      : Promise.resolve();
    const has = (k) => Object.prototype.hasOwnProperty.call(values, k);
    const fire = (k, o, n) => {
      listeners.forEach((l) => {
        if (l.key === k) { try { l.cb(k, o, n, false); } catch (e) { console.error(e); } }
      });
    };
    impl.getvalue = (k, d) => (has(k) ? clone(values[k]) : d);
    impl.setvalue = (k, v) => {
      const o = values[k];
      values[k] = clone(v);
      fire(k, o, values[k]);
      send('vals:set', { k: k, v: values[k] }).catch(() => {});
    };
    impl.deletevalue = (k) => {
      if (!has(k)) return;
      const o = values[k];
      delete values[k];
      fire(k, o, undefined);
      send('vals:del', { k: k }).catch(() => {});
    };
    impl.listvalues = () => Object.keys(values);
    impl.getvalues = (keys) => {
      const out = {};
      if (Array.isArray(keys)) keys.forEach((k) => { out[k] = impl.getvalue(k); });
      else if (keys && typeof keys === 'object') Object.keys(keys).forEach((k) => { out[k] = impl.getvalue(k, keys[k]); });
      else Object.keys(values).forEach((k) => { out[k] = clone(values[k]); });
      return out;
    };
    impl.setvalues = (obj) => { Object.keys(obj || {}).forEach((k) => impl.setvalue(k, obj[k])); };
    impl.deletevalues = (keys) => { (keys || []).forEach((k) => impl.deletevalue(k)); };
    impl.addvaluechangelistener = (key, cb) => { const id = listenerSeq++; listeners.set(id, { key: key, cb: cb }); return id; };
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
        const e = {
          readyState: 4, status: 0, statusText: '', responseText: '', response: null,
          responseHeaders: '', finalUrl: url || d.url, context: d.context, error: message
        };
        if (kind === 'timeout') call('ontimeout', e);
        else if (kind === 'abort') call('onabort', e);
        else call('onerror', e);
        call('onloadend', e);
      };
      (async () => {
        let url;
        try { url = new URL(d.url, location.href).href; }
        catch (e) { finished = true; fail('error', 'Invalid URL', d.url); return; }

        const headers = Object.assign({}, d.headers || {});
        if (d.user) headers['Authorization'] = 'Basic ' + btoa(d.user + ':' + (d.password || ''));
        const req = {
          reqId: reqId, url: url, method: String(d.method || 'GET').toUpperCase(), headers: headers,
          anonymous: !!d.anonymous, timeout: d.timeout | 0, redirect: d.redirect || 'follow',
          responseType: d.responseType || ''
        };
        const data = d.data;
        if (data !== undefined && data !== null) {
          if (typeof data === 'string') {
            req.body = data;
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

        let r;
        try { r = await send('xhr', req); }
        catch (e) { r = { ok: false, kind: 'error', error: String((e && e.message) || e) }; }
        if (finished) return;
        finished = true;

        if (!r || !r.ok) { fail(r && r.kind, (r && r.error) || 'Network error', url); return; }

        const raw = r.res;
        const rt = req.responseType;
        let response;
        let responseText = '';
        if (rt === 'arraybuffer') response = b64ToBytes(raw.b64).buffer;
        else if (rt === 'blob') response = new Blob([b64ToBytes(raw.b64)], { type: raw.mime || '' });
        else {
          responseText = raw.text || '';
          if (rt === 'json') { try { response = JSON.parse(responseText); } catch (e) { response = null; } }
          else response = responseText;
        }
        const res = {
          readyState: 4, status: raw.status, statusText: raw.statusText, responseHeaders: raw.responseHeaders,
          finalUrl: raw.finalUrl, response: response, responseText: responseText, responseXML: null, context: d.context
        };
        const size = (raw.text ? raw.text.length : 0);
        call('onreadystatechange', res);
        call('onprogress', Object.assign({ lengthComputable: true, loaded: size, total: size }, res));
        call('onload', res);
        call('onloadend', res);
      })();
      return {
        abort: () => {
          if (finished) return;
          finished = true;
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

    /* ---------- notifications, tabs, downloads ---------- */
    impl.notification = (a, b, c, e) => {
      let o = {};
      if (a && typeof a === 'object') o = Object.assign({}, a);
      else { o.text = a; o.title = b; o.image = c; o.onclick = e; }
      return send('notify', {
        title: String(o.title || ''), text: String(o.text || ''),
        image: o.image ? String(o.image) : '', timeout: o.timeout | 0
      }).catch(() => {});
    };
    impl.opentab = (url, opts) => {
      const o = (typeof opts === 'boolean') ? { active: !opts } : (opts || {});
      const tab = { closed: false, onclose: null, tabId: null, close: () => { if (tab.tabId != null) send('tab-close', { tabId: tab.tabId }).catch(() => {}); } };
      let abs = url;
      try { abs = new URL(url, location.href).href; } catch (e) {}
      send('open-tab', { url: abs, active: o.active !== false && !o.background && !o.loadInBackground })
        .then((r) => { if (r) tab.tabId = r.tabId; }).catch(() => {});
      return tab;
    };
    impl.download = (a, b) => {
      const o = (a && typeof a === 'object') ? a : { url: a, name: b };
      const cb = (n, arg) => { if (typeof o[n] === 'function') { try { o[n](arg); } catch (e) { console.error(e); } } };
      let abs = o.url;
      try { abs = new URL(o.url, location.href).href; } catch (e) {}
      send('download', { url: abs, name: o.name || '', saveAs: !!o.saveAs })
        .then((r) => { if (r && r.ok) { cb('onload', {}); } else { cb('onerror', { error: 'not_succeeded', details: r && r.error }); } })
        .catch((e) => cb('onerror', { error: 'not_succeeded', details: String(e && e.message) }));
      return { abort: () => {} };
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
    impl.setclipboard = (text) => {
      const s = String(text);
      const fallback = () => {
        const ta = document.createElement('textarea');
        ta.value = s;
        ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
        (document.body || document.documentElement).appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) {}
        ta.remove();
      };
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(s).catch(fallback);
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

    /* ---------- menu commands (small floating menu, top frame only) ---------- */
    const commands = new Map();
    let cmdSeq = 1;
    let menuHost = null;
    let menuList = null;
    const renderMenu = () => {
      if (window.top !== window) return;
      if (!commands.size) { if (menuHost) menuHost.style.display = 'none'; return; }
      if (!menuHost) {
        menuHost = document.createElement('div');
        menuHost.setAttribute('data-corsair-gm-menu', ctx.id);
        const root = menuHost.attachShadow({ mode: 'open' });
        const slot = document.querySelectorAll('[data-corsair-gm-menu]').length;
        root.innerHTML =
          '<style>' +
          ':host{all:initial}' +
          '.pill{position:fixed;right:12px;bottom:' + (12 + slot * 38) + 'px;z-index:2147483647;font:12px/1 system-ui,sans-serif;direction:ltr}' +
          'button{all:unset;cursor:pointer;background:#2b1b4d;color:#fff;border:1px solid #7c5cff;border-radius:999px;padding:7px 11px;opacity:.55}' +
          'button:hover{opacity:1}' +
          '.list{display:none;position:absolute;right:0;bottom:34px;background:#1b1230;border:1px solid #7c5cff;border-radius:10px;padding:6px;min-width:190px;max-width:320px}' +
          '.pill.open .list{display:block}' +
          '.item{display:block;width:auto;padding:7px 9px;border-radius:6px;color:#fff;opacity:1;background:none;border:0;border-radius:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
          '.item:hover{background:#3a2766}' +
          '</style><div class="pill"><div class="list"></div><button class="toggle"></button></div>';
        const pill = root.querySelector('.pill');
        menuList = root.querySelector('.list');
        root.querySelector('.toggle').addEventListener('click', () => pill.classList.toggle('open'));
        (document.body || document.documentElement).appendChild(menuHost);
      }
      menuHost.style.display = '';
      const root = menuHost.shadowRoot;
      root.querySelector('.toggle').textContent = '\u{1F9E9} ' + (ctx.name || 'Script') + ' (' + commands.size + ')';
      menuList.textContent = '';
      commands.forEach((c) => {
        const b = document.createElement('button');
        b.className = 'item';
        b.textContent = c.name;
        b.addEventListener('click', () => {
          root.querySelector('.pill').classList.remove('open');
          try { c.fn(); } catch (e) { console.error(e); }
        });
        menuList.appendChild(b);
      });
    };
    impl.registermenucommand = (name, fn) => {
      const id = cmdSeq++;
      commands.set(id, { name: String(name), fn: fn });
      const go = () => { try { renderMenu(); } catch (e) { console.error(e); } };
      if (document.body) go(); else document.addEventListener('DOMContentLoaded', go, { once: true });
      return id;
    };
    impl.unregistermenucommand = (id) => { commands.delete(id); try { renderMenu(); } catch (e) {} };

    return { impl: impl, ready: ready };
  }

  /** Grants that need the extension bridge (and therefore the isolated user-script world). */
  const BRIDGE_KEYS = new Set([
    'getvalue', 'setvalue', 'deletevalue', 'listvalues', 'getvalues', 'setvalues', 'deletevalues',
    'addvaluechangelistener', 'removevaluechangelistener',
    'xmlhttprequest', 'notification', 'opentab', 'download'
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
    ['getresourceurl', 'GM_getResourceURL', 'getResourceUrl']
  ];

  function grantedKeys(meta) {
    const out = new Set();
    for (const g of (meta.grant || [])) {
      const m = /^GM[._](\w+)$/i.exec(g);
      if (m) out.add(m[1].toLowerCase());
    }
    return out;
  }

  /** True when the script uses GM_* functions that need the extension bridge. */
  function needsBridge(meta) {
    for (const k of grantedKeys(meta)) if (BRIDGE_KEYS.has(k)) return true;
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
   * Build the code string injected for a script.
   * User code and @require libraries share one async function scope,
   * so `return` and top-level `await` both work in userscripts.
   */
  function buildSource(record, plan) {
    const meta = record.meta || emptyMeta();
    const info = {
      script: {
        name: meta.name, namespace: meta.namespace, version: meta.version,
        description: meta.description, author: meta.author, grant: meta.grant,
        'run-at': meta.runAt, noframes: meta.noframes, matches: meta.match,
        includes: meta.include, excludes: meta.exclude, uuid: record.id,
        resources: (meta.resource || []).map(r => ({ name: r.name, url: r.url }))
      },
      scriptMetaStr: parseMetadata(record.code).headerText || '',
      scriptHandler: 'Corsair Unbound',
      version: extensionVersion(),
      injectInto: chooseWorld(meta) === 'MAIN' ? 'page' : 'content',
      scriptWillUpdate: Boolean(meta.updateURL || meta.downloadURL)
    };

    const parts = [];
    parts.push('(async function(){');

    if (plan.runtime) {
      parts.push(
        'const __f=' + JSON.stringify(plan.runtime) + ';' +
        'const __h=location.href,__n=__h.replace(/#.*$/,"");' +
        'const __t=(l)=>l.some(([s,fl])=>{try{const r=new RegExp(s,fl);return r.test(__h)||r.test(__n)}catch(e){return false}});' +
        'if(!__t(__f.i)||__t(__f.e))return;'
      );
    }

    if (meta.runAt === 'document-body') {
      parts.push(
        'if(!document.body){await new Promise(function(res){var o=new MutationObserver(function(){if(document.body){o.disconnect();res()}});o.observe(document,{childList:true,subtree:true})})}'
      );
    }

    const world = chooseWorld(meta);
    const keys = grantedKeys(meta);
    const resources = {};
    for (const [name, r] of Object.entries(record.resources || {})) {
      resources[name] = { text: typeof r.text === 'string' ? r.text : null, dataUrl: r.dataUrl || '' };
    }
    const ctx = {
      id: record.id,
      name: meta.name,
      bridge: world === 'USER_SCRIPT',
      wantsBridge: needsBridge(meta),
      needValues: Array.from(keys).some(k => VALUE_KEYS.has(k)),
      resources
    };

    let prelude =
      'const GM_info=' + JSON.stringify(info) + ';' +
      'const unsafeWindow=window;' +
      'const __gm=(' + gmRuntime.toString() + ')(' + JSON.stringify(ctx) + ');' +
      'await __gm.ready;' +
      'const GM={info:GM_info};';
    for (const [key, gmName, dotName] of GM_API) {
      if (!keys.has(key)) continue;
      prelude += 'const ' + gmName + '=__gm.impl.' + key + ';';
      if (key === 'xmlhttprequest') prelude += 'GM.' + dotName + '=__gm.impl.xmlhttprequestp;';
      else prelude += 'GM.' + dotName + '=function(){var a=arguments;return Promise.resolve().then(function(){return __gm.impl.' + key + '.apply(null,a)})};';
    }
    parts.push(prelude);

    // @require libraries first, then the user's own code
    const reqs = record.requires || {};
    for (const url of (meta.require || [])) {
      const text = reqs[resolveUrl(url, record.sourceUrl)];
      if (typeof text === 'string') {
        parts.push('\n;/* @require ' + url.replace(/\*\//g, '* /') + ' */\n' + text + '\n;');
      } else {
        parts.push('console.warn("[Corsair Userscripts] @require not cached: ' + url.replace(/["\\\n\r]/g, '') + '");');
      }
    }

    parts.push('\n' + String(record.code || '') + '\n');
    parts.push('})().catch(function(e){console.error("[Corsair Userscripts] ' + safeSourceName(meta.name) + ':",e)});');
    parts.push('\n//# sourceURL=corsair-userscript/' + safeSourceName(meta.name) + '.user.js');

    return parts.join('');
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

  function isFetchableUrl(u) {
    return /^(https?:|data:)/i.test(u);
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

  async function fetchDependencies(record, previous) {
    const warnings = [];
    const meta = record.meta;
    const prevReq = (previous && previous.requires) || {};
    const prevRes = (previous && previous.resources) || {};

    record.requires = {};
    for (const raw of (meta.require || [])) {
      const url = resolveUrl(raw, record.sourceUrl);
      if (!url || !isFetchableUrl(url)) { warnings.push(`@require skipped (unsupported URL): ${raw}`); continue; }
      if (typeof prevReq[url] === 'string') { record.requires[url] = prevReq[url]; continue; }
      try { record.requires[url] = await fetchText(url); }
      catch (e) { warnings.push(`@require failed: ${raw} (${e && e.message})`); }
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
    return Array.isArray(r[INDEX_KEY]) ? r[INDEX_KEY] : [];
  }

  async function writeIndex(ids) {
    await chrome.storage.local.set({ [INDEX_KEY]: unique(ids) });
  }

  async function readRecord(id) {
    const k = REC_PREFIX + id;
    const r = await chrome.storage.local.get(k);
    return r[k] || null;
  }

  async function writeRecord(rec) {
    await chrome.storage.local.set({ [REC_PREFIX + rec.id]: rec });
  }

  async function readAll() {
    const ids = await readIndex();
    if (!ids.length) return [];
    const keys = ids.map(id => REC_PREFIX + id);
    const r = await chrome.storage.local.get(keys);
    return ids.map(id => r[REC_PREFIX + id]).filter(Boolean);
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
      icon: meta.icon,
      enabled: rec.enabled !== false,
      matches: [...meta.match, ...meta.include],
      excludes: [...meta.exclude, ...meta.excludeMatch],
      grant: meta.grant,
      runAt: meta.runAt,
      world: chooseWorld(meta),
      noMatch: plan.noMatch,
      lines: code.split('\n').length,
      bytes: code.length,
      sourceUrl: rec.sourceUrl || '',
      updateURL: meta.updateURL,
      downloadURL: meta.downloadURL,
      lastError: rec.lastError || '',
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
    if (major && major < 120) {
      return { ok: false, code: 'old-chrome', chrome: major, message: 'Chrome 120 or newer is required for userscripts.' };
    }
    if (!chrome.userScripts) {
      return { ok: false, code: 'disabled', chrome: major, message: 'Enable "Allow User Scripts" for this extension.' };
    }
    try {
      await chrome.userScripts.getScripts();
      return { ok: true, chrome: major };
    } catch (e) {
      return { ok: false, code: 'disabled', chrome: major, message: (e && e.message) || 'User scripts are not enabled.' };
    }
  }

  /* ============================================================
     REGISTRATION
     ============================================================ */
  function buildRegistration(rec) {
    const meta = rec.meta || emptyMeta();
    const plan = buildPlan(meta);
    if (plan.noMatch) return { plan, registration: null };

    const registration = {
      id: rec.id,
      matches: plan.matches,
      allFrames: !meta.noframes,
      runAt: runAtToChrome(meta.runAt),
      world: chooseWorld(meta),
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

  let _syncPromise = null;
  function sync() {
    // Coalesce overlapping sync requests, but always run once more afterwards
    if (_syncPromise) {
      _syncPromise = _syncPromise.then(() => withLock(syncRegistrations), () => withLock(syncRegistrations));
    } else {
      _syncPromise = withLock(syncRegistrations);
    }
    const p = _syncPromise;
    p.finally(() => { if (_syncPromise === p) _syncPromise = null; }).catch(() => {});
    return p;
  }

  /* ============================================================
     CRUD
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

  function findByIdentity(records, meta) {
    if (!meta.name) return null;
    return records.find(r => r.meta && r.meta.name === meta.name && (r.meta.namespace || '') === (meta.namespace || '')) || null;
  }

  /**
   * Create or update a script.
   * input: { id?, code, enabled?, sourceUrl? }
   */
  async function save(input) {
    const code = String(input && input.code != null ? input.code : '');
    const { meta } = parseMetadata(code);
    if (!meta.name) meta.name = 'Untitled script';

    let previous = null;
    let id = input && input.id ? String(input.id) : '';
    if (id) previous = await readRecord(id);
    if (!previous && !id && input && input.sourceUrl) {
      previous = findByIdentity(await readAll(), meta);
      if (previous) id = previous.id;
    }
    if (!id) id = newId();

    const now = Date.now();
    const rec = {
      id,
      code,
      meta,
      enabled: input && input.enabled !== undefined ? Boolean(input.enabled) : (previous ? previous.enabled !== false : true),
      createdAt: previous ? previous.createdAt || now : now,
      updatedAt: now,
      sourceUrl: (input && input.sourceUrl) || (previous && previous.sourceUrl) || '',
      migratedFrom: (previous && previous.migratedFrom) || '',
      regSig: '',
      lastError: ''
    };

    const warnings = await fetchDependencies(rec, previous);

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
      sync: { ok: syncRes.ok, availability: syncRes.availability, errors: syncRes.errors }
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
    if (!/^https?:\/\//i.test(u)) return { ok: false, error: 'Only http(s) URLs can be imported' };
    let code;
    try { code = await fetchText(u); }
    catch (e) { return { ok: false, error: `Download failed: ${e && e.message}` }; }
    return save({ code, sourceUrl: u });
  }

  /* ============================================================
     GM BRIDGE (extension side)
     Messages arrive from user-script worlds via
     chrome.runtime.onUserScriptMessage (wired up in background.js).
     ============================================================ */
  const VALS_PREFIX = 'cus:vals:';
  const _valChains = new Map();
  const _xhrControllers = new Map();
  const _openedTabs = new Set();

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

  async function gmXhr(req) {
    const ctrl = new AbortController();
    _xhrControllers.set(req.reqId, ctrl);
    let timedOut = false;
    let timer = null;
    if (req.timeout > 0) timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, req.timeout);
    try {
      const init = {
        method: req.method || 'GET',
        headers: req.headers || {},
        credentials: req.anonymous ? 'omit' : 'include',
        redirect: req.redirect === 'manual' || req.redirect === 'error' ? req.redirect : 'follow',
        cache: 'no-store',
        signal: ctrl.signal
      };
      if (init.method !== 'GET' && init.method !== 'HEAD') {
        if (req.bodyB64) init.body = base64ToBytes(req.bodyB64);
        else if (typeof req.body === 'string') init.body = req.body;
      }
      const r = await fetch(req.url, init);
      const responseHeaders = Array.from(r.headers.entries()).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n';
      const mime = (r.headers.get('content-type') || '').split(';')[0].trim();
      const res = { status: r.status, statusText: r.statusText, responseHeaders, finalUrl: r.url || req.url, mime };
      if (req.responseType === 'arraybuffer' || req.responseType === 'blob') {
        res.b64 = bytesToBase64(await r.arrayBuffer());
      } else {
        res.text = await r.text();
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

  /** Handle one message from a user script. Returns the response object. */
  async function handleGmMessage(msg, sender) {
    if (!msg || msg.__cu !== 1 || typeof msg.id !== 'string' || !msg.id.startsWith(REG_PREFIX)) {
      return { ok: false, error: 'bad-message' };
    }
    const id = msg.id;
    const data = msg.data || {};

    switch (msg.op) {
      case 'vals:get':
        return { ok: true, values: await readVals(id) };

      case 'vals:set':
        return withValsLock(id, async () => {
          const vals = await readVals(id);
          vals[String(data.k)] = data.v;
          await chrome.storage.local.set({ [VALS_PREFIX + id]: vals });
          return { ok: true };
        });

      case 'vals:del':
        return withValsLock(id, async () => {
          const vals = await readVals(id);
          delete vals[String(data.k)];
          await chrome.storage.local.set({ [VALS_PREFIX + id]: vals });
          return { ok: true };
        });

      case 'xhr':
        return gmXhr(data);

      case 'xhr-abort': {
        const c = _xhrControllers.get(data.reqId);
        if (c) { c.__userAbort = true; c.abort(); }
        return { ok: true };
      }

      case 'notify': {
        const nid = 'gm-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        await chrome.notifications.create(nid, {
          type: 'basic',
          iconUrl: data.image || chrome.runtime.getURL('icons/icon128.png'),
          title: data.title || 'Userscript',
          message: data.text || ' '
        });
        if (data.timeout > 0) setTimeout(() => { try { chrome.notifications.clear(nid); } catch {} }, data.timeout);
        return { ok: true };
      }

      case 'open-tab': {
        const opts = { url: String(data.url || ''), active: data.active !== false };
        if (sender && sender.tab && sender.tab.id != null) opts.openerTabId = sender.tab.id;
        const tab = await chrome.tabs.create(opts);
        if (tab && tab.id != null) _openedTabs.add(tab.id);
        return { ok: true, tabId: tab && tab.id };
      }

      case 'tab-close': {
        if (_openedTabs.has(data.tabId)) {
          _openedTabs.delete(data.tabId);
          try { await chrome.tabs.remove(data.tabId); } catch {}
        }
        return { ok: true };
      }

      case 'download': {
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

  async function migrateLegacy() {
    const flag = await chrome.storage.local.get(MIGRATED_KEY);
    if (flag[MIGRATED_KEY]) return { ok: true, migrated: 0, skipped: true };

    let legacy = {};
    try {
      if (typeof CorsairStorage !== 'undefined') legacy = await CorsairStorage.get('customDomainScripts', {});
      else legacy = (await chrome.storage.local.get('customDomainScripts')).customDomainScripts || {};
    } catch { legacy = {}; }

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
        sourceUrl: '', migratedFrom: host, regSig: '', lastError: '',
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

    await chrome.storage.local.set({ [MIGRATED_KEY]: true });
    return { ok: true, migrated };
  }

  let _initPromise = null;
  function init() {
    if (!_initPromise) {
      _initPromise = (async () => {
        try { await migrateLegacy(); } catch (e) { console.warn('[Corsair Userscripts] migration failed:', e && e.message); }
        try { await sync(); } catch (e) { console.warn('[Corsair Userscripts] sync failed:', e && e.message); }
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
    chooseWorld,
    needsBridge,
    needsGM: needsBridge,
    handleGmMessage,
    gmRuntime,
    legacyToUserscript,
    checkAvailability,
    syncRegistrations,
    sync,
    list,
    get,
    save,
    remove,
    setEnabled,
    importFromUrl,
    migrateLegacy,
    init
  };
})();

globalThis.CorsairUserScripts = CorsairUserScripts;
