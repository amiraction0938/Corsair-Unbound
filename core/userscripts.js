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

  /** True when the script wants the GM_* API (needs the isolated USER_SCRIPT world). */
  function needsGM(meta) {
    return (meta.grant || []).some(g => /^GM[._]/i.test(g));
  }

  function chooseWorld(meta) {
    if (meta.injectInto === 'page') return 'MAIN';
    if (meta.injectInto === 'content') return 'USER_SCRIPT';
    return needsGM(meta) ? 'USER_SCRIPT' : 'MAIN';
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

    parts.push(
      'const GM_info=' + JSON.stringify(info) + ';' +
      'const unsafeWindow=window;' +
      'const GM_log=function(){console.log.apply(console,arguments)};' +
      'const GM_addStyle=function(css){var s=document.createElement("style");s.textContent=String(css);(document.head||document.documentElement).appendChild(s);return s};' +
      'const GM={info:GM_info,log:GM_log,addStyle:function(c){return Promise.resolve(GM_addStyle(c))}};'
    );

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
      await chrome.storage.local.remove(REC_PREFIX + id);
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
    needsGM,
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
