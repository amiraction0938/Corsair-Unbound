const CorsairSecurity = (() => {
  'use strict';

  function normalizeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const u = new URL(rawUrl.trim());
      u.username = '';
      u.password = '';
      return u.href;
    } catch {
      return '';
    }
  }

  function extractHostname(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const u = new URL(rawUrl.trim());
      return normalizeHostname(u.hostname);
    } catch {
      return '';
    }
  }

  function normalizeHostname(rawHost) {
    if (!rawHost || typeof rawHost !== 'string') return '';
    let host = rawHost.trim().toLowerCase();
    while (host.endsWith('.')) {
      host = host.slice(0, -1);
    }
    if (!host) return '';
    try {
      const dummy = new URL('http://' + host);
      return dummy.hostname.toLowerCase();
    } catch {
      return host.replace(/[\x00-\x1f\x7f\s]/g, '');
    }
  }

  function isValidHostname(host) {
    if (!host || typeof host !== 'string') return false;
    if (host.length === 0 || host.length > 253) return false;
    if (/[\x00-\x1f\x7f\s]/.test(host)) return false;
    if (host.includes('..')) return false;

    const parts = host.split('.');
    if (parts.length < 1) return false;

    for (const p of parts) {
      if (!p || p.length > 63) return false;
      if (p.startsWith('-') || p.endsWith('-')) return false;
      if (!/^[a-z0-9-]+$/i.test(p)) return false;
    }
    return true;
  }

  function sameOrSubdomain(candidate, base) {
    const c = normalizeHostname(candidate);
    const b = normalizeHostname(base);
    if (!c || !b) return false;
    if (c === b) return true;
    return c.endsWith('.' + b);
  }

  function fortressProfile(overrides = {}) {
    return {
      mode: 'fortress',
      protected: true,
      autoContainRedirects: true,
      clickbaitGuard: true,
      blockedDestinationDomains: [],
      notes: '',
      createdAt: Date.now(),
      updatedAt: Date.now(),
      ...overrides
    };
  }

  /**
   * Normalize a profile to a canonical shape.
   *
   * IMPORTANT: this function must preserve ANY field the caller put on
   * the profile that isn't explicitly cleaned — otherwise custom flags
   * like `autoArmed` / `autoArmedAt` / `autoArmReason` (written by the
   * auto-arm path in background.js) would get silently stripped on the
   * very next save, and `patchProfileAtomic` would appear to succeed
   * while losing the data.
   *
   * The explicit fields below are the ones we always normalize.
   * Everything else on the incoming object is spread through unchanged,
   * except sanitized to a safe string/number form.
   */
  function normalizeProfile(prof) {
    if (!prof || typeof prof !== 'object' || Array.isArray(prof)) {
      return fortressProfile();
    }

    const cleanDests = [];
    if (Array.isArray(prof.blockedDestinationDomains)) {
      for (const d of prof.blockedDestinationDomains) {
        const norm = normalizeHostname(d);
        if (norm && isValidHostname(norm) && !cleanDests.includes(norm)) {
          cleanDests.push(norm);
        }
      }
    }

    const out = {
      mode: prof.mode === 'fortress' ? 'fortress' : 'standard',
      protected: Boolean(prof.protected),
      autoContainRedirects: prof.autoContainRedirects !== false,
      clickbaitGuard: prof.clickbaitGuard !== false,
      blockedDestinationDomains: cleanDests.slice(0, 1000),
      notes: typeof prof.notes === 'string' ? sanitizeString(prof.notes, 500) : '',
      createdAt: Number(prof.createdAt) || Date.now(),
      updatedAt: Date.now()
    };

    // ---- Preserve custom / metadata fields ----
    // Any extra key on the incoming object is copied through, sanitized
    // to a primitive so it stays JSON-serializable and cannot smuggle
    // nested structures past the sanitization step.
    for (const [k, v] of Object.entries(prof)) {
      if (k in out) continue; // already handled above
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      if (typeof v === 'string') {
        out[k] = sanitizeString(v, 500);
      } else if (typeof v === 'number' && Number.isFinite(v)) {
        out[k] = v;
      } else if (typeof v === 'boolean') {
        out[k] = v;
      }
      // Objects / arrays / null are intentionally dropped — profiles
      // are meant to be flat. If a future field needs to be structured,
      // whitelist it explicitly above.
    }

    return out;
  }

  function sanitizeString(str, maxLen = 500) {
    if (typeof str !== 'string') return '';
    return str.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim().slice(0, maxLen);
  }

  function sanitizeObject(obj, depth = 0) {
    if (!obj || typeof obj !== 'object' || depth > 8) return null;
    if (Array.isArray(obj)) {
      return obj
        .slice(0, 100)
        .map(x => (typeof x === 'object' ? sanitizeObject(x, depth + 1) : sanitizeString(x)))
        .filter(x => x !== null);
    }
    const clean = {};
    for (const [k, v] of Object.entries(obj)) {
      if (typeof k !== 'string' || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      if (typeof v === 'string') {
        if (k.toLowerCase().includes('url') && (v.startsWith('http://') || v.startsWith('https://'))) {
          const norm = normalizeUrl(v);
          clean[k] = norm || sanitizeString(v);
        } else {
          clean[k] = sanitizeString(v);
        }
      } else if (typeof v === 'object' && v !== null) {
        const sub = sanitizeObject(v, depth + 1);
        if (sub !== null) clean[k] = sub;
      } else if (typeof v === 'number' || typeof v === 'boolean') {
        clean[k] = v;
      }
    }
    return clean;
  }

  const CUSTOM_SCRIPT_MAX_LEN = 5000;

  const CUSTOM_SCRIPT_BLOCKLIST = [
    { re: /document\s*\.\s*cookie/i, label: 'document.cookie access' },
    { re: /\blocalStorage\b/i, label: 'localStorage access' },
    { re: /\bsessionStorage\b/i, label: 'sessionStorage access' },
    { re: /\bindexedDB\b/i, label: 'indexedDB access' },
    { re: /\bfetch\s*\(/i, label: 'fetch() network call' },
    { re: /\bXMLHttpRequest\b/i, label: 'XMLHttpRequest' },
    { re: /\bnavigator\s*\.\s*sendBeacon\b/i, label: 'navigator.sendBeacon' },
    { re: /\bWebSocket\b/i, label: 'WebSocket' },
    { re: /\bchrome\s*\.\s*\w+/i, label: 'chrome.* extension API access' },
    { re: /\bimport\s*\(/i, label: 'dynamic import()' },
    { re: /\beval\s*\(/i, label: 'eval()' },
    { re: /\bnew\s+Function\s*\(/i, label: 'new Function()' },
    { re: /\bsetTimeout\s*\(\s*['"`]/i, label: "setTimeout('string', ...) — string form re-enters eval" },
    { re: /\bsetInterval\s*\(\s*['"`]/i, label: "setInterval('string', ...) — string form re-enters eval" },
    { re: /window\s*\.\s*top\b/i, label: 'window.top cross-frame access' },
    { re: /window\s*\.\s*parent\b/i, label: 'window.parent cross-frame access' },
    { re: /\bdocument\s*\.\s*domain\s*=/i, label: 'document.domain assignment' }
  ];

  function lintCustomScript(code) {
    if (typeof code !== 'string') return { ok: false, error: 'Script must be a string' };
    if (code.length > CUSTOM_SCRIPT_MAX_LEN) {
      return { ok: false, error: `Script too long (${code.length}/${CUSTOM_SCRIPT_MAX_LEN} chars)` };
    }
    const lines = code.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { re, label } of CUSTOM_SCRIPT_BLOCKLIST) {
        if (re.test(line)) {
          return { ok: false, error: `Blocked: ${label}`, line: i + 1 };
        }
      }
    }
    return { ok: true };
  }

  return {
    normalizeUrl,
    extractHostname,
    normalizeHostname,
    isValidHostname,
    sameOrSubdomain,
    fortressProfile,
    normalizeProfile,
    sanitizeString,
    sanitizeObject,
    lintCustomScript,
    CUSTOM_SCRIPT_MAX_LEN
  };
})();

globalThis.CorsairSecurity = CorsairSecurity;