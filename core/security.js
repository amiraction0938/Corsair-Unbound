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
    return {
      mode: prof.mode === 'fortress' ? 'fortress' : 'standard',
      protected: Boolean(prof.protected),
      autoContainRedirects: prof.autoContainRedirects !== false,
      clickbaitGuard: prof.clickbaitGuard !== false,
      blockedDestinationDomains: cleanDests.slice(0, 1000),
      notes: typeof prof.notes === 'string' ? sanitizeString(prof.notes, 500) : '',
      createdAt: Number(prof.createdAt) || Date.now(),
      updatedAt: Date.now()
    };
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

  return {
    normalizeUrl,
    extractHostname,
    normalizeHostname,
    isValidHostname,
    sameOrSubdomain,
    fortressProfile,
    normalizeProfile,
    sanitizeString,
    sanitizeObject
  };
})();

globalThis.CorsairSecurity = CorsairSecurity;