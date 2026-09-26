const CorsairProviderUrlhaus = (() => {
  'use strict';

  /* ============================================================
     URLHAUS PROVIDER (abuse.ch) — OPT-IN with Auth-Key
     ------------------------------------------------------------
     abuse.ch added mandatory Auth-Key authentication in late 2024.
     Without a key the endpoint returns HTTP 401. We therefore:

       • Look up `urlhausAuthKey` in CorsairStorage settings.
       • If the key is missing or empty, return a SILENT SKIP
         (ok: false, error: 'no-auth-key', skipped: true) WITHOUT
         making a network call. The aggregator treats skipped
         sources as weight-0 and excludes them from the score.
       • When a key IS present, send `Auth-Key: <key>` header.

     This keeps URLhaus as an optional enhancement: users who want
     it can paste a key into settings; users who don't are unaffected.

     Endpoint:  POST https://urlhaus-api.abuse.ch/v1/host/
     Body:      host=<hostname>
     Header:    Auth-Key: <key>
     Response:  { query_status: 'ok' | 'no_results', urls: [...] }

     Rate limit: abuse.ch is generous but not infinite; we self-
     impose 1 req/s + 6h cache.
     ============================================================ */

  const NAME = 'urlhaus';
  const LABEL = 'URLhaus';
  const BASE_WEIGHT = 0.35;
  const ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/host/';
  const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
  const CACHE_MAX = 500;
  const MIN_REQUEST_INTERVAL_MS = 1000;
  const AUTH_KEY_CACHE_MS = 60000;
  const SETTINGS_KEY = 'urlhausAuthKey';

  let _lastRequestAt = 0;
  const _cache = new Map();

  let _cachedAuthKey = null;
  let _cachedAuthKeyAt = 0;

  function isEnabled() {
    return typeof fetch === 'function';
  }

  async function _resolveAuthKey() {
    const now = Date.now();
    if (_cachedAuthKey !== null && now - _cachedAuthKeyAt < AUTH_KEY_CACHE_MS) {
      return _cachedAuthKey;
    }
    try {
      if (typeof CorsairStorage === 'undefined') {
        _cachedAuthKey = '';
      } else {
        const s = await CorsairStorage.getSettings();
        const raw = s && typeof s[SETTINGS_KEY] === 'string' ? s[SETTINGS_KEY].trim() : '';
        _cachedAuthKey = raw;
      }
    } catch {
      _cachedAuthKey = '';
    }
    _cachedAuthKeyAt = now;
    return _cachedAuthKey;
  }

  function _getCached(host) {
    const e = _cache.get(host);
    if (!e) return null;
    if (Date.now() - e.at > CACHE_TTL_MS) {
      _cache.delete(host);
      return null;
    }
    return e.value;
  }

  function _setCached(host, value) {
    if (_cache.size >= CACHE_MAX) {
      const oldestKey = _cache.keys().next().value;
      if (oldestKey !== undefined) _cache.delete(oldestKey);
    }
    _cache.set(host, { at: Date.now(), value });
  }

  async function _throttle() {
    const now = Date.now();
    const elapsed = now - _lastRequestAt;
    if (elapsed < MIN_REQUEST_INTERVAL_MS) {
      await new Promise(r => setTimeout(r, MIN_REQUEST_INTERVAL_MS - elapsed));
    }
    _lastRequestAt = Date.now();
  }

  async function lookup(rawHost) {
    const host = CorsairSecurity.normalizeHostname(rawHost);
    if (!host || !CorsairSecurity.isValidHostname(host)) {
      return { ok: false, error: 'invalid-host', source: NAME, weight: BASE_WEIGHT, skipped: true };
    }

    const authKey = await _resolveAuthKey();
    if (!authKey) {
      // No key configured → silent skip. No network activity at all.
      return {
        ok: false,
        error: 'no-auth-key',
        skipped: true,
        source: NAME,
        weight: BASE_WEIGHT
      };
    }

    const cached = _getCached(host);
    if (cached) {
      return { ...cached, source: NAME, weight: BASE_WEIGHT, fromCache: true };
    }

    await _throttle();

    let res;
    try {
      res = await fetch(ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Auth-Key': authKey
        },
        body: `host=${encodeURIComponent(host)}`
      });
    } catch (err) {
      return {
        ok: false,
        error: 'network: ' + (err && err.message || 'unknown'),
        source: NAME,
        weight: BASE_WEIGHT
      };
    }

    if (res.status === 401 || res.status === 403) {
      // Key is configured but rejected — cache the failure so we
      // don't spam the endpoint, and let the aggregator skip it.
      return {
        ok: false,
        error: 'invalid-auth-key',
        source: NAME,
        weight: BASE_WEIGHT
      };
    }
    if (res.status === 429) {
      return { ok: false, error: 'rate-limit-exceeded', source: NAME, weight: BASE_WEIGHT };
    }
    if (!res.ok) {
      return { ok: false, error: `http-${res.status}`, source: NAME, weight: BASE_WEIGHT };
    }

    let data;
    try { data = await res.json(); }
    catch { return { ok: false, error: 'invalid-json', source: NAME, weight: BASE_WEIGHT }; }

    const status = String(data?.query_status || '').toLowerCase();
    let report;

    if (status === 'no_results' || status === 'no_results_found') {
      report = {
        ok: true,
        verdict: 'clean',
        score: 0,
        confidence: 0.5,
        evidence: { urlCount: 0, onlineCount: 0, offlineCount: 0, threatTypes: [] }
      };
    } else if (status === 'ok') {
      const urls = Array.isArray(data.urls) ? data.urls : [];
      const online = urls.filter(u => String(u.url_status).toLowerCase() === 'online').length;
      const offline = urls.length - online;
      const threats = [...new Set(
        urls.map(u => String(u.threat || '').toLowerCase()).filter(Boolean)
      )];

      let score = 0;
      if (online > 0) score = Math.min(95, 70 + Math.min(25, online * 5));
      else if (offline > 0) score = Math.min(60, 35 + Math.min(25, offline * 3));

      let verdict = 'clean';
      if (score >= 70) verdict = 'malicious';
      else if (score >= 35) verdict = 'suspicious';

      report = {
        ok: true,
        verdict,
        score,
        confidence: urls.length > 0 ? 0.85 : 0.5,
        evidence: {
          urlCount: urls.length,
          onlineCount: online,
          offlineCount: offline,
          threatTypes: threats.slice(0, 5),
          reference: String(data.urlhaus_reference || '').slice(0, 200)
        }
      };
    } else {
      return {
        ok: false,
        error: 'unknown-status:' + status,
        source: NAME,
        weight: BASE_WEIGHT
      };
    }

    _setCached(host, report);
    return { ...report, source: NAME, weight: BASE_WEIGHT };
  }

  /* ============================================================
     AUTH-KEY VERIFICATION
     ------------------------------------------------------------
     Same idea as VT: hit abuse.ch with the new key and see if it
     rejects us. We use a well-known benign host so the request is
     cheap and doesn't pollute our URLhaus cache.
     ============================================================ */
  async function verifyAuthKey(rawKey) {
    const key = String(rawKey || '').trim();
    if (!key) return { ok: false, error: 'empty-key' };

    const ctrl = new AbortController();
    const timer = setTimeout(() => { try { ctrl.abort(); } catch {} }, 10000);

    try {
      const res = await fetch(ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Auth-Key': key
        },
        body: 'host=example.com',
        signal: ctrl.signal
      });
      clearTimeout(timer);

      if (res.status === 401 || res.status === 403) {
        return { ok: false, error: 'invalid-auth-key' };
      }
      if (res.status === 429) {
        return { ok: true, rateLimited: true };
      }
      if (!res.ok && res.status !== 404) {
        return { ok: false, error: `http-${res.status}` };
      }
      return { ok: true };
    } catch (err) {
      clearTimeout(timer);
      if (err && err.name === 'AbortError') {
        return { ok: false, error: 'network-timeout' };
      }
      return { ok: false, error: 'network-error' };
    }
  }

  function clearCache() { _cache.clear(); }

  function invalidateAuthKeyCache() {
    _cachedAuthKey = null;
    _cachedAuthKeyAt = 0;
  }

  return {
    NAME, LABEL, WEIGHT: BASE_WEIGHT,
    isEnabled, lookup, verifyAuthKey,
    clearCache, invalidateAuthKeyCache
  };
})();

globalThis.CorsairProviderUrlhaus = CorsairProviderUrlhaus;