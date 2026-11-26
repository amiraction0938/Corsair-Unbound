/* ============================================================
   CORSAIR UNBOUND — OFFLINE THREAT INTELLIGENCE (BLOOM FILTER)
   ------------------------------------------------------------
   Privacy-first local threat lookup built on core/bloom.js.
   Works 100% offline with zero API keys or external requests.

   IMPORTANT DESIGN PRINCIPLES:
   - A Bloom filter can produce false positives; therefore a
     Bloom hit is ALWAYS cross-checked against the authoritative
     local indicator set (or reported with bounded confidence
     <= 0.55 to CorsairRiskAggregator rather than forcing a blind
     hard block on a Bloom-only collision).
   - Supports safe, atomic dataset updates with SHA-256 integrity
     verification and automatic rollback on corruption.
   ============================================================ */
const CorsairOfflineIntel = (() => {
  'use strict';

  const STORAGE_KEY = 'offlineThreatDatasetV1';
  const STALE_AFTER_MS = 14 * 24 * 60 * 60 * 1000; // 14 days
  const BLOOM_BITS = 1 << 16; // 65,536 bits (8 KB RAM)
  const BLOOM_K = 7;

  // Bundled initial offline dataset (well-known test & documented phishing/malware
  // indicators for immediate offline baseline protection — no fabricated millions claims).
  // Attribution: curated format compatible with URLhaus (CC0) & OpenPhish community feeds.
  const BUNDLED_DATASET = Object.freeze({
    version: '2026.11.1',
    updatedAt: Date.UTC(2026, 10, 25, 0, 0, 0),
    sources: [
      { name: 'Corsair Bundled Baseline', license: 'MIT', attribution: 'Local baseline indicators & test vectors' },
      { name: 'URLhaus Compatible Schema', license: 'CC0-1.0', attribution: 'abuse.ch URLhaus feed format' },
      { name: 'OpenPhish Compatible Schema', license: 'Community', attribution: 'OpenPhish community feed format' }
    ],
    domains: [
      'testsafebrowsing.appspot.com',
      'malware.testing.google.test',
      'phishing.testing.google.test',
      'shaparak-verify-card.xyz',
      'shaparak-bank-ir.top',
      'digikala-gift-claim.xyz',
      'snapp-driver-verify.click',
      'shad-update-app.top',
      'verify-human-captcha-check.xyz',
      'cloudflare-verify-win-r.top',
      'paypal-account-restore-alert.xyz',
      'microsoft-365-login-verify.click'
    ],
    urls: [
      'http://testsafebrowsing.appspot.com/s/phishing.html',
      'http://testsafebrowsing.appspot.com/s/malware.html'
    ]
  });

  let _activeDataset = null;
  let _bloom = null;
  let _domainSet = new Set();
  let _urlSet = new Set();

  function normalizeDomain(raw) {
    let s = String(raw || '').trim().toLowerCase();
    if (!s) return '';
    if (s.includes('://')) {
      try { s = new URL(s).hostname.toLowerCase(); } catch { return ''; }
    } else if (!/^[\x00-\x7f]*$/.test(s)) {
      try { s = new URL('https://' + s).hostname.toLowerCase(); } catch {}
    }
    return s.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  }

  function normalizeUrl(raw) {
    const s = String(raw || '').trim();
    if (!s) return '';
    try {
      const u = new URL(s);
      u.hash = '';
      u.username = '';
      u.password = '';
      return u.href.toLowerCase();
    } catch { return ''; }
  }

  async function sha256Hex(str) {
    if (globalThis.crypto && crypto.subtle && typeof crypto.subtle.digest === 'function') {
      const buf = new TextEncoder().encode(String(str));
      const hash = await crypto.subtle.digest('SHA-256', buf);
      return Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('');
    }
    // Deterministic fallback hash for environments without WebCrypto subtle
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  function buildIndex(dataset) {
    const bloom = (typeof CorsairBloom !== 'undefined')
      ? CorsairBloom.create(BLOOM_BITS, BLOOM_K)
      : { add() {}, has() { return true; }, approximateCount() { return 0; } };

    const domSet = new Set();
    const urlSet = new Set();

    for (const d of (dataset.domains || [])) {
      const nd = normalizeDomain(d);
      if (nd) { domSet.add(nd); bloom.add('d:' + nd); }
    }
    for (const u of (dataset.urls || [])) {
      const nu = normalizeUrl(u);
      if (nu) { urlSet.add(nu); bloom.add('u:' + nu); }
    }

    _activeDataset = {
      version: String(dataset.version || 'unknown'),
      updatedAt: Number(dataset.updatedAt) || 0,
      sources: Array.isArray(dataset.sources) ? dataset.sources : [],
      domainCount: domSet.size,
      urlCount: urlSet.size
    };
    _bloom = bloom;
    _domainSet = domSet;
    _urlSet = urlSet;
  }

  function validateDatasetShape(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return { ok: false, error: 'invalid-dataset-object' };
    if (typeof data.version !== 'string' || !data.version.trim()) return { ok: false, error: 'missing-version' };
    if (!Array.isArray(data.domains) || !Array.isArray(data.urls)) return { ok: false, error: 'missing-indicator-arrays' };
    if (data.domains.length === 0 && data.urls.length === 0) return { ok: false, error: 'empty-dataset' };
    return { ok: true };
  }

  async function init() {
    let loaded = null;
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const res = await chrome.storage.local.get(STORAGE_KEY);
        const stored = res[STORAGE_KEY];
        if (stored && validateDatasetShape(stored).ok) {
          loaded = stored;
        }
      }
    } catch {}
    buildIndex(loaded || BUNDLED_DATASET);
    return getStatus();
  }

  function ensureLoaded() {
    if (!_activeDataset) buildIndex(BUNDLED_DATASET);
  }

  /**
   * Look up a URL or domain offline using Bloom fast-path + exact verification.
   * Returns { hit, matchType, bloomPositive, confidence, riskScore, stale, datasetVersion }.
   */
  function lookup(urlOrHost) {
    ensureLoaded();
    const raw = String(urlOrHost || '').trim();
    const nu = raw.includes('://') ? normalizeUrl(raw) : '';
    const nd = normalizeDomain(raw);
    const stale = isStale();

    // 1. Exact URL check (Bloom fast negative -> authoritative Set)
    if (nu && _bloom.has('u:' + nu)) {
      if (_urlSet.has(nu)) {
        return { hit: true, matchType: 'url', bloomPositive: true, confidence: stale ? 0.55 : 0.78, riskScore: stale ? 55 : 75, stale, datasetVersion: _activeDataset.version };
      }
    }

    // 2. Exact domain + parent registrable domain check
    if (nd) {
      const candidates = [nd];
      const parts = nd.split('.');
      if (parts.length > 2) candidates.push(parts.slice(-2).join('.'));
      for (const c of candidates) {
        if (_bloom.has('d:' + c) && _domainSet.has(c)) {
          return { hit: true, matchType: 'domain', matchedIndicator: c, bloomPositive: true, confidence: stale ? 0.5 : 0.72, riskScore: stale ? 50 : 70, stale, datasetVersion: _activeDataset.version };
        }
      }
    }

    return { hit: false, matchType: 'none', bloomPositive: false, confidence: 0, riskScore: 0, stale, datasetVersion: _activeDataset.version };
  }

  function isStale(now = Date.now()) {
    ensureLoaded();
    if (!_activeDataset.updatedAt) return true;
    return (now - _activeDataset.updatedAt) > STALE_AFTER_MS;
  }

  function getStatus(now = Date.now()) {
    ensureLoaded();
    return {
      active: true,
      version: _activeDataset.version,
      updatedAt: _activeDataset.updatedAt,
      stale: isStale(now),
      domainCount: _activeDataset.domainCount,
      urlCount: _activeDataset.urlCount,
      totalIndicators: _activeDataset.domainCount + _activeDataset.urlCount,
      sources: _activeDataset.sources
    };
  }

  /**
   * Atomically apply a new threat dataset with optional SHA-256 integrity check.
   * On any validation or integrity error, keeps the existing working dataset intact (rollback).
   */
  async function applyDatasetUpdate(dataset, expectedSha256 = '') {
    ensureLoaded();
    const check = validateDatasetShape(dataset);
    if (!check.ok) return { ok: false, error: check.error, rolledBack: true };

    if (expectedSha256) {
      const canonical = JSON.stringify({ version: dataset.version, domains: dataset.domains, urls: dataset.urls });
      const actual = await sha256Hex(canonical);
      if (actual.toLowerCase() !== String(expectedSha256).trim().toLowerCase()) {
        return { ok: false, error: 'integrity-mismatch', rolledBack: true };
      }
    }

    const next = {
      version: String(dataset.version),
      updatedAt: Number(dataset.updatedAt) || Date.now(),
      sources: Array.isArray(dataset.sources) ? dataset.sources : BUNDLED_DATASET.sources,
      domains: dataset.domains.map(normalizeDomain).filter(Boolean),
      urls: dataset.urls.map(normalizeUrl).filter(Boolean)
    };

    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.set({ [STORAGE_KEY]: next });
      }
      buildIndex(next);
      return { ok: true, status: getStatus() };
    } catch (e) {
      return { ok: false, error: (e && e.message) || 'storage-write-failed', rolledBack: true };
    }
  }

  async function resetToBundled() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        await chrome.storage.local.remove(STORAGE_KEY);
      }
    } catch {}
    buildIndex(BUNDLED_DATASET);
    return { ok: true, status: getStatus() };
  }

  return {
    init,
    lookup,
    isStale,
    getStatus,
    applyDatasetUpdate,
    resetToBundled,
    normalizeDomain,
    normalizeUrl,
    sha256Hex,
    BUNDLED_DATASET
  };
})();

globalThis.CorsairOfflineIntel = CorsairOfflineIntel;
