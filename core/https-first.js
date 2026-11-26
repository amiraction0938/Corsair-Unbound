/* ============================================================
   CORSAIR UNBOUND — HTTPS-FIRST PROTECTION (DNR)
   ------------------------------------------------------------
   Upgrades eligible http:// main-frame GET navigations to
   https:// using Chrome Manifest V3 declarativeNetRequest
   `upgradeScheme`.

   Rule ID Range: 950000 - 959999 (zero collision with
   BLOCK_BASE 100k, FORTRESS 800k, ALLOW 850k, USER_BLOCK 900k).
   Priority: 10 (strictly lower than Fortress 50 / Block 100).
   ============================================================ */
const CorsairHttpsFirst = (() => {
  'use strict';

  const RULE_ID = 950001;
  const RULE_MIN = 950000;
  const RULE_MAX = 959999;
  const PRIORITY = 10;

  const DEFAULT_EXCLUDED_DOMAINS = [
    'localhost',
    '127.0.0.1',
    'local',
    'lan',
    'internal',
    'home.arpa'
  ];

  function normalizeHost(raw) {
    return String(raw || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  }

  function isLocalOrPrivateHost(host) {
    const h = normalizeHost(host);
    if (!h) return true;
    if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.lan') || h.endsWith('.internal') || h.endsWith('.home.arpa')) return true;
    if (h === '::1' || h === '::' || /^fe[89ab][0-9a-f]:/.test(h) || /^f[cd][0-9a-f]{2}:/.test(h)) return true;
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
    if (v4) {
      const [a, b] = [Number(v4[1]), Number(v4[2])];
      return a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31);
    }
    return false;
  }

  function buildRule(exceptions = []) {
    const excluded = Array.from(new Set([
      ...DEFAULT_EXCLUDED_DOMAINS,
      ...(Array.isArray(exceptions) ? exceptions.map(normalizeHost).filter(Boolean) : [])
    ]));
    return {
      id: RULE_ID,
      priority: PRIORITY,
      action: { type: 'upgradeScheme' },
      condition: {
        urlFilter: 'http://',
        resourceTypes: ['main_frame'],
        requestMethods: ['get'],
        excludedRequestDomains: excluded
      }
    };
  }

  /**
   * Pure preview helper for deterministic verification of upgrade behavior.
   * Preserves hostname, path, query, and fragment; skips explicit non-80 ports,
   * loopback/private hosts, non-GET methods, and excluded domains.
   */
  function previewUpgrade(rawUrl, { enabled = true, method = 'GET', exceptions = [] } = {}) {
    if (!enabled) return { upgraded: false, url: rawUrl, reason: 'disabled' };
    if (String(method || 'GET').toUpperCase() !== 'GET') return { upgraded: false, url: rawUrl, reason: 'non-get-method' };

    let u;
    try { u = new URL(String(rawUrl || '')); } catch { return { upgraded: false, url: rawUrl, reason: 'invalid-url' }; }
    if (u.protocol !== 'http:') return { upgraded: false, url: u.href, reason: 'already-secure-or-non-http' };

    const host = normalizeHost(u.hostname);
    if (isLocalOrPrivateHost(host)) return { upgraded: false, url: u.href, reason: 'local-or-private-excluded' };
    if (u.port && u.port !== '80') return { upgraded: false, url: u.href, reason: 'custom-http-port' };

    const excList = Array.isArray(exceptions) ? exceptions.map(normalizeHost).filter(Boolean) : [];
    if (excList.some((d) => host === d || host.endsWith('.' + d))) {
      return { upgraded: false, url: u.href, reason: 'user-exception' };
    }

    u.protocol = 'https:';
    return { upgraded: true, url: u.href, reason: 'upgraded' };
  }

  /**
   * Synchronize ONLY the HTTPS-First DNR rule range [950000, 959999].
   * Never touches Fortress, Global Block, or User Block rules.
   */
  async function sync({ enabled = false, exceptions = [] } = {}) {
    if (typeof chrome === 'undefined' || !chrome.declarativeNetRequest) {
      return { ok: false, error: 'dnr-unavailable' };
    }
    try {
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      const ownIds = (Array.isArray(existing) ? existing : [])
        .filter((r) => r.id >= RULE_MIN && r.id <= RULE_MAX)
        .map((r) => r.id);

      const addRules = enabled ? [buildRule(exceptions)] : [];
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: ownIds,
        addRules
      });
      return { ok: true, enabled: Boolean(enabled), ruleCount: addRules.length };
    } catch (e) {
      return { ok: false, error: (e && e.message) || 'https-first-sync-failed' };
    }
  }

  return {
    RULE_ID,
    RULE_MIN,
    RULE_MAX,
    PRIORITY,
    DEFAULT_EXCLUDED_DOMAINS,
    isLocalOrPrivateHost,
    buildRule,
    previewUpgrade,
    sync
  };
})();

globalThis.CorsairHttpsFirst = CorsairHttpsFirst;
