/* ============================================================
   CORSAIR UNBOUND — TRACKING PARAMETER STRIPPING (DNR)
   ------------------------------------------------------------
   Removes verified advertising & referral tracking query
   parameters before eligible main-frame navigations leave the
   browser, using Chrome MV3 DNR `removeParams`.

   Platform note: Chrome DNR `removeParams` requires exact
   parameter names (wildcards such as `utm_*` are not supported).
   All supported parameters are explicitly enumerated below.

   Rule ID Range: 960000 - 969999 (zero collision with security
   rules). Priority: 15 (strictly below Fortress & Block rules).
   ============================================================ */
const CorsairTrackingStrip = (() => {
  'use strict';

  const RULE_ID = 960001;
  const RULE_MIN = 960000;
  const RULE_MAX = 969999;
  const PRIORITY = 15;

  const TRACKING_PARAMS = Object.freeze([
    // Standard UTM campaign parameters (explicitly enumerated for Chrome DNR)
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_name', 'utm_cid', 'utm_reader', 'utm_viz_id', 'utm_pubreferrer', 'utm_swu',
    // Ad click IDs & social referral trackers
    'fbclid', 'gclid', 'dclid', 'gbraid', 'wbraid', 'msclkid',
    'ttclid', 'twclid', 'igshid', 'yclid', 'rb_clickid', 's_cid',
    // Email marketing & CRM trackers
    'mc_cid', 'mc_eid', '_hsenc', '_hsmi', 'mkt_tok', 'vero_id', 'oly_enc_id', 'oly_anon_id'
  ]);

  const TRACKING_PARAM_SET = new Set(TRACKING_PARAMS);

  // Critical auth, OAuth, and payment domains excluded by default so checkout/login never breaks
  const DEFAULT_EXCLUDED_DOMAINS = Object.freeze([
    'accounts.google.com',
    'login.microsoftonline.com',
    'login.live.com',
    'appleid.apple.com',
    'checkout.stripe.com',
    'www.paypal.com',
    'shaparak.ir'
  ]);

  // Query parameter names indicating signed URLs or OAuth flows (preserved untouched in preview helper)
  const PROTECTED_SIGNATURE_PARAMS = new Set([
    'signature', 'sig', 'x-amz-signature', 'x-goog-signature', 'code', 'state', 'token', 'access_token', 'id_token', 'session', 'auth'
  ]);

  function normalizeHost(raw) {
    return String(raw || '').trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  }

  function buildRule(exceptions = []) {
    const excluded = Array.from(new Set([
      ...DEFAULT_EXCLUDED_DOMAINS,
      ...(Array.isArray(exceptions) ? exceptions.map(normalizeHost).filter(Boolean) : [])
    ]));
    return {
      id: RULE_ID,
      priority: PRIORITY,
      action: {
        type: 'redirect',
        redirect: {
          transform: {
            queryTransform: {
              removeParams: [...TRACKING_PARAMS]
            }
          }
        }
      },
      condition: {
        urlFilter: '|http',
        resourceTypes: ['main_frame'],
        excludedRequestDomains: excluded
      }
    };
  }

  /**
   * Pure URL cleanup helper for testing and local verification.
   * Preserves all non-tracking parameters, OAuth/payment domains, and signed URLs.
   */
  function stripUrl(rawUrl, { enabled = true, exceptions = [] } = {}) {
    if (!enabled) return { changed: false, url: rawUrl, removed: [] };
    let u;
    try { u = new URL(String(rawUrl || '')); } catch { return { changed: false, url: rawUrl, removed: [] }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { changed: false, url: u.href, removed: [] };

    const host = normalizeHost(u.hostname);
    const excList = [
      ...DEFAULT_EXCLUDED_DOMAINS,
      ...(Array.isArray(exceptions) ? exceptions.map(normalizeHost).filter(Boolean) : [])
    ];
    if (excList.some((d) => host === d || host.endsWith('.' + d))) {
      return { changed: false, url: u.href, removed: [] };
    }

    // Never touch signed URLs (e.g. S3/GCS presigned downloads)
    for (const key of u.searchParams.keys()) {
      if (key.toLowerCase() === 'x-amz-signature' || key.toLowerCase() === 'x-goog-signature') {
        return { changed: false, url: u.href, removed: [] };
      }
    }

    const removed = [];
    for (const key of Array.from(u.searchParams.keys())) {
      if (TRACKING_PARAM_SET.has(key) && !PROTECTED_SIGNATURE_PARAMS.has(key.toLowerCase())) {
        u.searchParams.delete(key);
        removed.push(key);
      }
    }
    return { changed: removed.length > 0, url: u.href, removed };
  }

  /**
   * Synchronize ONLY the Tracking Stripping DNR rule range [960000, 969999].
   * Never touches Fortress, Global Block, User Block, or HTTPS-First rules.
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
      return { ok: true, enabled: Boolean(enabled), ruleCount: addRules.length, paramCount: TRACKING_PARAMS.length };
    } catch (e) {
      return { ok: false, error: (e && e.message) || 'tracking-strip-sync-failed' };
    }
  }

  return {
    RULE_ID,
    RULE_MIN,
    RULE_MAX,
    PRIORITY,
    TRACKING_PARAMS,
    DEFAULT_EXCLUDED_DOMAINS,
    buildRule,
    stripUrl,
    sync
  };
})();

globalThis.CorsairTrackingStrip = CorsairTrackingStrip;
