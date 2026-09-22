const CorsairAlarms = (() => {
  'use strict';

  const FORTRESS_ALLOW_PREFIX = 'fortress-allow-';
  const WHITELIST_SYNC = 'whitelist-sync';
  const CACHE_CLEANUP = 'cache-cleanup';

  let _started = false;

  function isSupported() {
    return typeof chrome !== 'undefined' && chrome.alarms &&
           typeof chrome.alarms.create === 'function';
  }

  async function scheduleFortressAllowExpiry(ruleId, ttlMs) {
    if (!isSupported() || !Number.isInteger(ruleId)) return false;
    try {
      await chrome.alarms.create(`${FORTRESS_ALLOW_PREFIX}${ruleId}`, {
        when: Date.now() + Math.max(5000, Math.min(300000, ttlMs || 30000))
      });
      return true;
    } catch { return false; }
  }

  async function cancelFortressAllowExpiry(ruleId) {
    if (!isSupported() || !Number.isInteger(ruleId)) return false;
    try {
      await chrome.alarms.clear(`${FORTRESS_ALLOW_PREFIX}${ruleId}`);
      return true;
    } catch { return false; }
  }

  function installListener({ onFortressAllowExpire, onWhitelistSync, onCacheCleanup } = {}) {
    if (!isSupported() || _started) return;
    _started = true;
    try {
      chrome.alarms.onAlarm.addListener(async alarm => {
        try {
          if (!alarm || typeof alarm.name !== 'string') return;
          if (alarm.name.startsWith(FORTRESS_ALLOW_PREFIX)) {
            const ruleId = Number(alarm.name.slice(FORTRESS_ALLOW_PREFIX.length));
            if (Number.isInteger(ruleId) && typeof onFortressAllowExpire === 'function') {
              await onFortressAllowExpire(ruleId);
            }
          } else if (alarm.name === WHITELIST_SYNC) {
            if (typeof onWhitelistSync === 'function') await onWhitelistSync();
          } else if (alarm.name === CACHE_CLEANUP) {
            if (typeof onCacheCleanup === 'function') await onCacheCleanup();
          }
        } catch {}
      });
    } catch {}
  }

  async function scheduleWhitelistSync(periodInMinutes = 60 * 24 * 7) {
    if (!isSupported()) return false;
    try {
      await chrome.alarms.create(WHITELIST_SYNC, { periodInMinutes });
      return true;
    } catch { return false; }
  }

  async function scheduleCacheCleanup(periodInMinutes = 60 * 6) {
    if (!isSupported()) return false;
    try {
      await chrome.alarms.create(CACHE_CLEANUP, { periodInMinutes });
      return true;
    } catch { return false; }
  }

  async function restoreFortressAllowAlarms(sessionRules) {
    if (!isSupported() || !Array.isArray(sessionRules)) return 0;
    let restored = 0;
    for (const rule of sessionRules) {
      if (rule && Number.isInteger(rule.id) && rule.id >= 850000 && rule.id < 890000) {
        try {
          const existing = await chrome.alarms.get(`${FORTRESS_ALLOW_PREFIX}${rule.id}`);
          if (!existing) {
            await chrome.alarms.create(`${FORTRESS_ALLOW_PREFIX}${rule.id}`, {
              when: Date.now() + 60000
            });
            restored++;
          }
        } catch {}
      }
    }
    return restored;
  }

  return {
    FORTRESS_ALLOW_PREFIX,
    WHITELIST_SYNC,
    CACHE_CLEANUP,
    isSupported,
    scheduleFortressAllowExpiry,
    cancelFortressAllowExpiry,
    installListener,
    scheduleWhitelistSync,
    scheduleCacheCleanup,
    restoreFortressAllowAlarms
  };
})();

globalThis.CorsairAlarms = CorsairAlarms;