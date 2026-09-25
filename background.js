import './core/security.js';
import './core/i18n.js';
import './core/storage.js';
import './core/alarms.js';
import './core/dnr.js';
import './core/redirects.js';
import './core/threat-intel.js';
import './core/heuristics.js';
import './core/intelligence.js';
import './core/verifier.js';
import './core/observation.js';
import './core/evidence.js';
import './core/migration.js';
import './core/tool-router.js';
import './core/replay.js';
import './core/updater.js';

let _startupReconcilePromise = null;

/* ============================================================
   ALARMS WIRING
   ============================================================ */
if (typeof CorsairAlarms !== 'undefined' && CorsairAlarms.isSupported()) {
  CorsairAlarms.installListener({
    onFortressAllowExpire: async (ruleId) => {
      try {
        await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] });
      } catch {}
    },
    onWhitelistSync: async () => {
      try {
        if (typeof CorsairThreatIntel !== 'undefined' && typeof CorsairThreatIntel.refreshRemoteAllowlist === 'function') {
          await CorsairThreatIntel.refreshRemoteAllowlist();
        }
      } catch {}
    },
    onCacheCleanup: async () => {
      try {
        if (typeof CorsairStorage === 'undefined') return;
        const cache = await CorsairStorage.get('threatCache', {});
        const now = Date.now();
        const MAX_AGE = 30 * 24 * 60 * 60 * 1000;
        let changed = false;
        for (const host of Object.keys(cache || {})) {
          const lc = cache[host]?.lastChecked || 0;
          if (lc && now - lc > MAX_AGE) { delete cache[host]; changed = true; }
        }
        if (changed) await CorsairStorage.set('threatCache', cache);
      } catch {}
    }
  });
}

/* ============================================================
   POPUP BURST STATE
   ============================================================ */
const _popupBurst = new Map();
const _originCooldown = new Map();
const _recentTabCreates = [];
const POPUP_BURST_WINDOW_MS = 2500;
const POPUP_BURST_THRESHOLD = 3;
const BURST_COOLDOWN_MS = 10000;
const RECENT_TAB_WINDOW_MS = 4000;

function recordPopupBurst(host) {
  const now = Date.now();
  const arr = (_popupBurst.get(host) || []).filter(t => now - t < POPUP_BURST_WINDOW_MS);
  arr.push(now);
  _popupBurst.set(host, arr);
  return arr.length;
}
function isInCooldown(host) {
  const until = _originCooldown.get(host);
  if (!until) return false;
  if (Date.now() >= until) { _originCooldown.delete(host); return false; }
  return true;
}
function setCooldown(host) { _originCooldown.set(host, Date.now() + BURST_COOLDOWN_MS); }
function pushRecentTabCreate(rec) {
  const now = Date.now();
  while (_recentTabCreates.length && now - _recentTabCreates[0].ts > RECENT_TAB_WINDOW_MS) {
    _recentTabCreates.shift();
  }
  _recentTabCreates.push(rec);
}
function findRecentOpenerFor(tabId) {
  for (let i = _recentTabCreates.length - 1; i >= 0; i--) {
    const r = _recentTabCreates[i];
    if (r.tabId === tabId && r.sourceTabId) return r.sourceTabId;
  }
  return null;
}
function purgeRecentTabCreatesFor(tabId) {
  for (let i = _recentTabCreates.length - 1; i >= 0; i--) {
    const r = _recentTabCreates[i];
    if (r.tabId === tabId || r.sourceTabId === tabId) _recentTabCreates.splice(i, 1);
  }
}

/* ============================================================
   AUTO-SCAN + VERDICT PUSH + BADGE
   ============================================================ */
const _autoScannedTabs = new Map();

async function sendToTab(tabId, msg) {
  if (!Number.isInteger(tabId)) return;
  try { await chrome.tabs.sendMessage(tabId, msg); } catch {}
}

async function updateBadge(tabId, verdict) {
  if (!Number.isInteger(tabId)) return;
  let color = '#64748b', text = '?';
  const v = String(verdict || '').toLowerCase();
  if (v === 'malicious') { color = '#f43f5e'; text = '✗'; }
  else if (v === 'suspicious') { color = '#f59e0b'; text = '!'; }
  else if (v === 'clean') { color = '#10b981'; text = '✓'; }
  else if (v === 'allowlisted') { color = '#3b82f6'; text = '✓'; }
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
    await chrome.action.setBadgeText({ tabId, text });
  } catch {}
}

function clearBadge(tabId) {
  if (!Number.isInteger(tabId)) return;
  try { chrome.action.setBadgeText({ tabId, text: '' }); } catch {}
}

/* ============================================================
   AUTO-ARM FORTRESS / AUTO-BLOCK
   ============================================================ */
async function maybeAutoArmFortress(host, report) {
  try {
    if (!host) return;
    if (!report || report.status === 'error' || report.status === 'allowlisted') return;

    const settings = await CorsairStorage.getSettings();
    if (settings.autoArmFortress === false) return;

    try { await CorsairThreatIntel.loadRemoteAllowlist(); } catch {}
    if (CorsairThreatIntel.isAllowlisted(host)) return;

    const rawArm = Number(settings.autoArmFortressThreshold);
    const armMinRisk = Number.isFinite(rawArm)
      ? Math.max(1, Math.min(100, rawArm))
      : 10;

    const rawBlock = Number(settings.autoBlockThreshold);
    const blockMinRisk = Number.isFinite(rawBlock)
      ? Math.max(1, Math.min(100, rawBlock))
      : 70;

    const risk = Number(report.riskPercentage) || 0;
    if (risk < armMinRisk) return;

    const shouldBlock = risk >= blockMinRisk;

    const [existing, blockedList] = await Promise.all([
      CorsairStorage.getProfile(host),
      CorsairStorage.get('userBlockedDomains', [])
    ]);
    const isAlreadyBlocked = Array.isArray(blockedList) && blockedList.includes(host);

    /* ============ BLOCK PATH ============ */
    if (shouldBlock) {
      if (!isAlreadyBlocked) {
        try {
          await CorsairStorage.withPartitionLock('userBlockedDomains', async () => {
            const list = await CorsairStorage.get('userBlockedDomains', []);
            const set = new Set(Array.isArray(list) ? list : []);
            set.add(host);
            const arr = [...set].slice(-500);
            await CorsairStorage.set('userBlockedDomains', arr);
            await CorsairDNR.syncUserBlocklist(arr);
          });

          await CorsairStorage.appendEvent({
            type: 'auto_block',
            domain: host,
            reason: `auto-blocked at risk ${risk}% (threshold ${blockMinRisk}%)`,
            severity: 'high'
          });
          try {
            await CorsairEvidence.add({
              kind: 'auto_block',
              origin: host,
              tabId: null,
              data: { risk, threshold: blockMinRisk, verdict: report.verdict || 'unknown' }
            });
          } catch {}
        } catch {}
      }

      if (!existing || existing.autoArmed !== false) {
        await CorsairDNR.patchProfileAtomic(host, current => ({
          ...(current || CorsairSecurity.fortressProfile({})),
          protected: true,
          mode: 'fortress',
          autoContainRedirects: true,
          clickbaitGuard: true,
          autoArmed: true,
          autoArmedAt: Date.now(),
          autoArmReason: `auto-blocked at risk ${risk}% (threshold ${blockMinRisk}%)`
        }));
      }
      return;
    }

    /* ============ ARM-ONLY PATH ============ */
    if (existing && existing.autoArmed !== true) return;
    if (existing && existing.autoArmed === true && existing.protected === true) return;

    const res = await CorsairDNR.patchProfileAtomic(host, current => ({
      ...(current || CorsairSecurity.fortressProfile({})),
      protected: true,
      mode: 'fortress',
      autoContainRedirects: true,
      clickbaitGuard: true,
      autoArmed: true,
      autoArmedAt: Date.now(),
      autoArmReason: `risk ${risk}% ≥ ${armMinRisk}%`
    }));

    if (res && res.ok) {
      await CorsairStorage.appendEvent({
        type: 'auto_fortress_armed',
        domain: host,
        reason: `auto-armed at risk ${risk}% (threshold ${armMinRisk}%)`,
        severity: risk >= 60 ? 'high' : 'medium'
      });
      try {
        await CorsairEvidence.add({
          kind: 'auto_fortress_armed',
          origin: host,
          tabId: null,
          data: { risk, threshold: armMinRisk, verdict: report.verdict || 'unknown' }
        });
      } catch {}
    }
  } catch {}
}

async function pushVerdictToTab(tabId, report) {
  await sendToTab(tabId, { type: 'corsair-verdict', report });
  if (report && report.status !== 'error') {
    updateBadge(tabId, report.verdict || report.status).catch(() => {});
  }
}

async function maybeAutoScan(tabId, url) {
  try {
    const host = CorsairSecurity.extractHostname(url);
    if (!host) return;
    if (_autoScannedTabs.get(tabId) === host) return;
    _autoScannedTabs.set(tabId, host);

    const settings = await CorsairStorage.getSettings();
    if (!settings.threatIntelEnabled || !settings.threatIntelAutoScan) return;
    if (!settings.siteVerdictBanner) return;

    if (CorsairThreatIntel.isAllowlisted(host)) {
      updateBadge(tabId, 'allowlisted').catch(() => {});
      if (settings.notifyOnSafeSites === true) {
        await pushVerdictToTab(tabId, {
          host, status: 'allowlisted', verdict: 'clean',
          riskPercentage: 0, flaggedEngines: [],
          stats: { harmless: 85, malicious: 0, suspicious: 0, undetected: 0 }
        });
      }
      return;
    }

    const cached = await CorsairThreatIntel.getCachedReport(host);
    if (cached && !cached.stale) {
      await pushVerdictToTab(tabId, cached);
      maybeAutoArmFortress(host, cached).catch(() => {});
      return;
    }

    await sendToTab(tabId, { type: 'corsair-verdict-loading', host });
    const report = await CorsairThreatIntel.autoScan(host);
    if (report && report.status !== 'error') {
      await pushVerdictToTab(tabId, report);
      maybeAutoArmFortress(host, report).catch(() => {});
    } else {
      await sendToTab(tabId, { type: 'corsair-verdict-cancel' });
    }
  } catch {
    try { await sendToTab(tabId, { type: 'corsair-verdict-cancel' }); } catch {}
  }
}

/* ============================================================
   CUSTOM DOMAIN SCRIPTS
   ============================================================ */
const _scriptedTabs = new Map();

async function runCustomScriptForTab(tabId, host, url) {
  if (!Number.isInteger(tabId) || !host) return;

  if (!chrome.scripting || typeof chrome.scripting.executeScript !== 'function') {
    console.error('[Corsair CS] chrome.scripting NOT available! Reload extension and approve permissions.');
    return;
  }

  try {
    const scripts = await CorsairStorage.get('customDomainScripts', {});
    const entry = scripts[host];
    if (!entry || entry.enabled === false || !entry.code) return;

    const lint = CorsairSecurity.lintCustomScript(entry.code);
    if (!lint.ok) {
      console.warn(`[Corsair CS] ⛔ refusing to inject "${host}": ${lint.error}`);
      return;
    }

    const urlKey = String(url || ('host::' + host));
    if (_scriptedTabs.get(tabId) === urlKey) return;
    _scriptedTabs.set(tabId, urlKey);

    console.log(`[Corsair CS] ▶ injecting "${host}" into tab ${tabId} (url=${urlKey})`);

    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: false },
      world: 'MAIN',
      func: (userCode) => {
        console.log('[Corsair CS] ▶ page-side func reached:', location.href);

        const run = () => {
          try {
            const s = document.createElement('script');
            s.textContent = userCode;
            (document.head || document.documentElement || document.body).appendChild(s);
            s.remove();
            console.log('[Corsair CS] ✅ user code injected via <script> tag');
            return true;
          } catch (e) {
            console.error('[Corsair CS] ❌ inline injection failed:', e && e.message);
            return false;
          }
        };

        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', run, { once: true });
          return { scheduled: 'on-dom-ready' };
        }
        return { immediate: run() };
      },
      args: [String(entry.code)]
    });

    const r = results && results[0] && results[0].result;
    console.log('[Corsair CS] ✓ result:', r);
  } catch (err) {
    console.error('[Corsair CS] ❌ executeScript threw:', err && err.message, err);
  }
}

async function listCustomScripts() {
  const scripts = await CorsairStorage.get('customDomainScripts', {});
  return Object.entries(scripts || {}).map(([host, e]) => ({
    host,
    code: e.code || '',
    enabled: e.enabled !== false,
    createdAt: e.createdAt || 0,
    updatedAt: e.updatedAt || 0
  })).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

async function upsertCustomScript(host, patch) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h || !CorsairSecurity.isValidHostname(h)) return { ok: false, error: 'invalid-host' };

  if (typeof patch.code === 'string') {
    const lint = CorsairSecurity.lintCustomScript(patch.code);
    if (!lint.ok) {
      return { ok: false, error: lint.line ? `${lint.error} (line ${lint.line})` : lint.error };
    }
  }

  return CorsairStorage.withPartitionLock('globalSettings', async () => {
    const scripts = await CorsairStorage.get('customDomainScripts', {});
    const prev = scripts[h] || { createdAt: Date.now() };
    const next = {
      ...prev,
      enabled: patch.enabled !== undefined ? Boolean(patch.enabled) : (prev.enabled !== false),
      code: typeof patch.code === 'string' ? patch.code.slice(0, CorsairSecurity.CUSTOM_SCRIPT_MAX_LEN) : (prev.code || ''),
      createdAt: prev.createdAt || Date.now(),
      updatedAt: Date.now()
    };
    scripts[h] = next;
    await CorsairStorage.set('customDomainScripts', scripts);
    return { ok: true, entry: { host: h, ...next } };
  });
}

async function removeCustomScript(host) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h) return { ok: false, error: 'invalid-host' };
  return CorsairStorage.withPartitionLock('globalSettings', async () => {
    const scripts = await CorsairStorage.get('customDomainScripts', {});
    if (scripts[h]) {
      delete scripts[h];
      await CorsairStorage.set('customDomainScripts', scripts);
    }
    return { ok: true };
  });
}

/* ============================================================
   SAFE SCANNED DOMAINS
   ============================================================ */
async function listSafeScannedDomains() {
  const cache = await CorsairStorage.get('threatCache', {});
  const out = [];
  for (const [host, report] of Object.entries(cache || {})) {
    if (report && report.verdict === 'clean' && report.status !== 'allowlisted') {
      out.push({
        host,
        riskPercentage: report.riskPercentage || 0,
        lastChecked: report.lastChecked || 0,
        stats: report.stats || {}
      });
    }
  }
  return out.sort((a, b) => (b.lastChecked || 0) - (a.lastChecked || 0));
}
async function removeSafeScannedDomain(host) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h) return { ok: false, error: 'invalid-host' };
  return CorsairStorage.withPartitionLock('threatCache', async () => {
    const cache = await CorsairStorage.get('threatCache', {});
    if (cache && cache[h]) { delete cache[h]; await CorsairStorage.set('threatCache', cache); }
    return { ok: true };
  });
}
async function clearSafeScannedDomains() {
  return CorsairStorage.withPartitionLock('threatCache', async () => {
    const cache = await CorsairStorage.get('threatCache', {});
    let removed = 0;
    for (const host of Object.keys(cache || {})) {
      if (cache[host]?.verdict === 'clean' && cache[host]?.status !== 'allowlisted') {
        delete cache[host]; removed++;
      }
    }
    await CorsairStorage.set('threatCache', cache);
    return { ok: true, removed };
  });
}
async function bulkRemoveSafeScanned(hosts) {
  if (!Array.isArray(hosts) || !hosts.length) return { ok: true, removed: 0 };
  const targets = new Set(hosts.map(h => CorsairSecurity.normalizeHostname(h)).filter(Boolean));
  return CorsairStorage.withPartitionLock('threatCache', async () => {
    const cache = await CorsairStorage.get('threatCache', {});
    let removed = 0;
    for (const h of targets) if (cache[h]) { delete cache[h]; removed++; }
    await CorsairStorage.set('threatCache', cache);
    return { ok: true, removed };
  });
}

/* ============================================================
   TRUST DOMAIN
   ============================================================ */
async function trustDomain(host) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h || !CorsairSecurity.isValidHostname(h)) return { ok: false, error: 'invalid-host' };
  return CorsairStorage.withPartitionLock('globalSettings', async () => {
    const list = await CorsairStorage.get('userTrustedDomains', []);
    const set = new Set(Array.isArray(list) ? list : []);
    set.add(h);
    const arr = [...set].slice(-500);
    await CorsairStorage.set('userTrustedDomains', arr);
    try { CorsairThreatIntel.refreshUserTrusted(); } catch {}
    try {
      const blocked = await CorsairStorage.get('userBlockedDomains', []);
      if (Array.isArray(blocked) && blocked.includes(h)) {
        const nextBlocked = blocked.filter(d => d !== h);
        await CorsairStorage.set('userBlockedDomains', nextBlocked);
        CorsairDNR.syncUserBlocklist(nextBlocked);
      }
    } catch {}
    return { ok: true, domains: arr };
  });
}
async function untrustDomain(host) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h) return { ok: false, error: 'invalid-host' };
  return CorsairStorage.withPartitionLock('globalSettings', async () => {
    const list = await CorsairStorage.get('userTrustedDomains', []);
    const arr = (Array.isArray(list) ? list : []).filter(d => d !== h);
    await CorsairStorage.set('userTrustedDomains', arr);
    try { CorsairThreatIntel.refreshUserTrusted(); } catch {}
    return { ok: true, domains: arr };
  });
}

/* ============================================================
   USER BLOCKLIST
   ============================================================ */
async function blockDomainGlobally(host) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h || !CorsairSecurity.isValidHostname(h)) return { ok: false, error: 'invalid-host' };
  return CorsairStorage.withPartitionLock('userBlockedDomains', async () => {
    const list = await CorsairStorage.get('userBlockedDomains', []);
    const set = new Set(Array.isArray(list) ? list : []);
    set.add(h);
    const arr = [...set].slice(-500);
    await CorsairStorage.set('userBlockedDomains', arr);
    try {
      const trusted = await CorsairStorage.get('userTrustedDomains', []);
      if (Array.isArray(trusted) && trusted.includes(h)) {
        await CorsairStorage.set('userTrustedDomains', trusted.filter(d => d !== h));
        CorsairThreatIntel.refreshUserTrusted();
      }
    } catch {}
    const sync = await CorsairDNR.syncUserBlocklist(arr);
    return { ok: true, domains: arr, sync };
  });
}
async function unblockDomainGlobally(host) {
  const h = CorsairSecurity.normalizeHostname(host || '');
  if (!h) return { ok: false, error: 'invalid-host' };
  return CorsairStorage.withPartitionLock('userBlockedDomains', async () => {
    const list = await CorsairStorage.get('userBlockedDomains', []);
    const arr = (Array.isArray(list) ? list : []).filter(d => d !== h);
    await CorsairStorage.set('userBlockedDomains', arr);
    const sync = await CorsairDNR.syncUserBlocklist(arr);
    return { ok: true, domains: arr, sync };
  });
}

/* ============================================================
   SESSION RECONCILE
   ============================================================ */
async function reconcileSessionState() {
  try {
    if (typeof chrome === 'undefined' || !chrome.tabs?.query || typeof CorsairObservation === 'undefined') return;
    const tabs = await chrome.tabs.query({});
    const activeTabIds = (Array.isArray(tabs) ? tabs : []).map(t => t.id).filter(id => Number.isInteger(id));
    await CorsairObservation.reconcileSessionTabs(activeTabIds);
  } catch {}
}

/* ============================================================
   SENDER CLASSIFIER
   ============================================================ */
function classifySender(sender) {
  if (!sender || typeof sender !== 'object' || Array.isArray(sender)) return 'UNTRUSTED';
  const extId = (typeof chrome !== 'undefined' && chrome.runtime?.id) ? chrome.runtime.id : '';
  const extBaseUrl = (typeof chrome !== 'undefined' && chrome.runtime?.getURL) ? chrome.runtime.getURL('') : '';
  const senderUrl = typeof sender.url === 'string' ? sender.url : '';
  const senderOrigin = typeof sender.origin === 'string' ? sender.origin : '';
  if (extId && sender.id && sender.id !== extId) return 'UNTRUSTED';
  const isExtensionUrl = Boolean(extBaseUrl && senderUrl.startsWith(extBaseUrl));
  if (isExtensionUrl && (!extId || sender.id === extId)) return 'PRIVILEGED_INTERNAL';
  const hasTabContext = Boolean(sender.tab && typeof sender.tab === 'object');
  const hasExternalContext = Boolean(senderUrl || senderOrigin);
  if (hasTabContext && hasExternalContext && (!extId || sender.id === extId)) return 'PAGE_OBSERVATION';
  return 'UNTRUSTED';
}
globalThis.classifySender = classifySender;

/* ============================================================
   STARTUP
   ============================================================ */
async function performStartupDnrReconciliation() {
  if (_startupReconcilePromise) return _startupReconcilePromise;
  _startupReconcilePromise = (async () => {
    try {
      if (typeof CorsairStorage !== 'undefined' && typeof CorsairStorage.ensureReady === 'function') {
        await CorsairStorage.ensureReady();
      }
      if (typeof CorsairAlarms !== 'undefined' && CorsairAlarms.isSupported()) {
        CorsairAlarms.scheduleWhitelistSync(60 * 24 * 7).catch(() => {});
        CorsairAlarms.scheduleCacheCleanup(60 * 6).catch(() => {});
      }
      if (typeof CorsairThreatIntel !== 'undefined') {
        if (typeof CorsairThreatIntel.loadRemoteAllowlist === 'function') {
          CorsairThreatIntel.loadRemoteAllowlist().catch(() => {});
        }
        if (typeof CorsairThreatIntel.refreshUserTrusted === 'function') {
          CorsairThreatIntel.refreshUserTrusted();
        }
      }
      if (typeof CorsairDNR !== 'undefined' && typeof CorsairDNR.syncUserBlocklist === 'function') {
        try {
          const blocked = await CorsairStorage.get('userBlockedDomains', []);
          CorsairDNR.syncUserBlocklist(blocked).catch(() => {});
        } catch {}
      }
      if (typeof CorsairDNR !== 'undefined' && typeof CorsairDNR.reconcileDnrRegistry === 'function') {
        const r = await CorsairDNR.reconcileDnrRegistry();
        try {
          const allowRules = await CorsairDNR.listFortressAllowRules();
          if (typeof CorsairAlarms !== 'undefined' && CorsairAlarms.isSupported()) {
            await CorsairAlarms.restoreFortressAllowAlarms(allowRules);
          }
        } catch {}
        return r;
      }
    } catch (err) {
      return { ok: false, error: err.message, rulesPreserved: true };
    } finally {
      _startupReconcilePromise = null;
    }
  })();
  return _startupReconcilePromise;
}

/* ============================================================
   UPDATER
   ============================================================ */
async function initUpdater() {
  try {
    if (typeof CorsairUpdater === 'undefined') return;

    // Detect if this is a post-update launch.
    // recordInstalledVersion() returns { changed, from, to } where
    // `from` is null on the very first install (no previous version
    // recorded yet). We only log an "extension_updated" event when we
    // actually transitioned from one concrete version to another —
    // otherwise the activity feed would receive a misleading
    // "Updated from vunknown to v1.7.0" entry on every fresh install.
    const installInfo = await CorsairUpdater.recordInstalledVersion();
    if (installInfo.changed && installInfo.from) {
      try {
        await CorsairStorage.appendEvent({
          type: 'extension_updated',
          domain: '',
          reason: `Updated from v${installInfo.from} to v${installInfo.to}`,
          severity: 'info'
        });
      } catch {}
    }

    // Schedule periodic background check (fires every 6h)
    await CorsairUpdater.scheduleBackgroundCheck();

    // One immediate check on startup
    const result = await CorsairUpdater.checkForUpdates({ force: false });
    if (result && result.hasUpdate) {
      await CorsairUpdater.notifyIfUpdateAvailable(result);
    }
  } catch {}
}

/* Listen for the update-check alarm */
try {
  if (typeof chrome !== 'undefined' && chrome.alarms?.onAlarm) {
    chrome.alarms.onAlarm.addListener(async alarm => {
      try {
        if (alarm?.name !== CorsairUpdater?.ALARM_NAME) return;
        await CorsairUpdater.runBackgroundCheck();
      } catch {}
    });
  }
} catch {}

/* Handle notification clicks and buttons */
try {
  if (typeof chrome !== 'undefined' && chrome.notifications?.onClicked) {
    chrome.notifications.onClicked.addListener(async (notificationId) => {
      try {
        if (!notificationId || !notificationId.startsWith('corsair-update-')) return;
        // Open the dashboard with the update modal flag
        await chrome.tabs.create({
          url: chrome.runtime.getURL('dashboard.html?update=1')
        });
        try { chrome.notifications.clear(notificationId); } catch {}
      } catch {}
    });
  }
} catch {}

try {
  if (typeof chrome !== 'undefined' && chrome.notifications?.onButtonClicked) {
    chrome.notifications.onButtonClicked.addListener(async (notificationId, buttonIndex) => {
      try {
        if (!notificationId || !notificationId.startsWith('corsair-update-')) return;
        if (buttonIndex === 0) {
          await chrome.tabs.create({
            url: chrome.runtime.getURL('dashboard.html?update=1')
          });
        }
        try { chrome.notifications.clear(notificationId); } catch {}
      } catch {}
    });
  }
} catch {}

chrome.runtime.onStartup.addListener(() => {
  performStartupDnrReconciliation().catch(() => {});
  reconcileSessionState().catch(() => {});
  setupContextMenus();
  initUpdater().catch(() => {});
});
chrome.runtime.onInstalled.addListener(() => {
  performStartupDnrReconciliation().catch(() => {});
  reconcileSessionState().catch(() => {});
  setupContextMenus();
  initUpdater().catch(() => {});
});

/* ============================================================
   COMMANDS
   ============================================================ */
try {
  chrome.commands.onCommand.addListener(async (command) => {
    try {
      if (command === 'open-dashboard') {
        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') }).catch(() => {});
      } else if (command === 'toggle-fortress') {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.url) return;
        const host = CorsairSecurity.extractHostname(tab.url);
        if (!host) return;
        const profile = await CorsairStorage.getProfile(host);
        const isArmed = profile?.protected === true && profile?.mode === 'fortress';
        const patch = isArmed
          ? { protected: false, mode: 'standard' }
          : { protected: true, mode: 'fortress', autoContainRedirects: true, clickbaitGuard: true };
        await CorsairDNR.patchProfileAtomic(host, current => ({
          ...(current || CorsairSecurity.fortressProfile({})),
          ...patch
        }));
      }
    } catch {}
  });
} catch {}

/* ============================================================
   CONTEXT MENUS
   ============================================================ */
let _contextMenusInstalled = false;
let _contextMenusInFlight = false;

async function setupContextMenus() {
  if (typeof chrome === 'undefined' || !chrome.contextMenus) return;
  if (_contextMenusInstalled || _contextMenusInFlight) return;
  _contextMenusInFlight = true;

  try {
    await new Promise(resolve => {
      try {
        chrome.contextMenus.removeAll(() => {
          try { void chrome.runtime.lastError; } catch {}
          resolve();
        });
      } catch { resolve(); }
    });

    const items = [
      { id: 'corsair-scan-link',    title: '🔬 Scan this link with Corsair',    contexts: ['link'] },
      { id: 'corsair-scan-page',    title: '🔬 Scan this page with Corsair',    contexts: ['page'] },
      { id: 'corsair-block-domain', title: '🚫 Block this domain with Corsair', contexts: ['link', 'page'] }
    ];

    for (const item of items) {
      await new Promise(resolve => {
        try {
          chrome.contextMenus.create(item, () => {
            try { void chrome.runtime.lastError; } catch {}
            resolve();
          });
        } catch { resolve(); }
      });
    }

    _contextMenusInstalled = true;
  } catch {
    // best-effort
  } finally {
    _contextMenusInFlight = false;
  }
}

function notify(title, message) {
  try {
    if (typeof chrome.notifications?.create === 'function') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title,
        message
      });
    }
  } catch {}
}

try {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    try {
      if (info.menuItemId === 'corsair-scan-link' || info.menuItemId === 'corsair-scan-page') {
        const targetUrl = info.menuItemId === 'corsair-scan-link' ? info.linkUrl : (info.pageUrl || tab?.url);
        if (!targetUrl) return;
        notify('Corsair Unbound', 'Submitting to VirusTotal…');
        const result = await CorsairThreatIntel.scanUrl(targetUrl);
        const v = String(result.verdict || result.status || 'unknown').toUpperCase();
        const detail = result.status === 'pending'
          ? 'Still analyzing — check the dashboard analyzer in a moment.'
          : (result.flaggedEngines?.length ? `Flagged by ${result.flaggedEngines.length} engine(s).` : 'No engines flagged this URL.');
        notify(`Corsair scan: ${v}`, `${targetUrl}\n${detail}`);
      } else if (info.menuItemId === 'corsair-block-domain') {
        const targetUrl = info.linkUrl || info.pageUrl || tab?.url;
        const host = CorsairSecurity.extractHostname(targetUrl || '');
        if (!host) return;
        const r = await blockDomainGlobally(host);
        notify('Corsair Unbound', r.ok ? `🚫 ${host} is now blocked everywhere.` : `Could not block ${host}: ${r.error || 'unknown error'}`);
      }
    } catch (err) {
      notify('Corsair Unbound', `Scan failed: ${err.message}`);
    }
  });
} catch {}

/* ============================================================
   DOWNLOAD GUARD
   ============================================================ */
try {
  chrome.downloads.onCreated.addListener(async (item) => {
    try {
      const settings = await CorsairStorage.getSettings();
      if (settings.downloadGuard !== true) return;
      const host = CorsairSecurity.extractHostname(item.url || '') || CorsairSecurity.extractHostname(item.finalUrl || '');
      if (!host) return;
      if (CorsairThreatIntel.isAllowlisted(host)) return;
      const report = await CorsairThreatIntel.getCachedReport(host);
      if (report?.verdict !== 'malicious') return;
      try { await chrome.downloads.cancel(item.id); } catch {}
      try { await chrome.downloads.erase({ id: item.id }); } catch {}
      await CorsairStorage.appendEvent({
        type: 'download_blocked', domain: host,
        destination: item.finalUrl || item.url,
        reason: 'malicious-download-source', severity: 'high'
      });
      await CorsairEvidence.add({
        kind: 'download_blocked', origin: host, tabId: null,
        data: { filename: item.filename || '', url: item.url }
      });
      if (settings.notifications === true && typeof chrome.notifications?.create === 'function') {
        chrome.notifications.create({
          type: 'basic', iconUrl: 'icons/icon128.png',
          title: 'Corsair Shield — Download Blocked',
          message: `Blocked malicious download from ${host}`
        }).catch(() => {});
      }
    } catch {}
  });
} catch {}

/* ============================================================
   CONTAINMENT HELPERS
   ============================================================ */
async function closeTabSafe(tabId) { try { await chrome.tabs.remove(tabId); } catch {} }

async function logContainment({ type, sourceHost, destinationHost, reason, tabId }) {
  try {
    await CorsairStorage.appendEvent({
      type: type || 'popup_blocked',
      domain: sourceHost,
      destination: destinationHost,
      reason, severity: 'high', tabId
    });
  } catch {}
  try {
    await CorsairEvidence.add({
      kind: type || 'popup_blocked',
      origin: sourceHost, tabId: tabId || null,
      data: { destination: destinationHost, reason }
    });
  } catch {}
}

async function notifyContainment(reason, sourceHost, destinationHost) {
  try {
    const settings = await CorsairStorage.getSettings();
    if (settings.notifications !== true) return;
    if (typeof chrome.notifications?.create === 'function') {
      chrome.notifications.create({
        type: 'basic', iconUrl: 'icons/icon128.png',
        title: 'Corsair Shield — Contained',
        message: `${reason}: ${sourceHost} → ${destinationHost || '?'}`
      }).catch(() => {});
    }
  } catch {}
}

/* ============================================================
   POPUP DEFENSE — unified handler
   ------------------------------------------------------------
   With `incognito: "spanning"` (see manifest.json), all tabs —
   regular AND incognito — are visible to this single service
   worker. We handle containment at the `tabs.onCreated` layer
   because "Open link in private window" from the context menu
   is a BROWSER action that never fires webNavigation events.

   Containment signals (any one is enough):
     • the destination is on the source profile's blocklist
     • a popup burst was detected (>3 in 2.5s)
     • we are inside a burst cooldown
     • openerTabId points to an armed Fortress page AND the new
       tab's URL is cross-origin AND the tab was NOT user-initiated

   User-initiated tabs are recognized by NOT having an
   openerTabId, OR by arriving without a preceding right-click
   heuristic. Context-menu tabs DO have an openerTabId, so we
   cannot rely on that alone; the burst/cooldown signal is what
   protects legitimate right-click usage.
   ============================================================ */
chrome.tabs.onCreated.addListener(async tab => {
  try {
    const newTabId = tab.id;
    if (!Number.isInteger(newTabId)) return;

    let openerId = tab.openerTabId;
    // If there's no opener, the user opened this tab themselves
    // (address bar, bookmark, new window). Leave it alone.
    if (!Number.isInteger(openerId)) return;

    // Wait a tick for the tab's URL to be populated.
    let destUrl = tab.pendingUrl || tab.url || '';
    if (!destUrl) {
      await new Promise(r => setTimeout(r, 150));
      const fresh = await chrome.tabs.get(newTabId).catch(() => null);
      if (!fresh) return; // tab already gone
      destUrl = fresh.pendingUrl || fresh.url || '';
    }

    const opener = await chrome.tabs.get(openerId).catch(() => null);
    if (!opener?.url) return;

    const originHost = CorsairSecurity.extractHostname(opener.url);
    if (!originHost) return;

    const profile = await CorsairStorage.getProfile(originHost);
    if (!profile || profile.protected !== true || profile.mode !== 'fortress') return;

    const destHost = CorsairSecurity.extractHostname(destUrl);

    // Same-origin new tabs are legitimate.
    if (destHost && CorsairSecurity.sameOrSubdomain(destHost, originHost)) return;

    // Is the destination on the profile's explicit blocklist?
    const blockedList = Array.isArray(profile.blockedDestinationDomains)
      ? profile.blockedDestinationDomains
      : [];
    const isExplicitlyBlocked = Boolean(
      destHost && blockedList.some(d => destHost === d || CorsairSecurity.sameOrSubdomain(destHost, d))
    );

    // Burst / cooldown signal.
    const burstCount = recordPopupBurst(originHost);
    const burstDetected = burstCount >= POPUP_BURST_THRESHOLD;
    const cooldownActive = isInCooldown(originHost);

    // A single blank tab from an armed source is ambiguous — could
    // be a legitimate "Open in new tab" that then navigates. Only
    // contain it when we ALSO have a burst or cooldown signal.
    const isBlank = !destUrl || destUrl === 'about:blank';

    if (isBlank && !burstDetected && !cooldownActive) {
      // Give the page a moment to fill the URL in. If it stays
      // blank AND the user did not navigate, we leave it.
      return;
    }

    const shouldContain =
      isExplicitlyBlocked ||
      burstDetected ||
      cooldownActive;

    if (!shouldContain) return;

    if (burstDetected || cooldownActive) setCooldown(originHost);

    const reason = isExplicitlyBlocked
      ? 'profile-destination-blocked'
      : (burstDetected || cooldownActive)
        ? 'popup-burst-contained'
        : 'fortress-popup-lockdown';

    await closeTabSafe(newTabId);
    await logContainment({
      type: 'popup_blocked',
      sourceHost: originHost,
      destinationHost: destHost || 'about:blank',
      reason,
      tabId: newTabId
    });
    await notifyContainment('Popup blocked', originHost, destHost);
  } catch {}
});

/* ============================================================
   POPUP DEFENSE — webNavigation layer
   ------------------------------------------------------------
   Still useful for cases where the popup goes through the
   standard navigation pipeline (script-driven window.open).
   Same containment rules as above.
   ============================================================ */
chrome.webNavigation.onCreatedNavigationTarget.addListener(async details => {
  try {
    const sourceTabId = details.sourceTabId;
    const newTabId = details.tabId;
    const url = details.url || '';
    if (!Number.isInteger(sourceTabId) || !Number.isInteger(newTabId)) return;

    const sourceTab = await chrome.tabs.get(sourceTabId).catch(() => null);
    if (!sourceTab?.url) return;

    const originHost = CorsairSecurity.extractHostname(sourceTab.url);
    if (!originHost) return;

    const profile = await CorsairStorage.getProfile(originHost);
    if (!profile || profile.protected !== true || profile.mode !== 'fortress') return;

    const destHost = CorsairSecurity.extractHostname(url);
    const blockedList = Array.isArray(profile.blockedDestinationDomains)
      ? profile.blockedDestinationDomains
      : [];
    const isExplicitlyBlocked = Boolean(
      destHost && blockedList.some(d => destHost === d || CorsairSecurity.sameOrSubdomain(destHost, d))
    );

    const burstCount = recordPopupBurst(originHost);
    const burstDetected = burstCount >= POPUP_BURST_THRESHOLD;
    const cooldownActive = isInCooldown(originHost);

    const shouldContain = isExplicitlyBlocked || burstDetected || cooldownActive;
    if (!shouldContain) return;

    if (burstDetected || cooldownActive) setCooldown(originHost);

    pushRecentTabCreate({ tabId: newTabId, sourceTabId, ts: Date.now() });

    const reason = isExplicitlyBlocked
      ? 'profile-destination-blocked'
      : 'popup-burst-contained';

    await closeTabSafe(newTabId);
    await logContainment({
      type: 'popup_blocked', sourceHost: originHost,
      destinationHost: destHost || 'about:blank',
      reason, tabId: newTabId
    });
    await notifyContainment('Popup blocked', originHost, destHost);
  } catch {}
});
/* ============================================================
   NAVIGATION — onBeforeNavigate
   ============================================================ */
chrome.webNavigation.onBeforeNavigate.addListener(async details => {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  if (!Number.isInteger(tabId)) return;
  try {
    await CorsairRedirects.beginNavigation({
      tabId, frameId: details.frameId, url: details.url,
      initiator: details.initiator || null,
      transitionType: details.transitionType || 'link',
      qualifiers: details.transitionQualifiers || []
    });
  } catch {}
});

/* ============================================================
   NAVIGATION — onCommitted
   ============================================================ */
chrome.webNavigation.onCommitted.addListener(async details => {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  if (!Number.isInteger(tabId)) return;

  try {
    const currentUrlForScript = CorsairSecurity.normalizeUrl(details.url);
    const destinationHostForScript = CorsairSecurity.extractHostname(currentUrlForScript);
    if (destinationHostForScript) {
      runCustomScriptForTab(tabId, destinationHostForScript, currentUrlForScript).catch(() => {});
    }
  } catch {}

  try {
    let chain = await CorsairRedirects.reconcileCommittedHop({
      tabId, frameId: details.frameId, url: details.url,
      qualifiers: details.transitionQualifiers || [],
      transitionType: details.transitionType || 'link'
    });
    if (!chain) chain = await CorsairRedirects.getTabChain(tabId);
    if (!chain || !Array.isArray(chain.hops) || chain.hops.length === 0) return;

    const currentUrl = CorsairSecurity.normalizeUrl(details.url);
    const destinationHost = CorsairSecurity.extractHostname(currentUrl);
    const sourceHost = CorsairSecurity.normalizeHostname(chain.sourceHost);

    maybeAutoScan(tabId, currentUrl).catch(() => {});

    const settings = await CorsairStorage.getSettings();
    const profile = await CorsairStorage.getProfile(sourceHost);
    if (!profile || profile.protected !== true || profile.mode !== 'fortress') return;

    const effectiveProfile = { ...profile, maxRedirectHops: Number(settings.maxRedirectHops) || 8 };
    const threatReport = await CorsairThreatIntel.getCachedReport(destinationHost);
    const recentEvents = await CorsairStorage.getEvents(50);
    const intel = CorsairIntelligence.classifySignals({
      events: recentEvents,
      chain: { ...chain, threatIntel: threatReport },
      destination: destinationHost,
      source: sourceHost, tabId,
      profile: effectiveProfile
    });

    const assessment = CorsairVerifier.evaluateRedirectChain({
      profile: effectiveProfile, chain, intelligence: intel,
      destination: destinationHost, source: sourceHost
    });

    if (assessment.shouldContain) {
      await CorsairDNR.ensureNavigationBlock(sourceHost, destinationHost, assessment.reason).catch(() => {});
      await CorsairStorage.appendEvent({
        type: 'navigation_contained',
        domain: sourceHost, destination: destinationHost,
        reason: assessment.reason, severity: 'high', tabId
      });
      if (assessment.fallbackUrl && typeof chrome.tabs?.update === 'function') {
        chrome.tabs.update(tabId, { url: assessment.fallbackUrl }).catch(() => {});
      }
    }
  } catch {}
});

/* ============================================================
   TABS UPDATED
   ============================================================ */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'loading' || !tab?.url) return;
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
    clearBadge(tabId);
    _scriptedTabs.delete(tabId);
  }
});

/* ============================================================
   TABS REMOVED
   ============================================================ */
chrome.tabs.onRemoved.addListener(async tabId => {
  try {
    if (typeof CorsairObservation !== 'undefined' && typeof CorsairObservation.clear === 'function') {
      await CorsairObservation.clear(tabId);
    }
    const token = await CorsairRedirects.getGenerationToken(tabId);
    await CorsairRedirects.clearChainIfTabClosed(tabId, token);
    _autoScannedTabs.delete(tabId);
    _scriptedTabs.delete(tabId);
    for (const [host, arr] of _popupBurst) {
      const now = Date.now();
      const keep = arr.filter(t => now - t < POPUP_BURST_WINDOW_MS);
      if (keep.length) _popupBurst.set(host, keep);
      else _popupBurst.delete(host);
    }
    purgeRecentTabCreatesFor(tabId);
  } catch {}
});

/* ============================================================
   MESSAGE HANDLER
   ============================================================ */
chrome.runtime.onMessage.addListener((m, s, send) => {
  (async () => {
    try {
      if (!m || typeof m !== 'object' || !m.type) {
        send({ ok: false, error: 'invalid-message' });
        return;
      }

      const capability = classifySender(s);
      if (capability === 'PAGE_OBSERVATION') {
        if (m.type !== 'page-observation' &&
            m.type !== 'content-popup-blocked' &&
            m.type !== 'content-link-allow' &&
            m.type !== 'trust-domain' &&
            m.type !== 'block-domain-global') {
          send({ ok: false, error: 'unauthorized-sender' });
          return;
        }
      } else if (capability !== 'PRIVILEGED_INTERNAL') {
        send({ ok: false, error: 'unauthorized-sender' });
        return;
      }

      switch (m.type) {

        /* ============ BLOCKED PAGE ============ */
        case 'blocked-page-escape': {
          const tabId = s?.tab?.id;
          if (Number.isInteger(tabId)) {
            try {
              await chrome.tabs.update(tabId, { url: 'about:blank' });
            } catch {
              try { await chrome.tabs.remove(tabId); } catch {}
            }
          }
          send({ ok: true });
          break;
        }
        case 'open-dashboard': {
          try {
            await chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
            send({ ok: true });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ CUSTOM SCRIPTS ============ */
        case 'get-custom-scripts': {
          try { send({ ok: true, scripts: await listCustomScripts() }); }
          catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'upsert-custom-script': {
          try { send(await upsertCustomScript(m.host || '', { code: m.code, enabled: m.enabled })); }
          catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'remove-custom-script': {
          try { send(await removeCustomScript(m.host || '')); }
          catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'toggle-custom-script': {
          try { send(await upsertCustomScript(m.host || '', { enabled: m.enabled !== false })); }
          catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ LANGUAGE ============ */
        case 'get-language': {
          try {
            const r = await chrome.storage.local.get('language');
            send({ ok: true, language: r.language || 'en' });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'set-language': {
          try {
            await chrome.storage.local.set({ language: String(m.language || 'en') });
            send({ ok: true });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ TRUST ============ */
        case 'trust-domain': { send(await trustDomain(m.host || '') || { ok: true }); break; }
        case 'untrust-domain': { send(await untrustDomain(m.host || '') || { ok: true }); break; }
        case 'block-domain-global': { send(await blockDomainGlobally(m.host || '') || { ok: true }); break; }
        case 'unblock-domain-global': { send(await unblockDomainGlobally(m.host || '') || { ok: true }); break; }
        case 'get-user-blocked': {
          const list = await CorsairStorage.get('userBlockedDomains', []);
          send({ ok: true, domains: Array.isArray(list) ? list : [] });
          break;
        }
        case 'get-user-trusted': {
          const list = await CorsairStorage.get('userTrustedDomains', []);
          send({ ok: true, domains: Array.isArray(list) ? list : [] });
          break;
        }

        /* ============ CONTENT ============ */
        case 'content-popup-blocked': {
          const pageHost = CorsairSecurity.extractHostname(m.page || '') || CorsairSecurity.normalizeHostname(m.host || '');
          const destHost = CorsairSecurity.extractHostname(m.url || '') || CorsairSecurity.normalizeHostname(m.url || '');
          await logContainment({
            type: 'popup_blocked', sourceHost: pageHost,
            destinationHost: destHost || 'about:blank',
            reason: String(m.reason || 'content-popup-blocked').slice(0, 60),
            tabId: s?.tab?.id || null
          });
          send({ ok: true });
          break;
        }
        case 'content-link-allow': {
          const src = CorsairSecurity.normalizeHostname(m.source || '');
          const dst = CorsairSecurity.normalizeHostname(m.destination || '');
          if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) {
            send({ ok: false, error: 'invalid-domain' });
            break;
          }
          if (src === dst || CorsairSecurity.sameOrSubdomain(dst, src)) {
            send({ ok: true, skipped: 'same-origin' });
            break;
          }
          try {
            const res = await CorsairDNR.installFortressAllow(src, dst, 15000);
            if (res && res.ok && Number.isInteger(res.ruleId)) {
              CorsairAlarms.scheduleFortressAllowExpiry(res.ruleId, 15000).catch(() => {});
            }
            send(res || { ok: true });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ THREAT INTEL ============ */
        case 'query-threat-intel': {
          const host = CorsairSecurity.normalizeHostname(m.domain || '');
          if (!host || !CorsairSecurity.isValidHostname(host)) { send({ ok: false, error: 'invalid-domain' }); break; }
          try {
            const report = await CorsairThreatIntel.queryDomain(host, { force: m.force === true });
            const tabId = s?.tab?.id;
            if (Number.isInteger(tabId) && report && report.status !== 'error') {
              const settings = await CorsairStorage.getSettings();
              if (settings.siteVerdictBanner) await pushVerdictToTab(tabId, report);
            }
            if (report && report.status !== 'error') {
              maybeAutoArmFortress(host, report).catch(() => {});
            }
            send({ ok: true, report });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'deep-scan-domain': {
          const host = CorsairSecurity.normalizeHostname(m.domain || '');
          if (!host || !CorsairSecurity.isValidHostname(host)) {
            send({ ok: false, error: 'invalid-domain' });
            break;
          }
          try {
            const report = await CorsairThreatIntel.deepScan(host);
            send({ ok: true, report });
          } catch (err) {
            send({ ok: false, error: err.message });
          }
          break;
        }
        case 'get-threat-intel': {
          const host = CorsairSecurity.normalizeHostname(m.domain || '');
          send({ ok: true, report: await CorsairThreatIntel.getCachedReport(host) });
          break;
        }
        case 'assess-heuristics': {
          const host = CorsairSecurity.normalizeHostname(m.domain || '');
          if (!host) { send({ ok: false, error: 'invalid-domain' }); break; }
          const report = await CorsairThreatIntel.getCachedReport(host);
          const result = CorsairHeuristics.analyze(host, { creationDate: report?.creationDate || null });
          send({ ok: true, heuristics: result });
          break;
        }
        case 'clear-threat-cache': { await CorsairThreatIntel.clearCache(); send({ ok: true }); break; }
        case 'scan-url': {
          try {
            const result = await CorsairThreatIntel.scanUrl(m.url || '');
            send({ ok: true, result });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ SAFE SCANNED ============ */
        case 'get-safe-scanned-domains': { send({ ok: true, domains: await listSafeScannedDomains() }); break; }
        case 'remove-safe-scanned-domain': { send(await removeSafeScannedDomain(m.domain || '') || { ok: true }); break; }
        case 'bulk-remove-safe-scanned': { send(await bulkRemoveSafeScanned(m.hosts || []) || { ok: true }); break; }
        case 'clear-safe-scanned-domains': { send(await clearSafeScannedDomains() || { ok: true }); break; }
        case 'export-safe-list': {
          const domains = await listSafeScannedDomains();
          send({
            ok: true,
            export: {
              format: 'corsair-safe-list', version: 1,
              exportedAt: Date.now(),
              domains: domains.map(d => ({ host: d.host, stats: d.stats, lastChecked: d.lastChecked }))
            }
          });
          break;
        }
        case 'import-safe-list': {
          try {
            const payload = m.data || {};
            if (payload.format !== 'corsair-safe-list') throw new Error('invalid-format');
            const incoming = Array.isArray(payload.domains) ? payload.domains : [];
            const cache = await CorsairStorage.get('threatCache', {});
            let added = 0;
            for (const item of incoming) {
              const h = CorsairSecurity.normalizeHostname(item.host || '');
              if (!h || !CorsairSecurity.isValidHostname(h)) continue;
              if (!cache[h]) {
                cache[h] = {
                  host: h, status: 'analyzed', verdict: 'clean',
                  riskPercentage: Number(item.stats?.malicious || 0) * 25,
                  flaggedEngines: [],
                  stats: item.stats || { harmless: 0, malicious: 0, suspicious: 0, undetected: 0 },
                  lastChecked: Number(item.lastChecked) || Date.now()
                };
                added++;
              }
            }
            await CorsairStorage.set('threatCache', cache);
            send({ ok: true, imported: added, total: incoming.length });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ WHITELIST ============ */
        case 'get-allowlist-stats': {
          try { await CorsairThreatIntel.loadRemoteAllowlist(); } catch {}
          send({ ok: true, stats: CorsairThreatIntel.getAllowlistSize() });
          break;
        }
        case 'sync-whitelist': {
          try {
            const r = await CorsairThreatIntel.refreshRemoteAllowlist();
            send({ ok: true, result: r, stats: CorsairThreatIntel.getAllowlistSize() });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ STORAGE ============ */
        case 'get-storage-usage': {
          try {
            const total = await CorsairStorage.estimateTotalStorageBytes(true);
            const profileCount = Object.keys(await CorsairStorage.getProfiles()).length;
            const userTrusted = await CorsairStorage.get('userTrustedDomains', []);
            const userBlocked = await CorsairStorage.get('userBlockedDomains', []);
            const cache = await CorsairStorage.get('threatCache', {});
            const safeCount = Object.values(cache).filter(r => r?.verdict === 'clean' && r?.status !== 'allowlisted').length;
            const customScripts = await CorsairStorage.get('customDomainScripts', {});
            send({
              ok: true,
              usage: {
                totalBytes: total.total,
                breakdown: total.byKey,
                profileCount,
                userTrustedCount: Array.isArray(userTrusted) ? userTrusted.length : 0,
                userBlockedCount: Array.isArray(userBlocked) ? userBlocked.length : 0,
                safeScannedCount: safeCount,
                threatCacheCount: Object.keys(cache || {}).length,
                customScriptsCount: Object.keys(customScripts || {}).length
              }
            });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'wipe-all-data': {
          try {
            await CorsairStorage.withTransactionGateExclusive(async () => {
              if (typeof chrome !== 'undefined' && chrome.storage?.local) await chrome.storage.local.clear();
              if (typeof chrome !== 'undefined' && chrome.storage?.session) await chrome.storage.session.clear();
            });
            send({ ok: true });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ CONFIG ============ */
        case 'export-config': {
          const exportData = await CorsairMigration.exportConfiguration();
          send({ ok: true, export: exportData, data: exportData });
          break;
        }
        case 'import-config': {
          const importRes = await CorsairMigration.executeImportTransaction({
            ...(m.data || m.candidate || {}),
            restoreTelemetry: m.restoreTelemetry === true
          });
          send(importRes);
          break;
        }

        /* ============ PROFILES ============ */
        case 'get-profiles': { send({ ok: true, profiles: await CorsairStorage.getProfiles() }); break; }
        case 'get-profile': {
          const host = CorsairSecurity.normalizeHostname(m.domain);
          send({ ok: true, profile: await CorsairStorage.getProfile(host) });
          break;
        }
        case 'patch-profile': {
          const host = CorsairSecurity.normalizeHostname(m.domain);
          const safePatch = CorsairSecurity.sanitizeObject(m.patch) || {};
          send(await CorsairDNR.patchProfileAtomic(host, current => ({
            ...(current || CorsairSecurity.fortressProfile({})),
            ...safePatch
          })));
          break;
        }
        case 'remove-profile': {
          const host = CorsairSecurity.normalizeHostname(m.domain);
          const result = await CorsairStorage.withTransactionGateExclusive(async () => {
            const snapshot = await CorsairStorage.getProfile(host);
            if (!snapshot) return { ok: true, removed: false };
            await CorsairStorage.withMultiPartitionLock(['dnrRuleRegistry', 'domainProfiles'], async () => {
              return CorsairDNR.withDnrLock(() => CorsairDNR.removeRulesForHostUnlocked(host));
            });
            await CorsairStorage.removeProfileUnlocked(host);
            await CorsairStorage.appendEventUnlocked({ type: 'domain_removed', domain: host, severity: 'info' });
            return { ok: true, removed: true };
          });
          try { await CorsairDNR.reconcileDnrRegistry(); } catch {}
          send(result);
          break;
        }

        /* ============ SETTINGS ============ */
        case 'get-settings': { send({ ok: true, settings: await CorsairStorage.getSettings() }); break; }
        case 'patch-settings': { send({ ok: true, settings: await CorsairStorage.patchSettings(m.patch) }); break; }
        case 'get-api-key-secure': {
          try { send({ ok: true, apiKey: await CorsairStorage.getApiKeySecure() }); }
          catch (err) { send({ ok: false, error: err.message }); }
          break;
        }
        case 'set-api-key-secure': {
          try {
            await CorsairStorage.setApiKeySecure(m.apiKey || '');
            send({ ok: true });
          } catch (err) { send({ ok: false, error: err.message }); }
          break;
        }

        /* ============ TELEMETRY ============ */
        case 'get-events': { send({ ok: true, events: await CorsairStorage.getEvents(m.limit || 200) }); break; }
        case 'clear-events': { await CorsairStorage.clearEvents(); send({ ok: true }); break; }
        case 'get-graph': { send({ ok: true, graph: await CorsairStorage.getGraph() }); break; }
        case 'clear-telemetry': { await CorsairStorage.clearTransientTelemetry(); send({ ok: true }); break; }
        case 'get-evidence': {
          const evidence = typeof CorsairEvidence !== 'undefined'
            ? (Number.isInteger(m.tabId) ? await CorsairEvidence.byTab(m.tabId, m.limit) : await CorsairEvidence.recent(m.limit))
            : [];
          send({ ok: true, evidence });
          break;
        }
        case 'clear-evidence': {
          if (typeof chrome !== 'undefined' && chrome.storage?.local) {
            await CorsairStorage.withTransactionGateShared(async () => {
              await CorsairStorage.withPartitionLock('evidenceStore', async () => {
                await chrome.storage.local.set({ evidenceStore: [] });
              });
            });
          }
          send({ ok: true });
          break;
        }
        case 'get-network-observation': {
          const obs = (typeof CorsairObservation !== 'undefined' && Number.isInteger(m.tabId))
            ? await CorsairObservation.get(m.tabId) : [];
          const limit = Math.max(1, Math.min(500, Number(m.limit) || obs.length));
          send({ ok: true, observation: obs.slice(-limit) });
          break;
        }
        case 'clear-network-observation': {
          if (typeof CorsairObservation !== 'undefined' && Number.isInteger(m.tabId)) {
            await CorsairObservation.clear(m.tabId);
          }
          send({ ok: true });
          break;
        }

        /* ============ RISK ============ */
        case 'assess-domain-risk': {
          const domain = CorsairSecurity.normalizeHostname(m.domain || '');
          if (!domain || !CorsairSecurity.isValidHostname(domain)) { send({ ok: false, error: 'invalid-domain' }); break; }
          const [profile, events, chains, threatIntel, settings2] = await Promise.all([
            CorsairStorage.getProfile(domain),
            CorsairStorage.getEvents(500),
            CorsairStorage.getChains(200),
            CorsairThreatIntel.getCachedReport(domain),
            CorsairStorage.getSettings()
          ]);
          const effectiveProfile = { ...(profile || {}), maxRedirectHops: Number(settings2.maxRedirectHops) || 8 };
          const relevantEvents = events.filter(e => {
            const a = CorsairSecurity.normalizeHostname(e.domain || '');
            const b = CorsairSecurity.normalizeHostname(e.destination || '');
            return a === domain || b === domain;
          });
          const chain = chains.find(c => CorsairSecurity.normalizeHostname(c.sourceHost || '') === domain) || null;
          const destination = chain?.committedUrl ? CorsairSecurity.extractHostname(chain.committedUrl) : '';
          const assessment = CorsairIntelligence.classifySignals({
            events: relevantEvents, chain, destination, source: domain,
            tabId: Number.isInteger(m.tabId) ? m.tabId : null,
            profile: { ...effectiveProfile, threatIntel }
          });
          send({ ok: true, assessment });
          break;
        }
        case 'get-regression-cases': { send({ ok: true, cases: await CorsairStorage.getRegressionCases() }); break; }
        case 'run-regressions': { send({ ok: true, result: await CorsairReplay.runAll() }); break; }

        /* ============ DIAGNOSTICS ============ */
        case 'get-diagnostics': {
          const [settings, profiles, dnrRules, dnrRegistry, graph, totalStorage] = await Promise.all([
            CorsairStorage.getSettings(),
            CorsairStorage.getProfiles(),
            CorsairDNR.listCorsairRules(),
            CorsairStorage.getDnrRegistry(),
            CorsairStorage.getGraph(),
            CorsairStorage.estimateTotalStorageBytes()
          ]);
          const fortressRules = await CorsairDNR.listFortressCatchAllRules();
          send({
            ok: true,
            diagnostics: {
              settings,
              profileCount: Object.keys(profiles || {}).length,
              dnrRuleCount: dnrRules.length,
              fortressCatchAllCount: fortressRules.length,
              dnrRegistryNextId: dnrRegistry.nextId,
              graphNodeCount: Object.keys(graph.nodes || {}).length,
              graphEdgeCount: (graph.edges || []).length,
              totalStorageBytes: totalStorage.total,
              storageBreakdown: totalStorage.byKey
            }
          });
          break;
        }
        case 'get-agent-context': {
          const ctx = await CorsairStorage.getAgentContext({ domain: m.domain || '', limit: m.limit || 50 });
          send({ ok: true, context: ctx });
          break;
        }
        case 'fortress-allow': {
          const src = CorsairSecurity.normalizeHostname(m.source || '');
          const dst = CorsairSecurity.normalizeHostname(m.destination || '');
          if (!CorsairSecurity.isValidHostname(src) || !CorsairSecurity.isValidHostname(dst)) {
            send({ ok: false, error: 'invalid-domain' });
            break;
          }
          const ttl = Math.max(5000, Math.min(300000, Number(m.ttlMs) || 60000));
          const res = await CorsairDNR.installFortressAllow(src, dst, ttl);
          if (res && res.ok && Number.isInteger(res.ruleId)) {
            CorsairAlarms.scheduleFortressAllowExpiry(res.ruleId, ttl).catch(() => {});
          }
          send(res);
          break;
        }
        case 'page-observation': {
          const obs = m.observation;
          if (!obs || typeof obs !== 'object' || !obs.url) { send({ ok: false, error: 'invalid-observation-payload' }); break; }
          if (s.tab?.id && Number.isInteger(s.tab.id)) {
            const tabChain = await CorsairRedirects.getTabChain(s.tab.id);
            if (tabChain) {
              tabChain.clickbaitScore = Number(obs.clickbaitScore) || 0;
              tabChain.clickbaitTriggers = Array.isArray(obs.clickbaitTriggers) ? obs.clickbaitTriggers : [];
              await CorsairRedirects.setTabChain(s.tab.id, tabChain);
            }
          }
          send({ ok: true });
          break;
        }

        /* ============ UPDATER ============ */
        case 'check-for-update': {
          try {
            const r = await CorsairUpdater.checkForUpdates({ force: m.force === true });
            send({ ok: true, result: r });
          } catch (err) {
            send({ ok: false, error: err.message });
          }
          break;
        }
        case 'download-update': {
          try {
            const r = await CorsairUpdater.downloadUpdateZip();
            send(r);
          } catch (err) {
            send({ ok: false, error: err.message });
          }
          break;
        }

        default: { send({ ok: false, error: 'unknown-message-type' }); break; }
      }
    } catch (err) { send({ ok: false, error: err.message }); }
  })();
  return true;
});