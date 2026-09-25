/* ============================================================
   CORSAIR UNBOUND — UPDATER
   ------------------------------------------------------------
   Handles:
     - periodic version check against GitHub
     - desktop notifications on new release
     - download of the new version ZIP
     - install instructions state

   NOTE: unpacked Chrome extensions cannot self-replace their
   files. The best we can do is notify + download + guide. Data
   in chrome.storage.local is preserved across manual reloads,
   so user settings/profiles/cache survive the update.
   ============================================================ */
const CorsairUpdater = (() => {
  'use strict';

  const GITHUB_USER = 'amiraction0938';
  const GITHUB_REPO = 'Corsair-Unbound';
  const GITHUB_BRANCH = 'main';
  const REPO_URL = `https://github.com/${GITHUB_USER}/${GITHUB_REPO}`;
  const MANIFEST_URL =
    `https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/manifest.json`;
  const ZIP_URL =
    `https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.zip`;

  const CHECK_TTL_MS = 6 * 60 * 60 * 1000;      // 6h
  const CACHE_KEY = 'versionCheckCache';
  const ALARM_NAME = 'corsair-update-check';
  const NOTIFIED_KEY = 'updaterLastNotifiedVersion';
  const INSTALLED_AT_KEY = 'updaterLastInstalledVersion';

  /* ============================================================
     VERSION HELPERS
     ============================================================ */
  function parseVersion(str) {
    const m = String(str || '').trim().match(/^(\d+)\.(\d+)\.(\d+)/);
    if (!m) return null;
    return {
      major: Number(m[1]),
      minor: Number(m[2]),
      patch: Number(m[3]),
      str: `${m[1]}.${m[2]}.${m[3]}`
    };
  }

  function compareVersions(a, b) {
    const va = parseVersion(a);
    const vb = parseVersion(b);
    if (!va || !vb) return 0;
    if (va.major !== vb.major) return va.major - vb.major;
    if (va.minor !== vb.minor) return va.minor - vb.minor;
    return va.patch - vb.patch;
  }

  function getCurrentVersion() {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime?.getManifest) {
        return String(chrome.runtime.getManifest().version || '0.0.0');
      }
    } catch {}
    return '0.0.0';
  }

  /* ============================================================
     CACHE
     ============================================================ */
  async function getCache() {
    try {
      const r = await chrome.storage.local.get(CACHE_KEY);
      return r[CACHE_KEY] || null;
    } catch { return null; }
  }

  async function setCache(data) {
    try { await chrome.storage.local.set({ [CACHE_KEY]: data }); } catch {}
  }

  /* ============================================================
     UPDATE CHECK
     ============================================================ */
  async function checkForUpdates({ force = false } = {}) {
    const current = getCurrentVersion();
    const cached = await getCache();

    if (!force && cached && (Date.now() - (cached.checkedAt || 0)) < CHECK_TTL_MS) {
      return { ...cached, current, cached: true };
    }

    try {
      const res = await fetch(MANIFEST_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const latest = String(data.version || '').trim();
      if (!latest) throw new Error('Missing version in remote manifest');

      const cmp = compareVersions(latest, current);
      const result = {
        current,
        latest,
        hasUpdate: cmp > 0,
        isAhead: cmp < 0,
        upToDate: cmp === 0,
        repoUrl: REPO_URL,
        zipUrl: ZIP_URL,
        checkedAt: Date.now(),
        error: null
      };
      await setCache(result);

      // Record the first-install baseline for future migrations
      try {
        const installed = await chrome.storage.local.get(INSTALLED_AT_KEY);
        if (!installed[INSTALLED_AT_KEY]) {
          await chrome.storage.local.set({ [INSTALLED_AT_KEY]: current });
        }
      } catch {}

      return result;
    } catch (err) {
      const fallback = {
        current,
        latest: cached?.latest || null,
        hasUpdate: cached?.hasUpdate || false,
        isAhead: cached?.isAhead || false,
        upToDate: cached?.upToDate || false,
        repoUrl: REPO_URL,
        zipUrl: ZIP_URL,
        checkedAt: cached?.checkedAt || 0,
        error: err.message || 'check-failed'
      };
      return fallback;
    }
  }

  /* ============================================================
     DESKTOP NOTIFICATION
     ============================================================ */
  async function notifyIfUpdateAvailable(result) {
    if (!result || !result.hasUpdate || !result.latest) return false;

    // Don't spam — only notify once per version
    try {
      const r = await chrome.storage.local.get(NOTIFIED_KEY);
      if (r[NOTIFIED_KEY] === result.latest) return false;
    } catch {}

    if (typeof chrome === 'undefined' || !chrome.notifications?.create) return false;

    try {
      await chrome.notifications.create('corsair-update-' + result.latest, {
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: `Corsair Unbound v${result.latest} is available`,
        message: `You have v${result.current}. Click to download and install.`,
        priority: 1,
        requireInteraction: false,
        buttons: [{ title: 'Open Dashboard' }]
      });
      await chrome.storage.local.set({ [NOTIFIED_KEY]: result.latest });
      return true;
    } catch { return false; }
  }

  /* ============================================================
     DOWNLOAD UPDATE ZIP
     ============================================================ */
  async function downloadUpdateZip() {
    if (typeof chrome === 'undefined' || !chrome.downloads?.download) {
      return { ok: false, error: 'downloads-unavailable' };
    }
    try {
      const id = await chrome.downloads.download({
        url: ZIP_URL,
        filename: `corsair-unbound-${GITHUB_BRANCH}.zip`,
        saveAs: false,
        conflictAction: 'overwrite'
      });
      return { ok: true, downloadId: id };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /* ============================================================
     PERIODIC BACKGROUND CHECK (alarms)
     ============================================================ */
  async function scheduleBackgroundCheck() {
    if (typeof chrome === 'undefined' || !chrome.alarms?.create) return;
    try {
      await chrome.alarms.create(ALARM_NAME, { periodInMinutes: 6 * 60 });
    } catch {}
  }

  async function runBackgroundCheck() {
    try {
      const result = await checkForUpdates({ force: true });
      if (result && result.hasUpdate) {
        await notifyIfUpdateAvailable(result);
      }
      return result;
    } catch { return null; }
  }

  /* ============================================================
     MIGRATION HELPER
     ------------------------------------------------------------
     Called on startup. If the running version is different from
     the last recorded "installed" version, we know the user just
     replaced the files. Defaults for any NEW settings keys are
     automatically merged by CorsairStorage.ensureReady().
     ============================================================ */
  async function recordInstalledVersion() {
    const current = getCurrentVersion();
    try {
      const r = await chrome.storage.local.get(INSTALLED_AT_KEY);
      const previous = r[INSTALLED_AT_KEY] || null;
      if (previous !== current) {
        await chrome.storage.local.set({
          [INSTALLED_AT_KEY]: current,
          updaterLastUpdatedAt: Date.now()
        });
        return { changed: true, from: previous, to: current };
      }
      return { changed: false, version: current };
    } catch {
      return { changed: false, version: current };
    }
  }

  return {
    // Public API
    checkForUpdates,
    notifyIfUpdateAvailable,
    downloadUpdateZip,
    scheduleBackgroundCheck,
    runBackgroundCheck,
    recordInstalledVersion,
    getCurrentVersion,
    compareVersions,
    parseVersion,

    // Constants for UI
    GITHUB_USER,
    GITHUB_REPO,
    GITHUB_BRANCH,
    repoUrl: REPO_URL,
    zipUrl: ZIP_URL,
    ALARM_NAME
  };
})();

globalThis.CorsairUpdater = CorsairUpdater;