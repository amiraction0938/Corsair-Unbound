/* ============================================================
   CORSAIR UNBOUND — UPDATER (PATH A)
   ------------------------------------------------------------
   The extension's ONLY job:
     • Fetch latest.json from GitHub Releases
     • Compare installed version with latest stable
     • Show the user what's available + where to get the launcher
     • Detect "we just got updated" (via getManifest().version)
     • Log extension_updated events for the Activity Log

   The extension DOES NOT download the ZIP itself.
   The Windows launcher (launcher/updater.ps1) handles:
     • Fetching latest.json again for its own use
     • Downloading the release ZIP exactly once
     • SHA-256 verification against latest.json.sha256
     • Backup / extraction / file replacement
     • Opening chrome://extensions for the Reload step
   ============================================================ */
const CorsairUpdater = (() => {
  'use strict';

  const GITHUB_USER = 'amiraction0938';
  const GITHUB_REPO = 'Corsair-Unbound';
  const REPO_URL = `https://github.com/${GITHUB_USER}/${GITHUB_REPO}`;
  const RELEASES_URL = `${REPO_URL}/releases`;
  const LATEST_JSON_URL = `${REPO_URL}/releases/latest/download/latest.json`;
  const LAUNCHER_URL = `${REPO_URL}/releases/latest/download/corsair-unbound-updater.ps1`;

  const CHECK_TTL_MS = 60 * 60 * 1000;          // 1 hour
  const CACHE_KEY = 'updaterV2Cache';
  const ALARM_NAME = 'corsair-update-check-v2';
  const NOTIFIED_KEY = 'updaterV2LastNotifiedVersion';
  const INSTALLED_AT_KEY = 'updaterV2LastInstalledVersion';

  const EXPECTED_ASSET_NAME = 'corsair-unbound-extension.zip';
  const STABLE_TAG_RE = /^v\d+\.\d+\.\d+$/;

  const ALLOWED_DOWNLOAD_PREFIXES = [
    `https://github.com/${GITHUB_USER}/${GITHUB_REPO}/`,
    'https://objects.githubusercontent.com/'
  ];

  /* ============================================================
     VERSION HELPERS
     ============================================================ */
  function parseVersion(str) {
    const m = String(str || '').trim().match(/^[vV]?(\d+)\.(\d+)\.(\d+)$/);
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
     FETCH latest.json
     ------------------------------------------------------------
     Every field is validated before anything is trusted:
       version       — must parse as MAJOR.MINOR.PATCH
       tag           — must be exactly 'v' + version
       stable tag    — must match /^v\d+\.\d+\.\d+$/
       download_url  — must be on our repo's release asset hosts
       asset name    — must be exactly corsair-unbound-extension.zip
       sha256        — must be exactly 64 lowercase hex chars
       published_at  — if present, must parse as ISO 8601
       mandatory     — optional boolean, default false
     Any failure → thrown error. No insecure fallback.
     ============================================================ */
  async function fetchLatestManifest() {
    const res = await fetch(LATEST_JSON_URL, { cache: 'no-store' });
    if (!res.ok) throw new Error(`latest-json-http-${res.status}`);

    let json;
    try { json = await res.json(); }
    catch { throw new Error('latest-json-invalid-json'); }

    if (!json || typeof json !== 'object' || Array.isArray(json)) {
      throw new Error('latest-json-not-object');
    }

    // ---- version ----
    const parsed = parseVersion(json.version);
    if (!parsed) throw new Error('latest-json-bad-version');

    // ---- tag must be exactly v + version ----
    const tag = String(json.tag || '').trim();
    if (tag !== `v${parsed.str}`) throw new Error('latest-json-tag-mismatch');
    if (!STABLE_TAG_RE.test(tag)) throw new Error('latest-json-not-stable');

    // ---- download_url ----
    const downloadUrl = String(json.download_url || '').trim();
    if (!downloadUrl) throw new Error('latest-json-no-url');
    if (!ALLOWED_DOWNLOAD_PREFIXES.some(p => downloadUrl.startsWith(p))) {
      throw new Error('latest-json-untrusted-url');
    }
    try {
      const u = new URL(downloadUrl);
      const lastSegment = u.pathname.split('/').filter(Boolean).pop() || '';
      if (lastSegment !== EXPECTED_ASSET_NAME) {
        throw new Error('latest-json-wrong-asset');
      }
    } catch (e) {
      if (e.message === 'latest-json-wrong-asset') throw e;
      throw new Error('latest-json-bad-url');
    }

    // ---- sha256: exactly 64 lowercase hex ----
    const sha256 = String(json.sha256 || '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      throw new Error('latest-json-bad-sha256');
    }

    // ---- published_at (optional but if present must be valid) ----
    const publishedAt = String(json.published_at || '');
    if (publishedAt && Number.isNaN(Date.parse(publishedAt))) {
      throw new Error('latest-json-bad-date');
    }

    // ---- notes (optional, capped) ----
    const notes = String(json.notes || '').slice(0, 4000);

    // ---- mandatory (optional) ----
    const mandatory = json.mandatory === true;

    return {
      version: parsed.str,
      tag,
      downloadUrl,
      sha256,
      publishedAt,
      notes,
      mandatory
    };
  }

  /* ============================================================
     PUBLIC: checkForUpdates
     ============================================================ */
  async function checkForUpdates({ force = false } = {}) {
    const current = getCurrentVersion();

    // Cache hit (only when not forced)
    if (!force) {
      try {
        const cached = (await chrome.storage.local.get(CACHE_KEY))[CACHE_KEY];
        if (cached && Date.now() - (cached.checkedAt || 0) < CHECK_TTL_MS) {
          return { ...cached, current, cached: true };
        }
      } catch {}
    }

    try {
      const manifest = await fetchLatestManifest();
      const cmp = compareVersions(manifest.version, current);

      const result = {
        current,
        latest: manifest.version,
        tag: manifest.tag,
        hasUpdate: cmp > 0,
        isAhead: cmp < 0,
        upToDate: cmp === 0,
        source: 'latest-json',
        repoUrl: REPO_URL,
        releaseUrl: `${RELEASES_URL}/tag/${manifest.tag}`,
        releaseBody: manifest.notes,
        publishedAt: manifest.publishedAt,
        zipUrl: manifest.downloadUrl,
        zipName: EXPECTED_ASSET_NAME,
        expectedSha256: manifest.sha256,
        mandatory: manifest.mandatory,
        checkedAt: Date.now(),
        error: null
      };

      try { await chrome.storage.local.set({ [CACHE_KEY]: result }); } catch {}
      return result;
    } catch (err) {
      // No insecure fallback. Return last known good cache (marked stale)
      // or an explicit error result. Never silently accept a raw manifest
      // from the branch tip.
      try {
        const cached = (await chrome.storage.local.get(CACHE_KEY))[CACHE_KEY];
        if (cached) {
          return { ...cached, current, cached: true, stale: true, error: err.message };
        }
      } catch {}

      return {
        current,
        latest: null,
        hasUpdate: false,
        isAhead: false,
        upToDate: false,
        source: 'none',
        repoUrl: REPO_URL,
        releaseUrl: RELEASES_URL,
        releaseBody: '',
        publishedAt: null,
        zipUrl: null,
        zipName: null,
        expectedSha256: null,
        mandatory: false,
        checkedAt: Date.now(),
        error: err.message
      };
    }
  }

  /* ============================================================
     BACKGROUND: notification + alarm
     ============================================================ */
  async function notifyIfUpdateAvailable(result) {
    if (!result?.hasUpdate || !result.latest) return false;

    // Don't spam the same version twice.
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
        message: `You have v${result.current}. Open the dashboard to update.`,
        priority: 1,
        requireInteraction: false,
        buttons: [{ title: 'Open Dashboard' }]
      });
      await chrome.storage.local.set({ [NOTIFIED_KEY]: result.latest });
      return true;
    } catch { return false; }
  }

  async function scheduleBackgroundCheck() {
    if (typeof chrome === 'undefined' || !chrome.alarms?.create) return;
    try {
      await chrome.alarms.create(ALARM_NAME, { periodInMinutes: 6 * 60 });
    } catch {}
  }

  async function runBackgroundCheck() {
    try {
      const r = await checkForUpdates({ force: true });
      if (r?.hasUpdate) await notifyIfUpdateAvailable(r);
      return r;
    } catch { return null; }
  }

  /* ============================================================
     INSTALLED VERSION MIGRATION (called from background.js)
     ------------------------------------------------------------
     Writes to `updaterV2LastInstalledVersion`. Dashboard uses a
     DIFFERENT key (`updaterV2DashboardSeenVersion`) so the toast
     can be shown even after background has already logged the
     event. See dashboard.js detectExtensionUpdate().
     ============================================================ */
  async function recordInstalledVersion() {
    const current = getCurrentVersion();
    try {
      const r = await chrome.storage.local.get(INSTALLED_AT_KEY);
      const prev = r[INSTALLED_AT_KEY] || null;
      if (prev !== current) {
        await chrome.storage.local.set({
          [INSTALLED_AT_KEY]: current,
          updaterLastUpdatedAt: Date.now()
        });
        return { changed: true, from: prev, to: current };
      }
      return { changed: false, version: current };
    } catch {
      return { changed: false, version: current };
    }
  }

  /* ============================================================
     PATH-A STUBS — back-compat only
     ------------------------------------------------------------
     dashboard.js does NOT call these in Path A. background.js
     still has handlers for 'download-update' and
     'reveal-downloaded-file'. Those handlers should be removed
     when background.js is updated. These stubs return an error
     so nothing crashes if the old handlers are still present.
     ============================================================ */
  async function downloadUpdateZip() {
    return {
      ok: false,
      error: 'path-a-no-download',
      message: 'Path A does not download the ZIP inside the extension. Use the Windows launcher.'
    };
  }

  async function revealDownloadedFile() {
    return {
      ok: false,
      error: 'path-a-no-download',
      message: 'Path A does not download the ZIP inside the extension.'
    };
  }

  async function openDownloadsFolder() {
    if (typeof chrome === 'undefined' || !chrome.downloads?.showDefaultFolder) {
      return { ok: false, error: 'downloads-unavailable' };
    }
    try {
      await chrome.downloads.showDefaultFolder();
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /* ============================================================
     EXPORTS
     ============================================================ */
  return {
    // Public API
    checkForUpdates,
    notifyIfUpdateAvailable,
    scheduleBackgroundCheck,
    runBackgroundCheck,
    recordInstalledVersion,
    getCurrentVersion,
    compareVersions,
    parseVersion,

    // Path-A stubs (back-compat with old background.js handlers)
    downloadUpdateZip,
    revealDownloadedFile,
    openDownloadsFolder,

    // Constants — used by dashboard.js and background.js
    GITHUB_USER,
    GITHUB_REPO,
    repoUrl: REPO_URL,
    releasesUrl: RELEASES_URL,
    latestJsonUrl: LATEST_JSON_URL,
    launcherDownloadUrl: LAUNCHER_URL,
    ALARM_NAME,
    EXPECTED_ASSET_NAME
  };
})();

globalThis.CorsairUpdater = CorsairUpdater;