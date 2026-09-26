/* ============================================================
   CORSAIR UNBOUND — UPDATER
   ------------------------------------------------------------
   Checks for updates via the GitHub Releases API, downloads
   the latest published ZIP, and guides the user through a
   data-preserving manual reload.

   IMPORTANT — what this can and cannot do:

     ✅ Check for new releases (GitHub API)
     ✅ Show a desktop notification + dashboard banner
     ✅ Download the release ZIP asset with one click
     ✅ Open the file in Explorer / Finder
     ✅ Guide the user to chrome://extensions
     ❌ Cannot replace its own files (Chrome blocks it)
     ❌ Cannot reload itself (Chrome blocks it)
     ❌ Cannot run install scripts (Chrome blocks it)

   Unpacked Chrome extensions require a manual reload. Users'
   data lives in chrome.storage.local, NOT in the extension
   files — so it survives every update automatically.
   ============================================================ */
const CorsairUpdater = (() => {
  'use strict';

  const GITHUB_USER = 'amiraction0938';
  const GITHUB_REPO = 'Corsair-Unbound';
  const GITHUB_BRANCH = 'main';
  const REPO_URL = `https://github.com/${GITHUB_USER}/${GITHUB_REPO}`;
  const RELEASES_URL = `${REPO_URL}/releases`;
  const LATEST_RELEASE_API = `https://api.github.com/repos/${GITHUB_USER}/${GITHUB_REPO}/releases/latest`;

  // Fallback source: raw manifest.json on the main branch.
  // Only used when the Releases API is unavailable (rate limit,
  // network hiccup, or the repo has no published releases yet).
  const MANIFEST_FALLBACK_URL =
    `https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/manifest.json`;

  // Fallback download if no release asset is available. Downloads
  // the branch tip as a ZIP. Less ideal but keeps the flow working.
  const BRANCH_ZIP_FALLBACK_URL =
    `https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.zip`;

  const CHECK_TTL_MS = 6 * 60 * 60 * 1000;      // 6h cache
  const CACHE_KEY = 'versionCheckCache';
  const ALARM_NAME = 'corsair-update-check';
  const NOTIFIED_KEY = 'updaterLastNotifiedVersion';
  const INSTALLED_AT_KEY = 'updaterLastInstalledVersion';

  // The exact ZIP filename we expect inside the release assets.
  // Anything else in the release is ignored — this prevents a
  // malicious repo compromise from swapping in a different file.
  const EXPECTED_ASSET_NAME = 'corsair-unbound-extension.zip';

  /* ============================================================
     VERSION HELPERS
     ============================================================ */
  function _normalizeTag(tag) {
    const s = String(tag || '').trim();
    if (!s) return '';
    return s.replace(/^[vV]/, '');
  }

  function parseVersion(str) {
    const m = String(str || '').trim().match(/^[vV]?(\d+)\.(\d+)\.(\d+)/);
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
     RELEASE ASSET PICKER
     ------------------------------------------------------------
     Given the release JSON from the GitHub API, find the asset
     whose name matches EXPECTED_ASSET_NAME exactly. This is the
     ONLY file we will ever offer for download.
     ============================================================ */
  function _pickReleaseAsset(assets) {
    if (!Array.isArray(assets)) return null;
    for (const a of assets) {
      if (!a || typeof a !== 'object') continue;
      if (a.name !== EXPECTED_ASSET_NAME) continue;
      if (a.state !== 'uploaded') continue;
      if (typeof a.browser_download_url !== 'string') continue;
      if (!/^https:\/\/github\.com\//.test(a.browser_download_url)) continue;
      return a;
    }
    return null;
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
     UPDATE CHECK — via GitHub Releases API
     ============================================================ */
  async function checkForUpdates({ force = false } = {}) {
    const current = getCurrentVersion();
    const cached = await getCache();

    if (!force && cached && (Date.now() - (cached.checkedAt || 0)) < CHECK_TTL_MS) {
      return { ...cached, current, cached: true };
    }

    // ---- Primary: GitHub Releases API ----
    try {
      const res = await fetch(LATEST_RELEASE_API, {
        headers: {
          'Accept': 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28'
        },
        cache: 'no-store'
      });

      if (res.status === 404) {
        // Repo has no published releases yet — fall through to manifest.
        throw new Error('no-releases-published');
      }
      if (res.status === 403 || res.status === 429) {
        // Rate limited. Fall through to manifest, but log it.
        throw new Error('rate-limited');
      }
      if (!res.ok) {
        throw new Error(`github-api-${res.status}`);
      }

      const data = await res.json();
      const tag = String(data.tag_name || '').trim();
      const latest = _normalizeTag(tag);
      if (!latest) throw new Error('release-missing-tag');

      const asset = _pickReleaseAsset(data.assets);
      const cmp = compareVersions(latest, current);

      const result = {
        current,
        latest,
        tag,
        hasUpdate: cmp > 0,
        isAhead: cmp < 0,
        upToDate: cmp === 0,
        source: 'releases-api',
        repoUrl: REPO_URL,
        releaseUrl: typeof data.html_url === 'string' ? data.html_url : RELEASES_URL,
        releaseName: String(data.name || tag),
        releaseBody: String(data.body || '').slice(0, 4000),
        publishedAt: data.published_at || null,
        zipUrl: asset ? asset.browser_download_url : BRANCH_ZIP_FALLBACK_URL,
        zipName: asset ? asset.name : `corsair-unbound-${GITHUB_BRANCH}.zip`,
        zipSize: asset ? Number(asset.size) || 0 : 0,
        fromReleaseAsset: Boolean(asset),
        checkedAt: Date.now(),
        error: null
      };

      await setCache(result);
      try {
        const installed = await chrome.storage.local.get(INSTALLED_AT_KEY);
        if (!installed[INSTALLED_AT_KEY]) {
          await chrome.storage.local.set({ [INSTALLED_AT_KEY]: current });
        }
      } catch {}

      return result;
    } catch (primaryErr) {
      // ---- Fallback: raw manifest.json on main branch ----
      try {
        const res = await fetch(MANIFEST_FALLBACK_URL, { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const latest = String(data.version || '').trim();
        if (!latest) throw new Error('manifest-missing-version');

        const cmp = compareVersions(latest, current);
        const result = {
          current,
          latest,
          tag: `v${latest}`,
          hasUpdate: cmp > 0,
          isAhead: cmp < 0,
          upToDate: cmp === 0,
          source: 'manifest-fallback',
          repoUrl: REPO_URL,
          releaseUrl: RELEASES_URL,
          releaseName: `v${latest}`,
          releaseBody: '',
          publishedAt: null,
          zipUrl: BRANCH_ZIP_FALLBACK_URL,
          zipName: `corsair-unbound-${GITHUB_BRANCH}.zip`,
          zipSize: 0,
          fromReleaseAsset: false,
          checkedAt: Date.now(),
          error: null
        };
        await setCache(result);
        return result;
      } catch (fallbackErr) {
        // Both failed — return the cached result if we have one,
        // otherwise surface the primary error.
        const fallback = {
          current,
          latest: cached?.latest || null,
          tag: cached?.tag || null,
          hasUpdate: cached?.hasUpdate || false,
          isAhead: cached?.isAhead || false,
          upToDate: cached?.upToDate || false,
          source: 'cache',
          repoUrl: REPO_URL,
          releaseUrl: RELEASES_URL,
          releaseName: cached?.releaseName || null,
          releaseBody: cached?.releaseBody || '',
          publishedAt: cached?.publishedAt || null,
          zipUrl: cached?.zipUrl || BRANCH_ZIP_FALLBACK_URL,
          zipName: cached?.zipName || `corsair-unbound-${GITHUB_BRANCH}.zip`,
          zipSize: cached?.zipSize || 0,
          fromReleaseAsset: cached?.fromReleaseAsset || false,
          checkedAt: cached?.checkedAt || 0,
          error: primaryErr.message || 'check-failed'
        };
        return fallback;
      }
    }
  }

  /* ============================================================
     DESKTOP NOTIFICATION
     ============================================================ */
  async function notifyIfUpdateAvailable(result) {
    if (!result || !result.hasUpdate || !result.latest) return false;

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
        message: `You have v${result.current}. Click to view the update guide.`,
        priority: 1,
        requireInteraction: false,
        buttons: [{ title: 'Open Dashboard' }]
      });
      await chrome.storage.local.set({ [NOTIFIED_KEY]: result.latest });
      return true;
    } catch { return false; }
  }

  /* ============================================================
     DOWNLOAD RELEASE ZIP
     ------------------------------------------------------------
     Downloads the release asset (or branch ZIP as fallback) to
     the user's default Downloads folder. We use `saveAs: false`
     so the file lands without a dialog.
     ============================================================ */
  async function downloadUpdateZip(overrideUrl = null) {
    if (typeof chrome === 'undefined' || !chrome.downloads?.download) {
      return { ok: false, error: 'downloads-unavailable' };
    }
    try {
      // Trust ONLY URLs we resolved ourselves — the caller cannot
      // pass an arbitrary URL in. If overrideUrl is missing, we
      // re-read the last cached check.
      let url = overrideUrl;
      if (!url) {
        const cached = await getCache();
        url = cached?.zipUrl || BRANCH_ZIP_FALLBACK_URL;
      }

      // Hard validation: only allow GitHub release-asset or
      // archive URLs from OUR repo.
      const allowedPrefixes = [
        `https://github.com/${GITHUB_USER}/${GITHUB_REPO}/`,
        `https://objects.githubusercontent.com/`,
        `https://codeload.github.com/${GITHUB_USER}/${GITHUB_REPO}/`
      ];
      const isAllowed = allowedPrefixes.some(p => url.startsWith(p));
      if (!isAllowed) {
        return { ok: false, error: 'invalid-download-url' };
      }

      const id = await chrome.downloads.download({
        url,
        filename: EXPECTED_ASSET_NAME,
        saveAs: false,
        conflictAction: 'overwrite'
      });
      return { ok: true, downloadId: id };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /* Reveal the downloaded ZIP in the user's file manager. */
  async function revealDownloadedFile(downloadId) {
    if (typeof chrome === 'undefined' || !chrome.downloads?.show) {
      return { ok: false, error: 'downloads-unavailable' };
    }
    if (!Number.isInteger(downloadId)) {
      return { ok: false, error: 'invalid-download-id' };
    }
    try {
      await chrome.downloads.show(downloadId);
      return { ok: true };
    } catch (err) {
      return { ok: false, error: err.message };
    }
  }

  /* Open the OS default Downloads folder. */
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
     INSTALLED-VERSION MIGRATION HELPER
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
    revealDownloadedFile,
    openDownloadsFolder,
    scheduleBackgroundCheck,
    runBackgroundCheck,
    recordInstalledVersion,
    getCurrentVersion,
    compareVersions,
    parseVersion,

    // Internal helpers — exposed for tests
    _normalizeTag,
    _pickReleaseAsset,

    // Constants for UI
    GITHUB_USER,
    GITHUB_REPO,
    GITHUB_BRANCH,
    EXPECTED_ASSET_NAME,
    repoUrl: REPO_URL,
    releasesUrl: RELEASES_URL,
    ALARM_NAME
  };
})();

globalThis.CorsairUpdater = CorsairUpdater;