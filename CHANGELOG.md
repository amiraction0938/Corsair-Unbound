# Changelog

All notable changes to Corsair Unbound are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Userscript manager (Tampermonkey-style)** — the old one-script-per-domain feature is replaced by a full userscript engine built on the official `chrome.userScripts` API (`core/userscripts.js`). Scripts now run even on sites with strict CSP.
- Standard metadata block support: `@name`, `@namespace`, `@version`, `@description`, `@author`, `@match`, `@include` (globs and `/regex/`), `@exclude`, `@exclude-match`, `@run-at` (`document-start/body/end/idle`), `@noframes`, `@require`, `@resource`, `@grant`, `@inject-into`, `@connect`, `@updateURL`, `@downloadURL`.
- Multiple scripts per site, enable/disable per script, import from URL or `.user.js` file, and re-importing the same `@name`/`@namespace` updates in place.
- `@require` libraries and `@resource` files are downloaded and cached at install time. User code and `@require` code share one async scope, so `return` and top-level `await` work.
- Dashboard: new Userscripts panel with a template editor and a one-time "Allow User Scripts" setup notice.
- **GM API:** `GM_getValue/setValue/deleteValue/listValues` (+ `GM_getValues/setValues/deleteValues`, `GM_addValueChangeListener`), `GM_xmlhttpRequest` (cross-origin, no CORS limits, JSON/blob/arraybuffer, timeout, abort), `GM_notification`, `GM_openInTab`, `GM_download`, `GM_setClipboard`, `GM_addStyle`, `GM_addElement`, `GM_log`, `GM_registerMenuCommand` (floating in-page menu), `GM_getResourceText/URL`, `GM_info`, `unsafeWindow`, plus the promise-based `GM.*` equivalents. Only granted functions are defined, like Tampermonkey.
- Scripts that only need local helpers (`GM_addStyle`, `GM_setClipboard`, `GM_registerMenuCommand`, ...) run in the page world, so `unsafeWindow` can reach page variables; scripts that use storage/network GM functions run in the isolated sandbox world.
- Three one-click demo scripts in the dashboard for first-time testing.

### Changed
- **No script restrictions** — the content blocklist (`document.cookie`, `WebSocket`, `eval`, `chrome.*`, `window.top`, ...) and the 200,000-character size cap were removed. Whatever the user installs is what runs.
- Minimum Chrome version is now 120. New permissions: `userScripts`, `unlimitedStorage`.
- Legacy per-domain scripts are migrated automatically to `@match *://host/*` + `*://*.host/*` userscripts (the old data is left untouched).

### Fixed
- **Userscript list could not be scrolled** once it filled up: the cards were shrinking inside the flex column instead of overflowing. The list now scrolls inside a bounded height with a visible scrollbar, and a just-saved script is scrolled into view and highlighted.
- Editor: closing with Esc, the X button or a click on the backdrop silently discarded unsaved code. It now asks first. The Tab key no longer breaks Ctrl+Z, and the unsaved marker clears when you undo back to the saved text.
- Userscripts that redeclare `unsafeWindow`, `GM_info` or a `GM_*` helper with `var`/`function` crashed with a SyntaxError; these names are now function parameters.
- Importing two scripts without an `@name` could overwrite each other; scripts are now matched by source URL first and by `@name`/`@namespace` only when the header really has a name. Re-importing the same URL updates in place even if the name changed.
- Simplified the registration sync (single mutex) and added a test for rapid consecutive saves.
- After turning on "Allow User Scripts", returning to the dashboard re-checks automatically and registers your scripts, without a manual reload.

### Added (dashboard)
- Each userscript card shows its target domains as tidy colour-coded badges in the top-right corner ("All sites", "Local files" and regex rules get their own style; extra domains collapse into a "+N" badge with a tooltip).
- Search box and script counter above the list; scripts are sorted alphabetically.

### Added (backup, guide, layout)
- **Backups now include your userscripts** (code, enabled state, cached `@require`/`@resource`, and the values saved with `GM_setValue`) and, optionally, your **API keys** (VirusTotal and URLhaus). A new "Include API keys in the backup" checkbox (on by default) sits above the backup buttons; the confirmation dialog states clearly whether the file holds keys in plain text. Backup format v12; older backups still import, and their per-domain scripts are converted to userscripts.
- **Userscript guide in English and Persian** with a one-click "Prompt for AI" tab: header reference, page vs sandbox mode, every GM function, gotchas, and a ready prompt plus a checklist of what to tell an AI so it writes a correct script.
- Dashboard reorganised: the sidebar is grouped (Monitor / Protection / Tools / System), Userscripts has its own page (it used to sit inside Security), and the Settings page is split into labelled groups (Protection, Threat intelligence, Alerts & banners, Logging). No setting was removed or renamed.
- The userscript search box now has proper styling.

### Fixed (storage / security)
- **`QuotaExceededError: global storage cap 10485760 bytes exceeded` switched the protection off.** The security storage budget summed *every* key in `chrome.storage.local`, so userscript data (code, cached `@require` libraries, `@resource` files, `GM_setValue` values) counted against it. Once it filled up, every security write (activity log, domain profiles, DNR rule registry, threat cache, settings) failed. Userscript keys (`cus:*`) are now excluded from the security budget, and the hard cap itself was raised from 10 MB to 100 MB (the extension has the `unlimitedStorage` permission, so this is only our own safety net). The cap still protects against runaway security data, and tests cover both directions.
- Storage usage panel now counts the new userscripts (it was still reading the legacy per-domain map) and reports their size separately.

### Fixed (backup)
- The tour text claimed the API key is "never included in backups" and "never written to disk"; both statements were out of date and are corrected (README, SECURITY.md and README.fa.md as well).

### Removed
- The notification bell (🔔) in the dashboard header and its panel.

### Known limitations
- Users must enable "Allow User Scripts" for the extension once in `chrome://extensions` (Chrome requirement; Tampermonkey needs the same).
- Scripts that use storage/network `GM_*` functions run in the isolated sandbox world, where `unsafeWindow` cannot read the page's own JS variables. Use `@grant none` (or `@inject-into page`, which disables those functions) for that.
- Not implemented yet: `GM_cookie`, `GM_getTab/saveTab`, notification click callbacks, cross-tab `GM_addValueChangeListener` events, and setting forbidden headers (`Cookie`, `Referer`, `User-Agent`) in `GM_xmlhttpRequest`.
- Scripts run once per page load (as in Tampermonkey); SPA route changes do not re-run them.
- Backup export/import does not include the new userscripts yet.

### Planned
- Optional local blocklist import from uBlock Origin / AdGuard / hosts files
- Redirect-chain visualizer in the dashboard
- Rule playground (dry-run DNR + heuristics without enforcement)
- Additional threat-intelligence providers (URLhaus, PhishTank, Safe Browsing)

---

## [1.9.1] — 2026

### Added
- **Direct Release Button** — the update modal now features a button that takes the user directly to the GitHub Releases page to download the launcher.
- **Bilingual Release Notes** — GitHub Actions now automatically generates release notes in both English and Persian to help non-technical users update safely.

### Fixed
- **Safety Fix in Updater** — the PowerShell launcher previously attempted to remove empty directories during cleanup, causing a dangerous prompt. It now strictly targets files and ignores directories.

---

## [1.9.0] — 2026

### Added
- **"Path A" Secure Updater Architecture** — completely replaced the old raw ZIP download method. Updates are now managed by a standalone, SHA-256 verified PowerShell launcher (`launcher/updater.ps1`).
- **`latest.json` Metadata** — releases now include a secure metadata file that validates versions, download URLs, and SHA-256 hashes before any update attempt.
- **CI Release Workflow** — GitHub Actions now rigorously tests, packages, hashes, and publishes releases automatically upon tagging.

### Changed
- **`core/updater.js`** — completely rewritten to only fetch and validate `latest.json` without downloading the ZIP payload.
- **Dashboard UI** — redesigned the update modal to guide users through the new launcher-based update flow.
- **Documentation** — fully updated README and SECURITY.md to reflect the new threat model.

### Fixed
- **Select Dropdown Visibility** — fixed a CSS bug where activity filter dropdowns appeared white on white in dark mode.
- **Trusted/Blocked Domains Scrolling** — fixed a flexbox layout issue preventing lists from scrolling properly when they exceeded screen height.
- **Take Tour Bug** — fixed an issue where starting the guided tour from the onboarding screen would occasionally fail to highlight the correct panel.

---

## [1.8.3] — 2025

### Fixed
- **VirusTotal API key now survives browser restarts** — the key was previously stored in `chrome.storage.session`, which Chrome clears when the browser closes. Users would restart their machine and unknowingly lose threat intelligence protection. The default is now `chrome.storage.local` (AES-GCM wrapped), with an opt-in "session only" toggle in the API view. A warning banner also appears if the key disappears when it was expected to persist.

### Changed
- `core/storage.js` — new `persistApiKey` setting (default `true`); new `getApiKeyStatus()` for detecting silently missing keys; `setApiKeySecure` clears both stores before writing so switching modes never leaves a stale copy.
- `background.js` — added `get-api-key-status` message handler.
- `dashboard.html` — added the persist toggle and missing-key warning UI.
- `dashboard.js` — new `renderApiKeyWarning()` and persist toggle listener.

---

## [1.8.2] — 2025

### Fixed
- **Activity Log filter limit clamp** — `core/event-filter.js` treated `limit: 0` as "no preference" and silently fell back to the default of 200, which contradicted the documented "clamped to [1, 1000]" contract. `0` is now correctly clamped to `1`.
- **Updater now uses the GitHub Releases API** — the previous implementation polled `raw.githubusercontent.com/.../main/manifest.json` and downloaded `archive/refs/heads/main.zip`. That meant any commit on `main` (including unreleased work) could trigger a false update notification, and users always downloaded the unstable branch tip. The updater now queries `/releases/latest` and downloads the exact `corsair-unbound-extension.zip` asset from the published release. If no release exists or the API is unavailable, it falls back gracefully to the manifest endpoint.

### Added
- **Activity Log search and filters** — the Activity view now has a filter bar with free-text search (across domain, type, reason, and destination), a severity dropdown (All / High / Medium / Low / Info), and an auto-populated event-type dropdown. A live counter shows `X / Y events` next to the controls.
- **"Show in Folder" button** in the update modal — after downloading the update ZIP, users get a one-click button to reveal the downloaded file in their OS file manager, plus a fallback that opens the default Downloads folder.
- **`core/event-filter.js`** — a new pure module (`CorsairEventFilter`) with `filterEvents()` and `collectEventTypes()`. Fully unit-tested; independent of any Chrome API.
- **`tests/updater.test.js`** — 16 new tests covering `parseVersion`, `compareVersions`, `_normalizeTag`, and `_pickReleaseAsset` (including a security test that verifies non-GitHub download URLs are rejected).
- **`tests/event-filter.test.js`** — 28 new tests covering severity, type, search, combined filters, limit clamping, and edge cases.

### Changed
- `dashboard.html` — added the filter bar UI and the "Show in Folder" button; loaded `core/event-filter.js` before `dashboard.js`.
- `dashboard.css` — new styles for `.activity-filter-bar` with responsive layout.
- `dashboard.js` — added `activityFilters` state, rewrote `renderEvents()` to use the filter module, added `refreshActivityTypeFilter()`, and wired up the new filter listeners.
- `background.js` — added `reveal-downloaded-file` and `open-downloads-folder` message handlers.

### Security
- The updater now refuses to download from any URL that does not match `https://github.com/amiraction0938/Corsair-Unbound/...`, `https://objects.githubusercontent.com/`, or `https://codeload.github.com/...`. This blocks a hostile release asset from pointing the download at an unrelated host.
- Only an asset named exactly `corsair-unbound-extension.zip` is ever selected from a release.

---

## [1.8.1] — 2025

### Fixed
- **RTL regression** — `core/i18n.js` is loaded both as an extension-page script (dashboard, popup, blocked) AND as a content script on every http(s) page. `applyDirection()` and `apply()` mutated `document.documentElement` unconditionally, which corrupted third-party pages' own `lang` / `dir` / class state when a Persian or Arabic language was active. Both functions now short-circuit unless running on an extension-owned page.
- **Custom script injection on CSP-restricted sites** — removed the `eval()` and `Function` constructor fallbacks. Only inline `<script>` tag injection is used, which is the only method that reliably survives Content Security Policy on modern sites. Added a hard lint pre-check (`CorsairSecurity.lintCustomScript`) that rejects scripts containing dangerous patterns before they are stored.
- **Custom script hierarchical host matching** — registering a script for `expl.com` now applies to all subdomains (`mp.expl.com`, `cdn.expl.com`, etc.) via a parent-domain walk, instead of only matching the exact host.
- **Custom script SPA navigation** — added a top-level `chrome.webNavigation.onHistoryStateUpdated` listener so scripts re-inject on `pushState` / `replaceState` route changes (React Router, Vue Router, Next.js, etc.). Previously they only ran on full page loads.
- **Custom script iframe injection** — `allFrames: true` is now used so scripts can reach elements that sites render inside iframes.
- **Custom script deduplication** — replaced exact-URL comparison with a 400ms timestamped window, so revisiting the same URL re-injects instead of skipping.
- **Memory leak** — `onHistoryStateUpdated` was previously registered *inside* `onCommitted`, stacking a new listener on every navigation. Moved to top-level registration.

### Added
- **`content-frame-guard.js`** — isolated-world frame guard that runs at `document_start` in every frame, generates a per-page nonce, and relays popup-block events from the MAIN world to the background service worker. The nonce handshake prevents a page from spoofing a "fortress disarmed" message.
- **`content-main-world.js`** — MAIN-world guard that overrides `window.open` synchronously before any page script can grab it. Fails closed until the first authenticated state broadcast arrives.
- **`content-security-guard.js`** — passive detection layers for clipboard hijacking, CSP violations, and form-jacking (sensitive form data posted to a cross-registrable-domain host).
- **Path-scoped Fortress** — profiles can declare `pathScopes` to restrict fortress activation to specific URL prefixes (`/admin`, `/settings`). DNR catch-all is skipped for path-scoped profiles and enforcement is done at the content-frame level.
- **Bloom filter** (`core/bloom.js`) — fast negative lookups for the allowlist. Skips the O(n) iteration over 20,000+ remote domains for hosts that are definitely not on the list.
- **User blocklist** (`syncUserBlocklist`) — manually blocked domains install session DNR rules that redirect `main_frame` requests to `blocked.html`.

### Changed
- `background.js` — the `notify()` and `notifyContainment()` helpers were removed. Context-menu actions and containment events now log to the activity feed instead of firing desktop notifications on every action.

---

## [1.8.0] — 2025

### Added
- **Multi-language interface** — English, فارسی, العربية, Español, Deutsch, Français, Русский, 中文.
- **Full RTL support** for Persian and Arabic (text-only; layout stays LTR for consistency).
- **Localized in-page verdict banner** — verdict, reasons, and action buttons all use the active language.
- **In-extension update checker** — periodic GitHub version check, dashboard banner, ZIP download helper, and a manual install guide modal.
- **Per-frame popup interception** — popup defense now runs at both the `tabs.onCreated` layer and the `webNavigation.onCreatedNavigationTarget` layer, plus content-script `window.open` override and anchor modifier-click interception.
- **Additional navigation and content security controls** — clipboard hijack detection, CSP violation monitoring, form-jacking detection.

### Changed
- Sidebar-based dashboard layout replaces the previous single-column scroll.
- Update banner and modal replace the old raw-JSON update notification.

---

## [1.5.0] — 2025

### Added
- **Heuristic Analysis Engine** (`core/heuristics.js`)
  - Typosquatting detection (digit substitution, hyphens, Levenshtein distance)
  - Suspicious TLD list (Freenom, `.top`, `.xyz`, `.zip`, etc.)
  - Homograph attack detection (mixed scripts)
  - Punycode / IDN detection
  - Recently-registered domain detection (from VT)
  - Brand-in-subdomain detection
- **Alarm-based TTL** (`core/alarms.js`) — replaces unreliable `setTimeout`
  - Fortress-allow rule expiry now survives service worker restarts
  - Scheduled whitelist sync (weekly)
  - Scheduled cache cleanup (every 6 hours)
- **Extension Badge** — colored icon per tab (green/yellow/red/blue)
- **Trust Button** on verdict banner — one-click whitelist
- **User Trusted Domains** — separate list from safe-scanned cache
- **Download Guard** — blocks downloads from malicious sources
- **Keyboard Shortcuts** (`Ctrl+Shift+F`, `Ctrl+Shift+E`)
- **Dashboard: Search + Bulk actions** for safe-scanned domains
- **Dashboard: Theme Toggle** (light/dark)
- **Dashboard: Privacy & Data panel** — storage usage + wipe-all
- **Export/Import separate Safe List** (as `.json`)
- **Incognito mode** — split mode
- **2-second auto-dismiss** for all in-page banners (except VT loading)

### Changed
- Version bumped from 1.4.0 to 1.5.0
- `manifest.json` — added `alarms` permission, `commands`, `incognito: split`
- Dashboard header — removed top-level Export/Import (moved to Backup section)
- Safe-scanned domains panel moved above guide
- Behavior Intelligence and Evidence Store moved above Domain Profiles
- Network Observation panel moved to bottom

### Fixed
- Fortress-allow TTL now survives service worker restarts
- Settings defaults now consistently applied on first install
- `maxRedirectHops` now respects dashboard setting
- Popup auto-dismiss timing unified at 2 seconds

---

## [1.4.0] — 2025

### Added
- Fortress catch-all with DNR session rules
- VirusTotal BYOK integration with rate-limited request queue
- Smart whitelist (Cisco OpenDNS weekly sync)
- Auto threat scan on navigation
- Domain analyzer dashboard view

---

## [1.3.0] — 2025

### Added
- Fortress popup lockdown with burst detection
- Redirect storm containment
- Auto-scan with desktop notifications (later removed in 1.8.1)

---

## [1.2.0] — 2025

### Added
- Initial deterministic DNR enforcement
- Redirect chain tracking

---

## [1.1.0] — 2025

### Added
- First public release

---

[Unreleased]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.9.1...HEAD
[1.9.1]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.8.3...v1.9.0
[1.8.3]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.8.2...v1.8.3
[1.8.2]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.5.0...v1.8.0
[1.5.0]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/amiraction0938/Corsair-Unbound/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/amiraction0938/Corsair-Unbound/releases/tag/v1.1.0