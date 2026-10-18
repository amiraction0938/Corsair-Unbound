# Changelog

All notable changes to Corsair Unbound are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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