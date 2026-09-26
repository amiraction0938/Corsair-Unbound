# Changelog

## [1.8.2]

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

## [1.8.0]
## [Unreleased] — Security & Repository Hardening

### Added

- Security audit documentation with explicit threat-model and update-channel limitations
- Update policy documentation for unpacked installations
- Local credential and secret scanning at scripts/security-audit.mjs
- Dedicated GitHub Actions security-audit workflow
- Expanded ignore rules for credentials, certificates, archives, environment files, and release payloads

### Changed

- Refreshed the English and Persian READMEs to match v1.8.1
- Clarified the difference between application-level API-key protection and a real password vault
- Documented the current mutable-main-branch updater limitation
- Improved repository hygiene without changing the extension core protection logic

### Security

- Current-tree review found no hard-coded VirusTotal API key
- Privileged API-key messaging is separated from page-observation messaging
- Backup/export removes legacy plaintext API-key fields

> Audit note: the current-source review is bounded. It is not a cryptographic guarantee that every historical Git object or future release is clean.

## [1.8.1] — Current

See repository history for the current 1.8.1 feature changes.

## [1.8.0]

- Multi-language interface
- RTL support for Persian and Arabic
- Localized in-page verdict banner
- In-extension update checker
- Per-frame popup interception
- Additional navigation and content security controls
