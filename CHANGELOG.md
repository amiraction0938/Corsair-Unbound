# Changelog

## [1.8.0]

### Fixed
- **`README.md` encoding** — the file was previously saved with broken UTF-8 (mojibake throughout). It has been rewritten with correct UTF-8 so all Persian, Arabic, Chinese, and emoji characters display properly
- **In-page verdict banner now respects the user's language** — `content.js` previously had no access to `core/i18n.js` because it was not listed in the same `content_scripts` entry. Every string inside the banner was hardcoded English. The manifest now loads `core/i18n.js` before `content.js`, and every user-facing string in the banner (loading text, verdict labels, reason list, Trust/Block button labels, confirmation dialog) is now routed through `CorsairI18n.t()`
- **`blocked.html` is now localized** — the DNR redirect target page now loads `core/i18n.js` and every string is translated

### Changed
- `manifest.json` — version bumped to 1.8.0; `content.js` content-script entry now includes `core/i18n.js`; `blocked.html`, `blocked.js`, and `core/i18n.js` added to `web_accessible_resources` so the blocked page can load them
- `content.js` — added a small `ensureI18n()` bootstrap that awaits `CorsairI18n.load()` before rendering any banner
- `dashboard.js` — removed the misleading `_skipSettingsRender` flag from `saveSettings` (it was a no-op)

### Added
- New i18n keys under the `banner.*` and `blocked.*` namespaces (English baseline; other languages fall back gracefully)

## [1.7.0]

### Added
- **Multi-language interface** (`core/i18n.js`) — full UI translation for English, فارسی, العربية, Español, Deutsch, Français, Русский and 中文, with automatic RTL text layout for Persian and Arabic and a language switcher in the dashboard
- **In-extension update checker** (`core/updater.js`)
- **`content-frame-guard.js`** — per-frame popup interception at `document_start`

### Changed
- Navigation containment split across two content scripts
- `manifest.json` — version bumped to 1.7.0
- Dashboard sidebar/header gained a language switcher and an "About" section

## [1.5.0] — 2025
- Heuristic Analysis Engine
- Alarm-based TTL
- Extension Badge
- Trust Button on verdict banner
- User Trusted Domains
- Download Guard
- Keyboard Shortcuts
- Dashboard: Search + Bulk actions
- Dashboard: Theme Toggle
- Dashboard: Privacy & Data panel
- Export/Import separate Safe List
- Incognito mode — split mode
- 2-second auto-dismiss for all in-page banners
- `README.md`, `LICENSE`, `CHANGELOG.md`

## [1.4.0]
- Fortress catch-all with DNR session rules
- VT BYOK integration
- Smart whitelist (Cisco OpenDNS)
- Auto threat scan
- Domain analyzer dashboard

## [1.3.0]
- Fortress popup lockdown
- Redirect storm containment
- Auto-scan with notifications

## [1.2.0]
- Initial deterministic DNR enforcement
- Redirect chain tracking

## [1.1.0]
- First public release