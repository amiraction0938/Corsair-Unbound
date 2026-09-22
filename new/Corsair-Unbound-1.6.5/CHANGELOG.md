# Changelog

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
- `README.md`, `LICENSE`, `CHANGELOG.md`

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