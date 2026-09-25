# 🏴☠️ Corsair Unbound v1.8.0

Local-first browser shield for Chrome (MV3) with deterministic DNR enforcement, fortress catch-all, redirect-chain observation, heuristic analysis, BYOK VirusTotal integration, and full multi-language support.

## Features

### Protection
- **Fortress Mode** — per-domain lockdown via DNR session rules
- **Frame-Level Navigation Guard** — a dedicated guard script runs in *every* frame on the page (including third-party ad/tracker iframes) to intercept malicious `window.open()` calls and popup-shaped links at the earliest possible moment
- **Popup Lockdown** — burst detection + cooldown containment
- **Redirect Storm Containment** — intelligence-based auto-block
- **Download Guard** — blocks downloads from malicious sources
- **External Meta Refresh Stripper**

### Intelligence
- **VirusTotal BYOK** — 4 req/min, rate-limited queue
- **Heuristic Engine** — typosquatting, homograph, suspicious TLD, recently-registered domains, brand-in-subdomain detection
- **Smart Whitelist** — 500+ built-in + Cisco OpenDNS sync
- **User Trusted Domains** — one-click trust from banner
- **Behavior Intelligence** — real-time signal classification

### UX
- **Multi-Language Interface** — English, فارسی, العربية, Español, Deutsch, Français, Русский, 中文, with full RTL text support for Persian and Arabic
- **In-Page Verdict Banner** — top-right corner of every non-whitelisted site, **now fully localized** (v1.8.0)
- **Extension Badge** — green/yellow/red/blue status per tab
- **Keyboard Shortcuts** — `Ctrl+Shift+F` (Fortress), `Ctrl+Shift+E` (Dashboard)
- **Full Dashboard** — analyzer, safe list, privacy controls, settings, language switcher
- **Light/Dark Theme**
- **Built-in Update Checker** — periodic check against the GitHub repo, desktop notification, one-click download, and a step-by-step install guide

### Data
- **Safe Scanned Domains** — local cache with search + bulk actions
- **Backup & Restore** — full config JSON export/import, versioned migration
- **Safe List Export/Import** — separate file for portability
- **Privacy Controls** — storage stats + wipe-all
- **Regression Suite** — deterministic replay

## Install

1. `chrome://extensions` → **Developer mode**
2. **Load unpacked** → select this directory
3. Get a free VirusTotal API key from https://www.virustotal.com/gui/my-apikey
4. Paste it in **Dashboard → API & Intelligence**
5. Enable **VirusTotal Threat Intelligence** + **Auto-Scan**
6. Pick your language from the dashboard's language switcher

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Shift+F` | Toggle Fortress on current tab |
| `Ctrl+Shift+E` | Open Corsair Dashboard |

## Privacy

**Everything is stored locally in your browser. Nothing is uploaded.**

- Profiles, settings, cache → `chrome.storage.local`
- Redirect chains, tab state → `chrome.storage.session`
- VT API key → stored locally (encrypted in session storage), sent **directly** to VirusTotal (never to us)
- Whitelisted domains → **never** sent to VirusTotal (quota saving)
- Update checks → a single read of `manifest.json` from the public GitHub repo; no telemetry is sent

Use **Dashboard → Privacy & Data → Wipe ALL Local Data** to fully reset.

## Architecture
manifest.json
background.js service worker
content-frame-guard.js runs in every frame — window.open()/popup interception (ISOLATED world)
content-main-world.js runs in every frame — MAIN-world window.open override (nonce-authenticated)
content.js runs in top frame only — banner, observation, scanning (now i18n-enabled)
popup.html/css/js extension action popup
dashboard.html/css/js full dashboard
blocked.html DNR redirect target (now i18n-enabled)
core/
security.js sanitization, normalize
storage.js transactional storage
alarms.js chrome.alarms wrapper
dnr.js declarativeNetRequest
redirects.js chain tracking
threat-intel.js VT + whitelist
heuristics.js typosquat/homograph
intelligence.js signal classification
verifier.js containment decision
observation.js network observation
evidence.js evidence store
migration.js backup/restore (versioned)
tool-router.js bounded tool API
replay.js regression fixtures
i18n.js translations for 8 languages + RTL support
updater.js GitHub-based update checker


## Changelog

See `CHANGELOG.md`.

## License

MIT — see `LICENSE`