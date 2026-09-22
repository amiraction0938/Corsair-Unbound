# Corsair Unbound 1.1.0

Corsair Unbound is a local-first Chrome MV3 browser shield combining deterministic Fortress enforcement with redirect-chain observation, behavior intelligence, evidence, a persistent site graph, diagnostics, and a full local dashboard.

## Features

- Fortress domain profiles
- Safe Redirect Resolver controls
- Dynamic Declarative Net Request enforcement
- Navigation containment and blocked-destination rules
- Redirect-chain tracking
- Page and network observation
- Persistent site graph
- Behavior intelligence and risk assessment
- Evidence and activity telemetry
- Full Dashboard
- Popup quick controls
- Backup / Restore with optional telemetry restore
- Replay / Regression
- Agent context and bounded tool router
- Storage quotas, locking, rollback and startup reconciliation

## Install

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Choose **Load unpacked**.
4. Select this project directory.

Use the toolbar popup for quick protection controls. Open **Dashboard** for settings, profiles, activity, observation, intelligence, evidence, agent context, replay and backup/restore.

## Architecture

The hardened current runtime is the source of truth for storage, DNR, security and transaction semantics. The product UI restores the feature surface of the v8 implementation while using the current backend contracts.

## Local-first

Profiles, policy state, graph data, evidence and telemetry remain local to the extension unless explicitly exported by the user.

# Corsair Unbound v1.4.0

Local-first browser shield with deterministic DNR enforcement, fortress 
catch-all, threat intelligence (BYOK), and smart whitelist.

## Features
- Fortress catch-all (DNR session rules)
- Popup lockdown (burst detection + cooldown)
- Redirect storm containment (verifier + intelligence)
- VirusTotal BYOK integration (4 req/min)
- Smart whitelist (500+ built-in + OpenDNS sync)
- Auto threat scan with notifications
- Domain analyzer dashboard
- Full backup/restore
- Regression test fixtures

## Install
1. chrome://extensions → Developer mode
2. Load unpacked → select this directory
3. (Optional) Set VirusTotal API key in Dashboard

## Privacy
All data local. VT key stored locally. Queries go directly to VT.
# 🏴‍☠️ Corsair Unbound

Local-first browser shield for Chrome (MV3) with deterministic DNR enforcement, 
fortress catch-all, heuristic analysis, and BYOK VirusTotal integration.

## Features

### Protection
- **Fortress Mode** — per-domain lockdown via DNR session rules
- **Popup Lockdown** — burst detection + cooldown containment
- **Redirect Storm Containment** — intelligence-based auto-block
- **Download Guard** — blocks downloads from malicious sources
- **External Meta Refresh Stripper**

### Intelligence
- **VirusTotal BYOK** — 4 req/min, rate-limited queue
- **Heuristic Engine** — typosquatting, homograph, suspicious TLD, recent domain
- **Smart Whitelist** — 500+ built-in + Cisco OpenDNS sync
- **User Trusted Domains** — one-click trust from banner
- **Behavior Intelligence** — real-time signal classification

### UX
- **In-Page Verdict Banner** — top-right corner of every non-whitelisted site
- **Extension Badge** — green/yellow/red status per tab
- **Keyboard Shortcuts** — `Ctrl+Shift+F` (Fortress), `Ctrl+Shift+E` (Dashboard)
- **Full Dashboard** — analyzer, safe list, privacy controls, settings
- **Light/Dark Theme**

### Data
- **Safe Scanned Domains** — local cache with search + bulk actions
- **Backup & Restore** — full config JSON export/import
- **Safe List Export/Import** — separate file for portability
- **Privacy Controls** — storage stats + wipe-all
- **Regression Suite** — deterministic replay

## Install

1. `chrome://extensions` → **Developer mode**
2. **Load unpacked** → select this directory
3. Get a free VirusTotal API key from https://www.virustotal.com/gui/my-apikey
4. Paste it in **Dashboard → Global Settings**
5. Enable **VirusTotal Threat Intelligence** + **Auto-Scan**

## Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Shift+F` | Toggle Fortress on current tab |
| `Ctrl+Shift+E` | Open Corsair Dashboard |

## Privacy

**Everything is stored locally in your browser. Nothing is uploaded.**

- Profiles, settings, cache → `chrome.storage.local`
- Redirect chains, tab state → `chrome.storage.session`
- VT API key → stored locally, sent **directly** to VirusTotal (never to us)
- Whitelisted domains → **never** sent to VirusTotal (quota saving)

Use **Dashboard → Privacy & Data → Wipe ALL Local Data** to fully reset.

## Architecture
manifest.json
background.js (service worker)
content.js (per-tab)
popup.html/css/js (extension action popup)
dashboard.html/css/js (full dashboard)
blocked.html (DNR redirect target)
core/
security.js sanitization, normalize
storage.js transactional storage
alarms.js chrome.alarms wrapper (NEW)
dnr.js declarativeNetRequest
redirects.js chain tracking
threat-intel.js VT + whitelist
heuristics.js typosquat/homograph (NEW)
intelligence.js signal classification
verifier.js containment decision
observation.js network observation
evidence.js evidence store
migration.js backup/restore
tool-router.js bounded tool API
replay.js regression fixtures

## License

MIT — see `LICENSE`