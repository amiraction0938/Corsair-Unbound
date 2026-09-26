# 🏴‍☠️ Corsair Unbound

<p align="center">
  <strong>Current release: v1.8.0</strong>
</p>

<p align="center">
  <img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound" width="100%">
</p>

<h2 align="center">Security • Freedom • A Right for Everyone</h2>
<p align="center"><strong>Nothing can limit us.</strong></p>

<p align="center">
  <a href="README.fa.md"><strong>🇮🇷 Persian Documentation</strong></a>
</p>

Corsair Unbound is a local-first Chrome Manifest V3 browser shield focused on deterministic navigation protection, Fortress enforcement, redirect containment, heuristic analysis, optional threat intelligence, and a full local dashboard. Everything runs on your device — no accounts, no cloud, no telemetry.

---

## ✨ Highlights

- **Fortress Mode** — per-domain lockdown via DNR session rules
- **Frame-Level Navigation Guard** — popup interception in every frame, including third-party ad iframes
- **Popup Lockdown** — burst detection + cooldown containment
- **Redirect Storm Containment** — intelligence-based auto-block
- **Download Guard** — blocks downloads from malicious sources
- **Heuristic Engine** — typosquatting, homograph, suspicious TLD, recently-registered domains
- **Optional VirusTotal BYOK** — 4 req/min, rate-limited queue
- **Smart Whitelist** — 500+ built-in domains + Cisco OpenDNS sync
- **Multi-Language Interface** — 8 languages with full RTL support (فارسی, العربية)
- **Full Dashboard** — analyzer, safe list, privacy controls, language switcher
- **Backup & Restore** — full config export/import, versioned migration
- **Built-in Update Checker** — desktop notification + one-click download

---

## 🛡️ Protection

| Feature | Description |
|---|---|
| **Fortress Mode** | Per-domain lockdown via DNR session rules |
| **Frame-Level Navigation Guard** | A dedicated guard script runs in *every* frame on the page (including third-party ad/tracker iframes) to intercept malicious `window.open()` calls and popup-shaped links at the earliest possible moment |
| **Popup Lockdown** | Burst detection + cooldown containment |
| **Redirect Storm Containment** | Intelligence-based auto-block |
| **Download Guard** | Blocks downloads from malicious sources |
| **External Meta Refresh Stripper** | Removes `<meta http-equiv="refresh">` to external domains |

## 🧠 Intelligence

| Feature | Description |
|---|---|
| **VirusTotal BYOK** | 4 req/min, rate-limited queue |
| **Heuristic Engine** | Typosquatting, homograph, suspicious TLD, recently-registered domains, brand-in-subdomain detection |
| **Smart Whitelist** | 500+ built-in + Cisco OpenDNS sync |
| **User Trusted Domains** | One-click trust from banner |
| **Behavior Intelligence** | Real-time signal classification |

## 🎨 UX

- **Multi-Language Interface** — English, فارسی, العربية, Español, Deutsch, Français, Русский, 中文 — with full RTL text support for Persian and Arabic
- **In-Page Verdict Banner** — top-right corner of every non-whitelisted site, **fully localized**
- **Extension Badge** — green/yellow/red/blue status per tab
- **Keyboard Shortcuts** — `Ctrl+Shift+F` (Fortress), `Ctrl+Shift+E` (Dashboard)
- **Full Dashboard** — analyzer, safe list, privacy controls, settings, language switcher
- **Light/Dark Theme**
- **Built-in Update Checker** — periodic check against the GitHub repo, desktop notification, one-click download, and a step-by-step install guide

## 💾 Data

- **Safe Scanned Domains** — local cache with search + bulk actions
- **Backup & Restore** — full config JSON export/import, versioned migration
- **Safe List Export/Import** — separate file for portability
- **Privacy Controls** — storage stats + wipe-all
- **Regression Suite** — deterministic replay

---

## 📦 Install

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select the **repository root** (the folder containing `manifest.json`)
5. Open the extension popup and launch the **Dashboard**
6. *(Optional)* Get a free VirusTotal API key from https://www.virustotal.com/gui/my-apikey and paste it in **Dashboard → API & Intelligence**
7. Pick your language from the dashboard's language switcher

> **Tip:** After updating from an older version, click the ↻ **Reload** button on `chrome://extensions` — your profiles, settings, and cache will be preserved.

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Shift+F` | Toggle Fortress on current tab |
| `Ctrl+Shift+E` | Open Corsair Dashboard |

---

## 🔐 Privacy and API credentials


Corsair Unbound follows a **local-first** model.

- The source tree does **not** contain a hard-coded VirusTotal API key or any personal credential.
- VirusTotal support is **BYOK** (Bring Your Own Key): the extension reads a key supplied in local settings and sends supported queries **directly** to VirusTotal.
- Profiles, settings, observations, evidence, and telemetry stay in **extension storage** unless the user explicitly exports them.
- **Whitelisted domains** are never sent to VirusTotal (quota saving).
- **Update checks** are a single read of `manifest.json` from the public GitHub repo — no telemetry is sent.

Use **Dashboard → Privacy & Data → Wipe ALL Local Data** to fully reset.

See [SECURITY.md](SECURITY.md) for credential-handling guidance.

---
---

## 🔒 Why does the extension request access to all websites?

Corsair Unbound requests:

```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

This permission is intentional and is required for the extension's protection model.

Corsair Unbound operates directly inside web pages and across frames, so broad host access is necessary for features such as:

- Frame-level popup interception
- MAIN-world `window.open()` protection
- Navigation and redirect containment
- In-page verdict banner
- Per-domain Fortress enforcement

### Security model

- No telemetry or account system
- No remote code loading
- No external runtime dependencies
- All protection logic ships with the extension
- Source code is fully inspectable

Like any browser extension with broad host permissions, a compromised extension would become a high-impact browser component. Keeping the project local-first, dependency-light, and fully open source helps reduce that risk by allowing users to inspect exactly what is shipped.

## 🏗️ Architecture

```text
.
├── assets/
│   └── corsair-unbound-hero.png
├── core/
│   ├── security.js            sanitization, normalize
│   ├── storage.js             transactional storage
│   ├── alarms.js              chrome.alarms wrapper
│   ├── dnr.js                 declarativeNetRequest
│   ├── redirects.js           chain tracking
│   ├── threat-intel.js        VT + whitelist
│   ├── heuristics.js          typosquat/homograph
│   ├── intelligence.js        signal classification
│   ├── verifier.js            containment decision
│   ├── observation.js         network observation
│   ├── evidence.js            evidence store
│   ├── migration.js           backup/restore (versioned)
│   ├── tool-router.js         bounded tool API
│   ├── replay.js              regression fixtures
│   ├── i18n.js                translations for 8 languages + RTL support
│   └── updater.js             GitHub-based update checker
├── icons/
├── background.js              service worker
├── content-frame-guard.js     per-frame popup interception (ISOLATED world)
├── content-main-world.js      MAIN-world window.open override (nonce-authenticated)
├── content.js                 top-frame banner + observation (i18n-enabled)
├── popup.html / popup.css / popup.js
├── dashboard.html / dashboard.css / dashboard.js
├── blocked.html / blocked.js  DNR redirect target (i18n-enabled)
├── manifest.json
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── README.md
└── README.fa.md
