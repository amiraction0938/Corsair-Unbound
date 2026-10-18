<div align="center">

# 🏴‍☠️ Corsair Unbound

<strong>Local browser shield for Chrome (Manifest V3)</strong>

<p>
  <a href="README.fa.md">🇮🇷 فارسی</a> ·
  <a href="SECURITY.md">🔒 Security</a> ·
  <a href="docs/SECURITY-AUDIT.md">🧪 Security Audit</a> ·
  <a href="docs/UPDATE-POLICY.md">🔄 Update Policy</a>
</p>

<img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound" width="100%">

</div>

Corsair Unbound is a local-first browser shield for Chrome Manifest V3 focused on deterministic navigation protection, Fortress enforcement, redirect containment, heuristic analysis, optional threat intelligence, and a full local dashboard.

The extension is designed to keep its core logic and user data on the device. Optional VirusTotal integration is BYOK (Bring Your Own Key): when enabled, the requested reputation and analysis traffic is sent directly to VirusTotal.

## ✨ Features

### 🛡️ Protection

- **Fortress Mode** — per-domain lockdown through DNR session rules
- **Frame-Level Navigation Guard** — protection in every matching frame, including third-party iframes
- **Popup Lockdown** — burst detection with cooldown containment
- **Redirect Storm Containment** — intelligence-based containment for redirect abuse
- **Download Guard** — blocks downloads associated with malicious sources
- **External Meta Refresh Stripper** — blocks external meta-refresh navigation
- **Content Security Guard** — clipboard, CSP, and form-jacking related protection signals

### 🧠 Intelligence

- **VirusTotal BYOK** — optional threat intelligence with a rate-limited request queue
- **Heuristic Engine** — typosquatting, homograph, suspicious TLD, recently registered domains, and brand-in-subdomain signals
- **Smart Allowlist** — built-in trusted domains plus remote allowlist synchronization
- **User Trusted Domains** — one-click trust from the in-page verdict banner
- **Behavior Intelligence** — real-time signal classification and risk aggregation
- **Multi-Source Intelligence** — combines local heuristics with supported external threat-intelligence providers

### 🎨 User Experience

- **Multi-Language Interface** — English, فارسی, العربية, Español, Deutsch, Français, Русский, 中文
- **Full RTL Support** — dedicated right-to-left text rendering for Persian and Arabic
- **In-Page Verdict Banner** — localized verdicts for non-allowlisted sites
- **Extension Badge** — per-tab security status
- **Keyboard Shortcuts** — Ctrl+Shift+F for Fortress, Ctrl+Shift+E for Dashboard
- **Full Dashboard** — analyzer, safe list, privacy controls, settings, API & intelligence, and language switching
- **Light/Dark Theme**
- **Built-in Update Checker** — secure GitHub version check, desktop notification, and a dedicated Windows launcher for one-click, SHA-256 verified updates.
- **Onboarding Wizard** — first-run guided setup with language choice, API key entry, and preference selection
- **Guided Product Tour** — 7-step overlay tour of the dashboard's main areas

### 💾 Data & Reliability

- **Safe Scanned Domains** — local cache with search and bulk actions
- **Backup & Restore** — versioned JSON export/import with sensitive-field removal
- **Safe List Export/Import** — portable safe-list file
- **Privacy Controls** — storage statistics and full local wipe
- **Regression Suite** — deterministic replay tests
- **Security Audit Tooling** — repository credential checks and manifest-risk checks

## 📦 Installation

### Load unpacked

1. Open <code>chrome://extensions</code>
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the repository root, the folder containing <code>manifest.json</code>
5. Open the Corsair Unbound popup and launch the Dashboard
6. Optional: get a free VirusTotal API key from https://www.virustotal.com/gui/my-apikey
7. Paste it into **Dashboard → API & Intelligence**
8. Enable **VirusTotal Threat Intelligence** and **Auto-Scan** when needed
9. Choose your preferred language

> After updating an unpacked installation, replace the extension files and click **Reload** in <code>chrome://extensions</code>. Browser-side extension storage is preserved.

## 🔑 API Key & Privacy

Corsair Unbound does not ship with a hard-coded VirusTotal API key.

### BYOK model

- You enter your own VirusTotal API key locally.
- There are no Corsair Unbound servers receiving the key.
- VirusTotal requests are sent directly to VirusTotal when the feature is enabled.
- Allowlisted domains are intentionally skipped for VirusTotal lookups.
- Backup/export logic removes legacy plaintext API-key fields.
- The repository security policy prohibits committing API keys, tokens, passwords, cookies, or private keys.

### Important storage limitation

The active key is stored outside the normal settings payload using an application-level encrypted/obfuscated representation.

This reduces ordinary plaintext exposure, but it is **not a password vault** and is not a cryptographic boundary against a compromised extension build or a fully privileged attacker on the browser profile. The extension must be able to recover the key at runtime to call VirusTotal.

Use **Dashboard → Privacy & Data → Wipe ALL Local Data** to clear local extension data.

See [SECURITY.md](SECURITY.md) and [docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md).

## 🔄 Updates

Corsair Unbound features a secure, two-part update system designed specifically for unpacked installations without relying on the Chrome Web Store.

### How it works
1. **The Extension** periodically checks a secure `latest.json` file hosted on GitHub Releases.
2. When a new version is found, the dashboard informs you and provides a link to the update page.
3. **The Windows Updater (`updater.ps1`)** does the heavy lifting. You download it once, and it:
   - Downloads the latest extension ZIP directly from GitHub.
   - Calculates and verifies the **SHA-256 hash** against the official release metadata to ensure the file has not been tampered with.
   - Automatically creates a timestamped backup of your current extension.
   - Safely replaces the extension files without touching your data.
   - Opens Chrome for you to simply click the "Reload" button.

### Update security
Because this is a security extension, the update process is built around integrity. The updater will refuse to install any file that does not perfectly match the SHA-256 hash published in the official release. The extension itself never downloads the ZIP, preventing any remote code execution risks.

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| Ctrl+Shift+F | Toggle Fortress on the current tab |
| Ctrl+Shift+E | Open the Corsair Dashboard |

## 🏗️ Architecture

    .
    ├── assets/
    │   └── corsair-unbound-hero.png
    ├── core/
    │   ├── security.js            sanitization, normalization, validation
    │   ├── storage.js             transactional storage + API-key handling
    │   ├── alarms.js              chrome.alarms wrapper
    │   ├── bloom.js               fast allowlist negative lookups
    │   ├── dnr.js                 declarativeNetRequest enforcement
    │   ├── redirects.js           redirect-chain tracking
    │   ├── risk-aggregator.js     weighted multi-source risk scoring
    │   ├── providers/
    │   │   └── urlhaus.js         abuse.ch URLhaus provider (opt-in)
    │   ├── threat-intel.js        VirusTotal + allowlist intelligence
    │   ├── heuristics.js          typosquat/homograph heuristics
    │   ├── intelligence.js        signal classification
    │   ├── verifier.js            containment decisions
    │   ├── observation.js         network observation
    │   ├── evidence.js            evidence store
    │   ├── migration.js           versioned backup/restore migration
    │   ├── tool-router.js         bounded internal tool API
    │   ├── replay.js              regression fixtures
    │   ├── event-filter.js        pure activity-log filter helpers
    │   ├── i18n.js                8-language translations + RTL support
    │   └── updater.js             GitHub latest.json update checker
    ├── icons/
    ├── launcher/
    │   └── updater.ps1            secure Windows update launcher
    ├── background.js              service worker
    ├── content-frame-guard.js     frame-level popup interception
    ├── content-main-world.js      MAIN-world window.open protection
    ├── content-security-guard.js  clipboard/CSP/form-jacking guard
    ├── content.js                 top-frame banner and observation
    ├── popup.html / popup.css / popup.js
    ├── dashboard.html / dashboard.css / dashboard.js
    ├── blocked.html / blocked.js
    ├── manifest.json
    ├── scripts/
    │   ├── build.mjs
    │   └── security-audit.mjs
    ├── tests/
    ├── CHANGELOG.md
    ├── INSTALL.md
    ├── LICENSE
    ├── SECURITY.md
    └── README.md / README.fa.md

## 🧪 Verification

Run the existing regression suite:

    npm ci
    npm test

Run the local repository audit:

    node scripts/security-audit.mjs

Scan reachable Git history from a normal clone:

    node scripts/security-audit.mjs --history

The audit reports file names and finding types only; it does not print matched secret values.

## 📚 Documentation

- [English README](README.md)
- [README فارسی](README.fa.md)
- [Security Policy](SECURITY.md)
- [Security Audit](docs/SECURITY-AUDIT.md)
- [Update Policy](docs/UPDATE-POLICY.md)
- [Install Guide](INSTALL.md)
- [Changelog](CHANGELOG.md)

## 📜 License

MIT — see [LICENSE](LICENSE)