# 🏴‍☠️ Corsair Unbound

<p align="center">
  <strong>Current release: 1.7.0</strong>
</p>

<p align="center">
  <img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound" width="100%">
</p>

<h2 align="center">Security • Freedom • A Right for Everyone</h2>
<p align="center"><strong>Nothing can limit us.</strong></p>

<p align="center">
  <a href="README.fa.md"><strong>🇮🇷 Persian Documentation</strong></a>
</p>

Corsair Unbound is a local-first Chrome Manifest V3 browser shield focused on deterministic navigation protection, Fortress enforcement, redirect containment, heuristic analysis, optional threat intelligence, and a polished Security Command Center dashboard.

## Current release

**1.7.0 is the current release line.** The dashboard is now organized as a production-style command center with focused views, guided onboarding, interactive product tours, domain intelligence, security controls, privacy tools, and update awareness.

## Highlights

### 🛡️ Protection
- Fortress Mode and deterministic Declarative Net Request (DNR) enforcement
- Popup, new-tab, download, and redirect containment
- Navigation isolation across frames
- Heuristic and behavior-based security signals
- Deterministic verification before enforcement

### 🧠 Intelligence
- Optional VirusTotal BYOK integration
- Domain analysis and cached intelligence
- Heuristic signals for suspicious domains
- Safe-scanned and user-trusted domain management
- Context-menu access to security analysis

### 🖥️ Security Command Center
- Overview with live protection status
- Activity and evidence views
- Domain Intelligence
- Security controls
- Privacy & local-data controls
- API & Intelligence configuration
- Settings and About
- Smooth view, drawer, modal, loading, success, and error states
- Dark/light theme support
- Keyboard-friendly interaction and responsive layout

### 🧭 Onboarding & guided tour
New users get a step-by-step first-launch experience covering the key setup flow, including VirusTotal API configuration when enabled. A guided product tour then highlights the important areas of the Security Command Center.

### 🔄 Update awareness
The extension can check the configured GitHub release source for newer versions, notify the user when an update is available, and provide guided update instructions while preserving local extension data.

## Install

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked**.
4. Select the **repository root**.
5. Open the extension popup and launch **Dashboard**.

For the optional VirusTotal integration:

1. Sign in to VirusTotal.
2. Obtain your API key from the VirusTotal API-key page.
3. Open **Dashboard → API & Intelligence**.
4. Paste the key into the local API configuration field.
5. Save and verify the connection.

## Privacy and API credentials

Corsair Unbound follows a **local-first / BYOK** model.

- The source tree does not contain a personal VirusTotal API key or other embedded credential.
- The VirusTotal key is supplied by the user at runtime and stored in extension storage.
- Supported VirusTotal queries are sent directly to VirusTotal.
- Profiles, settings, observations, evidence, cached intelligence, and telemetry remain in extension storage unless the user explicitly exports them.
- No arbitrary remote telemetry is part of the product architecture.

See [SECURITY.md](SECURITY.md) for release hygiene and credential-handling guidance.

## Project structure

```text
.
├── .github/
│   └── workflows/
├── assets/
│   └── corsair-unbound-hero.png
├── core/
├── icons/
├── background.js
├── blocked.html
├── blocked.js
├── content.js
├── content-frame-guard.js
├── popup.html / popup.css / popup.js
├── dashboard.html / dashboard.css / dashboard.js
├── manifest.json
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── README.md
└── README.fa.md
```

The active repository tree is the current release line. Older versions remain available through Git history rather than being mixed into the production source tree.

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Shift+F` | Toggle Fortress on the current tab |
| `Ctrl+Shift+E` | Open the Corsair Dashboard |

## License

MIT — see [LICENSE](LICENSE).
