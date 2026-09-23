# Corsair Unbound

<p align="center">
  <strong>Current release: 1.6.5</strong>
</p>

<p align="center">
  <img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound" width="100%">
</p>

<h2 align="center">Security • Freedom • A Right for Everyone</h2>
<p align="center"><strong>Nothing can limit us.</strong></p>

<p align="center">
  <a href="README.fa.md"><strong>🇮🇷 Persian Documentation</strong></a>
</p>

Corsair Unbound is a local-first Chrome Manifest V3 browser shield focused on deterministic navigation protection, Fortress enforcement, redirect containment, heuristic analysis, optional threat intelligence, and a full local dashboard.

## Current release

**1.6.5 is the repository root.** There is no extra folder to enter before loading the extension.

## Highlights

- Fortress Mode and deterministic DNR enforcement
- Popup and redirect containment
- Download protection
- Heuristic and behavior intelligence
- Optional VirusTotal BYOK
- Smart whitelist and trusted domains
- Full Dashboard
- Backup, restore, and privacy controls
- Replay and regression support
- Alarm-based TTL and recovery
- Incognito split mode
- Internationalization support

## Install

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked**.
4. Select the **repository root**.
5. Open the popup and launch **Dashboard**.

## Privacy and API credentials

Corsair Unbound follows a local-first model.

The 1.6.5 source tree does not contain a hard-coded VirusTotal API key or other personal credential. VirusTotal support is BYOK: the extension reads a key supplied in local settings and sends supported queries directly to VirusTotal.

Profiles, settings, observations, evidence, and telemetry stay in extension storage unless the user explicitly exports them.

See [SECURITY.md](SECURITY.md) for credential-handling guidance.

## Project structure

```text
.
├── assets/
│   └── corsair-unbound-hero.png
├── core/
├── icons/
├── .github/
├── background.js
├── content.js
├── popup.html / popup.css / popup.js
├── dashboard.html / dashboard.css / dashboard.js
├── blocked.html
├── manifest.json
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── README.md
└── README.fa.md
```

The repository root is the active 1.6.5 extension source. Older versions remain available in Git history rather than mixed into the active project tree.

## License

MIT — see [LICENSE](LICENSE).
