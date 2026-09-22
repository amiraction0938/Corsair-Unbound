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

- Open the 1.6.5 package: `new/Corsair-Unbound-1.6.5/`
- Manifest: `new/Corsair-Unbound-1.6.5/manifest.json`
- Changelog: `new/Corsair-Unbound-1.6.5/CHANGELOG.md`
- License: `new/Corsair-Unbound-1.6.5/LICENSE`

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

## Install 1.6.5

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked**.
4. Select `new/Corsair-Unbound-1.6.5/`.

The repository root is not the current 1.6.5 extension directory.

## Privacy and API credentials

Corsair Unbound follows a local-first model.

The 1.6.5 source tree does not contain a hard-coded VirusTotal API key or other personal credential. VirusTotal support is BYOK: the extension reads a key supplied in local settings and sends supported queries directly to VirusTotal.

Profiles, settings, observations, evidence, and telemetry stay in extension storage unless the user explicitly exports them.

See [SECURITY.md](SECURITY.md) for credential-handling guidance.

## Repository map

```text
.
├── new/
│   └── Corsair-Unbound-1.6.5/   ← current release
├── assets/
│   └── corsair-unbound-hero.png
├── Corsair-Unbound-v8-fixed/    ← historical reference
├── core/, *.js, *.html, *.css  ← earlier runtime snapshot
└── .github/                     ← repository workflows
```

## License

MIT — see `new/Corsair-Unbound-1.6.5/LICENSE`.
