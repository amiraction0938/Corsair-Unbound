<div align="center">

# 🏴‍☠️ Corsair Unbound

### Your browser. Your control.

**A local-first security and privacy toolkit for Google Chrome.**

<p>
  <a href="README.fa.md">🇮🇷 فارسی</a> ·
  <a href="SECURITY.md">🔒 Security Policy</a> ·
  <a href="INSTALL.md">📦 Installation Guide</a> ·
  <a href="docs/SECURITY-AUDIT.md">🧪 Security Audit</a>
</p>

<p>
  <a href="https://github.com/amiraction0938/Corsair-Unbound/releases/latest"><img src="https://img.shields.io/github/v/release/amiraction0938/Corsair-Unbound?display_name=tag&style=for-the-badge&color=7c5ce7" alt="Latest release"></a>
  <a href="https://github.com/amiraction0938/Corsair-Unbound/blob/main/LICENSE"><img src="https://img.shields.io/github/license/amiraction0938/Corsair-Unbound?style=for-the-badge" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Chrome Manifest V3">
</p>

<a href="https://github.com/amiraction0938/Corsair-Unbound/releases/latest"><strong>⬇️ Download the latest version</strong></a>

<img src="assets/corsair-unbound-hero.png" alt="Corsair Unbound — local-first browser security" width="100%">

</div>

---

> **What's new in v1.13.0:** **Automatic Userscript Execution** (zero popup clicks required, automatic registration recovery across updates & Chrome 138+ setup guidance), **AI Script Studio** (originating-tab context, anti-prompt-injection framing, CSP-safe static security review, one-time Chrome 135+ `userScripts.execute` preview, explicit approval), and **AI Providers & Models** with first-class local LLM support (`llama.cpp`, `Ollama`, `LM Studio`, `vLLM`, `LocalAI`, `Jan`, `KoboldCpp`, etc.) + cloud adapters. See [docs/AI-SCRIPT-STUDIO.md](docs/AI-SCRIPT-STUDIO.md).
>
> **Previously in v1.12.0:** Five new local-first security layers — **Credential & Phishing Form Guard** (pre-submit Shadow-DOM warning, zero credential-value reading), **ClickFix & Fake-CAPTCHA Protection**, **Offline Bloom-Filter Threat Intelligence** (zero API keys, SHA-256 verified), **HTTPS-First DNR upgrades** (`950000–959999`), and **Tracking Parameter Stripping** (`960000–969999`). See [CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md).
>
> **Previously in v1.11.0:** Unified Obsidian/Porcelain design system (`core/design-system.css`) with cohesive SVG iconography across Dashboard, Popup, and Blocked page, plus a Tampermonkey-class Userscripts engine with syntax-highlighted local editor, `GM_getTab`/`GM_saveTab`, cross-tab value sync, `.user.js` auto-install, and 1-click inject-anywhere controls. See [CHANGELOG.md](CHANGELOG.md) and [docs/USERSCRIPTS-COMPATIBILITY.md](docs/USERSCRIPTS-COMPATIBILITY.md).

## A calmer, more controlled browsing experience

The web is useful, but not every page, popup, redirect, or download deserves your trust.

**Corsair Unbound** adds a layer of browser-side protection to Chrome. It combines navigation controls, frame-level guards, suspicious-domain analysis, and optional threat-intelligence lookups in one local dashboard.

It is designed around a simple principle: **keep the core protection and your browsing data on your device wherever practical.**

> Corsair Unbound is a security tool, not a guarantee that every malicious page or attack will be detected. Keep Chrome and your operating system updated, and use your judgment when browsing.

## What can it do?

| Protection | What it does |
| --- | --- |
| **Navigation protection** | Applies browser rules to restrict navigation to blocked domains. |
| **Frame-level guard** | Helps contain popup and navigation abuse in matching frames, including third-party iframes. |
| **Phishing heuristics** | Looks for signals such as typosquatting, homograph tricks, suspicious TLDs, and brand names hidden in subdomains. |
| **Redirect containment** | Detects and contains suspicious redirect patterns and redirect storms. |
| **Fortress Mode** | Lets you lock down a domain with session-based browser rules. |
| **Download Guard** | Helps block downloads associated with malicious sources. |
| **Popup protection** | Detects bursts of popup activity and applies cooldown containment. |
| **Privacy controls** | Gives you local data controls, storage information, backup, restore, and wipe options. |

### More than a warning banner

- **Local security dashboard** — overview, analytics, activity log, domain intelligence, security, privacy, userscripts, and settings.
- **Eight interface languages** — English, فارسی, العربية, Español, Deutsch, Français, Русский, and 中文.
- **RTL support** — dedicated right-to-left layouts for Persian and Arabic.
- **Userscripts** — manage custom scripts for sites you choose. Only install scripts you trust; scripts can access page data according to their permissions and matching rules.
- **Custom trusted domains** — manage your own allowlist.
- **Light and dark themes** — choose the dashboard appearance that suits you.
- **Keyboard shortcuts** — <code>Ctrl+Shift+F</code> for Fortress and <code>Ctrl+Shift+E</code> for the dashboard.

## Get started

<div align="center">

### Ready to try it?

<a href="https://github.com/amiraction0938/Corsair-Unbound/releases/latest"><img src="https://img.shields.io/badge/Download-Corsair%20Unbound-7656d6?style=for-the-badge&logo=github&logoColor=white" alt="Download Corsair Unbound"></a>

<sub>Download the ZIP from the latest GitHub Release.</sub>

</div>

### Install in Chrome

Corsair Unbound is currently distributed as an **unpacked Chrome extension**. It is not currently listed on the Chrome Web Store, so installation requires Chrome's Developer mode.

1. Download <code>corsair-unbound-extension.zip</code> from the [latest release](https://github.com/amiraction0938/Corsair-Unbound/releases/latest).
2. Extract the ZIP to a permanent folder, for example <code>C:\CorsairUnbound</code>. Do not delete or move this folder after installation.
3. In Chrome, open <code>chrome://extensions</code>.
4. Turn on **Developer mode**.
5. Select **Load unpacked** and choose the extracted folder containing <code>manifest.json</code>.
6. Pin Corsair Unbound to the toolbar, open it, and follow the first-run setup.

**Need more detail?** Follow the [step-by-step installation guide](INSTALL.md).

## Privacy and network use

Corsair Unbound is **local-first**, not a cloud account or a remote browsing service.

- Core extension logic and its local security data are stored in your browser.
- The project does not operate a Corsair Unbound server that receives your browsing history or API keys.
- **VirusTotal is optional (BYOK):** if you add your own API key and enable the integration, relevant lookup requests are sent directly from the extension to VirusTotal.
- **URLhaus is optional:** it is skipped when no URLhaus Auth-Key is configured; when configured and used, lookup requests go to the URLhaus service.
- The extension checks GitHub Releases for update metadata. The separate Windows updater downloads the release archive, checks its SHA-256 against the published metadata, creates a backup, and installs the files after you run it.

### Permissions deserve transparency

The extension requests access to HTTP and HTTPS pages so its navigation, frame, and page-level protections can work across websites. This is broad access by design and is also a meaningful security responsibility.

Review the [Security Policy](SECURITY.md) to understand the permission model, API-key handling, userscript risks, and update limitations before installing.

## Optional threat intelligence

You can use Corsair Unbound without configuring external threat-intelligence keys. For additional lookups:

- **VirusTotal:** add your own API key under **Dashboard → API & Intelligence**.
- **URLhaus:** add an Auth-Key under the same area if you want to enable that provider.

These services have their own terms, rate limits, and privacy policies. Enabling them means relevant domain information is sent to the selected provider. Do not add an API key unless you understand and accept that data flow.

## Updating

1. Open the latest [GitHub Release](https://github.com/amiraction0938/Corsair-Unbound/releases/latest).
2. Download <code>corsair-unbound-updater.ps1</code> and run it with PowerShell.
3. Review the prompts and select or confirm your Corsair Unbound installation folder.
4. The updater verifies the release ZIP's SHA-256, creates a backup, and installs the new files.
5. Open <code>chrome://extensions</code> and click **Reload** on Corsair Unbound.

See the [installation and update guide](INSTALL.md) for the full procedure. The updater is a user-run Windows helper; it is not a silent self-updater.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| <code>Ctrl+Shift+F</code> | Toggle Fortress on the current tab |
| <code>Ctrl+Shift+E</code> | Open the Corsair Unbound dashboard |

You can review or change extension shortcuts at <code>chrome://extensions/shortcuts</code>.

## Testing and development

Requirements: Node.js and npm.

```bash
npm ci
npm test
npm run build
node scripts/security-audit.mjs
node scripts/security-audit.mjs --history
```

The test suite and static security audit are useful safeguards, but passing checks do not prove that the extension is free of vulnerabilities.

## Documentation

- [Installation & Update Guide](INSTALL.md)
- [Security Policy](SECURITY.md)
- [Security Audit](docs/SECURITY-AUDIT.md)
- [Update Policy](docs/UPDATE-POLICY.md)
- [Changelog](CHANGELOG.md)
- [فارسی — راهنمای فارسی](README.fa.md)

## Contributing and reporting security issues

Bug reports and thoughtful contributions are welcome. Please avoid posting credentials, private browsing data, or exploitable vulnerability details in public issues. For security-sensitive reports, follow the private reporting guidance in [SECURITY.md](SECURITY.md).

## License

Corsair Unbound is released under the [MIT License](LICENSE).
