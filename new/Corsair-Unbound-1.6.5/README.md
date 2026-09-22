# Corsair Unbound 1.6.5

Local-first Chrome MV3 browser shield with deterministic enforcement, Fortress protection, redirect containment, heuristic analysis, optional threat intelligence, and a full security dashboard.

## Protection

- Fortress Mode with per-domain DNR lockdown.
- Popup lockdown with burst detection and cooldown containment.
- Redirect storm containment and chain verification.
- Download protection for suspicious navigation.
- Deterministic blocked-destination handling.

## Intelligence

- Heuristic analysis for typosquatting, homographs, suspicious TLDs, Punycode/IDN, and related domain-risk signals.
- Behavior intelligence across navigation, redirect, popup, download, and containment signals.
- Optional VirusTotal BYOK integration.
- Smart whitelist with built-in trusted domains and optional OpenDNS synchronization.
- User trusted domains.

## User experience

- In-page verdict banner and trust controls.
- Per-tab extension badge.
- Keyboard shortcuts:
  - Ctrl+Shift+F / Command+Shift+F — toggle Fortress.
  - Ctrl+Shift+E / Command+Shift+E — open Dashboard.
- Full Dashboard for analysis, safe lists, privacy controls, settings, evidence, and diagnostics.
- Light/Dark theme.
- Internationalization support.

## Data and recovery

- Local configuration, evidence, observation, and telemetry storage.
- Full backup and restore.
- Separate safe-list export and import.
- Storage statistics and wipe-all controls.
- Deterministic replay and regression support.
- Alarm-based TTL handling and session recovery.
- Incognito split mode.

## Install

1. Open chrome://extensions.
2. Enable Developer mode.
3. Choose Load unpacked.
4. Select this directory: new/Corsair-Unbound-1.6.5/.
5. Open the popup and launch Dashboard.

No build step is required for the current unpacked extension.

## VirusTotal BYOK and privacy

Corsair Unbound does not embed a VirusTotal API key in the source code.

When VirusTotal intelligence is enabled, the extension reads settings.vtApiKey from local extension storage and sends domain queries directly to VirusTotal. The repository contains the integration logic, not a personal API credential.

Core profiles, settings, evidence, observations, and telemetry remain local unless explicitly exported by the user.

## Architecture

    manifest.json
    background.js
    content.js
    popup.html / popup.css / popup.js
    dashboard.html / dashboard.css / dashboard.js
    blocked.html
    icons/
    core/
      alarms.js
      dnr.js
      evidence.js
      heuristics.js
      i18n.js
      intelligence.js
      migration.js
      observation.js
      redirects.js
      replay.js
      security.js
      storage.js
      threat-intel.js
      tool-router.js
      verifier.js

See CHANGELOG.md for release history.

## License

MIT — see LICENSE.
