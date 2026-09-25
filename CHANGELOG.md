# Changelog

All notable changes to Corsair Unbound are documented here.

## [1.7.0] — Security Command Center

### Added

- **Production-style Dashboard redesign**
  - Sidebar navigation with focused views instead of one long settings page.
  - Overview / Security Status as the primary landing view.
  - Dedicated Activity, Domain Intelligence, Security, Privacy, API & Intelligence, Settings, and About views.
  - Recent Activity, behavior intelligence, evidence, domain profiles, and diagnostics organized into focused areas.
  - Animated page transitions, drawers, modals, toasts, loading states, and status feedback.
  - Dark/light theme support retained and integrated into the new navigation model.
- **First-launch onboarding**
  - Step-by-step welcome and initial setup flow.
  - Clear VirusTotal API-key configuration guidance.
  - Local save and verification flow with explicit success/error states.
- **Interactive product tour**
  - Guided walkthrough of the key Dashboard areas.
  - Keyboard navigation and dismiss/complete controls.
- **Update awareness**
  - Background version checks against the configured GitHub release source.
  - New-version notification flow.
  - Guided download/update instructions that preserve local extension data.
- **Navigation isolation**
  - Added frame-level navigation guarding via `content-frame-guard.js`.
  - Added dedicated blocked-navigation UI logic in `blocked.js`.
- **Context-menu intelligence access**
  - Added browser context-menu integration for security analysis workflows.
- **Release runtime improvements**
  - Added updater runtime support in `core/updater.js`.
  - Extended Manifest V3 permissions/resources for the new runtime surface.

### Changed

- Dashboard information architecture changed from a long single-page layout to a multi-view Security Command Center.
- Domain analysis, activity/history, security controls, privacy, API configuration, and settings are now separated into clearer user-facing areas.
- First-install experience now introduces the product before dropping the user into the full Dashboard.
- API configuration is presented as an explicit setup task rather than a buried global setting.
- Update-related controls are surfaced in the Dashboard About/update flow.

### Fixed

- Improved Dashboard interaction robustness with guarded event wiring and clearer state transitions.
- Improved user feedback for scan, configuration, update, loading, and failure states.
- Reduced UI clutter by moving advanced functionality into focused sections.

### Security / Privacy

- Preserved the local-first architecture and BYOK credential model.
- No personal API key or other private credential is embedded in the source tree.
- Security enforcement remains deterministic and separate from observation/telemetry behavior.

## [1.6.5] — Finalized release build

- Finalized the 1.6.5 release package and version metadata.
- Consolidated release documentation around the current product surface.
- Documented BYOK VirusTotal handling and local-first data behavior.
- Added repository validation and credential-pattern scanning for the 1.6.5 tree.

## [1.5.0] — 2025

### Added

- Heuristic Analysis Engine.
- Alarm-based TTL handling.
- Extension badge with per-tab status.
- Trust button and user trusted domains.
- Download guard.
- Keyboard shortcuts.
- Dashboard search, bulk actions, theme toggle, and privacy/data controls.
- Separate safe-list export/import.
- Incognito split mode.
- Automatic banner dismissal.

### Changed

- Added alarms permission and command shortcuts.
- Reworked dashboard information hierarchy.
- Unified Fortress allow-rule expiry around alarms.

### Fixed

- Fortress TTL recovery after service-worker restarts.
- First-install settings defaults.
- Dashboard maxRedirectHops handling.
- Popup auto-dismiss timing.

## [1.4.0]

- Fortress catch-all with DNR session rules.
- VirusTotal BYOK integration.
- Smart whitelist with OpenDNS synchronization.
- Automatic threat scanning.
- Domain analyzer dashboard.

## [1.3.0]

- Fortress popup lockdown.
- Redirect storm containment.
- Auto-scan with notifications.

## [1.2.0]

- Initial deterministic DNR enforcement.
- Redirect chain tracking.

## [1.1.0]

- First public release.
