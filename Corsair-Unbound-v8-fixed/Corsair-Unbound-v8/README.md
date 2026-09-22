# Corsair Unbound v5

Local-first defensive Chrome MV3 extension with: Fortress domain profiles; Safe Redirect Resolver; redirect-chain observation and deterministic verification; popup/new-tab/download guards; Dynamic Declarative Net Request enforcement for verified suspicious source-to-destination navigation pairs; persistent site knowledge graph and evidence; replay/regression cases; and a typed tool router for local agents/LLMs.

## Load
1. Extract the ZIP.
2. Open `chrome://extensions`.
3. Enable Developer mode.
4. Load unpacked and select this folder.
5. Test Protect Domain -> Fortress.
6. Open the service worker console and check for runtime errors.

## Safety invariants
- Local-first telemetry.
- Observation is not treated as blocking.
- Redirects are auto-contained only after deterministic verification says `suspicious`.
- DNR blocking uses source/destination pairs instead of a blanket cross-site block.
- Agent access goes through `tool-call`; no arbitrary eval or unrestricted Chrome API is exposed.


## Backup / Restore
The dashboard can export a `.corsair.json` backup containing global settings, domain profiles, regression cases, DNR diagnostics, and optional telemetry. Import validates the Corsair format and restores settings/profiles immediately; optional telemetry restore is opt-in.


## 5.1 dashboard recovery
- Fixed dashboard null-element handler errors with guarded event binding.
- Added `.corsair.json` full configuration export/import.
- Export includes global settings, all domain profiles, regression cases and diagnostic telemetry.
- Telemetry restore is opt-in on import.
- Imported profiles/settings trigger DNR rebuild automatically.


## v8 — Defensive Intelligence
Behavior correlation correlates recent navigation, redirect, popup, new-tab and download signals into a local risk assessment with confidence and false-positive dampening for same-site/user-initiated navigation.
