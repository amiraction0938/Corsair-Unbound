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