# Corsair Unbound

**Version:** 1.1.0  
**Platform:** Chrome / Manifest V3  
**Model:** Local-first browser security

Corsair Unbound is a local-first Chrome MV3 browser shield that combines deterministic Fortress enforcement with redirect-chain observation, behavior intelligence, evidence, a persistent site graph, diagnostics, replay/regression tooling, and a full local dashboard.

> The repository root is the current product source of truth. The historical v8 tree is preserved under `Corsair-Unbound-v8-fixed/Corsair-Unbound-v8/` for reference.

## Product surface

- **Fortress domain profiles** — explicit protection state and per-domain policy.
- **Safe Redirect Resolver** — local redirect controls and deterministic chain tracking.
- **Declarative Net Request (DNR)** — source/destination enforcement rules.
- **Navigation containment** — blocked-destination and popup/new-tab guards.
- **Observation & graph** — page/network observations and a persistent site graph.
- **Behavior intelligence** — local signal correlation, scoring, confidence, and verdicts.
- **Evidence & telemetry** — bounded local evidence and activity data.
- **Dashboard** — settings, profiles, activity, observation, intelligence, evidence, agent context, backup/restore, and regression tools.
- **Replay / Regression** — deterministic local regression cases for runtime behavior.
- **Recovery & durability** — storage quotas, locking, rollback, migration, and startup reconciliation.
- **Tool router** — bounded local agent context without exposing unrestricted Chrome APIs.

## Repository structure

```text
.
├── background.js            # MV3 service worker and message/API boundary
├── content.js               # page-side observation bridge
├── popup.html / popup.js    # quick controls
├── dashboard.html/js/css   # full local dashboard
├── core/
│   ├── dnr.js               # DNR registry and rule reconciliation
│   ├── evidence.js          # bounded evidence store
│   ├── intelligence.js      # behavior scoring and assessment
│   ├── migration.js         # export/import and recovery
│   ├── observation.js       # page/network observation
│   ├── redirects.js         # redirect-chain state and guards
│   ├── replay.js            # regression/replay support
│   ├── security.js          # validation and normalization helpers
│   ├── storage.js           # local/session persistence and locking
│   ├── tool-router.js       # bounded agent/tool surface
│   └── verifier.js           # deterministic navigation verification
├── tests/
│   └── self-test.mjs        # focused Node-based runtime self-test
├── .github/workflows/
│   └── validate.yml         # syntax, manifest, and self-test validation
└── Corsair-Unbound-v8-fixed/
    └── Corsair-Unbound-v8/  # historical reference implementation
```

## Install locally

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked**.
4. Choose the repository root.
5. Open the extension popup and use **Dashboard** for full controls.

No build step is required for the current unpacked extension.

## Validation

The repository includes a focused self-test and GitHub Actions validation.

The validation workflow checks:

- JavaScript syntax for the runtime and core modules.
- Manifest validity and referenced UI/icon files.
- The deterministic local self-test in `tests/self-test.mjs`.

For a local check:

```bash
node --check background.js
node --check content.js
node --check popup.js
node --check dashboard.js

for f in core/*.js; do
  node --check "$f"
done

node tests/self-test.mjs
```

## Backup and restore

The Dashboard can export a `.corsair.json` backup containing configuration, domain profiles, regression cases, DNR diagnostics, and optional telemetry.

Telemetry restore is explicitly opt-in during import.

## Local-first behavior

Profiles, policy state, graph data, evidence, and telemetry remain in extension storage unless the user explicitly exports them.

## Historical source

The `Corsair-Unbound-v8-fixed/Corsair-Unbound-v8/` tree is retained as a historical reference point for the original product surface. It is **not** the runtime source of truth for the current 1.1.0 release.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
