# Gemini Handoff Contract — Corsair Unbound v8

Improve the project without reducing defensive behavior or collapsing it into a simple extension.

## Non-negotiable invariants
1. `Protect Domain` immediately creates/updates a Fortress profile with all protections enabled.
2. Safe Redirect Resolver remains available and local-first.
3. Observation and enforcement remain separate.
4. Never use `webNavigation` return values as blocking.
5. Verified suspicious redirect pairs are enforced by `declarativeNetRequest` dynamic rules.
6. Domain profiles remain independent.
7. Preserve Search, Activity, Evidence, Site Graph, Replay/Regression, and Tool Router.
8. No arbitrary remote telemetry.
9. Agent/LLM uses Tool Router; no unrestricted Chrome APIs or arbitrary JS execution.
10. Existing APIs remain compatible unless migration is documented.

## Architecture
Protection → Observation → Evidence → Graph → Deterministic Verification → Enforcement → Replay/Regression → Agent Context.

## Agent tools
Read-only: `get_context`, `get_profile`, `get_events`, `get_evidence`, `get_graph`, `get_chains`, `get_regressions`, `run_regressions`, `list_rules`, `verify_redirect`.
Controlled: `protect_domain`, `patch_profile`, `block_destination`, `unblock_destination`, `capture_regression`.

## Definition of done
Syntax checks, core tests, security regression tests, Service Worker start without console errors, and documentation updates are mandatory.


## 5.1 dashboard recovery
- Fixed dashboard null-element handler errors with guarded event binding.
- Added `.corsair.json` full configuration export/import.
- Export includes global settings, all domain profiles, regression cases and diagnostic telemetry.
- Telemetry restore is opt-in on import.
- Imported profiles/settings trigger DNR rebuild automatically.


## v8 Defensive Intelligence
- Behavior correlation is local-first and deterministic.
- Same-site and typed/user-initiated navigation is damped to reduce false positives.
- High-risk containment requires a protected profile and policy flags; no remote reputation service is required.
- Preserve `core/intelligence.js` and its APIs unless a migration is documented and tests are updated.
- Add detectors by extending signal scoring rather than replacing the verifier.
