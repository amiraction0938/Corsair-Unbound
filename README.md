# Corsair Unbound

Corsair Unbound is a Manifest V3, local-first browser shield focused on deterministic navigation containment, declarative network enforcement, redirect-chain analysis, evidence capture, and a bounded local site graph.

## Included

- Manifest V3 service worker with local storage and session state.
- Fortress domain profiles with explicit blocked destinations.
- Dynamic Declarative Net Request rules for main-frame cross-domain containment.
- Redirect-chain tracking per tab.
- Site observation into a bounded graph.
- Evidence and activity telemetry with storage budgets.
- Import/export and diagnostics through the runtime message API.
- A small popup for enabling Fortress and managing blocked destinations for the active site.

## Load in Chrome

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked**.
4. Select the extracted `corsair-unbound-v1.0.2` directory.
5. Open any HTTP/HTTPS page and click the Corsair Unbound toolbar button.

## Validation

Run the included syntax/self-test from the project root:

```text
node tests/self-test.mjs
```

All runtime JavaScript files should pass `node --check` before packaging.

## Notes

Dynamic DNR rules are persistent browser state. The service worker reconciles the registry against the live dynamic rule set at install/startup and after profile changes.
