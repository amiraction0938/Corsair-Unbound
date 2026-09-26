# Security

## Scope

Corsair Unbound is a local-first Chrome Manifest V3 extension that operates on web pages and uses broad `http` and `https` host permissions as part of its protection model.

Because the extension runs in page contexts and can inspect or influence navigation-related events, a compromised release could have a high security impact. The project therefore treats source integrity, release hygiene, and credential handling as security-sensitive concerns.

## Credential policy

Corsair Unbound is intended to keep credentials out of the source tree.

- Do not commit VirusTotal API keys, OAuth tokens, cookies, passwords, private keys, or other credentials.
- VirusTotal support is BYOK: the key is supplied by the user at runtime and stored in extension storage.
- Do not paste personal credentials into Issues, Pull Requests, or documentation.
- Before publishing a release, review the complete diff and verify that no credentials or unintended files were added.
- Keep the packaged extension self-contained and avoid introducing unnecessary runtime dependencies.

## Host permissions

The manifest requests:

```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

This is required for the current protection model, including frame-level popup interception, MAIN-world `window.open()` protection, navigation and redirect containment, in-page verdict banners, and per-domain Fortress enforcement.

This permission is high-impact. Anyone distributing a modified or compromised build could potentially use the same host scope for malicious page access. Users should install releases from trusted sources and review release changes when practical.

## Runtime and supply-chain considerations

The project is designed to remain local-first and self-contained:

- No telemetry or account system is required.
- Protection logic ships with the extension.
- No remote JavaScript is loaded as part of the extension runtime.
- The repository contains no hard-coded personal credentials.
- Optional third-party threat intelligence is explicit and user-controlled through BYOK.

If dependencies are introduced in the future, they should be pinned and reviewed before release, with special attention to code that can execute inside content scripts or the extension service worker.

## Reporting

For a suspected security issue, use GitHub's private security reporting features where available rather than posting a secret publicly.

When reporting, include the affected version, a clear description of the issue, reproduction steps, and the minimum evidence needed to validate the report. Do not include credentials or other secrets.

## Release hygiene

Before creating a release:

1. Review the full source diff since the previous release.
2. Verify `manifest.json` permissions and host permissions are intentional.
3. Check for accidentally added credentials, tokens, private keys, or sensitive local files.
4. Syntax-check JavaScript and exercise the relevant regression checks available in the repository.
5. Review any newly introduced dependencies or remote endpoints.
6. Test the packaged extension in Chrome before distribution.

Security-sensitive changes should be reviewed with particular care because this extension has broad page access.

## User data and privacy

Corsair Unbound follows a local-first model. Extension settings, profiles, observations, evidence, and related state are kept in extension storage unless the user explicitly exports them.

Optional VirusTotal lookups are sent directly to VirusTotal using the user's own API key. Whitelisted domains are intentionally excluded from VirusTotal lookups.

