# Security

## Credential policy

Corsair Unbound is intended to keep credentials out of the source tree.

- Do not commit VirusTotal API keys, OAuth tokens, cookies, passwords, private keys, or other credentials.
- VirusTotal support is BYOK: the key is supplied by the user at runtime and stored in extension storage.
- Do not paste personal credentials into Issues, Pull Requests, or documentation.
- Before publishing a release, run the repository validation workflow and review changed files.

## Reporting

For a suspected security issue, use GitHub's private security reporting features where available rather than posting a secret publicly.

## Release hygiene

The 1.6.5 validation workflow validates the Manifest V3 package, syntax-checks the JavaScript runtime, and scans the release tree for high-signal credential patterns.