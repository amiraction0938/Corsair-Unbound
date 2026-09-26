# Security Policy

## Scope

Corsair Unbound is a local-first Chrome Manifest V3 extension. Its current protection model requires broad HTTP and HTTPS host access so that page and frame protection can run at navigation time.

This is a high-impact permission model. A compromised build could therefore have meaningful access to web-page contexts.

## Credential policy

The repository must never contain live credentials.

Do not commit:

- VirusTotal API keys
- OAuth or access tokens
- cookies or session credentials
- passwords
- private keys or certificates
- service-account credentials
- personal authentication material

Do not place secrets in logs, tests, fixtures, screenshots, issues, pull requests, documentation, or generated release payloads.

VirusTotal support is BYOK: the user supplies the key at runtime.

## Current API-key design

The active VirusTotal key is stored outside the ordinary settings payload and uses an application-level encrypted/obfuscated representation.

This reduces ordinary plaintext storage exposure, but it is not a password-manager-grade vault. The extension must recover the key at runtime, so a compromised extension build or highly privileged local attacker may still recover or misuse it.

Backup/export paths remove legacy plaintext fields such as vtApiKey before writing portable settings.

## Message boundary

The background service worker classifies incoming message senders into capability levels.

The current design distinguishes:

- privileged internal extension pages
- page-observation contexts
- untrusted senders

Privileged API-key read/write operations are behind the privileged capability path. Page-observation messages are restricted to the smaller observation message set.

## Host permissions

The current manifest requests:

    http://*/*
    https://*/*

These permissions are intentional for frame-level protection, navigation observation, in-page verdicts, and Fortress enforcement.

They also define the primary blast-radius consideration if the extension source or release process is compromised.

## Remote inputs and update risk

The project uses external network inputs for optional threat intelligence and for its built-in updater.

The current updater:

- reads the public GitHub manifest.json
- compares versions locally
- downloads the mutable main branch ZIP
- does not verify a signed release or immutable commit digest before download

It must therefore be treated as a convenience update path, not as a cryptographically verified software supply-chain channel.

## Remote code

The extension should remain self-contained at runtime.

Do not introduce:

- remote JavaScript execution
- remotely hosted extension scripts
- dynamic code loading without explicit security review
- unnecessary third-party runtime dependencies

## Dependency hygiene

Before adding or upgrading a dependency:

1. review package provenance
2. review the lockfile diff
3. review code execution surface
4. run the full test suite
5. run scripts/security-audit.mjs
6. review the complete Git diff

## Release hygiene

Before publishing:

1. inspect the complete source diff
2. verify manifest permissions
3. run the test suite
4. run the security audit
5. check for credentials and sensitive local files
6. review newly introduced network endpoints
7. review workflow and release changes
8. inspect final package contents

## Reporting a vulnerability

Do not publish secrets or exploit details in a public issue.

Use GitHub private security reporting features when available. Include the affected version, impact description, reproduction steps, and only the minimum evidence needed to validate the report.

## Audit transparency

The repository includes static security-audit tooling and CI checks.

A passing static audit does not prove that the extension is vulnerability-free. It is a guardrail against common repository mistakes, not a substitute for a full security assessment.
