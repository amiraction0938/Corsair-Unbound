# Corsair Unbound — Security Audit

**Audit date:** 2026-09-26  
**Reviewed branch:** main  
**Reviewed version:** 1.8.1

## Executive summary

The public repository was reviewed for accidental credential exposure, privileged API-key access, manifest risk, update-channel risk, and repository hygiene.

### Current findings

| Area | Result | Notes |
|---|---|---|
| Live VirusTotal API key in current source | **Not found** | Current-tree searches did not identify a hard-coded live key |
| API-key message exposure | **Restricted** | Background sender classification separates privileged extension pages from page observation |
| Legacy plaintext key handling | **Mitigated** | Legacy vtApiKey is migrated out of normal settings |
| Backup/export of legacy key | **Mitigated** | Backup logic removes vtApiKey, apiKey, and urlhausAuthKey |
| Host permission blast radius | **High by design** | HTTP and HTTPS host permissions cover all pages |
| Remote JavaScript | **Not observed** | Reviewed extension runtime ships its scripts locally |
| Update integrity | **Open risk** | Current updater follows mutable main without signature/hash verification |
| Ignore hygiene | **Improved** | Credential, certificate, archive, environment, and release-payload patterns are ignored |
| Historical secret guarantee | **Not absolute** | Full provider-side secret scanning was not available in this review |

## API-key review

The current source contains the expected x-apikey header used to send a user-supplied VirusTotal key to VirusTotal. The header itself is not a leaked credential.

The active key is kept outside the normal settings object and uses the secure storage path. Legacy migration removes vtApiKey from normal settings after migration.

The important limitation is that the extension must recover the key at runtime. The storage mechanism is therefore not a password-vault boundary against a compromised extension or a fully privileged attacker controlling the browser profile.

## Message-boundary review

The service worker classifies incoming senders into capability levels:

- privileged internal extension pages
- page-observation contexts
- untrusted senders

Privileged API-key read/write operations are behind the privileged capability path. Page-observation traffic is restricted to its reduced message set.

This materially reduces the risk of a hostile web page using the content-message surface to directly request the API key.

## Manifest review

Current host permissions:

    http://*/*
    https://*/*

The manifest also requests storage, declarativeNetRequest, webNavigation, tabs, downloads, windows, notifications, alarms, scripting, and contextMenus.

These permissions match the current architecture, but the broad host scope is the primary blast-radius concern if the extension is compromised.

## Update-channel review

The updater currently reads:

    https://raw.githubusercontent.com/amiraction0938/Corsair-Unbound/main/manifest.json

and downloads:

    https://github.com/amiraction0938/Corsair-Unbound/archive/refs/heads/main.zip

It compares versions but does not pin the update to an immutable commit digest and does not verify a cryptographic release signature before download.

This is the main remaining supply-chain limitation in the non-core architecture.

## Repository-history limitation

The available GitHub integration exposed the public repository, current source tree, and visible commit history, but not GitHub provider-side secret-scanning APIs.

A local full-history clone was also unavailable in this review environment because github.com could not be resolved from the container runtime.

The audit therefore does not claim an absolute historical-secret guarantee.

The repository now includes scripts/security-audit.mjs --history so maintainers can run a reachable-blob scan in a normal Git checkout.

## Release checklist

Run before each release:

    npm ci
    npm test
    node scripts/security-audit.mjs
    node scripts/security-audit.mjs --history

Then inspect:

- git diff
- git diff --cached
- manifest.json
- workflow changes
- newly introduced network endpoints
- generated ZIP/package contents

## Current status

**No current-source API-key leak was identified in this review.**

This is a bounded audit result, not a claim that the extension is vulnerability-free or that every historical Git object is guaranteed clean.
