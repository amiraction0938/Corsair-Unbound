# Changelog

All notable changes to Corsair Unbound are documented here.

## [Unreleased] — Security & Repository Hardening

### Added

- Security audit documentation with explicit threat-model and update-channel limitations
- Update policy documentation for unpacked installations
- Local credential and secret scanning at scripts/security-audit.mjs
- Dedicated GitHub Actions security-audit workflow
- Expanded ignore rules for credentials, certificates, archives, environment files, and release payloads

### Changed

- Refreshed the English and Persian READMEs to match v1.8.1
- Clarified the difference between application-level API-key protection and a real password vault
- Documented the current mutable-main-branch updater limitation
- Improved repository hygiene without changing the extension core protection logic

### Security

- Current-tree review found no hard-coded VirusTotal API key
- Privileged API-key messaging is separated from page-observation messaging
- Backup/export removes legacy plaintext API-key fields

> Audit note: the current-source review is bounded. It is not a cryptographic guarantee that every historical Git object or future release is clean.

## [1.8.1] — Current

See repository history for the current 1.8.1 feature changes.

## [1.8.0]

- Multi-language interface
- RTL support for Persian and Arabic
- Localized in-page verdict banner
- In-extension update checker
- Per-frame popup interception
- Additional navigation and content security controls
