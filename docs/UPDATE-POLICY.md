# Corsair Unbound — Update Policy

## Current mechanism

Corsair Unbound is distributed as an unpacked Chrome extension.

The built-in updater is a helper rather than a full automatic installer because unpacked Chrome extensions cannot safely self-replace their own source files.

Current flow:

    public GitHub manifest.json
            |
            v
    version comparison
            |
            v
    desktop notification
            |
            v
    GitHub main-branch ZIP
            |
            v
    manual file replacement
            |
            v
    chrome://extensions -> Reload

## What the updater verifies

- The public manifest.json is reachable.
- The remote manifest contains a syntactically valid version.
- The remote version is newer than the installed version.

## What the updater does not verify

- Signed release metadata
- A trusted checksum tied to a release
- Immutable commit pinning
- Trusted build provenance
- Reproducible build output

## Safe procedure for sensitive installations

1. Open the Corsair Unbound GitHub repository.
2. Inspect the target commit or release.
3. Review the diff from the currently installed source/version.
4. Check that manifest permissions have not unexpectedly expanded.
5. Run the full test suite.
6. Run the repository security audit.
7. Replace the unpacked files.
8. Open chrome://extensions and click Reload.
9. Confirm the installed version.

## Why this matters

The current updater follows the mutable main branch. If the repository account, repository contents, or publishing workflow were compromised, the updater could retrieve modified extension source.

For this reason, the convenience updater should not be treated as equivalent to a signed software-update system.

## Future hardening path

These improvements can be added without changing the extension protection core:

- immutable release tags
- release checksums
- signed release metadata
- commit/digest pinning
- pre-download verification
- optional reproducible-build verification
