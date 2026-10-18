#!/usr/bin/env bash
# ============================================================
# Corsair Unbound — Standalone Launcher (Linux/macOS)
# ============================================================
set -euo pipefail

REPO="${CORSAIR_REPO:-amiraction0938/Corsair-Unbound}"
EXT_DIR="${1:-$(cd "$(dirname "$0")/../extension" && pwd)}"
LATEST_JSON="https://github.com/${REPO}/releases/latest/download/latest.json"
ZIP_NAME="corsair-unbound-extension.zip"

say()  { printf '\033[36m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[32m✓ %s\033[0m\n' "$*"; }
err()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; }

say "Fetching latest.json ..."
MANIFEST="$(curl -fsSL "$LATEST_JSON")"
LATEST_VERSION="$(printf '%s' "$MANIFEST" | grep -o '"version"[^,]*' | head -1 | cut -d'"' -f4)"
EXPECTED_SHA="$(printf '%s' "$MANIFEST" | grep -o '"sha256"[^,]*' | head -1 | cut -d'"' -f4)"
DOWNLOAD_URL="$(printf '%s' "$MANIFEST" | grep -o '"download_url"[^,]*' | head -1 | cut -d'"' -f4)"

if [ -z "$LATEST_VERSION" ] || [ -z "$EXPECTED_SHA" ] || [ -z "$DOWNLOAD_URL" ]; then
  err "Invalid latest.json"; exit 1
fi
ok "Latest version: $LATEST_VERSION"

if [ ! -f "$EXT_DIR/manifest.json" ]; then
  err "Extension not found at $EXT_DIR"; exit 1
fi
CURRENT_VERSION="$(grep -o '"version"[^,]*' "$EXT_DIR/manifest.json" | head -1 | cut -d'"' -f4)"
ok "Current version: $CURRENT_VERSION"

# Version compare (returns 1 if $1 > $2)
ver_gt() {
  [ "$1" = "$2" ] && return 1
  local IFS=.
  local -a a=($1) b=($2)
  for i in 0 1 2; do
    [ "${a[$i]:-0}" -gt "${b[$i]:-0}" ] && return 0
    [ "${a[$i]:-0}" -lt "${b[$i]:-0}" ] && return 1
  done
  return 1
}

if ! ver_gt "$LATEST_VERSION" "$CURRENT_VERSION"; then
  ok "Already up to date."; exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "Downloading $DOWNLOAD_URL ..."
curl -fsSL "$DOWNLOAD_URL" -o "$TMP/$ZIP_NAME"

say "Verifying SHA-256 ..."
ACTUAL_SHA="$(shasum -a 256 "$TMP/$ZIP_NAME" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  err "SHA-256 mismatch!"
  echo "  expected: $EXPECTED_SHA"
  echo "  actual:   $ACTUAL_SHA"
  exit 2
fi
ok "Integrity verified."

BACKUP="$EXT_DIR/../extension-backup-$(date +%Y%m%d-%H%M%S)"
say "Backing up to $BACKUP ..."
cp -a "$EXT_DIR" "$BACKUP"
ok "Backup created."

say "Extracting ..."
unzip -q "$TMP/$ZIP_NAME" -d "$TMP/extracted"
SRC="$TMP/extracted"
if [ "$(find "$SRC" -maxdepth 1 -type d | wc -l)" -eq 2 ] && [ -f "$(find "$SRC" -maxdepth 2 -name manifest.json | head -1)" ]; then
  SRC="$(dirname "$(find "$SRC" -maxdepth 2 -name manifest.json | head -1)")"
fi

say "Replacing files ..."
rsync -a --delete "$SRC/" "$EXT_DIR/"
ok "Files replaced."

echo
ok "Update to v$LATEST_VERSION applied."
echo "Open chrome://extensions and click ↻ Reload on Corsair Unbound."
case "$(uname -s)" in
  Darwin) open -a "Google Chrome" "chrome://extensions" 2>/dev/null || true ;;
  Linux)  xdg-open "chrome://extensions" 2>/dev/null || true ;;
esac