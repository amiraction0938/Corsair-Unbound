#!/usr/bin/env bash
# ============================================================
# Corsair Unbound - Standalone Launcher (Linux/macOS)
# ============================================================
# SECURITY NOTES (what this script now enforces):
#  - the repository is fixed; the old CORSAIR_REPO environment override is gone, because any
#    program able to set it could point the updater at a malicious repository
#  - latest.json values are validated with strict patterns BEFORE use (version, sha256, url)
#  - the download url must be exactly this repo's release asset, over https only
#  - the ZIP is refused if it has absolute / ".." paths or symlinks
#  - the target folder must really be a Corsair Unbound extension before "rsync --delete" runs
# ============================================================
set -euo pipefail

REPO="amiraction0938/Corsair-Unbound"
EXT_DIR="${1:-$(cd "$(dirname "$0")/../extension" 2>/dev/null && pwd || true)}"
LATEST_JSON="https://github.com/${REPO}/releases/latest/download/latest.json"
ZIP_NAME="corsair-unbound-extension.zip"
MAX_ZIP_BYTES=$((200 * 1024 * 1024))

say()  { printf '\033[36m-> %s\033[0m\n' "$*"; }
ok()   { printf '\033[32mOK: %s\033[0m\n' "$*"; }
err()  { printf '\033[31mERR: %s\033[0m\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

command -v curl  >/dev/null 2>&1 || die "curl is required"
command -v unzip >/dev/null 2>&1 || die "unzip is required"
command -v rsync >/dev/null 2>&1 || die "rsync is required"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum  >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else die "sha256sum or shasum is required"; fi
}

# read one string field out of a flat JSON object
json_field() { printf '%s' "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed -E 's/^[^:]*:[[:space:]]*"([^"]*)"$/\1/'; }

manifest_field() { grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" | head -1 | sed -E 's/^[^:]*:[[:space:]]*"([^"]*)"$/\1/'; }

[ -n "$EXT_DIR" ] && [ -f "$EXT_DIR/manifest.json" ] || die "Extension not found (pass the extension folder as the first argument)"
[ "$(manifest_field "$EXT_DIR/manifest.json" name)" = "Corsair Unbound" ] || die "$EXT_DIR is not a Corsair Unbound extension folder; refusing to touch it"
EXT_DIR="$(cd "$EXT_DIR" && pwd)"
case "$EXT_DIR" in /|"$HOME"|/usr|/etc|/var|/bin|/opt) die "Refusing to update a system folder: $EXT_DIR";; esac

say "Fetching latest.json ..."
MANIFEST="$(curl --proto '=https' --tlsv1.2 -fsSL --max-time 30 "$LATEST_JSON")" || die "Could not download latest.json"

LATEST_VERSION="$(json_field "$MANIFEST" version)"
LATEST_TAG="$(json_field "$MANIFEST" tag)"
EXPECTED_SHA="$(json_field "$MANIFEST" sha256 | tr 'A-F' 'a-f')"
DOWNLOAD_URL="$(json_field "$MANIFEST" download_url)"

[[ "$LATEST_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Invalid version in latest.json"
[ "$LATEST_TAG" = "v${LATEST_VERSION}" ]            || die "tag/version mismatch in latest.json"
[[ "$EXPECTED_SHA" =~ ^[a-f0-9]{64}$ ]]             || die "Invalid sha256 in latest.json"
EXPECTED_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ZIP_NAME}"
[ "$DOWNLOAD_URL" = "$EXPECTED_URL" ]               || die "Untrusted download_url in latest.json"
ok "Latest version: $LATEST_VERSION"

CURRENT_VERSION="$(manifest_field "$EXT_DIR/manifest.json" version)"
[[ "$CURRENT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Cannot read the installed version"
ok "Current version: $CURRENT_VERSION"

# Version compare (returns 0 if $1 > $2)
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
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-time 300 --max-filesize "$MAX_ZIP_BYTES" "$DOWNLOAD_URL" -o "$TMP/$ZIP_NAME" || die "Download failed"

say "Verifying SHA-256 ..."
ACTUAL_SHA="$(sha256_of "$TMP/$ZIP_NAME")"
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  err "SHA-256 mismatch!"; echo "  expected: $EXPECTED_SHA"; echo "  actual:   $ACTUAL_SHA"
  exit 2
fi
ok "Integrity verified."

say "Checking ZIP entries ..."
while IFS= read -r entry; do
  case "$entry" in
    /*|[A-Za-z]:*|*..[/\\]*|*[/\\]..|..) die "ZIP contains an unsafe path: $entry";;
  esac
done < <(unzip -Z1 "$TMP/$ZIP_NAME")
[ "$(unzip -Z1 "$TMP/$ZIP_NAME" | wc -l)" -le 5000 ] || die "ZIP has too many entries"

say "Extracting ..."
mkdir "$TMP/extracted"
unzip -q "$TMP/$ZIP_NAME" -d "$TMP/extracted"
if find "$TMP/extracted" -type l | grep -q .; then die "ZIP contains symbolic links; refusing to install"; fi

SRC="$TMP/extracted"
if [ ! -f "$SRC/manifest.json" ]; then
  inner="$(find "$SRC" -maxdepth 2 -name manifest.json | head -1)"
  [ -n "$inner" ] && SRC="$(dirname "$inner")"
fi
[ -f "$SRC/manifest.json" ] || die "The package has no manifest.json"
[ "$(manifest_field "$SRC/manifest.json" name)" = "Corsair Unbound" ]     || die "The package is not Corsair Unbound"
[ "$(manifest_field "$SRC/manifest.json" version)" = "$LATEST_VERSION" ]   || die "The package version does not match latest.json"

BACKUP="${EXT_DIR}-backup-$(date +%Y%m%d-%H%M%S)"
say "Backing up to $BACKUP ..."
cp -a "$EXT_DIR" "$BACKUP"
ok "Backup created."

say "Replacing files ..."
rsync -a --delete "$SRC/" "$EXT_DIR/"
ok "Files replaced."

echo
ok "Update to v$LATEST_VERSION applied."
echo "Open chrome://extensions and click Reload on Corsair Unbound."
case "$(uname -s)" in
  Darwin) open -a "Google Chrome" "chrome://extensions" 2>/dev/null || true ;;
  Linux)  xdg-open "chrome://extensions" 2>/dev/null || true ;;
esac
