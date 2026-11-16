# ============================================================
# Corsair Unbound - Manual Update Script
# ------------------------------------------------------------
# Downloads the latest release ZIP from GitHub, VERIFIES it, and extracts it
# to a staging folder. Then guides the user to swap the files.
#
# SECURITY: the old version trusted the GitHub API blindly, never checked a
# checksum and used Expand-Archive. Now it uses the same checks as the
# launcher: strict latest.json validation, exact-asset url, SHA-256
# verification, safe extraction, and a Corsair Unbound manifest check before
# -AutoReplace touches any folder.
#
# Usage:
#   .\scripts\update.ps1
#   .\scripts\update.ps1 -AutoReplace -ExtensionPath 'C:\path\to\extension'
#
# The user's extension data lives in chrome.storage.local, NOT in these
# files, so nothing is lost when files are replaced.
# ============================================================

param(
  [string]$ExtensionPath = '',
  [switch]$AutoReplace
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

# The repository is fixed on purpose (the old -Repo parameter let anything redirect the updater).
$Repo = 'amiraction0938/Corsair-Unbound'
$ExpectedZipName = 'corsair-unbound-extension.zip'
$LatestJsonUrl = "https://github.com/$Repo/releases/latest/download/latest.json"

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

function Test-TrustedDownloadUrl($url, $tag) {
  try { $u = [System.Uri]([string]$url) } catch { return $false }
  if ($u.Scheme -ne 'https') { return $false }
  if ($u.UserInfo -or -not $u.IsDefaultPort) { return $false }
  if ($u.Host -ne 'github.com') { return $false }
  if ($u.Query -or $u.Fragment) { return $false }
  return ($u.AbsolutePath -ieq "/$Repo/releases/download/$tag/$ExpectedZipName")
}

function Test-ExtensionFolder($dir) {
  $mf = Join-Path $dir 'manifest.json'
  if (-not (Test-Path $mf)) { return $false }
  try {
    $m = Get-Content $mf -Raw | ConvertFrom-Json
    return ($m.manifest_version -eq 3 -and $m.name -eq 'Corsair Unbound')
  } catch { return $false }
}

function Expand-ZipSafely($zipPath, $destDir) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
  try {
    if ($zip.Entries.Count -gt 5000) { throw "ZIP has too many entries" }
    $total = 0L
    foreach ($entry in $zip.Entries) {
      $total += $entry.Length
      if ($total -gt 200MB) { throw "ZIP is unexpectedly large when extracted" }
      $name = $entry.FullName
      if ([string]::IsNullOrWhiteSpace($name)) { continue }
      if ([System.IO.Path]::IsPathRooted($name) -or $name -match '(^|[/\\])\.\.([/\\]|$)' -or $name -match '^[A-Za-z]:') {
        throw "ZIP contains unsafe path: $name"
      }
    }
  } finally { $zip.Dispose() }
  if (Test-Path $destDir) { Remove-Item $destDir -Recurse -Force }
  New-Item -ItemType Directory -Path $destDir -Force | Out-Null
  [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destDir)
}

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  Corsair Unbound - Update Helper' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''

# ---- 1. Read and validate latest.json ----
Write-Host '[1/5] Fetching and validating release metadata...' -ForegroundColor Yellow
try { $latest = Invoke-RestMethod -Uri $LatestJsonUrl -UseBasicParsing -TimeoutSec 30 }
catch { Fail "Could not reach GitHub: $_" }

if (-not $latest.version -or $latest.version -notmatch '^\d+\.\d+\.\d+$') { Fail 'Invalid version in latest.json' }
$tag = "v$($latest.version)"
if ($latest.tag -ne $tag) { Fail 'tag/version mismatch in latest.json' }
if (-not (Test-TrustedDownloadUrl $latest.download_url $tag)) { Fail 'Untrusted download_url in latest.json' }
if (-not $latest.sha256 -or $latest.sha256 -notmatch '^[a-fA-F0-9]{64}$') { Fail 'Invalid sha256 in latest.json' }
Write-Host "      Latest release: $tag" -ForegroundColor Green
Write-Host ''

# ---- 2. Download + verify ----
Write-Host '[2/5] Downloading ZIP and verifying SHA-256...' -ForegroundColor Yellow
$work = Join-Path $env:TEMP ("corsair-unbound-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$tmpZip = Join-Path $work $ExpectedZipName
Invoke-WebRequest -Uri $latest.download_url -OutFile $tmpZip -UseBasicParsing -TimeoutSec 300
$actual = (Get-FileHash -Path $tmpZip -Algorithm SHA256).Hash.ToLower()
if ($actual -ne ([string]$latest.sha256).ToLower()) {
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
  Fail "SHA-256 mismatch! expected $($latest.sha256) but got $actual. The download was NOT used."
}
Write-Host '      SHA-256 verified.' -ForegroundColor Green
Write-Host ''

# ---- 3. Extract to staging ----
Write-Host '[3/5] Extracting to staging folder...' -ForegroundColor Yellow
$staging = Join-Path $work 'staging'
Expand-ZipSafely $tmpZip $staging
$root = $staging
if (-not (Test-Path (Join-Path $root 'manifest.json'))) {
  $dirs = @(Get-ChildItem -Path $staging -Directory)
  if ($dirs.Count -eq 1 -and (Test-Path (Join-Path $dirs[0].FullName 'manifest.json'))) { $root = $dirs[0].FullName }
}
if (-not (Test-ExtensionFolder $root)) { Fail 'The downloaded package is not a valid Corsair Unbound extension.' }
Write-Host "      Staging: $root" -ForegroundColor Green
Write-Host ''

# ---- 4. Show where to install / auto-replace ----
Write-Host '[4/5] Files ready.' -ForegroundColor Yellow
if ($AutoReplace -and $ExtensionPath -and (Test-Path $ExtensionPath)) {
  if (-not (Test-ExtensionFolder $ExtensionPath)) {
    Fail "'$ExtensionPath' is not a Corsair Unbound extension folder. Nothing was changed."
  }
  Write-Host "      Auto-replacing files in: $ExtensionPath" -ForegroundColor Yellow
  Copy-Item -Path (Join-Path $root '*') -Destination $ExtensionPath -Recurse -Force
  Write-Host '      Files replaced.' -ForegroundColor Green
} else {
  Write-Host ''
  Write-Host '      Next steps:' -ForegroundColor White
  Write-Host '        1. Open your Corsair Unbound extension folder' -ForegroundColor White
  Write-Host '        2. Replace all files with the contents of:' -ForegroundColor White
  Write-Host "           $root" -ForegroundColor Cyan
  Write-Host '        3. Open chrome://extensions' -ForegroundColor White
  Write-Host '        4. Click the reload button on Corsair Unbound' -ForegroundColor White
  Write-Host ''
  Write-Host '      To auto-replace instead, run:' -ForegroundColor DarkGray
  Write-Host "        .\scripts\update.ps1 -AutoReplace -ExtensionPath 'C:\path\to\extension'" -ForegroundColor DarkGray
}

# ---- 5. Open chrome://extensions ----
Write-Host '[5/5] Opening chrome://extensions...' -ForegroundColor Yellow
Start-Process 'chrome.exe' -ArgumentList 'chrome://extensions' -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  Done. Your data (settings, profiles, blocklists) is safe.' -ForegroundColor Cyan
Write-Host '  After swapping files, click reload in chrome://extensions.' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''
