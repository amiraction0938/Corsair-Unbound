# ============================================================
# Corsair Unbound — Manual Update Script
# ------------------------------------------------------------
# Downloads the latest release ZIP from GitHub and extracts it
# to a staging folder. Then guides the user to swap the files.
#
# Usage:
#   .\scripts\update.ps1
#
# The user's extension data lives in chrome.storage.local, NOT
# in these files, so nothing is lost when files are replaced.
# ============================================================

param(
  [string]$Repo = 'amiraction0938/Corsair-Unbound',
  [string]$ExtensionPath = '',
  [switch]$AutoReplace
)

$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host '  Corsair Unbound — Update Helper' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''

# ---- 1. Query GitHub API for the latest release ----
Write-Host '[1/5] Querying GitHub for the latest release...' -ForegroundColor Yellow
$apiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
  $release = Invoke-RestMethod -Uri $apiUrl -Headers @{
    'Accept' = 'application/vnd.github+json'
    'User-Agent' = 'Corsair-Unbound-Updater'
  } -UseBasicParsing
} catch {
  Write-Host "ERROR: Could not reach GitHub API: $_" -ForegroundColor Red
  exit 1
}

$tag = $release.tag_name
$asset = $release.assets | Where-Object { $_.name -eq 'corsair-unbound-extension.zip' } | Select-Object -First 1

if (-not $asset) {
  Write-Host "ERROR: No release asset named 'corsair-unbound-extension.zip' found." -ForegroundColor Red
  exit 1
}

Write-Host "      Latest release: $tag" -ForegroundColor Green
Write-Host "      Asset: $($asset.name) ($([math]::Round($asset.size / 1KB, 1)) KB)" -ForegroundColor Green
Write-Host ''

# ---- 2. Download the ZIP ----
Write-Host '[2/5] Downloading ZIP...' -ForegroundColor Yellow
$tmpZip = Join-Path $env:TEMP "corsair-unbound-$tag.zip"
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tmpZip -UseBasicParsing
Write-Host "      Saved to: $tmpZip" -ForegroundColor Green
Write-Host ''

# ---- 3. Extract to staging ----
Write-Host '[3/5] Extracting to staging folder...' -ForegroundColor Yellow
$staging = Join-Path $env:TEMP "corsair-unbound-$tag-staging"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
Expand-Archive -Path $tmpZip -DestinationPath $staging -Force
Write-Host "      Staging: $staging" -ForegroundColor Green
Write-Host ''

# ---- 4. Show where to install ----
Write-Host '[4/5] Files ready.' -ForegroundColor Yellow

if ($AutoReplace -and $ExtensionPath -and (Test-Path $ExtensionPath)) {
  Write-Host "      Auto-replacing files in: $ExtensionPath" -ForegroundColor Yellow
  Copy-Item -Path (Join-Path $staging '*') -Destination $ExtensionPath -Recurse -Force
  Write-Host '      ✅ Files replaced.' -ForegroundColor Green
} else {
  Write-Host ''
  Write-Host '      Next steps:' -ForegroundColor White
  Write-Host '        1. Open your Corsair Unbound extension folder' -ForegroundColor White
  Write-Host '        2. Replace all files with the contents of:' -ForegroundColor White
  Write-Host "           $staging" -ForegroundColor Cyan
  Write-Host '        3. Open chrome://extensions' -ForegroundColor White
  Write-Host '        4. Click the ↻ reload button on Corsair Unbound' -ForegroundColor White
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
Write-Host '  After swapping files, click ↻ reload in chrome://extensions.' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ''