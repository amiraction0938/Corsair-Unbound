<#
.SYNOPSIS
    Corsair Unbound — Windows Updater (Path A)

.DESCRIPTION
    Standalone updater for the Corsair Unbound Chrome extension.

    The extension does NOT download updates. This launcher:
      1. Reads latest.json from the GitHub Releases CDN
      2. Compares installed version with latest
      3. Downloads the release ZIP (once)
      4. Verifies SHA-256 against latest.json
      5. Creates a timestamped backup
      6. Replaces extension files (never touching user data)
      7. Opens chrome://extensions for the final Reload step

    Chrome storage (settings, blocklists, profiles, cache) lives
    in Chrome's profile directory, NOT in the extension folder —
    so it survives every update automatically.

    First run: asks the user to select the extension directory.
    Config: %APPDATA%\CorsairUnbound\config.json
    File manifest: %APPDATA%\CorsairUnbound\installed-files.json

.NOTES
    Requires Windows PowerShell 5.1+ (built into Windows 10/11).
    Does NOT require admin rights (extension folder must be writable).

.LINK
    https://github.com/amiraction0938/Corsair-Unbound
#>

param(
    [string]$ExtensionPath = "",
    [switch]$Force,
    [switch]$Reset
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
$Repo              = 'amiraction0938/Corsair-Unbound'
$LatestJsonUrl     = "https://github.com/$Repo/releases/latest/download/latest.json"
$ExpectedZipName   = 'corsair-unbound-extension.zip'
$AppDataDir        = Join-Path $env:APPDATA 'CorsairUnbound'
$ConfigPath        = Join-Path $AppDataDir 'config.json'
$InstalledFilePath = Join-Path $AppDataDir 'installed-files.json'

# ----------------------------------------------------------------------------
# Console helpers
# ----------------------------------------------------------------------------
function Write-Step($msg) { Write-Host "-> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "OK: $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "ERR: $msg" -ForegroundColor Red }
function Write-Note($msg) { Write-Host "    $msg" -ForegroundColor Gray }

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
function Load-Config {
    if (-not (Test-Path $ConfigPath)) { return $null }
    try {
        $c = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        if (-not $c.extensionPath) { return $null }
        return $c
    } catch { return $null }
}

function Save-Config($extPath) {
    if (-not (Test-Path $AppDataDir)) {
        New-Item -ItemType Directory -Path $AppDataDir -Force | Out-Null
    }
    $data = [ordered]@{
        extensionPath = (Resolve-Path $extPath).Path
        configuredAt  = (Get-Date).ToUniversalTime().ToString('o')
    }
    ($data | ConvertTo-Json) | Set-Content -Path $ConfigPath -Encoding UTF8 -Force
}

# ----------------------------------------------------------------------------
# Manifest validation
# ----------------------------------------------------------------------------
function Test-ExtensionManifest($dir) {
    if (-not $dir -or -not (Test-Path $dir)) { return $null }
    $manifestPath = Join-Path $dir 'manifest.json'
    if (-not (Test-Path $manifestPath)) { return $null }
    try {
        $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($m.manifest_version -ne 3) { return $null }
        if ($m.name -ne 'Corsair Unbound') { return $null }
        if ($m.version -notmatch '^\d+\.\d+\.\d+$') { return $null }
        return $m
    } catch { return $null }
}

# ----------------------------------------------------------------------------
# Fetch and validate latest.json
# ----------------------------------------------------------------------------
function Get-LatestManifest {
    Write-Step "Fetching release metadata..."
    $res = Invoke-RestMethod -Uri $LatestJsonUrl -UseBasicParsing -TimeoutSec 30

    if (-not $res.version) { throw "latest.json is missing 'version'" }
    if ($res.version -notmatch '^\d+\.\d+\.\d+$') { throw "latest.json has invalid version: $($res.version)" }
    if (-not $res.tag) { throw "latest.json is missing 'tag'" }
    if ($res.tag -ne "v$($res.version)") { throw "latest.json tag/version mismatch" }
    if ($res.tag -notmatch '^v\d+\.\d+\.\d+$') { throw "Non-stable tag: $($res.tag)" }
    if (-not $res.download_url) { throw "latest.json is missing 'download_url'" }
    if (-not ($res.download_url -like "https://github.com/$Repo/releases/download/*")) {
        throw "download_url is not a GitHub release asset URL"
    }
    if (-not ($res.download_url -like "*$ExpectedZipName")) {
        throw "download_url does not point to $ExpectedZipName"
    }
    if (-not $res.sha256 -or $res.sha256 -notmatch '^[a-fA-F0-9]{64}$') {
        throw "latest.json has invalid sha256"
    }
    if ($res.published_at) {
        $null = [DateTime]::Parse($res.published_at)
    }
    return $res
}

# ----------------------------------------------------------------------------
# Version compare
# ----------------------------------------------------------------------------
function Compare-VersionString($a, $b) {
    return ([version]$a).CompareTo([version]$b)
}

# ----------------------------------------------------------------------------
# Download + SHA-256
# ----------------------------------------------------------------------------
function Save-VerifiedZip($url, $expectedSha, $outPath) {
    Write-Step "Downloading release ZIP..."
    Invoke-WebRequest -Uri $url -OutFile $outPath -UseBasicParsing -TimeoutSec 300

    Write-Step "Verifying SHA-256..."
    $actual   = (Get-FileHash -Path $outPath -Algorithm SHA256).Hash.ToLower()
    $expected = $expectedSha.ToLower()
    if ($actual -ne $expected) {
        throw "SHA-256 mismatch.`n  expected: $expected`n  actual:   $actual"
    }
    Write-Ok "SHA-256 verified ($($actual.Substring(0, 16))...)"
}

# ----------------------------------------------------------------------------
# ZIP extraction with traversal protection
# ----------------------------------------------------------------------------
function Expand-ZipSafely($zipPath, $destDir) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    Write-Step "Validating ZIP entries..."
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ([System.IO.Path]::IsPathRooted($name)) {
                throw "ZIP contains absolute path: $name"
            }
            if ($name -match '(^|[/\\])\.\.([/\\]|$)') {
                throw "ZIP contains path traversal: $name"
            }
            if ($name -match '^[A-Za-z]:') {
                throw "ZIP contains drive-letter path: $name"
            }
            if ($name -match '(^|[/\\])(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.[^/\\]*)?$') {
                throw "ZIP contains Windows reserved name: $name"
            }
        }
    } finally {
        $zip.Dispose()
    }

    Write-Step "Extracting to staging directory..."
    if (Test-Path $destDir) { Remove-Item -Path $destDir -Recurse -Force }
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destDir)

    # Post-extraction safety check
    $resolvedDest = (Resolve-Path $destDir).Path
    Get-ChildItem -Path $destDir -Recurse -File | ForEach-Object {
        if (-not $_.FullName.StartsWith($resolvedDest, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Extracted file escaped target directory: $($_.FullName)"
        }
    }

    Write-Ok "Extracted $((Get-ChildItem -Path $destDir -Recurse -File).Count) files"
}

function Find-ExtractedRoot($extractDir) {
    # Case 1: manifest.json directly in extractDir
    if (Test-Path (Join-Path $extractDir 'manifest.json')) { return $extractDir }

    $topDirs = Get-ChildItem -Path $extractDir -Directory
    if ($topDirs.Count -eq 1) {
        $inner = $topDirs[0].FullName
        # Case 2: manifest.json inside single top dir
        if (Test-Path (Join-Path $inner 'manifest.json')) { return $inner }
        # Case 3: manifest.json inside single-top-dir/dist/
        $distDir = Join-Path $inner 'dist'
        if (Test-Path (Join-Path $distDir 'manifest.json')) { return $distDir }
    }
    return $extractDir
}

# ----------------------------------------------------------------------------
# Backup
# ----------------------------------------------------------------------------
function New-ExtensionBackup($extDir) {
    $parent = Split-Path $extDir -Parent
    $backupName = "extension-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $backupPath = Join-Path $parent $backupName
    Write-Step "Creating backup at $backupPath..."
    Copy-Item -Path $extDir -Destination $backupPath -Recurse -Force
    Write-Ok "Backup created"
    return $backupPath
}

# ----------------------------------------------------------------------------
# Installed-files manifest
# ----------------------------------------------------------------------------
function Load-InstalledFiles {
    if (-not (Test-Path $InstalledFilePath)) { return @() }
    try {
        $data = Get-Content $InstalledFilePath -Raw | ConvertFrom-Json
        if ($data.files -and $data.files -is [array]) {
            return @($data.files)
        }
        return @()
    } catch { return @() }
}

function Save-InstalledFiles($files) {
    if (-not (Test-Path $AppDataDir)) {
        New-Item -ItemType Directory -Path $AppDataDir -Force | Out-Null
    }
    $data = [ordered]@{
        files        = @($files)
        lastUpdateAt = (Get-Date).ToUniversalTime().ToString('o')
    }
    ($data | ConvertTo-Json -Depth 4) | Set-Content -Path $InstalledFilePath -Encoding UTF8 -Force
}

function Get-RelativeFiles($rootDir) {
    $resolved = (Resolve-Path $rootDir).Path
    Get-ChildItem -Path $rootDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($resolved.Length).TrimStart('\', '/')
        $rel -replace '\\', '/'
    }
}

# ----------------------------------------------------------------------------
# Apply update: remove obsolete managed files, copy new files
# ----------------------------------------------------------------------------
function Apply-Update {
    param($extDir, $extractedDir, $oldFiles, $newFiles)

    $newSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($f in $newFiles) { $null = $newSet.Add($f) }
    $obsolete = @($oldFiles | Where-Object { -not $newSet.Contains($_) })

    $resolvedExt = (Resolve-Path $extDir).Path

    if ($obsolete.Count -gt 0) {
        Write-Step "Removing $($obsolete.Count) obsolete file(s)..."
        foreach ($rel in $obsolete) {
            $full = Join-Path $extDir $rel
            if (-not (Test-Path $full)) { continue }
            $resolvedFull = (Resolve-Path $full).Path
            if (-not $resolvedFull.StartsWith($resolvedExt, [System.StringComparison]::OrdinalIgnoreCase)) {
                Write-Note "Skipping suspicious path: $rel"
                continue
            }
            Remove-Item -Path $full -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Step "Installing $($newFiles.Count) file(s)..."
    $resolvedExtracted = (Resolve-Path $extractedDir).Path
    Get-ChildItem -Path $extractedDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($resolvedExtracted.Length).TrimStart('\', '/')
        $dest = Join-Path $extDir $rel
        $destDir = Split-Path $dest -Parent
        if ($destDir -and -not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Copy-Item -Path $_.FullName -Destination $dest -Force
    }
    Write-Ok "Files installed"
}

# ----------------------------------------------------------------------------
# Open Chrome
# ----------------------------------------------------------------------------
function Open-ChromeExtensions {
    Write-Step "Attempting to open chrome://extensions..."
    $chromePaths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LocalAppData\Google\Chrome\Application\chrome.exe"
    )
    foreach ($p in $chromePaths) {
        if (Test-Path $p) {
            try {
                Start-Process -FilePath $p -ArgumentList "chrome://extensions" -ErrorAction Stop
                Write-Ok "Chrome launched"
                return $true
            } catch {
                Write-Note "Launch failed from $p"
            }
        }
    }
    Write-Note "Chrome not found automatically."
    return $false
}

# ----------------------------------------------------------------------------
# Folder picker (initial setup)
# ----------------------------------------------------------------------------
function Select-ExtensionFolder {
    Write-Step "Please select the Corsair Unbound extension folder..."
    Write-Note "It must contain manifest.json"
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select the Corsair Unbound extension folder (contains manifest.json)"
    $dialog.ShowNewFolderButton = $false
    $result = $dialog.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $dialog.SelectedPath
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
function Main {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "  Corsair Unbound - Windows Updater" -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""

    if ($Reset) {
        if (Test-Path $ConfigPath) { Remove-Item $ConfigPath -Force }
        if (Test-Path $InstalledFilePath) { Remove-Item $InstalledFilePath -Force }
        Write-Note "Config reset. Setup mode will run."
    }

    # ---- Resolve extension folder ----
    $config = Load-Config
    $extDir = $null
    if ($ExtensionPath) {
        $extDir = $ExtensionPath
    } elseif ($config -and (Test-Path $config.extensionPath)) {
        $extDir = $config.extensionPath
    }

    if (-not $extDir -or -not (Test-ExtensionManifest $extDir)) {
        Write-Note "First-time setup required."
        $selected = Select-ExtensionFolder
        if (-not $selected) { Write-Err "No folder selected. Aborting."; exit 1 }
        if (-not (Test-ExtensionManifest $selected)) {
            Write-Err "Selected folder does not contain a valid Corsair Unbound manifest.json"
            exit 1
        }
        Save-Config $selected
        $extDir = (Resolve-Path $selected).Path
        Write-Ok "Config saved to $ConfigPath"
    }

    # ---- Validate installed extension ----
    $installed = Test-ExtensionManifest $extDir
    if (-not $installed) {
        Write-Err "Installed extension at $extDir is not a valid Corsair Unbound installation."
        exit 1
    }
    $currentVersion = $installed.version
    Write-Ok "Installed: v$currentVersion at $extDir"

    # ---- Fetch latest metadata ----
    $latest = Get-LatestManifest
    Write-Ok "Latest available: v$($latest.version)"

    if (-not $Force) {
        $cmp = Compare-VersionString $latest.version $currentVersion
        if ($cmp -le 0) { Write-Ok "Already up to date."; exit 0 }
    }

    # ---- Download & verify ----
    $tempDir = Join-Path $env:TEMP "corsair-update-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $zipPath = Join-Path $tempDir $ExpectedZipName

    try {
        Save-VerifiedZip $latest.download_url $latest.sha256 $zipPath

        $extractDir = Join-Path $tempDir 'extracted'
        Expand-ZipSafely $zipPath $extractDir
        $innerRoot = Find-ExtractedRoot $extractDir

        $newManifest = Test-ExtensionManifest $innerRoot
        if (-not $newManifest) { throw "Downloaded package has no valid manifest.json" }
        if ($newManifest.version -ne $latest.version) {
            throw "Manifest version ($($newManifest.version)) != latest.json ($($latest.version))"
        }
        Write-Ok "Package verified: v$($newManifest.version)"

        # ---- Backup ----
        $backupPath = New-ExtensionBackup $extDir

        # ---- Apply ----
        $oldFiles = Load-InstalledFiles
        $newFiles = @(Get-RelativeFiles $innerRoot)

        try {
            Apply-Update -extDir $extDir -extractedDir $innerRoot -oldFiles $oldFiles -newFiles $newFiles
        } catch {
            Write-Err "Installation failed: $_"
            Write-Step "Rolling back from backup..."
            $resolvedBackup = (Resolve-Path $backupPath).Path
            Get-ChildItem -Path $backupPath -Recurse -File | ForEach-Object {
                $rel = $_.FullName.Substring($resolvedBackup.Length).TrimStart('\', '/')
                $dest = Join-Path $extDir $rel
                $destDir = Split-Path $dest -Parent
                if ($destDir -and -not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                Copy-Item -Path $_.FullName -Destination $dest -Force
            }
            Write-Ok "Rollback complete. Extension restored to v$currentVersion"
            exit 1
        }

        # ---- Verify ----
        $finalManifest = Test-ExtensionManifest $extDir
        if (-not $finalManifest -or $finalManifest.version -ne $latest.version) {
            throw "Post-install verification failed"
        }

        Save-InstalledFiles $newFiles
        Write-Ok "Extension updated to v$($latest.version)"

        # ---- Open Chrome ----
        Start-Sleep -Seconds 3
        $opened = Open-ChromeExtensions

        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Green
        Write-Host "  Update complete: v$currentVersion -> v$($latest.version)" -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor Green
        if ($opened) {
            Write-Host "  Chrome was opened. If the version shown is still" -ForegroundColor Yellow
            Write-Host "  v$currentVersion, click Reload on Corsair Unbound." -ForegroundColor Yellow
        } else {
            Write-Host "  Open chrome://extensions in Chrome and click Reload" -ForegroundColor Yellow
            Write-Host "  on Corsair Unbound if it did not reload automatically." -ForegroundColor Yellow
        }
        Write-Host "  Backup: $backupPath" -ForegroundColor Gray
        Write-Host ""

    } finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

try {
    Main
} catch {
    Write-Err "Fatal error: $_"
    Write-Note "Full stack: $($_.ScriptStackTrace)"
    exit 1
}