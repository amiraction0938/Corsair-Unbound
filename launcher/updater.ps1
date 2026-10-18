<#
.SYNOPSIS
    Corsair Unbound — Windows Updater (Path A)
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
# Auto-Discovery Logic
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

function Find-ExtensionPath {
    # 1. Search Chrome Preferences (The active extension)
    Write-Step "Searching for active Corsair Unbound extension in Chrome..."
    $chromeProfiles = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Preferences",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Preferences",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 2\Preferences"
    )
    foreach ($pref in $chromeProfiles) {
        if (Test-Path $pref) {
            try {
                $json = Get-Content $pref -Raw | ConvertFrom-Json
                if ($json.extensions -and $json.extensions.settings) {
                    foreach ($ext in $json.extensions.settings.PSObject.Properties) {
                        if ($ext.Value.path -and (Test-Path $ext.Value.path)) {
                            if ($ext.Value.manifest -and $ext.Value.manifest.name -eq 'Corsair Unbound') {
                                return $ext.Value.path
                            }
                        }
                    }
                }
            } catch {}
        }
    }

    # 2. Check Config File (Fallback)
    $config = Load-Config
    if ($config -and (Test-Path $config.extensionPath) -and (Test-ExtensionManifest $config.extensionPath)) {
        return $config.extensionPath
    }

    # 3. Check if script is inside extension folder
    if (Test-Path (Join-Path $PSScriptRoot 'manifest.json')) {
        if (Test-ExtensionManifest $PSScriptRoot) {
            return $PSScriptRoot
        }
    }

    return $null
}

# ----------------------------------------------------------------------------
# Fetch and validate latest.json
# ----------------------------------------------------------------------------
function Get-LatestManifest {
    Write-Step "Fetching release metadata..."
    $res = Invoke-RestMethod -Uri $LatestJsonUrl -UseBasicParsing -TimeoutSec 30

    if (-not $res.version) { throw "latest.json is missing 'version'" }
    if ($res.version -notmatch '^\d+\.\d+\.\d+$') { throw "latest.json has invalid version" }
    if (-not $res.tag -or $res.tag -ne "v$($res.version)") { throw "latest.json tag/version mismatch" }
    if (-not $res.download_url -or -not ($res.download_url -like "https://github.com/$Repo/releases/download/*")) { throw "invalid download_url" }
    if (-not $res.sha256 -or $res.sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw "invalid sha256" }
    
    return $res
}

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
    if ($actual -ne $expectedSha.ToLower()) {
        throw "SHA-256 mismatch!`n  expected: $expectedSha`n  actual:   $actual"
    }
    Write-Ok "SHA-256 verified."
}

function Expand-ZipSafely($zipPath, $destDir) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Write-Step "Validating ZIP entries..."
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            if ([System.IO.Path]::IsPathRooted($name) -or $name -match '(^|[/\\])\.\.([/\\]|$)' -or $name -match '^[A-Za-z]:') {
                throw "ZIP contains unsafe path: $name"
            }
        }
    } finally { $zip.Dispose() }

    Write-Step "Extracting to staging directory..."
    if (Test-Path $destDir) { Remove-Item -Path $destDir -Recurse -Force }
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destDir)
    Write-Ok "Extracted files safely."
}

function Find-ExtractedRoot($extractDir) {
    if (Test-Path (Join-Path $extractDir 'manifest.json')) { return $extractDir }
    $topDirs = Get-ChildItem -Path $extractDir -Directory
    if ($topDirs.Count -eq 1) {
        $inner = $topDirs[0].FullName
        if (Test-Path (Join-Path $inner 'manifest.json')) { return $inner }
        $distDir = Join-Path $inner 'dist'
        if (Test-Path (Join-Path $distDir 'manifest.json')) { return $distDir }
    }
    return $extractDir
}

# ----------------------------------------------------------------------------
# Backup & Install
# ----------------------------------------------------------------------------
function New-ExtensionBackup($extDir) {
    $parent = Split-Path $extDir -Parent
    $backupName = "extension-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $backupPath = Join-Path $parent $backupName
    Write-Step "Creating backup at $backupPath..."
    Copy-Item -Path $extDir -Destination $backupPath -Recurse -Force
    Write-Ok "Backup created."
    return $backupPath
}

function Load-InstalledFiles {
    if (-not (Test-Path $InstalledFilePath)) { return @() }
    try {
        $data = Get-Content $InstalledFilePath -Raw | ConvertFrom-Json
        if ($data.files -and $data.files -is [array]) { return @($data.files) }
        return @()
    } catch { return @() }
}

function Save-InstalledFiles($files) {
    if (-not (Test-Path $AppDataDir)) { New-Item -ItemType Directory -Path $AppDataDir -Force | Out-Null }
    $data = [ordered]@{ files = @($files); lastUpdateAt = (Get-Date).ToUniversalTime().ToString('o') }
    ($data | ConvertTo-Json -Depth 4) | Set-Content -Path $InstalledFilePath -Encoding UTF8 -Force
}

function Get-RelativeFiles($rootDir) {
    $resolved = (Resolve-Path $rootDir).Path
    Get-ChildItem -Path $rootDir -Recurse -File | ForEach-Object {
        $_.FullName.Substring($resolved.Length).TrimStart('\', '/') -replace '\\', '/'
    }
}

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
            $item = Get-Item -Path $full -ErrorAction SilentlyContinue
            if ($item -and $item.PSIsContainer) { continue } # Skip directories!
            Remove-Item -Path $full -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Step "Installing $($newFiles.Count) file(s)..."
    $resolvedExtracted = (Resolve-Path $extractedDir).Path
    Get-ChildItem -Path $extractedDir -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($resolvedExtracted.Length).TrimStart('\', '/')
        $dest = Join-Path $extDir $rel
        $destDir = Split-Path $dest -Parent
        if ($destDir -and -not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Copy-Item -Path $_.FullName -Destination $dest -Force
    }
    Write-Ok "Files installed."
}

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
                Write-Ok "Chrome launched."
                return $true
            } catch {}
        }
    }
    return $false
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
        Write-Note "Config reset. Setup will run."
    }

    # ---- Resolve extension folder ----
    $extDir = $null
    if ($ExtensionPath) {
        $extDir = $ExtensionPath
    } else {
        $extDir = Find-ExtensionPath
    }

    if (-not $extDir -or -not (Test-ExtensionManifest $extDir)) {
        Write-Note "Could not auto-detect the extension folder."
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = "Select the Corsair Unbound extension folder (contains manifest.json)"
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { Write-Err "Cancelled."; exit 1 }
        $extDir = $dialog.SelectedPath
        if (-not (Test-ExtensionManifest $extDir)) { Write-Err "Invalid extension folder."; exit 1 }
        Save-Config $extDir
    } else {
        Write-Ok "Auto-detected extension folder: $extDir"
        Save-Config $extDir
    }

    $installed = Test-ExtensionManifest $extDir
    $currentVersion = $installed.version
    Write-Ok "Installed version: v$currentVersion"

    # ---- Fetch latest metadata ----
    $latest = Get-LatestManifest
    Write-Ok "Latest available: v$($latest.version)"

    if (-not $Force -and (Compare-VersionString $latest.version $currentVersion) -le 0) {
        Write-Ok "Already up to date. No action needed."
        exit 0
    }

    $tempDir = Join-Path $env:TEMP "corsair-update-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $zipPath = Join-Path $tempDir $ExpectedZipName

    try {
        Save-VerifiedZip $latest.download_url $latest.sha256 $zipPath
        $extractDir = Join-Path $tempDir 'extracted'
        Expand-ZipSafely $zipPath $extractDir
        $innerRoot = Find-ExtractedRoot $extractDir

        $newManifest = Test-ExtensionManifest $innerRoot
        if (-not $newManifest -or $newManifest.version -ne $latest.version) {
            throw "Downloaded package has invalid manifest or wrong version."
        }

        $backupPath = New-ExtensionBackup $extDir
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
                Copy-Item -Path $_.FullName -Destination (Join-Path $extDir $rel) -Force
            }
            Write-Ok "Rollback complete."
            exit 1
        }

        $finalManifest = Test-ExtensionManifest $extDir
        if (-not $finalManifest -or $finalManifest.version -ne $latest.version) { throw "Post-install verification failed" }

        Save-InstalledFiles $newFiles
        Write-Ok "Extension updated to v$($latest.version)"

        Start-Sleep -Seconds 2
        $opened = Open-ChromeExtensions

        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Green
        Write-Host "  Update complete: v$currentVersion -> v$($latest.version)" -ForegroundColor Green
        Write-Host "==========================================" -ForegroundColor Green
        if ($opened) {
            Write-Host "  Chrome was opened. If the version is still old," -ForegroundColor Yellow
            Write-Host "  click Reload on Corsair Unbound in chrome://extensions." -ForegroundColor Yellow
        } else {
            Write-Host "  Open chrome://extensions in Chrome and click Reload." -ForegroundColor Yellow
        }
        Write-Host "  Backup: $backupPath" -ForegroundColor Gray
        Write-Host ""

    } finally {
        if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

try { Main } catch { Write-Err "Fatal error: $_"; exit 1 }