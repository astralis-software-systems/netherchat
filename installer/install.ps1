#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the Netherchat terminal client on Windows.
.DESCRIPTION
    Downloads the netherchat client for your architecture from GitHub releases,
    verifies its SHA-256, installs it to %LOCALAPPDATA%\Programs\netherchat, and
    adds that directory to your user PATH. Installs the endpoint client only by
    default; pass -WithServer to also install the netherchat-server relay binary,
    which already ships in the same release archive (no extra download).
.EXAMPLE
    irm https://netherchat.com/install.ps1 | iex
.EXAMPLE
    & ([scriptblock]::Create((irm https://netherchat.com/install.ps1))) -Version 1.2.0
.EXAMPLE
    & ([scriptblock]::Create((irm https://netherchat.com/install.ps1))) -WithServer
.EXAMPLE
    & ([scriptblock]::Create((irm https://netherchat.com/install.ps1))) -Uninstall
#>
[CmdletBinding()]
param(
    [string]$Version = $env:NETHERCHAT_VERSION,
    [string]$BinDir = $env:NETHERCHAT_BIN_DIR,
    [switch]$WithServer,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$Repo = 'salehkreiner/netherchat'
$Binary = 'netherchat.exe'
$ServerBinary = 'netherchat-server.exe'

function Step($m) { Write-Host "> $m" -ForegroundColor Magenta }
function Ok($m) { Write-Host "  + $m" -ForegroundColor Green }
function Warn($m) { Write-Host "  ! $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "error: $m" -ForegroundColor Red; exit 1 }

if (-not $BinDir) { $BinDir = Join-Path $env:LOCALAPPDATA 'Programs\netherchat' }

function Remove-FromUserPath($dir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -and $userPath -like "*$dir*") {
        $new = ($userPath -split ';' | Where-Object { $_ -and $_ -ne $dir }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
        Ok "removed $dir from user PATH"
    }
}

# ---- uninstall --------------------------------------------------------------
if ($Uninstall) {
    $target = Join-Path $BinDir $Binary
    if (Test-Path $target) {
        Remove-Item $target -Force
        Ok "removed $target"
    }
    else {
        Warn "no $Binary found in $BinDir"
    }
    $serverTarget = Join-Path $BinDir $ServerBinary
    if (Test-Path $serverTarget) {
        Remove-Item $serverTarget -Force
        Ok "removed $serverTarget"
    }
    Remove-FromUserPath $BinDir
    exit 0
}

# ---- platform ---------------------------------------------------------------
Step 'Detecting platform'
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { Die "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
Ok "windows/$arch"

# ---- resolve version --------------------------------------------------------
Step 'Resolving release'
if (-not $Version -or $Version -eq 'latest') {
    $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'netherchat-installer' }
    $tag = $rel.tag_name
    if (-not $tag) { Die 'could not resolve the latest release (is the repo published yet?)' }
}
else {
    $tag = 'v' + ($Version -replace '^v', '')
}
$ver = $tag -replace '^v', ''
Ok "netherchat $ver"

# ---- download + verify + install --------------------------------------------
$archive = "netherchat_windows_$arch.zip"
$base = "https://github.com/$Repo/releases/download/$tag"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("netherchat-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Step "Downloading $archive"
    Invoke-WebRequest "$base/$archive" -OutFile (Join-Path $tmp $archive) -UseBasicParsing
    Ok 'downloaded'

    Step 'Verifying checksum'
    try {
        Invoke-WebRequest "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt') -UseBasicParsing
        $actual = (Get-FileHash (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLower()
        $line = Select-String -Path (Join-Path $tmp 'checksums.txt') -Pattern ([regex]::Escape($archive)) | Select-Object -First 1
        if ($line) {
            $expected = (($line.Line -split '\s+')[0]).ToLower()
            if ($actual -ne $expected) { Die "checksum mismatch for $archive" }
            Ok 'sha256 verified'
        }
        else {
            Warn "no checksum entry for $archive - skipping verification"
        }
    }
    catch {
        Warn 'checksums.txt unavailable - skipping verification'
    }

    Step 'Installing'
    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp -Force
    $src = Join-Path $tmp $Binary
    if (-not (Test-Path $src)) { Die "archive did not contain $Binary" }
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Copy-Item $src (Join-Path $BinDir $Binary) -Force
    Ok "installed to $(Join-Path $BinDir $Binary)"

    # Opt-in relay: the server binary already rode down inside this same archive, so
    # -WithServer installs it with zero extra download. If it is absent (an older
    # release), warn and continue - the client install must always succeed.
    if ($WithServer) {
        $serverSrc = Join-Path $tmp $ServerBinary
        if (Test-Path $serverSrc) {
            Copy-Item $serverSrc (Join-Path $BinDir $ServerBinary) -Force
            Ok "installed to $(Join-Path $BinDir $ServerBinary)"
        }
        else {
            Warn "this release has no $ServerBinary - the relay was not installed (the client is fine); get it via Docker or 'go build ./cmd/netherchat-server' - see docs/self-hosting.md"
        }
    }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- PATH (user scope) ------------------------------------------------------
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $BinDir), 'User')
    $env:Path += ';' + $BinDir
    Ok "added $BinDir to your user PATH (restart your terminal to pick it up)"
}

Write-Host ''
if ($WithServer) {
    Write-Host "Netherchat $ver installed - client + relay." -ForegroundColor Magenta -NoNewline
    Write-Host '  Messaging that lives below the surface.'
    Write-Host "  Connect:     netherchat connect ws://localhost:3000 --name $env:USERNAME"
    Write-Host '  Run a relay: netherchat-server --addr :3000   (or: docker run -p 3000:3000 salkreiner/netherchat)'
    Write-Host '               Full guide: docs/self-hosting.md'
}
else {
    Write-Host "Netherchat $ver installed - the endpoint client." -ForegroundColor Magenta -NoNewline
    Write-Host '  Messaging that lives below the surface.'
    Write-Host "  Connect:    netherchat connect ws://localhost:3000 --name $env:USERNAME"
    Write-Host '  Self-host:  re-run with -WithServer for the native relay (netherchat-server - already in'
    Write-Host '              this release, no extra download), or: docker run -p 3000:3000 salkreiner/netherchat'
    Write-Host '              Full guide: docs/self-hosting.md'
}
Write-Host ''
