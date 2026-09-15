<#
.SYNOPSIS
    Builds the Win32 app package (.intunewin) for the drive-map agent, on any platform.

.DESCRIPTION
    Microsoft's IntuneWinAppUtil.exe is Windows-only. This script uses the cross-platform
    SvRooij.ContentPrep.Cmdlet module, which produces a byte-compatible package
    (ToolVersion 1.8.6.0), so the build works on Linux and macOS build agents too.

    The script:
      1. Verifies client/config.json exists and is NOT the untouched sample - packaging the
         placeholder tenant would produce an app that silently fails to mount on every device.
      2. Stages ONLY the runtime files. The repo's docs, tests, deploy script and analyzer
         settings must never ship inside the package.
      3. Builds dist/Install-DriveMapAgent.intunewin.
      4. Round-trips it: unpacks the result and compares every file's SHA-256 against the
         staged source. A package that cannot be decrypted back to identical bytes is a
         package Intune will reject after upload, and that failure is far more annoying to
         diagnose from the portal than from here.

.PARAMETER SkipVerify
    Skip the round-trip verification. Not recommended.

.EXAMPLE
    ./tools/Build-IntuneWinPackage.ps1

.NOTES
    Install the packer once:
        Install-Module SvRooij.ContentPrep.Cmdlet -Scope CurrentUser
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path $PSScriptRoot '..' 'dist'),
    [switch] $SkipVerify
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step { param([string] $m) Write-Host ''; Write-Host "[build] $m" -ForegroundColor Cyan }
function Write-Ok   { param([string] $m) Write-Host "     OK   $m" -ForegroundColor Green }

$repoRoot  = Resolve-Path (Join-Path $PSScriptRoot '..')
$clientDir = Join-Path $repoRoot 'client'

# Only these ship. Anything else in client/ (or the repo) stays out of the package.
$payload = @(
    'Install-DriveMapAgent.ps1',
    'Uninstall-DriveMapAgent.ps1',
    'Detect-DriveMapAgent.ps1',
    'Invoke-DriveMapAgent.ps1',
    'package.json',
    'config.json'
)

# -----------------------------------------------------------------------------
Write-Step 'Checking prerequisites'
if (-not (Get-Module -ListAvailable SvRooij.ContentPrep.Cmdlet)) {
    throw "Missing packer. Install-Module SvRooij.ContentPrep.Cmdlet -Scope CurrentUser"
}
Import-Module SvRooij.ContentPrep.Cmdlet -ErrorAction Stop
Write-Ok "Packer $((Get-Module SvRooij.ContentPrep.Cmdlet).Version)"

$configPath = Join-Path $clientDir 'config.json'
if (-not (Test-Path $configPath)) {
    throw ("client/config.json not found. It is generated per tenant by " +
           "azure/Deploy-AzureFilesForCloudPC.ps1, and is gitignored because it carries a " +
           "real tenant ID. Copy client/config.sample.json and edit it if building by hand.")
}

# Guard against shipping the sample verbatim. The placeholder tenant produces a package that
# installs cleanly and then never maps a drive - a slow, confusing failure.
$cfg = Get-Content $configPath -Raw | ConvertFrom-Json
if ($cfg.tenantId -eq '00000000-0000-0000-0000-000000000000') {
    throw "client/config.json still has the sample placeholder tenantId. Generate a real one before packaging."
}
if ($cfg.mappings[0].uncPath -like '*stcloudpcfileseus01*') {
    Write-Warning "config.json still references the sample storage account. Verify this is intended."
}
Write-Ok "Config: tenant $($cfg.tenantId)"
Write-Ok "Config: $($cfg.mappings[0].uncPath) -> $($cfg.mappings[0].driveLetter):"

# -----------------------------------------------------------------------------
Write-Step 'Staging payload'
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("intunewin-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
try {
    foreach ($f in $payload) {
        $src = Join-Path $clientDir $f
        if (-not (Test-Path $src)) { throw "Payload file missing: client/$f" }
        Copy-Item $src -Destination $stage -Force
    }
    Write-Ok "$($payload.Count) file(s) staged"

    # -------------------------------------------------------------------------
    Write-Step 'Building package'
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $OutputPath = (Resolve-Path $OutputPath).Path

    New-IntuneWinPackage -SourcePath $stage `
                         -SetupFile (Join-Path $stage 'Install-DriveMapAgent.ps1') `
                         -DestinationPath $OutputPath -ErrorAction Stop | Out-Null

    $pkg = Join-Path $OutputPath 'Install-DriveMapAgent.intunewin'
    if (-not (Test-Path $pkg)) { throw "Build reported success but $pkg does not exist." }
    Write-Ok "$pkg ($([math]::Round((Get-Item $pkg).Length / 1KB, 1)) KB)"

    # -------------------------------------------------------------------------
    if (-not $SkipVerify) {
        Write-Step 'Verifying round-trip'
        $rt = Join-Path ([System.IO.Path]::GetTempPath()) ("intunewin-rt-" + [guid]::NewGuid().ToString('N'))
        try {
            Unlock-IntuneWinPackage -SourceFile $pkg -DestinationPath $rt -ErrorAction Stop | Out-Null

            $mismatch = 0
            foreach ($f in $payload) {
                $orig = Get-FileHash (Join-Path $stage $f) -Algorithm SHA256
                $back = Get-ChildItem -Path $rt -Recurse -Filter $f | Select-Object -First 1
                if (-not $back) { Write-Warning "  MISSING after round-trip: $f"; $mismatch++; continue }
                if ((Get-FileHash $back.FullName -Algorithm SHA256).Hash -ne $orig.Hash) {
                    Write-Warning "  HASH MISMATCH: $f"; $mismatch++
                } else {
                    Write-Host "     match  $f" -ForegroundColor DarkGray
                }
            }
            if ($mismatch -gt 0) { throw "$mismatch file(s) failed round-trip verification. Do not upload this package." }
            Write-Ok 'All payload files byte-identical after decrypt'
        } finally {
            Remove-Item $rt -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ''
    Write-Host '================ PACKAGE READY ================' -ForegroundColor Green
    Write-Host "  File    : $pkg"
    Write-Host "  SHA-256 : $((Get-FileHash $pkg -Algorithm SHA256).Hash.ToLower())"
    Write-Host ''
    Write-Host '  Install command   : powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-DriveMapAgent.ps1'
    Write-Host '  Uninstall command : powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-DriveMapAgent.ps1'
    Write-Host '  Install behavior  : System'
    Write-Host '  Detection         : custom script Detect-DriveMapAgent.ps1 (64-bit, not as logged-on user)'
    Write-Host ''
}
finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
