<#
.SYNOPSIS
    Removes the Azure Files drive-map agent. Runs as SYSTEM from the Intune Win32 app.

.NOTES
    LIMITATION - read before relying on this for a share decommission.

    Persistent drive mappings live in each user's HKCU hive. SYSTEM can only reach the
    hives that happen to be LOADED at uninstall time, which in practice means the user
    currently signed in. Profiles belonging to users who are not signed in keep their
    mapping, and it will reappear as a dead drive letter with a red X the next time they
    log on.

    This is provided AS IS and is not handled automatically. No run-once or Active Setup
    cleanup is registered. If you are retiring a share across an estate with multiple
    profiles per Cloud PC, remove the stale mappings deliberately - either reprovision the
    Cloud PCs, or push a user-context script that deletes HKCU:\Network\<letter> and the
    matching MountPoints2 entry.
#>
[CmdletBinding()]
param(
    [string] $InstallRoot = (Join-Path $env:ProgramData 'AzureFilesDriveMap'),
    [string] $TaskName,
    [string] $TaskPath
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

function Write-Uninstall { param([string] $m) Write-Host "[uninstall] $m" }

# --- task identity from the installed manifest --------------------------------
# Same source of truth the installer used, so uninstall cannot target the wrong task.
$manifestPath = Join-Path $InstallRoot 'package.json'
if (-not $TaskName) { $TaskName = 'AzureFilesDriveMap' }
if (-not $TaskPath) { $TaskPath = '\AzureFilesDriveMap\' }
if (Test-Path $manifestPath) {
    try {
        $mf = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if (-not $PSBoundParameters.ContainsKey('TaskName') -and ($mf.PSObject.Properties.Name -contains 'taskName')) { $TaskName = $mf.taskName }
        if (-not $PSBoundParameters.ContainsKey('TaskPath') -and ($mf.PSObject.Properties.Name -contains 'taskPath')) { $TaskPath = $mf.taskPath }
    } catch {
        Write-Uninstall "Could not read manifest, using defaults: $($_.Exception.Message)"
    }
}
Write-Uninstall "Target task: $($TaskPath.TrimEnd('\'))\$TaskName"

# --- scheduled task -----------------------------------------------------------
if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
    Write-Uninstall 'Scheduled task removed'
}

# --- per-user mappings from loaded hives --------------------------------------
$configPath = Join-Path $InstallRoot 'config.json'
$letters = @()
$uncPaths = @()
if (Test-Path $configPath) {
    try {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        $letters  = @($cfg.mappings.driveLetter)
        $uncPaths = @($cfg.mappings.uncPath)
    } catch { }
}

$cleanedHives = 0
if ($letters) {
    foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        # Skip machine/service SIDs and _Classes hives
        if ($hive.PSChildName -notmatch '^S-1-5-21-[\d-]+$') { continue }
        $cleanedHives++
        foreach ($l in $letters) {
            $key = "Registry::HKEY_USERS\$($hive.PSChildName)\Network\$l"
            if (Test-Path $key) {
                Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
                Write-Uninstall "Removed ${l}: mapping for $($hive.PSChildName)"
            }
        }
        # Also drop the Explorer MountPoints2 entry, otherwise the custom drive label
        # survives uninstall and decorates whatever gets mapped to that letter next.
        foreach ($unc in $uncPaths) {
            if (-not $unc) { continue }
            $mountPoint = '##' + $unc.TrimStart('\').Replace('\', '#')
            $mpKey = "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\$mountPoint"
            if (Test-Path $mpKey) {
                Remove-Item -Path $mpKey -Recurse -Force -ErrorAction SilentlyContinue
                Write-Uninstall "Removed MountPoints2 label entry for $($hive.PSChildName)"
            }
        }
    }
}
Write-Uninstall "Cleaned $cleanedHives loaded user hive(s). Unloaded profiles keep their mapping - see .NOTES."

# --- files --------------------------------------------------------------------
if (Test-Path $InstallRoot) {
    Remove-Item -Path $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Uninstall 'Install folder removed'
}

# --- detection stamp ----------------------------------------------------------
Remove-Item -Path 'HKLM:\SOFTWARE\AzureFilesDriveMap' -Recurse -Force -ErrorAction SilentlyContinue
Write-Uninstall 'Detection stamp removed'

# Event source and EnableLinkedConnections are intentionally left in place - other
# solutions may depend on them, and removing them needs a reboot.

Write-Uninstall 'Uninstall complete'
exit 0
