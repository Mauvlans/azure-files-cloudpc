<#
.SYNOPSIS
    Intune Win32 app detection script.

.DESCRIPTION
    Detected only when ALL of the following are true:
      * the installed manifest version matches the version this package expects
      * the agent script exists on disk
      * the scheduled task is registered and enabled

    Checking the task (not just the registry stamp) means a Cloud PC where the task was
    deleted or corrupted is reported as not-detected, and Intune reinstalls it.

    VERSION SOURCE - Intune runs detection scripts with NO arguments, so parameters can
    never be supplied at runtime. The expected values are therefore read from the
    package manifest that ships beside this script inside the .intunewin, exactly as the
    installer reads it. Bumping packageVersion in client/package.json is the single
    action that moves the whole package; there is no second value to keep in sync and
    no way for the install command and the detection rule to disagree.

    Intune rule: exit 0 + any STDOUT = detected. Exit 0 with no output = not detected.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

# --- what this package expects (from the manifest packaged alongside) ---------
$expectedVersion = $null
$taskName        = 'AzureFilesDriveMap'
$taskPath        = '\AzureFilesDriveMap\'

$packagedManifest = Join-Path $PSScriptRoot 'package.json'
if (Test-Path $packagedManifest) {
    try {
        $mf = Get-Content $packagedManifest -Raw | ConvertFrom-Json
        if ($mf.PSObject.Properties.Name -contains 'packageVersion') { $expectedVersion = $mf.packageVersion }
        if ($mf.PSObject.Properties.Name -contains 'taskName')       { $taskName        = $mf.taskName }
        if ($mf.PSObject.Properties.Name -contains 'taskPath')       { $taskPath        = $mf.taskPath }
    } catch { }
}

# No manifest means we cannot assert anything about what should be installed.
# Report not-detected rather than guessing a version and looping reinstalls.
if (-not $expectedVersion) { exit 0 }

# --- what is actually installed ----------------------------------------------
$stamp = Get-ItemProperty -Path 'HKLM:\SOFTWARE\AzureFilesDriveMap'
if (-not $stamp -or $stamp.Version -ne $expectedVersion) { exit 0 }

if (-not $stamp.InstallRoot) { exit 0 }
$agent = Join-Path $stamp.InstallRoot 'Invoke-DriveMapAgent.ps1'
if (-not (Test-Path $agent)) { exit 0 }

$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
if (-not $task -or $task.State -eq 'Disabled') { exit 0 }

Write-Output "AzureFilesDriveMap $($stamp.Version) detected"
exit 0
