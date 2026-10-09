<#
.SYNOPSIS
    Intune Win32 app detection script (SOURCE TEMPLATE - do not upload this file).

.DESCRIPTION
    Detected only when ALL of the following are true:
      * the installed manifest version matches the version this package expects
      * the agent script exists on disk
      * the scheduled task is registered and enabled

    Checking the task (not just the registry stamp) means a Cloud PC where the task was
    deleted or corrupted is reported as not-detected, and Intune reinstalls it.

    VERSION SOURCE - Intune does NOT run this file from the extracted package. The Intune
    Management Extension takes the script CONTENT, writes it to its own working directory
    and runs it there with no arguments and nothing beside it. $PSScriptRoot therefore
    does not point at the package and package.json is NOT readable at detection time.

    An earlier revision tried to read the manifest that way and failed closed: the file
    was never found, $expectedVersion stayed $null, and detection returned not-detected on
    every device forever - so Intune reinstalled the app on every evaluation cycle.

    The expected values are instead stamped in at build time by
    tools/Build-IntuneWinPackage.ps1, which writes dist/Detect-DriveMapAgent.ps1 with the
    placeholders below replaced from client/package.json. **Upload that generated file as
    the detection rule, not this template.** client/package.json remains the single source
    of truth - bumping packageVersion there still moves the whole package in one action.

    Intune rule: exit 0 + any STDOUT = detected. Exit 0 with no output = not detected.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'

# --- what this package expects -----------------------------------------------
# These three values are substituted by tools/Build-IntuneWinPackage.ps1.
$expectedVersion = '__PACKAGE_VERSION__'
$taskName        = '__TASK_NAME__'
$taskPath        = '__TASK_PATH__'

# Unsubstituted placeholders mean someone uploaded this template instead of the generated
# file. Fail closed (not-detected) AND say so on stderr: asserting an unsubstituted
# version would be worse, because a device could never match it and the app would
# reinstall in a loop with no explanation.
if ($expectedVersion -like '__*__') {
    Write-Error 'Detection template was not built. Upload dist/Detect-DriveMapAgent.ps1, not client/Detect-DriveMapAgent.ps1.'
    exit 0
}

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
