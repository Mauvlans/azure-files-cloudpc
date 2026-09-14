<#
.SYNOPSIS
    Installs the Azure Files drive-map agent. Runs as SYSTEM from an Intune Win32 app.

.DESCRIPTION
    * Copies the agent and its config to %ProgramData%\AzureFilesDriveMap
    * Locks the folder down (Users get read/execute only - the agent runs in user
      context, so a writable folder would be a trivially abusable execution path)
    * Registers the Application event log source used for reporting
    * Registers a scheduled task that runs the agent in the context of whichever
      user is signed in, on four triggers:
          - at logon                       (30s delay, network settle)
          - on remote session connect      (Cloud PC reconnect)
          - on workstation unlock
          - every N minutes                (catches the ~10h cloud TGT expiry mid-session)
    * Optionally sets EnableLinkedConnections
    * Stamps a registry key for Win32 app detection

.PARAMETER HealIntervalMinutes
    Repetition interval for the agent. This MUST be meaningfully smaller than
    config.json's tgt.renewThresholdMinutes, otherwise the agent can step straight over
    the renewal window: with a 60m interval and a 45m threshold, a run at T-50 sees
    "50 minutes left, nothing to do" and the next run lands at T+10, already expired.
    Default 30 against the default 45m threshold leaves a full run inside the window.
    The script validates the relationship against the shipped config and refuses to
    install if it does not hold.
#>
[CmdletBinding()]
param(
    [string] $InstallRoot        = (Join-Path $env:ProgramData 'AzureFilesDriveMap'),
    [string] $TaskName           = 'AzureFilesDriveMap',
    [string] $TaskPath           = '\AzureFilesDriveMap\',
    [int]    $HealIntervalMinutes = 30,
    [int]    $LogonDelaySeconds   = 30,
    [string] $PackageVersion      = '1.0.0',
    [switch] $EnableLinkedConnections
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$transcript = Join-Path $env:ProgramData 'AzureFilesDriveMap-install.log'
try { Start-Transcript -Path $transcript -Append -Force | Out-Null } catch { }

function Write-Install { param([string] $m) Write-Host "[install] $m" }

try {
    $sourceDir  = $PSScriptRoot
    $agentName  = 'Invoke-DriveMapAgent.ps1'
    $configName = 'config.json'
    $manifestName = 'package.json'

    foreach ($required in @($agentName, $manifestName)) {
        if (-not (Test-Path (Join-Path $sourceDir $required))) {
            throw "Package is missing '$required'. Build the .intunewin from the full client folder."
        }
    }

    # config.json is generated per tenant by azure/Deploy-AzureFilesForCloudPC.ps1 and is
    # NOT in source control (it carries a real tenant ID). Fail with an actionable message
    # rather than a confusing missing-file error if someone packages a fresh clone.
    if (-not (Test-Path (Join-Path $sourceDir $configName))) {
        throw ("Package is missing 'config.json'. It is generated for your tenant by " +
               "azure\Deploy-AzureFilesForCloudPC.ps1 (or copy client\config.sample.json " +
               "and edit it). Do not ship config.sample.json as-is.")
    }

    # ------------------------------------------------------------- manifest ---
    # package.json is the single source of truth for version / task identity.
    # Anything the caller did not explicitly override comes from here, so the
    # install command, the detection script and this installer cannot drift apart.
    $manifest = Get-Content -Path (Join-Path $sourceDir $manifestName) -Raw | ConvertFrom-Json
    foreach ($binding in @(
        @{ Param = 'PackageVersion';      Manifest = 'packageVersion'      }
        @{ Param = 'TaskName';            Manifest = 'taskName'            }
        @{ Param = 'TaskPath';            Manifest = 'taskPath'            }
        @{ Param = 'HealIntervalMinutes'; Manifest = 'healIntervalMinutes' }
        @{ Param = 'LogonDelaySeconds';   Manifest = 'logonDelaySeconds'   }
    )) {
        if (-not $PSBoundParameters.ContainsKey($binding.Param) -and
            ($manifest.PSObject.Properties.Name -contains $binding.Manifest)) {
            Set-Variable -Name $binding.Param -Value $manifest.($binding.Manifest) -Scope Script
        }
    }
    Write-Install "Manifest: version $PackageVersion, task $($TaskPath.TrimEnd('\'))\$TaskName"

    # ------------------------------------------------- interval sanity check ---
    # The agent only acts when the TGT is inside renewThresholdMinutes of expiry.
    # If it runs less often than that window is wide it can step over the window
    # entirely and only notice the expiry after the user has already lost access.
    $agentConfig = Get-Content -Path (Join-Path $sourceDir $configName) -Raw | ConvertFrom-Json
    $threshold = $agentConfig.tgt.renewThresholdMinutes
    if ($HealIntervalMinutes -ge $threshold) {
        throw ("HealIntervalMinutes ($HealIntervalMinutes) must be less than " +
               "config.json tgt.renewThresholdMinutes ($threshold), or the agent can " +
               "skip the renewal window entirely. Suggested: $([math]::Floor($threshold * 2 / 3)).")
    }
    Write-Install "Heal interval ${HealIntervalMinutes}m vs renewal threshold ${threshold}m - OK"

    # ---------------------------------------------------------------- files ---
    Write-Install "Install root: $InstallRoot"
    if (-not (Test-Path $InstallRoot)) { New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null }

    Copy-Item -Path (Join-Path $sourceDir $agentName)    -Destination $InstallRoot -Force
    Copy-Item -Path (Join-Path $sourceDir $configName)   -Destination $InstallRoot -Force
    Copy-Item -Path (Join-Path $sourceDir $manifestName) -Destination $InstallRoot -Force
    Write-Install 'Agent, config and manifest copied'

    # ------------------------------------------------------------------ acl ---
    # SYSTEM + Administrators full control; Users read & execute. Break inheritance
    # so a permissive ProgramData ACE cannot make the agent script writable.
    $acl = Get-Acl -Path $InstallRoot
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

    $rules = @(
        @{ Sid = 'S-1-5-18';     Rights = 'FullControl' }      # SYSTEM
        @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }      # BUILTIN\Administrators
        @{ Sid = 'S-1-5-32-545'; Rights = 'ReadAndExecute' }   # BUILTIN\Users
    )
    foreach ($r in $rules) {
        $identity = [System.Security.Principal.SecurityIdentifier]::new($r.Sid)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, $r.Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -Path $InstallRoot -AclObject $acl
    Write-Install 'ACLs applied (Users: read/execute)'

    # ------------------------------------------------------------ event log ---
    $source = 'AzureFilesDriveMap'
    if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, 'Application')
        Write-Install "Event source '$source' registered in Application log"
    } else {
        Write-Install "Event source '$source' already registered"
    }

    # -------------------------------------------------------- scheduled task ---
    $agentPath = Join-Path $InstallRoot $agentName
    $cfgPath   = Join-Path $InstallRoot $configName

    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden ' +
                   "-File `"$agentPath`" -ConfigPath `"$cfgPath`"")

    # Runs as whichever member of BUILTIN\Users is signed in, non-elevated.
    # Non-elevated matters: a mapping created in an elevated token is invisible to
    # Explorer in the standard token unless EnableLinkedConnections is set.
    $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited

    $triggers = New-Object System.Collections.Generic.List[object]

    $logon = New-ScheduledTaskTrigger -AtLogOn
    $logon.Delay = ([System.Xml.XmlConvert]::ToString([timespan]::FromSeconds($LogonDelaySeconds)))
    $triggers.Add($logon)

    # Repeating heal trigger. Anchored a few minutes out so install does not race logon.
    $heal = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
                -RepetitionInterval (New-TimeSpan -Minutes $HealIntervalMinutes)
    $triggers.Add($heal)

    # Session-state triggers: 3 = remote connect, 8 = session unlock.
    try {
        $cimClass = Get-CimClass -ClassName MSFT_TaskSessionStateChangeTrigger `
                                 -Namespace Root/Microsoft/Windows/TaskScheduler
        foreach ($state in 3, 8) {
            $sst = New-CimInstance -CimClass $cimClass -ClientOnly
            $sst.StateChange = [uint32]$state
            $sst.Enabled     = $true
            $triggers.Add($sst)
        }
        Write-Install 'Session-state triggers added (remote connect, unlock)'
    } catch {
        Write-Warning "Could not add session-state triggers: $($_.Exception.Message). Logon + repetition triggers still apply."
    }

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -DontStopOnIdleEnd `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
        -MultipleInstances IgnoreNew `
        -Compatibility Win8

    $full = "$($TaskPath.TrimEnd('\'))\$TaskName"
    if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Install 'Removed previous task registration'
    }

    Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath `
        -Action $action -Principal $principal -Trigger $triggers -Settings $settings `
        -Description 'Maps Azure Files shares and maintains the Entra Kerberos cloud TGT for this session.' | Out-Null
    Write-Install "Scheduled task registered: $full"

    # --------------------------------------------------- linked connections ---
    if ($EnableLinkedConnections) {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                         -Name 'EnableLinkedConnections' -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Install 'EnableLinkedConnections set (mappings visible to elevated processes; requires reboot)'
    }

    # ---------------------------------------------------------- detection ----
    $stampKey = 'HKLM:\SOFTWARE\AzureFilesDriveMap'
    if (-not (Test-Path $stampKey)) { New-Item -Path $stampKey -Force | Out-Null }
    New-ItemProperty -Path $stampKey -Name 'Version'     -Value $PackageVersion -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $stampKey -Name 'InstallRoot' -Value $InstallRoot    -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $stampKey -Name 'TaskPath'    -Value $full           -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $stampKey -Name 'InstalledUtc' -Value ((Get-Date).ToUniversalTime().ToString('o')) -PropertyType String -Force | Out-Null
    Write-Install "Detection stamp written ($PackageVersion)"

    # Kick it once for any user already signed in, so the drive appears without
    # waiting for the next trigger.
    try { Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath; Write-Install 'Initial run started' } catch { }

    Write-Install 'Install complete'
    $exit = 0
} catch {
    Write-Error "Install failed: $($_.Exception.Message)"
    $exit = 1603
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}

exit $exit
