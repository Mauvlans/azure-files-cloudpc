<#
.SYNOPSIS
    User-context agent that maps Azure Files shares to drive letters on an Entra joined
    Windows 365 Cloud PC, and keeps the mapping alive across the Entra Kerberos
    cloud TGT lifetime ceiling.

.DESCRIPTION
    Run by a scheduled task registered by Install-DriveMapAgent.ps1. Triggers:
      * At logon (30s delay)
      * On remote session connect  (Cloud PC reconnect)
      * On workstation unlock
      * Repeating every N minutes

    Each run does four things:
      1. PREFLIGHT   DNS resolution + TCP 445 reachability, with backoff. At logon the
                     vNIC is often not ready yet, so this retries rather than failing.
      2. TGT HEALTH  Reads the cloud TGT (krbtgt/KERBEROS.MICROSOFTONLINE.COM) expiry.
                     Microsoft Entra Kerberos does NOT support TGT renewal and the TGT
                     issued alongside the PRT lives ~10 hours. On a Cloud PC, where users
                     stay signed in for days, the ticket expires mid-session and the drive
                     starts returning access denied. When the TGT is missing or within
                     renewThresholdMinutes of expiry, the agent attempts re-acquisition.
      3. MAP         Idempotent. Leaves a healthy mapping alone, repairs a stale or
                     wrong-target one, creates a missing one.
      4. REPORT      Writes to a per-user log and to the Application event log so the
                     failure rate is measurable, not anecdotal.

.NOTES
    Re-acquisition (step 2) is a best-effort mitigation, not a Microsoft-supported renewal
    path. The only documented permanent fix for the 10-hour ceiling is an AD DS cloud trust,
    which requires hybrid-joined clients. See the spec's "TGT ceiling" section.

    Exit codes: 0 success | 2 kerberos unrecoverable | 3 network unreachable | 4 map failed
                5 unhandled exception (see the UNHANDLED line in the log, event 3006)
#>
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:EventSource = 'AzureFilesDriveMap'
$script:LogDir      = Join-Path $env:LOCALAPPDATA 'AzureFilesDriveMap\Logs'
$script:LogFile     = Join-Path $script:LogDir ("agent-{0:yyyyMMdd}.log" -f (Get-Date))
$script:ExitCode    = 0

#region logging ---------------------------------------------------------------

function Write-AgentLog {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('Information', 'Warning', 'Error')] [string] $Level = 'Information',
        [int] $EventId = 0
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level.Substring(0, 4).ToUpper(), $Message
    Write-Verbose $line
    try {
        if (-not (Test-Path $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
    } catch { }

    if ($EventId -gt 0) {
        try {
            Write-EventLog -LogName Application -Source $script:EventSource `
                           -EntryType $Level -EventId $EventId -Message $Message -ErrorAction Stop
        } catch { }   # source not registered yet - file log still has it
    }
}

function Remove-OldLogs {
    param([int] $KeepDays = 14)
    try {
        Get-ChildItem -Path $script:LogDir -Filter 'agent-*.log' -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch { }
}

#endregion

#region kerberos --------------------------------------------------------------

function Get-CloudTgt {
    <#
        Parses klist output for the Entra Kerberos cloud TGT
        (krbtgt/KERBEROS.MICROSOFTONLINE.COM) and returns its expiry.
    #>
    [CmdletBinding()]
    param([string] $Realm = 'KERBEROS.MICROSOFTONLINE.COM')

    $result = [pscustomobject]@{
        Present          = $false
        EndTime          = $null
        MinutesRemaining = $null
        ParseFailed      = $false
    }

    $output = $null
    try { $output = & klist.exe 2>&1 } catch {
        Write-AgentLog "klist.exe failed: $($_.Exception.Message)" -Level Warning
        return $result
    }
    if (-not $output) { return $result }

    $text    = ($output | Out-String) -split "`r?`n"
    $inBlock = $false

    foreach ($line in $text) {
        if ($line -match '^\s*#\d+>') { $inBlock = $false }
        if ($line -match "Server:\s*krbtgt/$([regex]::Escape($Realm))") { $inBlock = $true; continue }

        if ($inBlock -and $line -match '^\s*End Time:\s*(.+?)\s*(\(local\))?\s*$') {
            $result.Present = $true
            $raw = $Matches[1].Trim()
            try {
                $end = [datetime]::Parse($raw, [System.Globalization.CultureInfo]::CurrentCulture)
                $result.EndTime          = $end
                $result.MinutesRemaining = [math]::Round(($end - (Get-Date)).TotalMinutes, 1)
            } catch {
                # Locale-dependent klist formatting. Not fatal - we fall back to
                # reactive repair when the mount actually fails.
                $result.ParseFailed = $true
                Write-AgentLog "Could not parse TGT end time '$raw'" -Level Warning
            }
            break
        }
    }
    return $result
}

function Test-TgtUsable {
    <#
        A TGT counts as usable when it exists and has more than an hour of life left.
        An unparseable expiry is treated as usable: klist's date format is locale
        dependent, and a parse failure is not evidence of a bad ticket. When we are
        wrong about that, the mapping layer catches it reactively.
    #>
    param([AllowNull()] [object] $Tgt)
    if (-not $Tgt -or -not $Tgt.Present) { return $false }
    if ($Tgt.ParseFailed) { return $true }
    return ($Tgt.MinutesRemaining -gt 60)
}

function Invoke-TgtReacquisition {
    <#
        Best-effort re-acquisition of the cloud TGT without signing the user out.

        Ordering is deliberate and NON-destructive first. An earlier revision purged the
        ticket cache up front; that is actively harmful when this runs pre-emptively at
        renewThresholdMinutes, because the user still holds a working TGT with ~45
        minutes of life on it. Purging first converts "will break at lunchtime" into
        "broken right now" whenever re-acquisition fails - and re-acquisition failing is
        the expected case, since CloudKerberosTicketRetrievalEnabled is a logon-time
        path with no documented mid-session equivalent.

        So:
          1. Refresh the PRT (harmless).
          2. Probe the share to force a TGS request (harmless). If the TGT is healthy
             again, stop here - we never touched the cache.
          3. Only if the ticket is ALREADY absent or expired - i.e. there is nothing
             left to lose - purge and retry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ProbePath,
        [bool] $AllowTicketPurge = $false,
        [Parameter(Mandatory)] [AllowNull()] [object] $CurrentTgt
    )

    Write-AgentLog 'Cloud TGT missing or near expiry - attempting re-acquisition' -Level Warning -EventId 2001

    # --- 1. non-destructive: refresh the primary refresh token -----------------
    try {
        $null = & dsregcmd.exe /RefreshPrt 2>&1
        Write-AgentLog 'dsregcmd /RefreshPrt issued'
        Start-Sleep -Seconds 5
    } catch {
        Write-AgentLog "dsregcmd /RefreshPrt failed: $($_.Exception.Message)" -Level Warning
    }

    # --- 2. non-destructive: force a TGS request by touching the share ---------
    try { [void][System.IO.Directory]::Exists($ProbePath) } catch { }
    Start-Sleep -Seconds 3

    $tgt = Get-CloudTgt
    if (Test-TgtUsable -Tgt $tgt) {
        Write-AgentLog 'Re-acquisition succeeded without purging the ticket cache' -EventId 2002
        return $true
    }

    # --- 3. destructive: only when there is nothing left to lose ---------------
    # "Nothing to lose" = no TGT at all, or one that has already expired. A TGT that
    # is merely NEAR expiry is still doing useful work; we leave it alone and let the
    # next scheduled run try again.
    $haveLiveTicket = $CurrentTgt -and $CurrentTgt.Present -and
                      (($CurrentTgt.ParseFailed) -or ($CurrentTgt.MinutesRemaining -gt 0))

    if ($haveLiveTicket) {
        Write-AgentLog ('Re-acquisition did not refresh the TGT, but the existing ticket is still ' +
                        'valid - leaving the cache intact rather than purging a working ticket.') -Level Warning
        return $false
    }

    if (-not $AllowTicketPurge) {
        Write-AgentLog 'Ticket cache purge disabled by policy (tgt.allowTicketPurge=false)' -Level Warning
        Write-AgentLog 'Re-acquisition did not produce a usable cloud TGT' -Level Error -EventId 3001
        return $false
    }

    Write-AgentLog 'Cloud TGT already unusable - purging ticket cache as a last resort' -Level Warning
    try {
        $null = & klist.exe purge 2>&1
        Write-AgentLog 'klist purge issued'
        Start-Sleep -Seconds 3
    } catch {
        Write-AgentLog "klist purge failed: $($_.Exception.Message)" -Level Warning
    }

    try { [void][System.IO.Directory]::Exists($ProbePath) } catch { }
    Start-Sleep -Seconds 3

    $tgt = Get-CloudTgt
    if (Test-TgtUsable -Tgt $tgt) {
        Write-AgentLog 'Re-acquisition succeeded after ticket cache purge' -EventId 2002
        return $true
    }

    Write-AgentLog 'Re-acquisition did not produce a usable cloud TGT' -Level Error -EventId 3001
    return $false
}

function Show-UserNotification {
    param(
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Message
    )
    # Toast first; msg.exe as a fallback so the user is never left guessing.
    try {
        [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
                        [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $texts = $template.GetElementsByTagName('text')
        $texts.Item(0).AppendChild($template.CreateTextNode($Title))   | Out-Null
        $texts.Item(1).AppendChild($template.CreateTextNode($Message)) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        $aumid = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($aumid).Show($toast)
        return
    } catch {
        Write-AgentLog "Toast notification failed: $($_.Exception.Message)" -Level Warning
    }
    try { & msg.exe * /TIME:120 "$Title - $Message" 2>&1 | Out-Null } catch { }
}

#endregion

#region network + mapping -----------------------------------------------------

function Test-SmbEndpoint {
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [int] $Port = 445,
        [int] $TimeoutMs = 3000
    )
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Wait-ForSmbEndpoint {
    param(
        [Parameter(Mandatory)] [string] $ComputerName,
        [Parameter(Mandatory)] [int[]] $BackoffSeconds,
        [int] $MaxAttempts,
        [int] $TimeoutMs
    )
    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        if (Test-SmbEndpoint -ComputerName $ComputerName -TimeoutMs $TimeoutMs) {
            if ($i -gt 0) { Write-AgentLog "SMB endpoint reachable after $($i + 1) attempt(s)" }
            return $true
        }
        # No sleep after the final attempt - we are about to give up, and this runs
        # inside the task's 15 minute execution limit with MultipleInstances=IgnoreNew,
        # so a wedged run suppresses the next trigger.
        if ($i -eq $MaxAttempts - 1) { break }
        $wait = $BackoffSeconds[[math]::Min($i, $BackoffSeconds.Count - 1)]
        Write-AgentLog "TCP 445 to $ComputerName not reachable (attempt $($i + 1)/$MaxAttempts); waiting ${wait}s" -Level Warning
        Start-Sleep -Seconds $wait
    }
    return $false
}

function Get-MappingState {
    param([Parameter(Mandatory)] [string] $DriveLetter)
    $key = "HKCU:\Network\$DriveLetter"
    if (-not (Test-Path $key)) { return $null }
    try { return (Get-ItemProperty -Path $key -ErrorAction Stop).RemotePath } catch { return $null }
}

function Remove-Mapping {
    param([Parameter(Mandatory)] [string] $DriveLetter)
    try { & net.exe use "${DriveLetter}:" /delete /y 2>&1 | Out-Null } catch { }
    try { Remove-Item -Path "HKCU:\Network\$DriveLetter" -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

function Test-MappingHealthy {
    param([Parameter(Mandatory)] [string] $DriveLetter)
    # [IO.Directory]::Exists fails fast on a dead mapping instead of hanging like Test-Path can.
    try { return [System.IO.Directory]::Exists("${DriveLetter}:\") } catch { return $false }
}

function Set-DriveLabel {
    param([Parameter(Mandatory)] [string] $UncPath, [Parameter(Mandatory)] [string] $Label)
    try {
        $mountPoint = '##' + $UncPath.TrimStart('\').Replace('\', '#')
        $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\$mountPoint"
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name '_LabelFromReg' -Value $Label -PropertyType String -Force | Out-Null
    } catch {
        Write-AgentLog "Could not set drive label: $($_.Exception.Message)" -Level Warning
    }
}

function Set-DriveMapping {
    param(
        [Parameter(Mandatory)] [string] $DriveLetter,
        [Parameter(Mandatory)] [string] $UncPath,
        [string] $Label,
        [bool] $ForceRebuild = $false
    )

    $current = Get-MappingState -DriveLetter $DriveLetter

    if ($current -and ($current.TrimEnd('\') -ieq $UncPath.TrimEnd('\'))) {
        if ((-not $ForceRebuild) -and (Test-MappingHealthy -DriveLetter $DriveLetter)) {
            Write-AgentLog "${DriveLetter}: already mapped and healthy -> $UncPath"
            if ($Label) { Set-DriveLabel -UncPath $UncPath -Label $Label }
            return $true
        }
        Write-AgentLog "${DriveLetter}: mapped but not responding - rebuilding" -Level Warning -EventId 2003
        Remove-Mapping -DriveLetter $DriveLetter
    } elseif ($current) {
        Write-AgentLog "${DriveLetter}: points at '$current' instead of '$UncPath' - rebuilding" -Level Warning
        Remove-Mapping -DriveLetter $DriveLetter
    }

    # Kerberos supplies the credential; never pass one here.
    try {
        New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $UncPath -Persist -Scope Global -ErrorAction Stop | Out-Null
    } catch {
        Write-AgentLog "New-PSDrive failed for ${DriveLetter}: -> $UncPath : $($_.Exception.Message)" -Level Error -EventId 3002
        return $false
    }

    if (-not (Test-MappingHealthy -DriveLetter $DriveLetter)) {
        Write-AgentLog "${DriveLetter}: created but not accessible" -Level Error -EventId 3003
        return $false
    }

    if ($Label) { Set-DriveLabel -UncPath $UncPath -Label $Label }
    Write-AgentLog "${DriveLetter}: mapped -> $UncPath" -EventId 1001
    return $true
}

#endregion

#region main ------------------------------------------------------------------

Write-AgentLog "=== agent start (user=$env:USERNAME, host=$env:COMPUTERNAME, force=$Force) ==="
Remove-OldLogs

# Everything below runs inside try/catch. With $ErrorActionPreference='Stop' and no handler,
# any unhandled exception terminates the script and the error goes to stderr - which the
# scheduled task discards. The symptom is a log containing "agent start" and nothing else:
# no error, no exit line, no clue. The failure path is the one that most needs logging.
try {

if (-not (Test-Path $ConfigPath)) {
    Write-AgentLog "Config not found at $ConfigPath" -Level Error -EventId 3000
    exit 4
}
$config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

# --- preflight ---------------------------------------------------------------
$hosts = $config.mappings | ForEach-Object { ([uri]("file:" + $_.uncPath.Replace('\', '/'))).Host } | Select-Object -Unique
foreach ($h in $hosts) {
    $reachable = Wait-ForSmbEndpoint -ComputerName $h `
                                     -BackoffSeconds $config.preflight.backoffSeconds `
                                     -MaxAttempts $config.preflight.maxAttempts `
                                     -TimeoutMs $config.preflight.tcpTimeoutMs
    if (-not $reachable) {
        Write-AgentLog "SMB endpoint $h unreachable on 445 - aborting this run" -Level Error -EventId 3004
        exit 3
    }
}

# --- TGT health --------------------------------------------------------------
$probePath = $config.mappings[0].uncPath
$tgt = Get-CloudTgt -Realm $config.kerberosRealm

if ($tgt.Present -and -not $tgt.ParseFailed) {
    Write-AgentLog ("Cloud TGT valid for {0} minutes (expires {1:yyyy-MM-dd HH:mm})" -f $tgt.MinutesRemaining, $tgt.EndTime)
} elseif ($tgt.Present) {
    Write-AgentLog 'Cloud TGT present (expiry unknown)'
} else {
    Write-AgentLog 'No cloud TGT in this logon session' -Level Warning
}

$needsRenewal = (-not $tgt.Present) -or
                ((-not $tgt.ParseFailed) -and $tgt.MinutesRemaining -lt $config.tgt.renewThresholdMinutes)

if ($needsRenewal) {
    # Destructive ticket-cache purge is OPT-IN. It is only ever reached when the TGT is
    # already unusable (see Invoke-TgtReacquisition), but defaulting it off means an
    # estate that also holds AD DS Kerberos tickets cannot lose them by omission.
    $allowPurge = $false
    if ($config.tgt.PSObject.Properties.Name -contains 'allowTicketPurge') { $allowPurge = [bool]$config.tgt.allowTicketPurge }

    $recovered = $false
    $currentTgt = $tgt
    for ($attempt = 1; $attempt -le $config.tgt.maxRenewAttempts; $attempt++) {
        Write-AgentLog "Re-acquisition attempt $attempt of $($config.tgt.maxRenewAttempts)"
        if (Invoke-TgtReacquisition -ProbePath $probePath -AllowTicketPurge $allowPurge -CurrentTgt $currentTgt) {
            $recovered = $true
            break
        }
        # Re-read before the next attempt: the ticket may have expired in the interim,
        # which is what promotes the purge from "refused" to "permitted".
        $currentTgt = Get-CloudTgt -Realm $config.kerberosRealm
        Start-Sleep -Seconds 10
    }

    if (-not $recovered) {
        Write-AgentLog 'Cloud TGT could not be re-acquired in-session. User must sign out and back in.' -Level Error -EventId 3005
        if ($config.tgt.notifyUserOnFailure) {
            Show-UserNotification -Title 'Sign out to restore your file drive' `
                                  -Message 'Your secure session ticket for network drives has expired. Sign out of this Cloud PC and sign back in to restore access. Disconnecting alone will not fix it.'
        }
        $script:ExitCode = 2
        # Still attempt the mapping - an existing SMB session may keep working until
        # the next service ticket is needed.
    }
}

# --- map ---------------------------------------------------------------------
$failedRequired = $false
foreach ($m in $config.mappings) {
    $label = $null
    if ($m.PSObject.Properties.Name -contains 'label') { $label = $m.label }
    $ok = Set-DriveMapping -DriveLetter $m.driveLetter -UncPath $m.uncPath -Label $label -ForceRebuild ([bool]$Force)
    if (-not $ok -and $m.required) { $failedRequired = $true }
}

if ($failedRequired -and $script:ExitCode -eq 0) { $script:ExitCode = 4 }

}
catch {
    # Log the fault properly instead of dying silently to a discarded stderr stream.
    $err = $_
    Write-AgentLog "UNHANDLED: $($err.Exception.GetType().Name): $($err.Exception.Message)" -Level Error -EventId 3006
    if ($err.InvocationInfo) {
        Write-AgentLog "  at line $($err.InvocationInfo.ScriptLineNumber): $($err.InvocationInfo.Line.Trim())" -Level Error
    }
    if ($err.ScriptStackTrace) {
        foreach ($frame in ($err.ScriptStackTrace -split "`r?`n")) {
            if ($frame.Trim()) { Write-AgentLog "  $frame" -Level Error }
        }
    }
    if ($script:ExitCode -eq 0) { $script:ExitCode = 5 }
}

Write-AgentLog "=== agent end (exit $script:ExitCode) ==="
exit $script:ExitCode

#endregion
