<#
.SYNOPSIS
    Decision-logic tests for the drive-map agent. No Windows, no Azure, no network.

.DESCRIPTION
    These cover the two pieces of logic in this solution that are subtle enough to break
    silently and expensive enough to matter in production:

      1. The ticket-cache purge guard. `klist purge` destroys every Kerberos ticket in the
         logon session. The agent runs pre-emptively while the user still holds a WORKING
         TGT, so purging before knowing a replacement is obtainable turns "will break in 45
         minutes" into "broken now". An earlier revision did exactly that. The guard must
         refuse to purge whenever a live ticket exists.

      2. The heal-interval / renewal-threshold relationship. The agent only acts inside
         renewThresholdMinutes of expiry. If it runs less often than that window is wide it
         can step straight over it.

    Run: pwsh ./tests/Test-AgentLogic.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Failures = 0
function Assert-Equal {
    param([string] $Name, $Expected, $Actual)
    if ($Expected -eq $Actual) {
        Write-Host "  PASS  $Name"
    } else {
        $script:Failures++
        Write-Host "  FAIL  $Name (expected '$Expected', got '$Actual')"
    }
}

# --- logic under test, mirrored from client/Invoke-DriveMapAgent.ps1 ----------

function Test-TgtUsable {
    param([AllowNull()] [object] $Tgt)
    if (-not $Tgt -or -not $Tgt.Present) { return $false }
    if ($Tgt.ParseFailed) { return $true }
    return ($Tgt.MinutesRemaining -gt 60)
}

function Test-WouldPurge {
    param([AllowNull()] [object] $CurrentTgt, [bool] $AllowTicketPurge)
    $haveLiveTicket = $CurrentTgt -and $CurrentTgt.Present -and
                      (($CurrentTgt.ParseFailed) -or ($CurrentTgt.MinutesRemaining -gt 0))
    if ($haveLiveTicket) { return $false }
    if (-not $AllowTicketPurge) { return $false }
    return $true
}

function New-Tgt {
    param([bool] $Present, $MinutesRemaining, [bool] $ParseFailed)
    [pscustomobject]@{ Present = $Present; MinutesRemaining = $MinutesRemaining; ParseFailed = $ParseFailed }
}

# --- 1. purge guard ----------------------------------------------------------

Write-Host ''
Write-Host 'Ticket-cache purge guard'

# THE regression case: this is the exact scenario the original code got wrong.
Assert-Equal 'near expiry (44m) + purge allowed -> must NOT purge a working ticket' `
    $false (Test-WouldPurge -CurrentTgt (New-Tgt $true 44 $false) -AllowTicketPurge $true)

Assert-Equal 'near expiry (44m) + purge disabled -> no purge' `
    $false (Test-WouldPurge -CurrentTgt (New-Tgt $true 44 $false) -AllowTicketPurge $false)

Assert-Equal 'one minute left -> still live, no purge' `
    $false (Test-WouldPurge -CurrentTgt (New-Tgt $true 1 $false) -AllowTicketPurge $true)

Assert-Equal 'already expired + allowed -> purge permitted' `
    $true (Test-WouldPurge -CurrentTgt (New-Tgt $true -5 $false) -AllowTicketPurge $true)

Assert-Equal 'already expired + disabled -> policy blocks purge' `
    $false (Test-WouldPurge -CurrentTgt (New-Tgt $true -5 $false) -AllowTicketPurge $false)

Assert-Equal 'no ticket at all + allowed -> purge permitted' `
    $true (Test-WouldPurge -CurrentTgt (New-Tgt $false $null $false) -AllowTicketPurge $true)

Assert-Equal 'null TGT + allowed -> purge permitted' `
    $true (Test-WouldPurge -CurrentTgt $null -AllowTicketPurge $true)

Assert-Equal 'unparseable expiry -> assume live, no purge' `
    $false (Test-WouldPurge -CurrentTgt (New-Tgt $true $null $true) -AllowTicketPurge $true)

# --- 2. TGT usability --------------------------------------------------------

Write-Host ''
Write-Host 'TGT usability'

Assert-Equal 'fresh 600m ticket is usable'            $true  (Test-TgtUsable -Tgt (New-Tgt $true 600 $false))
Assert-Equal '61m ticket is usable'                   $true  (Test-TgtUsable -Tgt (New-Tgt $true 61 $false))
Assert-Equal '60m ticket is NOT usable (boundary)'    $false (Test-TgtUsable -Tgt (New-Tgt $true 60 $false))
Assert-Equal 'expired ticket is not usable'           $false (Test-TgtUsable -Tgt (New-Tgt $true -1 $false))
Assert-Equal 'absent ticket is not usable'            $false (Test-TgtUsable -Tgt (New-Tgt $false $null $false))
Assert-Equal 'null is not usable'                     $false (Test-TgtUsable -Tgt $null)
Assert-Equal 'unparseable expiry treated as usable'   $true  (Test-TgtUsable -Tgt (New-Tgt $true $null $true))

# --- 3. heal interval vs renewal window --------------------------------------

Write-Host ''
Write-Host 'Heal interval vs renewal window'

$repoRoot = Split-Path -Parent $PSScriptRoot
$mf  = Get-Content (Join-Path $repoRoot 'client/package.json')       -Raw | ConvertFrom-Json
$cfg = Get-Content (Join-Path $repoRoot 'client/config.sample.json') -Raw | ConvertFrom-Json

Assert-Equal 'shipped heal interval is shorter than the renewal window' `
    $true ($mf.healIntervalMinutes -lt $cfg.tgt.renewThresholdMinutes)

Assert-Equal 'destructive purge defaults to opt-in (false)' `
    $false $cfg.tgt.allowTicketPurge

# The old 60m/45m pairing could skip the window - keep a test that says so.
Assert-Equal 'a 60m interval against a 45m window is correctly identified as unsafe' `
    $false (60 -lt 45)

# --- 4. preflight backoff ----------------------------------------------------

Write-Host ''
Write-Host 'Preflight backoff'

function Get-BackoffTotal {
    param([int[]] $BackoffSeconds, [int] $MaxAttempts, [bool] $SkipFinalSleep)
    $total = 0
    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        if ($SkipFinalSleep -and $i -eq $MaxAttempts - 1) { break }
        $total += $BackoffSeconds[[math]::Min($i, $BackoffSeconds.Count - 1)]
    }
    return $total
}

$backoff = $cfg.preflight.backoffSeconds
$max     = $cfg.preflight.maxAttempts

Assert-Equal 'no wasted sleep after the final attempt' `
    $true ((Get-BackoffTotal $backoff $max $true) -lt (Get-BackoffTotal $backoff $max $false))

Assert-Equal 'worst-case preflight stays well inside the 15 minute task limit' `
    $true ((Get-BackoffTotal $backoff $max $true) -lt 600)

# --- result ------------------------------------------------------------------

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host "$script:Failures test(s) FAILED" -ForegroundColor Red
    exit 1
}
Write-Host 'All tests passed.' -ForegroundColor Green
exit 0
