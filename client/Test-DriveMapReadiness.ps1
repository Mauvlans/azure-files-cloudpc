<#
.SYNOPSIS
    Pilot / support diagnostic. Run in the USER context on a Cloud PC to find out which
    layer is broken before opening a ticket.

.EXAMPLE
    .\Test-DriveMapReadiness.ps1 -UncPath \\stcloudpcfileseus01.file.core.windows.net\cloudpc-data
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $UncPath,
    [string] $DriveLetter = 'X'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$results = New-Object System.Collections.Generic.List[object]
function Add-Check {
    param([string] $Name, [bool] $Pass, [string] $Detail)
    $results.Add([pscustomobject]@{ Check = $Name; Result = $(if ($Pass) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
}

$fqdn = ([uri]('file:' + $UncPath.Replace('\', '/'))).Host

# 1. Join state ---------------------------------------------------------------
$dsreg = & dsregcmd.exe /status 2>&1 | Out-String
$entraJoined = $dsreg -match 'AzureAdJoined\s*:\s*YES'
$prtOk       = $dsreg -match 'AzureAdPrt\s*:\s*YES'
Add-Check 'Entra joined'            $entraJoined 'dsregcmd /status -> AzureAdJoined'
Add-Check 'Primary Refresh Token'   $prtOk       'dsregcmd /status -> AzureAdPrt. NO here means the TGT cannot be minted.'

# 2. Client policy ------------------------------------------------------------
$ckPaths = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kerberos\Parameters'
)
$ck = $null
foreach ($p in $ckPaths) {
    $v = (Get-ItemProperty -Path $p -Name 'CloudKerberosTicketRetrievalEnabled' -ErrorAction SilentlyContinue).CloudKerberosTicketRetrievalEnabled
    if ($null -ne $v) { $ck = $v; break }
}
Add-Check 'CloudKerberosTicketRetrievalEnabled' ($ck -eq 1) "Value: $ck (expected 1, delivered by Intune settings catalog)"

# 3. Required services --------------------------------------------------------
foreach ($svc in 'WinHttpAutoProxySvc', 'iphlpsvc') {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Add-Check "Service $svc running" ($s -and $s.Status -eq 'Running') "Status: $($s.Status)"
}

# 4. DNS ----------------------------------------------------------------------
$dns = Resolve-DnsName -Name $fqdn -ErrorAction SilentlyContinue
$resolved = ($dns | Where-Object { $_.QueryType -eq 'A' } | Select-Object -First 1).IPAddress
$isPrivate = $resolved -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)'
Add-Check 'DNS resolves' ([bool]$resolved) "$fqdn -> $resolved $(if ($isPrivate) { '(private endpoint)' } else { '(public endpoint)' })"

# 5. SMB reachability ---------------------------------------------------------
# Null-guarded: Test-NetConnection returns nothing on some failure paths, and under
# StrictMode a bare property access would throw - in the one script support runs
# precisely when things are already broken.
$tcp = Test-NetConnection -ComputerName $fqdn -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
$tcpOk = [bool]($tcp -and $tcp.TcpTestSucceeded)
Add-Check 'TCP 445 reachable' $tcpOk 'Azure Files supports no alternate SMB port.'

# 6. Cloud TGT ----------------------------------------------------------------
$klist = & klist.exe 2>&1 | Out-String
$hasTgt = $klist -match 'krbtgt/KERBEROS\.MICROSOFTONLINE\.COM'
$endTime = $null
if ($hasTgt) {
    $block = ($klist -split '#\d+>') | Where-Object { $_ -match 'krbtgt/KERBEROS\.MICROSOFTONLINE\.COM' } | Select-Object -First 1
    if ($block -match 'End Time:\s*(.+?)\s*\(local\)') {
        try {
            $endTime = [datetime]::Parse($Matches[1].Trim(), [System.Globalization.CultureInfo]::CurrentCulture)
        } catch { }
    }
}
$mins = if ($endTime) { [math]::Round(($endTime - (Get-Date)).TotalMinutes) } else { $null }
Add-Check 'Cloud TGT present' $hasTgt $(if ($endTime) { "Expires $endTime ($mins min remaining). Entra Kerberos TGTs are ~10h and do NOT renew." } else { 'Expiry not parsed' })

# 7. Service ticket -----------------------------------------------------------
$hasCifs = $klist -match ([regex]::Escape("cifs/$fqdn"))
Add-Check 'CIFS service ticket' $hasCifs "Looking for cifs/$fqdn. Absent until the share is first accessed."

# 8. Mount --------------------------------------------------------------------
$mountOk = $false
try { $mountOk = [System.IO.Directory]::Exists($UncPath) } catch { }
Add-Check 'Share accessible' $mountOk $UncPath

# 9. Existing mapping ---------------------------------------------------------
$mapped = (Get-ItemProperty -Path "HKCU:\Network\$DriveLetter" -ErrorAction SilentlyContinue).RemotePath
Add-Check "Drive ${DriveLetter}: mapped" ([bool]$mapped) "RemotePath: $mapped"

# 10. Agent -------------------------------------------------------------------
# Task identity comes from the installed manifest so this check cannot drift from
# whatever the package actually registered.
$taskName = 'AzureFilesDriveMap'
$taskPath = '\AzureFilesDriveMap\'
$manifestPath = Join-Path $env:ProgramData 'AzureFilesDriveMap\package.json'
if (Test-Path $manifestPath) {
    try {
        $mf = Get-Content $manifestPath -Raw | ConvertFrom-Json
        if ($mf.PSObject.Properties.Name -contains 'taskName') { $taskName = $mf.taskName }
        if ($mf.PSObject.Properties.Name -contains 'taskPath') { $taskPath = $mf.taskPath }
    } catch { }
}
$task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue
$taskState = if ($task) { $task.State } else { 'not registered' }
Add-Check 'Agent scheduled task' ([bool]$task) "$($taskPath.TrimEnd('\'))\$taskName - State: $taskState"

$results | Format-Table -AutoSize
Write-Host ''
$failures = $results | Where-Object Result -eq 'FAIL'
if ($failures) {
    Write-Host "$($failures.Count) check(s) failed:" -ForegroundColor Red
    $failures | ForEach-Object { Write-Host "  - $($_.Check): $($_.Detail)" -ForegroundColor Red }
    Write-Host ''
    Write-Host 'Common causes:' -ForegroundColor Yellow
    Write-Host '  error 1327 on mount .... storage account app not excluded from MFA Conditional Access'
    Write-Host '  error 1326 on mount .... privatelink FQDN missing from the app identifierUris (PE only)'
    Write-Host '  access denied .......... share-level RBAC missing, or NTFS ACLs not set'
    Write-Host '  worked, now denied ..... 10h cloud TGT expired; sign out and back in'
} else {
    Write-Host 'All checks passed.' -ForegroundColor Green
}
