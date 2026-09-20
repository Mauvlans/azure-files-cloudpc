<#
.SYNOPSIS
    Measures SMB read/write throughput and latency against a mapped drive or UNC path.

.DESCRIPTION
    Three separate measurements, because they fail for different reasons:

      1. SEQUENTIAL WRITE  - large buffered writes. Bandwidth bound.
      2. SEQUENTIAL READ   - same file read back. Must defeat the client cache,
                             or you measure RAM and get absurd numbers.
      3. SMALL-FILE IOPS   - many tiny create/write/close cycles. Latency bound,
                             and the one that actually predicts how a file share
                             *feels* to users. Azure Files over a VPN or long
                             path is usually fine on bandwidth and poor here.

    Azure Files premium provisions IOPS and throughput per GiB of share quota,
    so a small share is slow by design, not by fault. Baseline before blaming
    the network.

.PARAMETER Path
    Target directory. Either a mapped drive (X:\) or a UNC path.

.PARAMETER SizeMB
    Size of the sequential test file. Default 256.

.PARAMETER SmallFileCount
    Number of small files for the IOPS test. Default 200.

.PARAMETER SmallFileKB
    Size of each small file in KB. Default 4.

.PARAMETER Iterations
    Repeat the whole suite N times and report per-run figures. Default 1.

.PARAMETER KeepFiles
    Leave test data behind instead of cleaning up.

.EXAMPLE
    .\Test-ShareThroughput.ps1 -Path X:\

.EXAMPLE
    .\Test-ShareThroughput.ps1 -Path \\examplestorage.file.core.windows.net\cloudpc-data -SizeMB 512 -Iterations 3

.NOTES
    Run NON-ELEVATED, in the same session that owns the Kerberos tickets.
    An elevated prompt is a different logon session with a different ticket
    cache and possibly no access at all.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Path,
    [ValidateRange(16, 8192)]  [int] $SizeMB = 256,
    [ValidateRange(10, 10000)] [int] $SmallFileCount = 200,
    [ValidateRange(1, 1024)]   [int] $SmallFileKB = 4,
    [ValidateRange(1, 20)]     [int] $Iterations = 1,
    [switch] $KeepFiles
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Head { param([string] $m) Write-Host "`n$m" -ForegroundColor Cyan }
function Write-Ok   { param([string] $m) Write-Host "  $m" -ForegroundColor Green }
function Write-Bad  { param([string] $m) Write-Host "  $m" -ForegroundColor Red }

# --- preflight ---------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Path)) {
    throw "Path not reachable: $Path"
}

$isElevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isElevated) {
    Write-Warning 'Running ELEVATED. Kerberos ticket caches are per-logon-session, so this may not reflect what the user experiences. Prefer a normal prompt.'
}

$workDir = Join-Path $Path ("_iotest_" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

# Buffer reused for sequential writes: 1 MiB of non-trivial data so any
# compression or dedupe in the path cannot fake the result.
$bufSize = 1MB
$buffer  = New-Object byte[] $bufSize
[System.Random]::new(42).NextBytes($buffer)

$results = @()

try {
    # --- where are we actually writing? ---------------------------------------
    Write-Head 'Target'
    $resolved = (Resolve-Path -LiteralPath $Path).ProviderPath
    Write-Host "  Path      : $resolved"
    try {
        $drive = Get-PSDrive -Name $resolved.Substring(0, 1) -ErrorAction Stop
        if ($drive.DisplayRoot) { Write-Host "  UNC       : $($drive.DisplayRoot)" }
    } catch { }

    # SMB session facts - dialect and encryption materially affect throughput.
    try {
        $server = if ($resolved -match '^\\\\([^\\]+)') { $Matches[1] }
                  elseif ($drive -and $drive.DisplayRoot -match '^\\\\([^\\]+)') { $Matches[1] }
                  else { $null }
        if ($server) {
            $conn = Get-SmbConnection -ServerName $server -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($conn) {
                Write-Host "  Dialect   : $($conn.Dialect)"
                Write-Host "  Encrypted : $($conn.Encrypted)"
            }
            $lat = Test-Connection -ComputerName $server -Count 4 -ErrorAction SilentlyContinue
            if ($lat) {
                $avg = ($lat | Measure-Object -Property ResponseTime -Average).Average
                Write-Host "  RTT avg   : $([math]::Round($avg,1)) ms"
            }
        }
    } catch { }

    foreach ($iter in 1..$Iterations) {
        if ($Iterations -gt 1) { Write-Head "--- Iteration $iter of $Iterations ---" }

        $bigFile = Join-Path $workDir "seq-$iter.bin"
        $row = [ordered]@{ Iteration = $iter }

        # --- 1. sequential write ---------------------------------------------
        Write-Head 'Sequential write'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $fs = [System.IO.File]::Open($bigFile, 'Create', 'Write', 'None')
        try {
            for ($i = 0; $i -lt $SizeMB; $i++) { $fs.Write($buffer, 0, $bufSize) }
            $fs.Flush($true)   # $true = flush to disk, not just to the OS cache
        } finally { $fs.Dispose() }
        $sw.Stop()
        $wMBps = [math]::Round($SizeMB / $sw.Elapsed.TotalSeconds, 2)
        $row.WriteMBps = $wMBps
        Write-Ok ("{0} MB in {1:N2}s  =  {2} MB/s" -f $SizeMB, $sw.Elapsed.TotalSeconds, $wMBps)

        # --- 2. sequential read ----------------------------------------------
        # FILE_FLAG_NO_BUFFERING is awkward from .NET, so instead defeat the
        # cache the practical way: SMB client caches aggressively, and re-reading
        # a file just written would measure local RAM. Dropping the SMB client
        # cache requires admin, so the honest approach is to report the caveat
        # rather than print a fake 3 GB/s.
        Write-Head 'Sequential read'
        $cacheWarning = $false
        try {
            # Best effort: close the SMB session so the next read goes over the wire.
            if ($server) {
                $null = Get-SmbConnection -ServerName $server -ErrorAction SilentlyContinue
                # Non-destructive; we cannot force a flush without admin rights.
                $cacheWarning = $true
            }
        } catch { }

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $fs = [System.IO.File]::Open($bigFile, 'Open', 'Read', 'None')
        try {
            $read = New-Object byte[] $bufSize
            while ($fs.Read($read, 0, $bufSize) -gt 0) { }
        } finally { $fs.Dispose() }
        $sw.Stop()
        $rMBps = [math]::Round($SizeMB / $sw.Elapsed.TotalSeconds, 2)
        $row.ReadMBps = $rMBps
        Write-Ok ("{0} MB in {1:N2}s  =  {2} MB/s" -f $SizeMB, $sw.Elapsed.TotalSeconds, $rMBps)
        if ($cacheWarning) {
            Write-Host '  NOTE: the SMB client cache may inflate this figure. A read faster' -ForegroundColor DarkYellow
            Write-Host '        than your link speed is cache, not throughput. Re-run after a' -ForegroundColor DarkYellow
            Write-Host '        reboot, or trust the write and IOPS numbers instead.' -ForegroundColor DarkYellow
        }

        # --- 3. small-file IOPS ----------------------------------------------
        Write-Head "Small-file IOPS ($SmallFileCount files x $SmallFileKB KB)"
        $smallDir = Join-Path $workDir "small-$iter"
        New-Item -ItemType Directory -Path $smallDir -Force | Out-Null
        $small = New-Object byte[] ($SmallFileKB * 1KB)
        [System.Random]::new(7).NextBytes($small)

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        for ($i = 0; $i -lt $SmallFileCount; $i++) {
            [System.IO.File]::WriteAllBytes((Join-Path $smallDir "f$i.dat"), $small)
        }
        $sw.Stop()
        $createPerSec = [math]::Round($SmallFileCount / $sw.Elapsed.TotalSeconds, 1)
        $msPerFile    = [math]::Round($sw.Elapsed.TotalMilliseconds / $SmallFileCount, 2)
        $row.CreatePerSec = $createPerSec
        $row.MsPerFile    = $msPerFile
        Write-Ok ("{0} files in {1:N2}s  =  {2} files/s  ({3} ms each)" -f $SmallFileCount, $sw.Elapsed.TotalSeconds, $createPerSec, $msPerFile)

        # enumerate + stat, the operation Explorer does constantly
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $null = Get-ChildItem -LiteralPath $smallDir -File | ForEach-Object { $_.Length }
        $sw.Stop()
        $row.ListMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
        Write-Ok ("Directory listing + stat: {0:N1} ms" -f $sw.Elapsed.TotalMilliseconds)

        # delete throughput - matters for profile/redirection workloads
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Remove-Item -LiteralPath $smallDir -Recurse -Force
        $sw.Stop()
        $row.DeletePerSec = [math]::Round($SmallFileCount / $sw.Elapsed.TotalSeconds, 1)
        Write-Ok ("Deleted {0} files in {1:N2}s  =  {2} files/s" -f $SmallFileCount, $sw.Elapsed.TotalSeconds, $row.DeletePerSec)

        Remove-Item -LiteralPath $bigFile -Force -ErrorAction SilentlyContinue
        $results += [pscustomobject]$row
    }

    # --- summary --------------------------------------------------------------
    Write-Head 'Summary'
    $results | Format-Table -AutoSize | Out-String | Write-Host

    if ($Iterations -gt 1) {
        $avgW = [math]::Round(($results | Measure-Object WriteMBps -Average).Average, 2)
        $avgR = [math]::Round(($results | Measure-Object ReadMBps  -Average).Average, 2)
        $avgI = [math]::Round(($results | Measure-Object CreatePerSec -Average).Average, 1)
        Write-Host "  Mean write : $avgW MB/s"
        Write-Host "  Mean read  : $avgR MB/s"
        Write-Host "  Mean create: $avgI files/s"
    }

    Write-Host ''
    Write-Host '  Interpreting the result:' -ForegroundColor Cyan
    Write-Host '   - Azure Files PREMIUM provisions IOPS/throughput per GiB of quota.'
    Write-Host '     A 1024 GiB share gets far more than a 100 GiB one. Slow small-file'
    Write-Host '     numbers on a small share are provisioning, not a fault.'
    Write-Host '   - Small-file create rate predicts perceived speed better than MB/s.'
    Write-Host '     Under ~50 files/s will feel sluggish in Explorer.'
    Write-Host '   - High RTT hurts small-file work far more than bandwidth does.'
    Write-Host '   - SMB encryption (AES-256-GCM) costs some throughput. That is a'
    Write-Host '     deliberate trade, not a defect.'
}
finally {
    if (-not $KeepFiles) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "`n  Test data left at: $workDir" -ForegroundColor DarkYellow
    }
}
