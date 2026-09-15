<#
.SYNOPSIS
    Deploys the two Intune policies this solution requires, and assigns them to a
    Cloud PC device group. Idempotent - safe to re-run.

.DESCRIPTION
    Creates, via the Settings Catalog (deviceManagement/configurationPolicies):

      1. "Cloud PC - Entra Kerberos TGT Retrieval"
         Kerberos > CloudKerberosTicketRetrievalEnabled = 1 (Enabled)

         REQUIRED. Without it the client never requests a cloud TGT during logon, and
         every mount falls back to NTLM. If the storage account is pinned to
         Kerberos-only authentication (as this solution's deploy script does), Azure
         Files rejects that outright and the drive simply never appears.

      2. "Cloud PC - Session Time Limits (Entra Kerberos TGT ceiling)"
         RDS session time limits: 9h max session with forced SIGN-OUT, 2h idle,
         1h disconnected.

         STRONGLY RECOMMENDED, and the reason is architectural rather than cosmetic.
         Microsoft Entra Kerberos does not support TGT renewal. The cloud TGT issued
         alongside the PRT lives roughly 10 hours, while Cloud PC sessions routinely
         last days, so the ticket expires mid-session and the mapped drive starts
         returning access denied. The client agent mitigates this on a best-effort
         basis but cannot remove the ceiling - the only documented permanent fix is an
         AD DS cloud trust, which is unavailable to cloud-native Entra-only clients.
         Bounding the session below the ticket lifetime converts an unpredictable
         mid-afternoon failure into a predictable daily sign-in.

         Note "max session time" must force a SIGN-OUT, not a disconnect. A disconnect
         leaves the logon session - and its dead TGT - intact, which does not help.

.PARAMETER GroupId
    Object ID of the Entra DEVICE group to assign both policies to. Should be the same
    group the ANC provisioning policy targets.

.PARAMETER MaxSessionMs
    Active session limit, in milliseconds, chosen from the ADMX-backed enum. This is NOT a
    free integer - the settings catalog exposes a fixed ladder of values and rejects
    anything else. Relevant rungs:
        28800000 =  8 hours   <- default, and the only sane pick against a ~10h TGT
        43200000 = 12 hours   <- EXCEEDS the TGT lifetime; defeats the purpose
    There is no 9-hour option, so 8h is used rather than rounding up past the ceiling.

.PARAMETER IdleSessionMs
    Idle session limit from the same enum. 7200000 = 2 hours.

.PARAMETER DisconnectedSessionMs
    Disconnected session limit from the same enum. 3600000 = 1 hour.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $GroupId,

    # Enum values only - see .PARAMETER notes. 8h keeps the session inside the ~10h TGT.
    [ValidateSet(3600000, 7200000, 10800000, 21600000, 28800000, 43200000)]
    [int] $MaxSessionMs = 28800000,          # 8 hours

    [ValidateSet(1800000, 3600000, 7200000, 10800000, 21600000)]
    [int] $IdleSessionMs = 7200000,          # 2 hours

    [ValidateSet(900000, 1800000, 3600000, 7200000, 10800000)]
    [int] $DisconnectedSessionMs = 3600000,  # 1 hour

    [switch] $SkipSessionLimits
)

<#
.EXAMPLE
    Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'
    .\Deploy-IntunePolicies.ps1 -GroupId '00000000-0000-0000-0000-0000000000b1' -WhatIf

.NOTES
    Requires: Microsoft.Graph.Authentication
    Graph scope: DeviceManagementConfiguration.ReadWrite.All
    Intune role: Policy and Profile Manager, or Intune Administrator

    All settingDefinitionId values below were read back from the live catalog
    (deviceManagement/configurationSettings) rather than assumed. The RDS session limits
    are ADMX-backed under admx_terminalserver, NOT under a remotedesktopservices policy
    path, and their limit values are FIXED ENUMS rather than free integers.
#>

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#region helpers ---------------------------------------------------------------

$script:StepNumber = 0
function Write-Step {
    param([string] $Message)
    $script:StepNumber++
    Write-Host ''
    Write-Host ("[{0:d2}] {1}" -f $script:StepNumber, $Message) -ForegroundColor Cyan
}
function Write-Ok   { param([string] $m) Write-Host "     OK   $m" -ForegroundColor Green }
function Write-Skip { param([string] $m) Write-Host "     ---  $m (already correct)" -ForegroundColor DarkGray }
function Write-Todo { param([string] $m) Write-Host "     TODO $m" -ForegroundColor Yellow }

function Invoke-Graph {
    <#
        Thin wrapper so every call reports the actual Graph error text. Intune's error
        bodies are nested JSON-in-JSON and Invoke-MgGraphRequest surfaces them poorly.
    #>
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [object] $Body
    )
    try {
        if ($Body) {
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body ($Body | ConvertTo-Json -Depth 20) -ContentType 'application/json' -ErrorAction Stop
        }
        return Invoke-MgGraphRequest -Method $Method -Uri $Uri -ErrorAction Stop
    } catch {
        $detail = $_.Exception.Message
        try {
            $raw = $_.ErrorDetails.Message
            if ($raw) {
                $parsed = $raw | ConvertFrom-Json
                if ($parsed.error.message) { $detail = $parsed.error.message }
            }
        } catch { }
        throw "Graph $Method $Uri failed: $detail"
    }
}

function Get-PolicyByName {
    param([Parameter(Mandatory)] [string] $Name)
    # Settings catalog policies live in beta for assignment support; $filter on name is
    # supported and avoids paging the whole estate.
    $escaped = $Name.Replace("'", "''")
    $r = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=name eq '$escaped'"
    if ($r.value -and $r.value.Count -gt 0) { return $r.value[0] }
    return $null
}

function Set-PolicyAssignment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    <#
        Adds the target group to a policy's assignments without clobbering any assignment
        that is already there - this may well be a shared device group with other policies
        and other targets attached.
    #>
    param(
        [Parameter(Mandatory)] [string] $PolicyId,
        [Parameter(Mandatory)] [string] $PolicyName,
        [Parameter(Mandatory)] [string] $TargetGroupId
    )
    # Declared properly rather than borrowing the parent scope's $PSCmdlet via dynamic
    # scoping - that works by accident and makes -WhatIf behaviour incidental.

    $existing = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/assignments"
    $already = @($existing.value | Where-Object { $_.target.groupId -eq $TargetGroupId })
    if ($already.Count -gt 0) {
        Write-Skip "Assignment to $TargetGroupId"
        return
    }

    $assignments = @()
    foreach ($a in @($existing.value)) {
        $assignments += @{ target = $a.target }
    }
    $assignments += @{
        target = @{
            '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
            groupId       = $TargetGroupId
        }
    }

    if ($PSCmdlet.ShouldProcess($PolicyName, "Assign to group $TargetGroupId")) {
        Invoke-Graph -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$PolicyId')/assign" `
            -Body @{ assignments = $assignments } | Out-Null
        Write-Ok "Assigned to $TargetGroupId"
    }
}

function New-OrUpdatePolicy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Description,
        [Parameter(Mandatory)] [array]  $Settings
    )

    $existing = Get-PolicyByName -Name $Name
    if ($existing) {
        Write-Skip "Policy '$Name' exists ($($existing.id))"
        return $existing.id
    }

    $body = @{
        name         = $Name
        description  = $Description
        platforms    = 'windows10'
        technologies = 'mdm'
        settings     = $Settings
    }

    if ($PSCmdlet.ShouldProcess($Name, 'Create settings catalog policy')) {
        $created = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies' -Body $body
        Write-Ok "Created policy '$Name' ($($created.id))"
        return $created.id
    }
    return $null
}

#endregion --------------------------------------------------------------------

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw "Missing module Microsoft.Graph.Authentication. Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
if (-not (Get-MgContext)) {
    throw "Not connected to Graph. Run: Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All'"
}

$ctx = Get-MgContext
Write-Host ''
Write-Host "Graph account : $($ctx.Account)"
Write-Host "Tenant        : $($ctx.TenantId)"

# -----------------------------------------------------------------------------
Write-Step "Validating target group $GroupId"
$group = Invoke-Graph -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId`?`$select=id,displayName,securityEnabled,groupTypes,membershipRule"
Write-Ok "Target: '$($group.displayName)'"
if (-not $group.securityEnabled) {
    Write-Warning 'Target is not a security group. Intune assignment requires a security group.'
}
Write-Host "     Note: assign to the DEVICE group the ANC provisioning policy targets." -ForegroundColor DarkGray

# -----------------------------------------------------------------------------
Write-Step 'Policy 1: Entra Kerberos cloud TGT retrieval'

# Settings catalog identifiers for Kerberos/CloudKerberosTicketRetrievalEnabled.
$kerberosSettings = @(
    @{
        '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationSetting'
        settingInstance     = @{
            '@odata.type'                = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId          = 'device_vendor_msft_policy_config_kerberos_cloudkerberosticketretrievalenabled'
            choiceSettingValue           = @{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value         = 'device_vendor_msft_policy_config_kerberos_cloudkerberosticketretrievalenabled_1'
                children      = @()
            }
        }
    }
)

$kerbPolicyId = New-OrUpdatePolicy `
    -Name 'Cloud PC - Entra Kerberos TGT Retrieval' `
    -Description ('Enables CloudKerberosTicketRetrievalEnabled so Entra joined Cloud PCs request a ' +
                  'Microsoft Entra Kerberos cloud TGT at logon. Required for Azure Files SMB mounts ' +
                  'authenticated with Entra Kerberos - without it, mounts fall back to NTLM and fail ' +
                  'against a Kerberos-only storage account.') `
    -Settings $kerberosSettings

if ($kerbPolicyId) {
    Set-PolicyAssignment -PolicyId $kerbPolicyId -PolicyName 'Cloud PC - Entra Kerberos TGT Retrieval' -TargetGroupId $GroupId
}

# -----------------------------------------------------------------------------
if ($SkipSessionLimits) {
    Write-Step 'Policy 2: Session time limits - SKIPPED by request'
    Write-Todo 'The ~10h cloud TGT ceiling remains unbounded. The agent mitigates it best-effort only.'
} else {
    Write-Step 'Policy 2: RDS session time limits (bounds the TGT ceiling)'

    # Helper: ADMX choice setting with a single nested choice child (the limit enum).
    function New-AdmxLimitSetting {
        param(
            [Parameter(Mandatory)] [string] $ParentId,
            [Parameter(Mandatory)] [string] $ChildId,
            [Parameter(Mandatory)] [int]    $ValueMs
        )
        @{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = @{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = $ParentId
                choiceSettingValue  = @{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = "${ParentId}_1"          # _1 = Enabled
                    children      = @(
                        @{
                            '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                            settingDefinitionId = $ChildId
                            choiceSettingValue  = @{
                                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                                value         = "${ChildId}_$ValueMs"
                                children      = @()
                            }
                        }
                    )
                }
            }
        }
    }

    $tsRoot = 'device_vendor_msft_policy_config_admx_terminalserver'

    $sessionSettings = @(
        # Active session limit.
        (New-AdmxLimitSetting `
            -ParentId "${tsRoot}_ts_sessions_limits_2" `
            -ChildId  "${tsRoot}_ts_sessions_limits_2_ts_sessions_activelimit" `
            -ValueMs  $MaxSessionMs),

        # Idle session limit.
        (New-AdmxLimitSetting `
            -ParentId "${tsRoot}_ts_sessions_idle_limit_2" `
            -ChildId  "${tsRoot}_ts_sessions_idle_limit_2_ts_sessions_idlelimittext" `
            -ValueMs  $IdleSessionMs),

        # Disconnected session limit.
        (New-AdmxLimitSetting `
            -ParentId "${tsRoot}_ts_sessions_disconnected_timeout_2" `
            -ChildId  "${tsRoot}_ts_sessions_disconnected_timeout_2_ts_sessions_enddisconnected" `
            -ValueMs  $DisconnectedSessionMs),

        # THE one that makes this a sign-out rather than a disconnect. Without it, hitting
        # the limit merely disconnects the session - the logon session and its dead cloud
        # TGT survive, so the drive stays broken and the whole policy achieves nothing.
        @{
            '@odata.type'   = '#microsoft.graph.deviceManagementConfigurationSetting'
            settingInstance = @{
                '@odata.type'       = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
                settingDefinitionId = "${tsRoot}_ts_session_end_on_limit_2"
                choiceSettingValue  = @{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                    value         = "${tsRoot}_ts_session_end_on_limit_2_1"   # Enabled
                    children      = @()
                }
            }
        }
    )

    $hrs = [math]::Round($MaxSessionMs / 3600000, 1)
    $sessionPolicyId = New-OrUpdatePolicy `
        -Name 'Cloud PC - Session Time Limits (Entra Kerberos TGT ceiling)' `
        -Description ("Bounds session length below the ~10 hour Microsoft Entra Kerberos cloud TGT " +
                      "lifetime. Entra Kerberos does not support TGT renewal, so a session that " +
                      "outlives its ticket loses access to Entra Kerberos authenticated Azure Files " +
                      "shares mid-session. Active limit ${hrs}h with forced sign-out (End session " +
                      "when time limits are reached = Enabled).") `
        -Settings $sessionSettings

    if ($sessionPolicyId) {
        Set-PolicyAssignment -PolicyId $sessionPolicyId -PolicyName 'Cloud PC - Session Time Limits' -TargetGroupId $GroupId
    }
}

# -----------------------------------------------------------------------------
Write-Host ''
Write-Host '================ INTUNE POLICIES COMPLETE ================' -ForegroundColor Green
Write-Host "  Target group : $($group.displayName) ($GroupId)"
Write-Host "  Policy 1     : Cloud PC - Entra Kerberos TGT Retrieval"
if (-not $SkipSessionLimits) {
    $h = [math]::Round($MaxSessionMs / 3600000, 1)
    Write-Host "  Policy 2     : Cloud PC - Session Time Limits (${h}h active, forced sign-out)"
}
Write-Host ''
Write-Host 'STILL REQUIRED - not automatable' -ForegroundColor Yellow
Write-Host '  Conditional Access: exclude the storage account app from MFA-requiring policies.'
Write-Host '  Mounts fail with error 1327 otherwise. This is a security owner decision.'
Write-Host ''
Write-Host 'Policy applies at next Intune sync (or force: Settings > Accounts > Access work'
Write-Host 'or school > Info > Sync). Verify on the Cloud PC with:'
Write-Host '  Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name CloudKerberosTicketRetrievalEnabled'
Write-Host ''
