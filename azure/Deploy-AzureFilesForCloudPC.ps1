<#
.SYNOPSIS
    Builds the Azure-side estate for mounting an Azure Files share as a drive letter
    on Microsoft Entra joined Windows 365 Cloud PCs that use an Azure Network Connection.

.DESCRIPTION
    Idempotent build script. Safe to re-run; every step is get-then-create.

    Creates / configures, in the region you specify:
      1.  Resource group
      2.  Storage account (FileStorage for premium, StorageV2 for standard), TLS1_2,
          HTTPS-only, blob public access off
      3.  Microsoft Entra Kerberos identity-based access on the file service
      4.  The SMB file share (created via the ARM control plane - no storage keys used)
      5.  Network exposure, either:
            -NetworkMode PrivateEndpoint  -> private endpoint + privatelink DNS zone + vnet link
                                             + public network access disabled
            -NetworkMode ServiceEndpoint  -> Microsoft.Storage service endpoint on the ANC
                                             subnet + storage firewall default-deny
      6.  Share-level RBAC for your user and admin groups
      7.  The auto-created Entra application:
            - admin consent for openid / profile / User.Read
            - "kdc_enable_cloud_group_sids" tag (cloud-only group SIDs)
            - privatelink identifierUris (PrivateEndpoint mode only)
      8.  Emits config.json for the Intune client package

    NOT automated (deliberately - these need a human decision):
      *  Excluding the storage account's Entra app from MFA Conditional Access policies.
         Without this, mounts fail with error 1327. The script prints the app name to exclude.
      *  Setting NTFS ACLs inside the share. Do that once from a pilot Cloud PC using an
         account holding "Storage File Data SMB Share Elevated Contributor".

.PARAMETER Location
    The Azure region to build in. Put this in the SAME region as the ANC vNet /
    Cloud PCs - every file operation pays this latency.

.EXAMPLE
    .\Deploy-AzureFilesForCloudPC.ps1 `
        -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroupName rg-cloudpc-files-eus `
        -Location eastus `
        -StorageAccountName stcloudpcfileseus01 `
        -ShareName cloudpc-data `
        -Sku Premium_ZRS `
        -NetworkMode PrivateEndpoint `
        -AncVirtualNetworkResourceId "/subscriptions/.../virtualNetworks/vnet-cloudpc-eus" `
        -AncSubnetName snet-cloudpc `
        -PrivateEndpointSubnetName snet-privatelink `
        -UserGroupObjectId 11111111-1111-1111-1111-111111111111 `
        -AdminGroupObjectId 22222222-2222-2222-2222-222222222222 `
        -GrantAdminConsent -EnableCloudOnlyGroupSids `
        -Verbose

.NOTES
    Requires: Az.Accounts, Az.Resources, Az.Storage, Az.Network, Az.PrivateDns,
              Microsoft.Graph.Authentication, Microsoft.Graph.Applications
    Caller needs: Owner or (Contributor + User Access Administrator) on the subscription,
                  and an Entra role able to grant admin consent (Cloud Application
                  Administrator or higher) if -GrantAdminConsent is used.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $ResourceGroupName,
    [Parameter(Mandatory)] [string] $Location,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string] $StorageAccountName,

    [ValidatePattern('^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$')]
    [string] $ShareName = 'cloudpc-data',

    [ValidateRange(100, 102400)]
    [int] $ShareQuotaGiB = 1024,

    [ValidateSet('Premium_LRS', 'Premium_ZRS', 'Standard_LRS', 'Standard_ZRS')]
    [string] $Sku = 'Premium_ZRS',

    [Parameter(Mandatory)]
    [ValidateSet('PrivateEndpoint', 'ServiceEndpoint')]
    [string] $NetworkMode,

    [Parameter(Mandatory)] [string] $AncVirtualNetworkResourceId,
    [Parameter(Mandatory)] [string] $AncSubnetName,

    # Defaults to the ANC subnet. A dedicated subnet is cleaner but not required.
    [string] $PrivateEndpointSubnetName,

    # Resource group that holds (or will hold) privatelink.file.core.windows.net.
    # Defaults to -ResourceGroupName.
    [string] $PrivateDnsZoneResourceGroupName,

    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $UserGroupObjectId,
    [ValidatePattern('^[0-9a-fA-F-]{36}$')] [string] $AdminGroupObjectId,

    [ValidatePattern('^[D-Zd-z]$')] [string] $DriveLetter = 'X',
    [string] $DriveLabel = 'Company Files',

    [switch] $GrantAdminConsent,
    [switch] $EnableCloudOnlyGroupSids,
    [switch] $DisableSharedKeyAccess,

    [hashtable] $Tags = @{ workload = 'windows365'; solution = 'azure-files-drive-map' },

    [string] $OutputConfigPath = (Join-Path $PSScriptRoot '..\client\config.json')
)

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

function Assert-Module {
    param([string[]] $Name)
    $missing = @()
    foreach ($n in $Name) {
        if (-not (Get-Module -ListAvailable -Name $n)) { $missing += $n }
    }
    if ($missing) {
        throw ("Missing required module(s): {0}`nInstall with: Install-Module {0} -Scope CurrentUser" -f ($missing -join ', '))
    }
}

function Get-ResourceIdPart {
    param([string] $ResourceId, [string] $Part)
    $segments = $ResourceId.Trim('/') -split '/'
    for ($i = 0; $i -lt $segments.Count - 1; $i++) {
        if ($segments[$i] -ieq $Part) { return $segments[$i + 1] }
    }
    throw "Could not find '$Part' in resource id '$ResourceId'."
}

#endregion --------------------------------------------------------------------

Assert-Module -Name @(
    'Az.Accounts', 'Az.Resources', 'Az.Storage', 'Az.Network', 'Az.PrivateDns'
)

Write-Step "Connecting to subscription $SubscriptionId"
if (-not (Get-AzContext -ErrorAction SilentlyContinue)) { Connect-AzAccount | Out-Null }
$ctx = Set-AzContext -Subscription $SubscriptionId
$tenantId = $ctx.Tenant.Id
Write-Ok "Tenant $tenantId"

if (-not $PrivateEndpointSubnetName)      { $PrivateEndpointSubnetName      = $AncSubnetName }
if (-not $PrivateDnsZoneResourceGroupName) { $PrivateDnsZoneResourceGroupName = $ResourceGroupName }

$isPremium = $Sku -like 'Premium_*'
$storageKind = if ($isPremium) { 'FileStorage' } else { 'StorageV2' }

# -----------------------------------------------------------------------------
Write-Step "Resource group '$ResourceGroupName' in '$Location'"
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    if ($PSCmdlet.ShouldProcess($ResourceGroupName, 'Create resource group')) {
        $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -Tag $Tags
        Write-Ok "Created"
    }
} else {
    if ($rg.Location -ne $Location) {
        Write-Warning "Resource group is in '$($rg.Location)' but -Location is '$Location'. Resources will be created in '$Location'."
    }
    Write-Skip "Resource group exists"
}

# -----------------------------------------------------------------------------
Write-Step "Storage account '$StorageAccountName' ($Sku / $storageKind)"
$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $sa) {
    $available = Get-AzStorageAccountNameAvailability -Name $StorageAccountName
    if (-not $available.NameAvailable) { throw "Storage account name '$StorageAccountName' is not available: $($available.Message)" }

    if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Create storage account')) {
        $newParams = @{
            ResourceGroupName      = $ResourceGroupName
            Name                   = $StorageAccountName
            Location               = $Location
            SkuName                = $Sku
            Kind                   = $storageKind
            MinimumTlsVersion      = 'TLS1_2'
            EnableHttpsTrafficOnly = $true
            AllowBlobPublicAccess  = $false
            PublicNetworkAccess    = if ($NetworkMode -eq 'PrivateEndpoint') { 'Disabled' } else { 'Enabled' }
            Tag                    = $Tags
        }
        if (-not $isPremium) { $newParams['EnableLargeFileShare'] = $true }
        $sa = New-AzStorageAccount @newParams
        Write-Ok "Created in $Location"
    }
} else {
    Write-Skip "Storage account exists ($($sa.Location))"
}

if (-not $sa) {
    Write-Warning 'Storage account was not created (-WhatIf). Remaining steps need a real account; stopping here.'
    return
}

# -----------------------------------------------------------------------------
Write-Step 'Enabling Microsoft Entra Kerberos on the file service'
# A storage account can only carry ONE identity source. If AD DS or Entra Domain
# Services is already configured, stop rather than silently flipping it.
$currentDirService = $null
if ($sa.AzureFilesIdentityBasedAuth) { $currentDirService = $sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions }

if ($currentDirService -in @('AD', 'AADDS')) {
    throw "Storage account already uses '$currentDirService' identity. Entra Kerberos cannot coexist with it. Resolve manually before re-running."
}
if ($currentDirService -eq 'AADKERB') {
    Write-Skip 'Entra Kerberos already enabled'
} elseif ($PSCmdlet.ShouldProcess($StorageAccountName, 'Enable Entra Kerberos')) {
    Set-AzStorageAccount -ResourceGroupName $ResourceGroupName `
                         -StorageAccountName $StorageAccountName `
                         -EnableAzureActiveDirectoryKerberosForFile $true | Out-Null
    Write-Ok 'Entra Kerberos enabled (storage account Entra application auto-created)'
    Start-Sleep -Seconds 10   # let the app registration materialise
}

# -----------------------------------------------------------------------------
Write-Step "File share '$ShareName' ($ShareQuotaGiB GiB)"
# New-AzRmStorageShare uses the ARM control plane - no storage account keys needed,
# so this still works with shared key access disabled.
$share = Get-AzRmStorageShare -ResourceGroupName $ResourceGroupName `
                              -StorageAccountName $StorageAccountName `
                              -Name $ShareName -ErrorAction SilentlyContinue
if (-not $share) {
    if ($PSCmdlet.ShouldProcess($ShareName, 'Create file share')) {
        $share = New-AzRmStorageShare -ResourceGroupName $ResourceGroupName `
                                      -StorageAccountName $StorageAccountName `
                                      -Name $ShareName -QuotaGiB $ShareQuotaGiB
        Write-Ok 'Created'
    }
} else {
    Write-Skip "Share exists (quota $($share.QuotaGiB) GiB)"
}

# -----------------------------------------------------------------------------
Write-Step 'Hardening the SMB protocol and file service properties'
# The network and RBAC layers were locked down above, but the SMB protocol settings
# themselves default to permissive (SMB 3.0+, RC4/AES-128 allowed, NTLMv2 offered).
# Pin them: SMB 3.1.1 only, AES-256-GCM channel encryption, Kerberos-only auth.
# NTLMv2 removal is what makes the Entra Kerberos requirement enforced rather than
# merely preferred - clients that fail to get a TGT are refused instead of silently
# downgrading and producing a confusing 1326.
try {
    $fileServiceParams = @{
        ResourceGroupName             = $ResourceGroupName
        StorageAccountName            = $StorageAccountName
        SmbProtocolVersion            = 'SMB3.1.1'
        SmbChannelEncryption          = 'AES-256-GCM'
        SmbAuthenticationMethod       = 'Kerberos'
        SmbKerberosTicketEncryption   = 'AES-256'
        EnableShareDeleteRetentionPolicy = $true
        ShareRetentionDays            = 7
    }
    if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Harden SMB protocol settings and enable share soft delete')) {
        Update-AzStorageFileServiceProperty @fileServiceParams | Out-Null
        Write-Ok 'SMB 3.1.1 / AES-256-GCM / Kerberos-only; share soft delete 7 days'
    }
} catch {
    # Older Az.Storage versions do not expose every one of these switches. Surface it
    # rather than failing the build - the solution works without the hardening, it is
    # just more permissive than it should be.
    Write-Warning ("Could not apply full SMB hardening: {0}" -f $_.Exception.Message)
    Write-Todo 'Set SMB protocol version / channel encryption / auth method manually, or update Az.Storage.'
}

# -----------------------------------------------------------------------------
Write-Step "Network exposure: $NetworkMode"

$vnetName   = Get-ResourceIdPart -ResourceId $AncVirtualNetworkResourceId -Part 'virtualNetworks'
$vnetRgName = Get-ResourceIdPart -ResourceId $AncVirtualNetworkResourceId -Part 'resourceGroups'
$vnet       = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $vnetRgName

if ($NetworkMode -eq 'ServiceEndpoint') {

    $subnet = $vnet.Subnets | Where-Object Name -eq $AncSubnetName
    if (-not $subnet) { throw "Subnet '$AncSubnetName' not found in vNet '$vnetName'." }

    # Modify the subnet object in place so existing NSG / route table / other service
    # endpoints are preserved.
    $existingServices = @()
    if ($subnet.ServiceEndpoints) { $existingServices = @($subnet.ServiceEndpoints.Service) }

    if ($existingServices -contains 'Microsoft.Storage') {
        Write-Skip 'Microsoft.Storage service endpoint present on ANC subnet'
    } elseif ($PSCmdlet.ShouldProcess($AncSubnetName, 'Add Microsoft.Storage service endpoint')) {
        $endpoint = New-Object Microsoft.Azure.Commands.Network.Models.PSServiceEndpoint
        $endpoint.Service = 'Microsoft.Storage'
        if (-not $subnet.ServiceEndpoints) { $subnet.ServiceEndpoints = @() }
        $subnet.ServiceEndpoints += $endpoint
        $vnet = Set-AzVirtualNetwork -VirtualNetwork $vnet
        $subnet = $vnet.Subnets | Where-Object Name -eq $AncSubnetName
        Write-Ok 'Service endpoint added'
    }

    $ruleSet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
    $alreadyAllowed = $ruleSet.VirtualNetworkRules | Where-Object { $_.VirtualNetworkResourceId -eq $subnet.Id }
    if ($alreadyAllowed) {
        Write-Skip 'ANC subnet already allowed on storage firewall'
    } elseif ($PSCmdlet.ShouldProcess($StorageAccountName, 'Allow ANC subnet on storage firewall')) {
        Add-AzStorageAccountNetworkRule -ResourceGroupName $ResourceGroupName `
                                        -Name $StorageAccountName `
                                        -VirtualNetworkResourceId $subnet.Id | Out-Null
        Write-Ok 'ANC subnet allowed'
    }

    if ($ruleSet.DefaultAction -ne 'Deny' -and $PSCmdlet.ShouldProcess($StorageAccountName, 'Set firewall default action to Deny')) {
        # Preserve whatever bypass is already configured rather than flattening it to
        # AzureServices - the account may legitimately need Logging/Metrics for a
        # diagnostic pipeline someone else owns.
        $bypass = 'AzureServices'
        if ($ruleSet.Bypass) {
            $existingBypass = @($ruleSet.Bypass -split '\s*,\s*' | Where-Object { $_ })
            if ($existingBypass -notcontains 'AzureServices') { $existingBypass += 'AzureServices' }
            $bypass = ($existingBypass | Select-Object -Unique) -join ','
        }
        Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $ResourceGroupName `
                                              -Name $StorageAccountName `
                                              -DefaultAction Deny -Bypass $bypass | Out-Null
        Write-Ok "Storage firewall set to default-deny (bypass: $bypass)"
    }

    $mountFqdn = "$StorageAccountName.file.core.windows.net"

} else {  # PrivateEndpoint

    $peSubnet = $vnet.Subnets | Where-Object Name -eq $PrivateEndpointSubnetName
    if (-not $peSubnet) { throw "Private endpoint subnet '$PrivateEndpointSubnetName' not found in vNet '$vnetName'." }

    $zoneName = 'privatelink.file.core.windows.net'
    $zone = Get-AzPrivateDnsZone -ResourceGroupName $PrivateDnsZoneResourceGroupName -Name $zoneName -ErrorAction SilentlyContinue
    if (-not $zone) {
        if ($PSCmdlet.ShouldProcess($zoneName, 'Create private DNS zone')) {
            $zone = New-AzPrivateDnsZone -ResourceGroupName $PrivateDnsZoneResourceGroupName -Name $zoneName
            Write-Ok "Created DNS zone $zoneName"
        }
    } else { Write-Skip "DNS zone $zoneName exists" }

    $linkName = "link-$vnetName"
    $link = Get-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $PrivateDnsZoneResourceGroupName `
                                               -ZoneName $zoneName -Name $linkName -ErrorAction SilentlyContinue
    if (-not $link) {
        if ($PSCmdlet.ShouldProcess($linkName, 'Link DNS zone to ANC vNet')) {
            New-AzPrivateDnsVirtualNetworkLink -ResourceGroupName $PrivateDnsZoneResourceGroupName `
                                               -ZoneName $zoneName -Name $linkName `
                                               -VirtualNetworkId $vnet.Id -EnableRegistration:$false | Out-Null
            Write-Ok 'DNS zone linked to ANC vNet'
        }
    } else { Write-Skip 'DNS zone already linked' }

    $peName = "pe-$StorageAccountName-file"
    $pe = Get-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName -Name $peName -ErrorAction SilentlyContinue
    if (-not $pe) {
        if ($PSCmdlet.ShouldProcess($peName, 'Create private endpoint')) {
            $plsc = New-AzPrivateLinkServiceConnection -Name "$peName-conn" `
                                                       -PrivateLinkServiceId $sa.Id -GroupId 'file'
            $pe = New-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName -Name $peName `
                                        -Location $Location -Subnet $peSubnet `
                                        -PrivateLinkServiceConnection $plsc -Force
            Write-Ok 'Private endpoint created'
        }
    } else { Write-Skip 'Private endpoint exists' }

    $zoneGroup = Get-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName `
                                           -PrivateEndpointName $peName -ErrorAction SilentlyContinue
    if (-not $zoneGroup) {
        if ($PSCmdlet.ShouldProcess($peName, 'Attach private DNS zone group')) {
            $zoneConfig = New-AzPrivateDnsZoneConfig -Name 'privatelink-file-core-windows-net' -PrivateDnsZoneId $zone.ResourceId
            New-AzPrivateDnsZoneGroup -ResourceGroupName $ResourceGroupName `
                                      -PrivateEndpointName $peName -Name 'default' `
                                      -PrivateDnsZoneConfig $zoneConfig -Force | Out-Null
            Write-Ok 'DNS zone group attached'
        }
    } else { Write-Skip 'DNS zone group exists' }

    if ($sa.PublicNetworkAccess -ne 'Disabled' -and $PSCmdlet.ShouldProcess($StorageAccountName, 'Disable public network access')) {
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName `
                             -PublicNetworkAccess Disabled | Out-Null
        Write-Ok 'Public network access disabled'
    }

    # Clients still mount the regular FQDN; privatelink DNS resolves it to the PE address.
    $mountFqdn = "$StorageAccountName.file.core.windows.net"
}

# -----------------------------------------------------------------------------
Write-Step 'Share-level RBAC'
$shareScope = "$($sa.Id)/fileServices/default/fileshares/$ShareName"

function Set-RoleAssignmentIfMissing {
    # SupportsShouldProcess declared properly rather than reaching the parent scope's
    # $PSCmdlet by dynamic scoping - that worked by accident and made -WhatIf behaviour
    # here incidental instead of designed.
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)] [string] $ObjectId,
        [Parameter(Mandatory)] [string] $RoleName,
        [Parameter(Mandatory)] [string] $Scope
    )
    $existing = Get-AzRoleAssignment -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $RoleName -ErrorAction SilentlyContinue |
                Where-Object { $_.Scope -eq $Scope }
    if ($existing) { Write-Skip "$RoleName -> $ObjectId"; return }
    if ($PSCmdlet.ShouldProcess($ObjectId, "Assign '$RoleName'")) {
        New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope $Scope | Out-Null
        Write-Ok "$RoleName -> $ObjectId"
    }
}

Set-RoleAssignmentIfMissing -ObjectId $UserGroupObjectId -RoleName 'Storage File Data SMB Share Contributor' -Scope $shareScope
if ($AdminGroupObjectId) {
    Set-RoleAssignmentIfMissing -ObjectId $AdminGroupObjectId -RoleName 'Storage File Data SMB Share Elevated Contributor' -Scope $shareScope
}
Write-Host '     Note: share-level permission changes take up to ~30 minutes to propagate.' -ForegroundColor DarkGray

# -----------------------------------------------------------------------------
Write-Step 'Configuring the storage account Entra application'
$appDisplayName = "[Storage Account] $StorageAccountName.file.core.windows.net"

$graphReady = $true
try {
    Assert-Module -Name @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')
} catch {
    $graphReady = $false
    Write-Warning $_.Exception.Message
}

if ($graphReady) {
    if (-not (Get-MgContext)) {
        Connect-MgGraph -TenantId $tenantId -Scopes 'Application.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All' -NoWelcome
    }

    $app = Get-MgApplication -Filter "displayName eq '$appDisplayName'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $app) {
        Write-Todo "Entra app '$appDisplayName' not found yet. It can take a few minutes to appear - re-run this script to finish app configuration."
    } else {
        Write-Ok "Found app $($app.Id)"

        # --- cloud-only group SIDs ---------------------------------------------
        if ($EnableCloudOnlyGroupSids) {
            $tag = 'kdc_enable_cloud_group_sids'
            $tags = @()
            if ($app.Tags) { $tags = @($app.Tags) }
            if ($tags -contains $tag) {
                Write-Skip "Tag '$tag' present"
            } elseif ($PSCmdlet.ShouldProcess($appDisplayName, "Add tag '$tag'")) {
                Update-MgApplication -ApplicationId $app.Id -Tags ($tags + $tag)
                Write-Ok "Tag '$tag' added (cloud-only group SIDs in Kerberos tickets)"
            }
        }

        # --- privatelink identifierUris ----------------------------------------
        if ($NetworkMode -eq 'PrivateEndpoint') {
            $uris = @($app.IdentifierUris)
            $wanted = @()
            foreach ($svc in 'HOST', 'CIFS', 'HTTP') {
                $wanted += "api://$tenantId/$svc/$StorageAccountName.privatelink.file.core.windows.net"
                $wanted += "$svc/$StorageAccountName.privatelink.file.core.windows.net"
            }
            $toAdd = $wanted | Where-Object { $uris -notcontains $_ }
            if (-not $toAdd) {
                Write-Skip 'privatelink identifierUris present'
            } elseif ($PSCmdlet.ShouldProcess($appDisplayName, 'Add privatelink identifierUris')) {
                Update-MgApplication -ApplicationId $app.Id -IdentifierUris ($uris + $toAdd)
                Write-Ok "Added $($toAdd.Count) privatelink identifierUris (prevents NTLM fallback / error 1326)"
            }
        }

        # --- admin consent ------------------------------------------------------
        if ($GrantAdminConsent) {
            $sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue | Select-Object -First 1
            $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'" | Select-Object -First 1
            if (-not $sp) {
                Write-Todo 'Service principal not found; grant admin consent in the portal.'
            } else {
                $grant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and consentType eq 'AllPrincipals'" -ErrorAction SilentlyContinue |
                         Where-Object { $_.ResourceId -eq $graphSp.Id } | Select-Object -First 1
                if ($grant) {
                    Write-Skip "Admin consent already granted ($($grant.Scope))"
                } elseif ($PSCmdlet.ShouldProcess($appDisplayName, 'Grant admin consent')) {
                    New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' `
                                                -ResourceId $graphSp.Id -Scope 'openid profile User.Read' | Out-Null
                    Write-Ok 'Admin consent granted for openid / profile / User.Read'
                }
            }
        } else {
            Write-Todo "Grant admin consent on '$appDisplayName' (API permissions -> Grant admin consent), or re-run with -GrantAdminConsent."
        }
    }
} else {
    Write-Todo "Install Microsoft.Graph.Applications, or configure '$appDisplayName' manually."
}

# -----------------------------------------------------------------------------
if ($DisableSharedKeyAccess) {
    Write-Step 'Disabling shared key (storage account key) access'
    if ($PSCmdlet.ShouldProcess($StorageAccountName, 'Disable shared key access')) {
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -AllowSharedKeyAccess $false | Out-Null
        Write-Ok 'Shared key access disabled - identity-based access only'
    }
}

# -----------------------------------------------------------------------------
Write-Step 'Emitting client package configuration'
$config = [ordered]@{
    schemaVersion   = 1
    generatedUtc    = (Get-Date).ToUniversalTime().ToString('o')
    tenantId        = $tenantId
    kerberosRealm   = 'KERBEROS.MICROSOFTONLINE.COM'
    tgt             = [ordered]@{
        renewThresholdMinutes = 45
        maxRenewAttempts      = 3
        notifyUserOnFailure   = $true
        # Purging the Kerberos ticket cache is destructive and only ever reached when
        # the TGT is already unusable. Emitted explicitly (rather than left to an
        # agent-side default) so generated configs cannot silently differ from the
        # checked-in one. Set true only in cloud-native estates with no AD DS tickets.
        allowTicketPurge      = $false
    }
    preflight       = [ordered]@{
        tcpTimeoutMs   = 3000
        maxAttempts    = 6
        backoffSeconds = @(5, 10, 20, 30, 60, 60)
    }
    mappings        = @(
        [ordered]@{
            driveLetter = $DriveLetter
            label       = $DriveLabel
            uncPath     = "\\$mountFqdn\$ShareName"
            required    = $true
        }
    )
}

$configJson = $config | ConvertTo-Json -Depth 6
$resolvedConfigPath = $OutputConfigPath
try { $resolvedConfigPath = [System.IO.Path]::GetFullPath($OutputConfigPath) } catch { }
$configDir = Split-Path -Parent $resolvedConfigPath
if ($configDir -and -not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir -Force | Out-Null }
$configJson | Set-Content -Path $resolvedConfigPath -Encoding UTF8
Write-Ok "Wrote $resolvedConfigPath"

# -----------------------------------------------------------------------------
Write-Host ''
Write-Host '================ BUILD COMPLETE ================' -ForegroundColor Green
Write-Host "  Region         : $Location"
Write-Host "  Storage account: $StorageAccountName ($Sku)"
Write-Host "  Share          : $ShareName ($ShareQuotaGiB GiB)"
Write-Host "  UNC path       : \\$mountFqdn\$ShareName"
Write-Host "  Network mode   : $NetworkMode"
Write-Host ''
Write-Host 'REMAINING MANUAL STEPS' -ForegroundColor Yellow
Write-Host "  1. Conditional Access: exclude the app"
Write-Host "        $appDisplayName"
Write-Host "     from every MFA-requiring policy. Mounts fail with error 1327 otherwise."
Write-Host "  2. Deploy the Intune settings catalog policy setting"
Write-Host "        Kerberos > CloudKerberosTicketRetrievalEnabled = 1 (Enabled)"
Write-Host "     to the Cloud PC device group. Use Settings Catalog, NOT OMA-URI."
Write-Host "  3. From a pilot Cloud PC signed in as a member of the admin group, mount the"
Write-Host "     share and set root NTFS ACLs with icacls, then remove the elevated role."
Write-Host "  4. Package .\client\ as a Win32 app and assign it to the Cloud PC device group."
Write-Host ''
