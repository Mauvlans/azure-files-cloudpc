# Azure Files drive mapping for Windows 365 Cloud PCs (Entra joined + ANC)

[![Validate](https://github.com/Mauvlans/azure-files-cloudpc/actions/workflows/validate.yml/badge.svg)](https://github.com/Mauvlans/azure-files-cloudpc/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Maps an Azure Files SMB share to a drive letter on Microsoft Entra joined Windows 365
Cloud PCs, authenticated with Microsoft Entra Kerberos, delivered entirely through Intune.

Built for Cloud PCs on an **Azure Network Connection** — the vNIC lives in your own vNet,
so SMB over 445 never leaves Azure.

> **Read [the TGT ceiling section](#the-constraint-you-need-to-plan-around) before you commit
> to a rollout date.** Microsoft Entra Kerberos does not support TGT renewal, and no client
> agent — including this one — can fully remove that constraint for cloud-native clients.

**New here?** Go to the [step-by-step deployment guide](#step-by-step-deployment-guide).
Something not working? Jump to [troubleshooting](#troubleshooting).

## Contents

```
azure/
  Deploy-AzureFilesForCloudPC.ps1   Idempotent Azure build: storage account, share,
                                    Entra Kerberos, networking, RBAC, Entra app config.
                                    Emits client/config.json.
client/
  Install-DriveMapAgent.ps1         Win32 app install (SYSTEM). Registers the scheduled task.
  Uninstall-DriveMapAgent.ps1       Win32 app uninstall.
  Detect-DriveMapAgent.ps1          Win32 app detection script.
  Invoke-DriveMapAgent.ps1          The agent. User context. Maps drives and manages the
                                    Entra Kerberos cloud TGT.
  Test-DriveMapReadiness.ps1        Ten-point diagnostic for pilot and support.
  config.sample.json                Template. The build script writes client/config.json
                                    for your tenant - that file is gitignored.
  package.json                      Version + task identity. Single source of truth, read
                                    by install, uninstall and detection alike.
intune/
  Deploy-IntunePolicies.ps1         Creates and assigns the two required Intune policies.
  Packaging-and-Assignment.md       Settings catalog policy, CA exclusion, Win32 app rules,
                                    session limits, monitoring event IDs.
tools/
  Build-IntuneWinPackage.ps1        Cross-platform .intunewin builder with round-trip
                                    verification. No Windows or IntuneWinAppUtil needed.
tests/
  Test-AgentLogic.ps1               Offline tests for the purge guard and timing logic.
                                    No Windows or Azure needed: pwsh ./tests/Test-AgentLogic.ps1
docs/
  Deployment-westus3.md             A real verified deployment: environment findings,
                                    results read back from ARM/Graph, bugs found, teardown.
```

## Step-by-step deployment guide

Follow these in order. **The order is not cosmetic** — steps 3 and 6 must both be done before
step 7, or the agent installs successfully and then fails every mount, and you will spend your
time debugging the agent instead of the thing actually blocking it.

Budget roughly 90 minutes end to end, most of it waiting on propagation.

---

### Step 0 — Confirm the target actually qualifies

Entra Kerberos needs a Cloud PC that is **both** Entra joined **and** on your ANC vNet. These
are independent properties, and it is entirely possible to have each one on a *different*
machine. Check before you build anything:

```powershell
# Join type must be AzureAd. ServerAd = hybrid, Workplace = registered - neither will work.
Connect-MgGraph -Scopes 'Device.Read.All'
Get-MgDevice -Filter "startswith(displayName,'CPC-')" |
    Select-Object DisplayName, TrustType, OperatingSystemVersion
```

```bash
# And the SAME machine must own a NIC in the ANC vNet
az network nic list --query "[?contains(name,'CPC-')].{name:name,ip:ipConfigurations[0].privateIPAddress,subnet:ipConfigurations[0].subnet.id}" -o table
```

You need `TrustType = AzureAd`, build **26100 or later**, and a NIC in your ANC subnet, all on
one device. If the only Entra-joined Cloud PC is Microsoft-hosted, provision one on the ANC
first — nothing downstream will work otherwise.

---

### Step 1 — Build the Azure side

```powershell
Connect-AzAccount
Connect-MgGraph -Scopes 'Application.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'

./azure/Deploy-AzureFilesForCloudPC.ps1 `
  -SubscriptionId              '<sub-guid>' `
  -ResourceGroupName           'rg-cloudpc-files' `
  -Location                    '<region of your ANC vNet>' `
  -StorageAccountName          '<globally unique, lowercase>' `
  -ShareName                   'cloudpc-data' `
  -Sku                         'Premium_ZRS' `
  -NetworkMode                 'ServiceEndpoint' `
  -AncVirtualNetworkResourceId '/subscriptions/.../virtualNetworks/<anc-vnet>' `
  -AncSubnetName               '<anc-subnet>' `
  -UserGroupObjectId           '<group of users who get the drive>' `
  -AdminGroupObjectId          '<group that will set NTFS ACLs>' `
  -DriveLetter 'X' -DriveLabel 'Company Files' `
  -EnableCloudOnlyGroupSids -GrantAdminConsent
```

Run it with `-WhatIf` first. It is idempotent — safe to re-run, and a second run reports every
step as already-correct.

**Choosing `-NetworkMode`:**

| Your vNet DNS | Use |
|---|---|
| Azure-provided (default) | `PrivateEndpoint` |
| Custom / on-prem DNS server | **`ServiceEndpoint`** |

If your vNet points at an on-prem DNS server that has no conditional forwarder for
`privatelink.file.core.windows.net` → `168.63.129.16`, a private endpoint resolves to the
**public** IP while the firewall denies public access. The mount fails with an error that looks
nothing like DNS. `ServiceEndpoint` has no DNS dependency.

> **It is normal for the Entra app step to report "not found yet" on the first run.** The
> storage account's Entra application takes a minute or two to replicate. Just run the script
> again and it will finish the app configuration.

Output: `client/config.json`, containing your tenant ID and UNC path.

---

### Step 2 — Deploy the Intune policies

```powershell
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'
./intune/Deploy-IntunePolicies.ps1 -GroupId '<cloud-pc-device-group>' -WhatIf
./intune/Deploy-IntunePolicies.ps1 -GroupId '<cloud-pc-device-group>'
```

Creates two settings catalog policies:

1. **`CloudKerberosTicketRetrievalEnabled = 1`** — required. Without it the client never
   requests a cloud TGT and every mount falls back to NTLM, which a Kerberos-only storage
   account rejects outright.
2. **Session time limits** — 8h active limit with forced sign-out. Bounds the TGT ceiling.
   Use `-SkipSessionLimits` to defer this one.

> **Check what else is in your target group first.** If it is a dynamic group matching
> `deviceModel -startsWith "Cloud PC"`, it may also capture AVD session hosts — an 8h forced
> sign-out on a persistent AVD desktop is a behaviour change you should make deliberately.

---

### Step 3 — Conditional Access exclusion ⚠️ REQUIRED, MANUAL

**Skip this and every mount fails with error 1327.** Not automatable, and it needs a security
owner's sign-off.

Entra admin center → **Protection → Conditional Access** → for every policy requiring MFA for
all cloud apps, exclude the application named:

```
[Storage Account] <storageAccountName>.file.core.windows.net
```

Scope the exclusion to that one app, not to all storage. Document it in your risk register.
The compensating controls are already in place: network isolation (service endpoint with
firewall default-deny), share-level RBAC, and NTFS ACLs. The share is not reachable from the
internet regardless of this exclusion.

---

### Step 4 — Verify the policy actually landed

Assigned is not the same as applied. On the pilot Cloud PC:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name CloudKerberosTicketRetrievalEnabled
```

Expect `1`. If nothing comes back, force a sync — **Settings → Accounts → Access work or
school → Info → Sync** — wait a few minutes, and check again. Do not continue until this
returns `1`; nothing downstream can work without it.

---

### Step 5 — Wait for RBAC propagation

Share-level role assignments take **up to 30 minutes**. Testing inside that window produces
access-denied failures that look like a permissions bug but are just propagation delay.

---

### Step 6 — Set NTFS ACLs ⚠️ REQUIRED, MANUAL

Share-level RBAC gets you *to* the share; NTFS ACLs control what you can do *inside* it. Both
are required.

From a pilot Cloud PC, signed in as a member of the admin group (which holds *Storage File Data
SMB Share Elevated Contributor*):

```powershell
net use Z: \\<storageaccount>.file.core.windows.net\<share>
icacls Z:\ /grant "<your-user-group>:(OI)(CI)M"
icacls Z:\ /remove "Authenticated Users"
net use Z: /delete
```

Then **remove the elevated role** — it exists only for this step.

---

### Step 7 — Build and assign the Win32 app

```powershell
Install-Module SvRooij.ContentPrep.Cmdlet -Scope CurrentUser   # once
./tools/Build-IntuneWinPackage.ps1
```

Produces `dist/Install-DriveMapAgent.intunewin`, verified by round-trip decryption. Works on
Linux and macOS as well as Windows — `IntuneWinAppUtil.exe` is not required.

Upload to Intune → **Apps → Windows → Add → Windows app (Win32)**:

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-DriveMapAgent.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-DriveMapAgent.ps1` |
| Install behavior | **System** |
| Architecture | 64-bit |
| Minimum OS | Windows 11 22H2 |
| Requirement rule | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild` ≥ `26100` |
| Detection | **Custom script** → `client/Detect-DriveMapAgent.ps1`, 64-bit, *not* as logged-on user |
| Assignment | **Required** → Cloud PC **device** group |

**Nothing maps the drive until this step is done.** The scheduled task that creates the mapping
is registered by the installer; with no app deployed, there is no agent on the device and `X:`
will simply never appear.

---

### Step 8 — Validate

On the pilot Cloud PC, in a **normal (non-elevated)** user session:

```powershell
.\Test-DriveMapReadiness.ps1 -UncPath \\<storageaccount>.file.core.windows.net\<share>
```

Ten checks, each PASS/FAIL, telling you exactly which layer is broken. Run this *first* on any
failure rather than guessing.

---

## Troubleshooting

Start with `Test-DriveMapReadiness.ps1`. Then match the symptom:

| Symptom | Most likely cause |
|---|---|
| **`X:` never appears at all** | The Win32 app is not installed (step 7). No app means no scheduled task, and nothing creates the mapping. Verify: `Get-ScheduledTask -TaskPath '\AzureFilesDriveMap\'` |
| **Error 1327** on mount | Conditional Access exclusion missing (step 3) |
| **Error 1326** on mount | Private endpoint mode with the privatelink FQDN missing from the app's `identifierUris` |
| **Access denied** | Share RBAC not propagated yet (wait 30 min), or NTFS ACLs not set (step 6) |
| **Worked, now denied** | The ~10h cloud TGT expired. Sign out and back in — *disconnecting is not enough* |
| **`CloudKerberosTicketRetrievalEnabled` absent** | Policy assigned but not yet applied. Force an Intune sync |
| **TCP 445 unreachable** | Service endpoint or firewall rule missing, or the Cloud PC is not on the ANC vNet |

**Diagnostic sources, in order of usefulness:**

```powershell
# 1. The ten-point diagnostic
.\Test-DriveMapReadiness.ps1 -UncPath \\<account>.file.core.windows.net\<share>

# 2. Is the agent even installed?
Get-ScheduledTask -TaskPath '\AzureFilesDriveMap\'
Get-ItemProperty 'HKLM:\SOFTWARE\AzureFilesDriveMap'

# 3. Agent log (per user, 14-day retention)
Get-Content "$env:LOCALAPPDATA\AzureFilesDriveMap\Logs\agent-*.log" -Tail 40

# 4. Event log - 3005 is the one that matters (TGT unrecoverable, user must sign out)
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='AzureFilesDriveMap'} -MaxEvents 20

# 5. Kerberos ticket state - look for krbtgt/KERBEROS.MICROSOFTONLINE.COM
klist

# 6. Join state and PRT - both must be YES
dsregcmd /status

# 7. Win32 app deployment log (if the app never installs)
Get-Content "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log" -Tail 50
```

Event IDs are documented in [`intune/Packaging-and-Assignment.md`](intune/Packaging-and-Assignment.md) §5.


## The constraint you need to plan around

Microsoft Entra Kerberos **does not support TGT renewal**. The cloud TGT issued alongside the
PRT lives roughly 10 hours. On a Cloud PC, where people stay signed in for days, the ticket
expires mid-session and the drive starts returning access denied. Microsoft's documented
temporary fix is "sign out and sign back in"; the documented permanent fix is an AD DS cloud
trust, which is **not available to cloud-native Entra-only clients**.

The agent attempts a mitigation — PRT refresh → forced Kerberos request, before expiry rather
than after — but set expectations accordingly: `CloudKerberosTicketRetrievalEnabled` is a
**logon-time** retrieval path with no documented mid-session equivalent, so re-acquisition
failing is the expected case, not the exception. The agent therefore never destroys a working
ticket to chase a new one: the cache purge is a last resort reached only when the TGT is
already absent or expired, and it is opt-in (`tgt.allowTicketPurge`, default `false`).

**Do not rely on the agent alone.** The one deterministic control available to cloud-native
Entra-only Cloud PCs is bounding session length — a max session time that forces a *sign-out*
(not a disconnect) inside the ~10 hour window. That converts an unpredictable mid-afternoon
failure into a predictable daily sign-in. Ship it alongside the agent from day one; see
`intune/Packaging-and-Assignment.md` §7.

Instrument event ID 3005 from day one regardless — it is how you measure whether the ceiling
is an annoyance or a blocker in your estate.

Read the spec for the full mitigation ladder before committing to a rollout date.

## Prerequisites

- Az PowerShell: `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.Network`, `Az.PrivateDns`
- Microsoft Graph: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`,
  `Microsoft.Graph.Identity.SignIns` (required for `-GrantAdminConsent`)
- Azure: Owner, or Contributor + User Access Administrator
- Entra: Cloud Application Administrator or higher (to grant admin consent)
- Cloud PC image: Windows 11 Enterprise 24H2 (build 26100) or later, current CU
- Target Cloud PC must be **both** Entra joined (`trustType=AzureAd`) **and** on the ANC.
  These are independent properties — verify both on the *same* machine before deploying.

## Deployment record

[`docs/Deployment-westus3.md`](docs/Deployment-westus3.md) is a real, verified run against a
live tenant: environment pre-flight, why ServiceEndpoint was chosen over PrivateEndpoint on
a vNet with on-prem DNS, every resource property read back from ARM/Graph, the four bugs the
execution exposed, and teardown.

## Contributing

CI runs on every push and PR: script parsing on Windows and Linux, PSScriptAnalyzer against
`PSScriptAnalyzerSettings.psd1`, the offline logic tests, and a config-consistency gate.

Run the same checks locally before opening a PR:

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
./tests/Test-AgentLogic.ps1
```

Two rules the config gate enforces, because both have already caused real bugs:

- `healIntervalMinutes` **must** be less than `tgt.renewThresholdMinutes`, or the agent can
  step straight over the renewal window.
- `tgt.allowTicketPurge` **must** default to `false`. Purging the Kerberos ticket cache is
  destructive and is only ever a last resort once the TGT is already unusable.

The excluded analyzer rules are documented with rationale in `PSScriptAnalyzerSettings.psd1`.
If you need to add an exclusion, explain why there rather than inline.

## Disclaimer

Provided as is under the MIT licence. Test in a pilot ring before touching production, and
read §6 of `intune/Packaging-and-Assignment.md` for the uninstall caveat around stale drive
mappings in profiles that are not signed in.
