# Azure Files drive mapping for Windows 365 Cloud PCs (Entra joined + ANC)

[![Validate](https://github.com/<org>s/azure-files-cloudpc/actions/workflows/validate.yml/badge.svg)](https://github.com/<org>s/azure-files-cloudpc/actions/workflows/validate.yml)
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
  Detect-DriveMapAgent.ps1          Detection rule TEMPLATE. The builder stamps the version
                                    in and writes dist/Detect-DriveMapAgent.ps1 - upload
                                    that, not this.
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
  Deployment-second-run.md          Second deployment. Root cause of a credential-prompt
                                    failure: share RBAC and the NTFS ACL named different
                                    groups. Current SMB settings and outstanding work.
  Set-RootAcl-RestApi.md            Set the share-root NTFS ACL from Linux/macOS over the
                                    Files REST API. No Windows box, no storage key.
  AD-DS-Auth-Notes.md               AD DS (vs Entra Kerberos) auth notes and gotchas.
```

## Deployment at a glance

Nine steps. **Three require a human** — they cannot be scripted, and skipping any of them
produces a mount failure that looks like something else entirely.

| # | Step | Who | Why it cannot be skipped |
|---|---|---|---|
| 0 | Confirm the target Cloud PC qualifies | you | Entra joined **and** on the ANC. Nothing works otherwise |
| 1 | Run the Azure build script | automated | Storage, share, Entra Kerberos, networking, RBAC, Entra app |
| 2 | Verify Entra Kerberos against ARM/Graph | you | The build script can report a false pass on the SPNs |
| 3 | Run the Intune policy script | automated | Without the Kerberos policy every mount falls back to NTLM |
| 4 | **Conditional Access exclusion** | 🔴 **MANUAL** | Error 1327 on every mount. Needs a security owner's sign-off |
| 5 | Confirm the policy reached LSA | you | Assigned ≠ applied |
| 6 | Wait ~30 min for RBAC propagation | — | Testing early looks like a permissions bug |
| 7 | **Set NTFS ACLs on the share root** | 🔴 **MANUAL** | RBAC gets you *to* the share; NTFS decides what you can do *inside* |
| 8 | Build and assign the Win32 app | you | Nothing maps the drive until the agent is deployed |
| 9 | Validate on the pilot Cloud PC | you | Only a successful mount proves the scenario |

**Steps 4 and 7 must both be done before step 8.** Otherwise the agent installs perfectly and
fails every mount, and you will spend your time debugging the agent rather than the thing
actually blocking it.

The three manual actions in full:

1. **Step 4 — CA exclusion.** Exclude `[Storage Account] <acct>.file.core.windows.net` from
   every MFA-requiring policy. Not automatable; needs a security owner.
2. **Step 7 — NTFS root ACL.** Grant the **same group** that holds the share-level RBAC role.
   A different group here is the single easiest way to build a share nobody can mount.
3. **Step 8 — Intune portal upload.** Create the Win32 app and assign it to a **device** group.

Budget roughly 90 minutes end to end, most of it waiting on propagation.

## Step-by-step deployment guide

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

### Step 2 — Verify Entra Kerberos ⚠️ VERIFY, DO NOT ASSUME

Step 1 already enables Entra Kerberos and configures the auto-created Entra application.
**Verify it anyway** — a build that printed "already correct" for the SPNs has shipped an
account whose SPNs were entirely lowercase. Read the values back from the API, not from the
script's output.

```bash
ACCT=<storageAccountName>; RG=<rg>; SUB=<sub-guid>

az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$ACCT?api-version=2023-05-01" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['properties']['azureFilesIdentityBasedAuthentication'])"

az rest --method get --url "https://graph.microsoft.com/v1.0/applications?\$filter=startswith(displayName,'[Storage Account] $ACCT')" \
  | python3 -c "
import json,sys
a=json.load(sys.stdin)['value'][0]
print('appId:',a['appId']);print('tags :',a.get('tags'))
[print('  uri:',u) for u in a['identifierUris']]"
```

All four must hold:

| Check | Expected | If wrong |
|---|---|---|
| `directoryServiceOptions` | `AADKERB` | Re-run step 1 |
| `identifierUris` | **six** entries, all **UPPERCASE** `HOST/` `CIFS/` `HTTP/` (bare + `api://<tenant>/…`) | Fix below |
| `tags` | contains `kdc_enable_cloud_group_sids` | Re-run step 1 with `-EnableCloudOnlyGroupSids` |
| Admin consent | `AllPrincipals` — `openid profile User.Read` | Re-run step 1 with `-GrantAdminConsent` |

**If the SPNs are lowercase**, replace the whole set — Graph rejects both cases at once
(`DuplicateValueInDifferentCase`), so you cannot append:

```powershell
$objId = '<application objectId>'; $t = '<tenantId>'; $acct = '<account>.file.core.windows.net'
$uris = @()
foreach ($svc in 'HOST','CIFS','HTTP') { $uris += "api://$t/$svc/$acct"; $uris += "$svc/$acct" }
Update-MgApplication -ApplicationId $objId -IdentifierUris $uris
```

Then on any client that already tried a mount: `klist purge`, followed by a **full sign-out
and sign-in** — not a disconnect. The cloud TGT is supplied at logon and cannot be re-minted
mid-session.

> Why lowercase SPNs matter so much: Entra still issues a valid AES-256 CIFS ticket, TCP 445
> still connects, and session setup then fails as an interactive **"Enter the user name"**
> prompt with *no entry in the SMB Security event log*. It reads exactly like a credential
> problem and is neither. See [troubleshooting](#troubleshooting).

---

### Step 3 — Deploy the Intune policies

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

### Step 4 — Conditional Access exclusion ⚠️ REQUIRED, MANUAL

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

### Step 5 — Verify the policy actually landed

Assigned is not the same as applied. On the pilot Cloud PC:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' `
  -Name CloudKerberosTicketRetrievalEnabled
```

Expect `1`. If nothing comes back, force a sync — **Settings → Accounts → Access work or
school → Info → Sync** — wait a few minutes, and check again. Do not continue until this
returns `1`; nothing downstream can work without it.

---

### Step 6 — Wait for RBAC propagation

Share-level role assignments take **up to 30 minutes**. Testing inside that window produces
access-denied failures that look like a permissions bug but are just propagation delay.

---

### Step 7 — Set NTFS ACLs ⚠️ REQUIRED, MANUAL

Share-level RBAC gets you *to* the share; NTFS ACLs control what you can do *inside* it. Both
are required.

> **⚠️ The two layers must name the SAME principal.** This is the single easiest way to build
> a share where every check passes and no one can mount it. Share RBAC and the NTFS ACL are
> set by different steps, in different tools, and they drift — a user who clears one gate but
> not the other gets an interactive **credential prompt**, not a clean access-denied, which
> sends you off debugging Kerberos. Before you write any ACL, confirm which group holds the
> share-scope role, and grant *that* group here. A policy-assignment group and a data-access
> group with similar names are very easy to confuse.

```bash
az role assignment list \
  --scope ".../storageAccounts/<acct>/fileServices/default/fileshares/<share>" -o table
```

**Check whether the root already has a descriptor before assuming it needs one.** A genuinely
new root has none at all, but a share that has ever been used carries a real one — possibly
granting the wrong group. Listing the root and finding existing directories is the tell.

From a pilot Cloud PC, signed in as a member of the admin group (which holds *Storage File Data
SMB Share Elevated Contributor*):

```powershell
net use Z: \\<storageaccount>.file.core.windows.net\<share>
icacls Z:\                                          # READ IT FIRST
icacls Z:\ /grant "<share-rbac-group>:(OI)(CI)M"    # the group from the RBAC query above
net use Z: /delete
```

Then **remove the elevated role** — it exists only for this step.

**No Windows box?** The Files REST API can set the root descriptor directly, with no storage
key — see [`docs/Set-RootAcl-RestApi.md`](docs/Set-RootAcl-RestApi.md). Note it needs
`Storage File Data Privileged Contributor`; *Elevated Contributor* is not sufficient for the
REST path and returns `AuthorizationPermissionMismatch`.

---

### Step 8 — Build and assign the Win32 app

```powershell
Install-Module SvRooij.ContentPrep.Cmdlet -Scope CurrentUser   # once
./tools/Build-IntuneWinPackage.ps1
```

Produces **two** files in `dist/`, verified by round-trip decryption. Works on Linux and macOS
as well as Windows — `IntuneWinAppUtil.exe` is not required.

| File | Use |
|---|---|
| `dist/Install-DriveMapAgent.intunewin` | The app package you upload |
| `dist/Detect-DriveMapAgent.ps1` | The detection rule script — **upload this one** |

> **Use the generated detection script, not `client/Detect-DriveMapAgent.ps1`.** Intune does
> not run detection scripts from the package: the Management Extension copies the script
> *content* elsewhere and runs it with nothing beside it, so a script that reads `package.json`
> at runtime always fails closed and the app reinstalls on every evaluation cycle. The builder
> stamps the expected version into the generated copy. The source template refuses to report
> detected if uploaded by mistake.

🔴 **MANUAL** — Intune portal → **Apps → Windows → Add → Windows app (Win32)**:

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-DriveMapAgent.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-DriveMapAgent.ps1` |
| Install behavior | **System** |
| Architecture | 64-bit |
| Minimum OS | Windows 11 22H2 |
| Requirement rule | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild` ≥ `26100` |
| Detection | **Custom script** → `dist/Detect-DriveMapAgent.ps1`, 64-bit, *not* as logged-on user |
| Assignment | **Required** → Cloud PC **device** group |

**Nothing maps the drive until this step is done.** The scheduled task that creates the mapping
is registered by the installer; with no app deployed, there is no agent on the device and `X:`
will simply never appear.

**Upgrading an existing deployment?** Bump `packageVersion` in `client/package.json` before
building. Detection matches on that exact version, so an unchanged version makes already-
deployed devices report compliant and silently skip the new agent.

---

### Step 9 — Validate

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
| **`X:` never appears at all** | The Win32 app is not installed (step 8). No app means no scheduled task, and nothing creates the mapping. Verify: `Get-ScheduledTask -TaskPath '\AzureFilesDriveMap\'` |
| **Scheduled task returns `0x4`, but running the agent manually works** | That is the agent's own exit code, not a Task Scheduler fault — a `required` mapping failed. At an `-AtLogOn` trigger the agent can run before CloudAP has delivered the cloud TGT, so the mount fails and the next run succeeds unaided. Agent ≥1.2.0 waits for the ticket and reports this case as **`0x6`** (transient) instead. On `0x4`, read the log: a real failure has a valid TGT in it. |
| **App reinstalls on every Intune evaluation cycle** | The detection rule is the unbuilt template (`client/Detect-DriveMapAgent.ps1`) instead of the generated `dist/Detect-DriveMapAgent.ps1`, so it can never report detected. Rebuild and re-upload the detection script |
| **A new agent version never reaches devices** | `packageVersion` was not bumped, so detection matches the already-installed version and Intune considers the device compliant |
| **Credential prompt** ("Enter the user name") with a valid CIFS ticket in `klist` and *no* SMB Security event | Two possible causes, both of which pass every individual check: (a) lowercase SPNs in the Entra app's `identifierUris` (step 2); (b) **share RBAC and the NTFS root ACL name different groups** (steps 1 and 7) — each gate is valid alone, but no principal clears both |
| **Error 1327** on mount | Conditional Access exclusion missing (step 4) |
| **Error 1326** on mount | Private endpoint mode with the privatelink FQDN missing from the app's `identifierUris` |
| **Access denied** | Share RBAC not propagated yet (wait 30 min), or NTFS ACLs not set (step 7) |
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

### Microsoft's validator

`Debug-AzStorageAccountAuth` names most faults in one line and is worth more than any amount
of symptom-reading. Run it from a Windows box:

```powershell
Install-Module AzFilesHybrid -Scope CurrentUser
Debug-AzStorageAccountAuth -StorageAccountName <acct> -ResourceGroupName <rg> `
  -UserName <upn> -FileShareName <share> -Verbose
```

**Three of its failures are not findings.** Acting on them wastes hours:

| Reported | Why it is not a fault |
|---|---|
| `CheckRBAC` Failed, with `-UserName`/`-FileShareName` omitted | The check could not run. Supply both parameters |
| `CheckRBAC` — *"User is a cloud-only user, cannot have RBAC access"* | A validator limitation: it looks for an `onPremisesSecurityIdentifier` and gives up when there is none. Entra Kerberos explicitly supports cloud-only identities — that is what the `kdc_enable_cloud_group_sids` tag is for |
| `CheckRegKey` Failed, while `Lsa\Kerberos\Parameters` shows `1` and `klist` holds a CIFS ticket | It reads the PolicyManager CSP path, not the LSA path. **A CIFS ticket cannot be obtained with cloud retrieval disabled**, so the ticket outranks the check |

If those are the only failures, the validator has found nothing — move to the layer it does
not inspect: the NTFS ACL (step 7).


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

[`docs/Deployment-second-run.md`](docs/Deployment-second-run.md) records a
second deployment, worth reading for two things the first did not hit: a bug in this repo's
own SPN-case idempotency check that reported success on an entirely lowercase account, and
the root cause of a credential-prompt mount failure — **share-level RBAC and the NTFS root
ACL named different groups**. It also covers why lowering SMB security is the wrong response
to that symptom, and the three client-side defects found only by running the agent on a real
Cloud PC.

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