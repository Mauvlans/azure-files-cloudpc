# Deployment record — westus3, Example Corp

Live deployment of the Azure side of this solution. Recorded because the execution found
four bugs that no amount of parsing, linting or offline testing would have caught, and
because the environment findings here generalise to any ANC deployment.

**Executed:** 2026-09-15 · **Region:** westus3 · **Operator:** Adam@example.com

---

## 1. Environment discovered

| Item | Value |
|---|---|
| Subscription | `Example Subscription` (`00000000-0000-0000-0000-000000000001`) |
| Tenant | `00000000-0000-0000-0000-000000000000` (Example Corp) |
| Caller roles | Owner + User Access Administrator |
| ANC vNet | `MVN-W3-VNET` (`MVN-Networking`), `10.10.0.0/16`, westus3 |
| ANC subnet | `AVDHosts` `10.10.2.0/24` |
| Target Cloud PC | `CPC-User-AAAAAA` — `trustType=AzureAd`, build 26200, NIC `10.10.2.6` |
| Target group | `MVN - Mapp Network Drive Tesating` (`00000000-264a-48bb-8591-1f9d17938917`) |

### Pre-flight gate that matters

Entra Kerberos requires the Cloud PC to be **both** Entra joined **and** on the ANC.
Check both before deploying — they are independent properties and it is entirely possible
to have each one on a different machine:

```bash
# Join type must be AzureAd, not ServerAd (hybrid) or Workplace
az rest --method get --url "https://graph.microsoft.com/v1.0/devices?\$filter=startswith(displayName,'CPC-')&\$select=displayName,trustType,operatingSystemVersion"

# And the same machine must own a NIC in the ANC vNet
az network nic list -o json | python3 -c "import json,sys;[print(n['name'], n['ipConfigurations'][0]['privateIPAddress']) for n in json.load(sys.stdin) if 'YOUR-VNET' in json.dumps(n)]"
```

In this estate the first attempt found `CPC-User-CCCCCC` on the ANC but hybrid-joined
(`ServerAd`/`OnPremiseCoManaged`), and an Entra-joined Cloud PC that was Microsoft-hosted
with no vNIC in the vNet. Neither could have worked. Deployment waited until
`CPC-User-AAAAAA` satisfied both.

---

## 2. Why ServiceEndpoint, not PrivateEndpoint

**This is the single most important environment finding.**

`MVN-W3-VNET` DNS is set to `10.20.30.40` — an on-premises DNS server reached over the
`MVN-Gilbert` IPsec S2S VPN (local network gateway prefix `10.0.0.0/16`). The subscription
has **zero private DNS zones** and **no Azure DNS Private Resolver**.

With `-NetworkMode PrivateEndpoint` the script would have created and linked
`privatelink.file.core.windows.net` correctly — and it would still have failed. The Cloud PC
asks `10.20.30.40` for DNS, that server has no conditional forwarder to Azure DNS
(`168.63.129.16`), so `<account>.file.core.windows.net` resolves to the **public** IP while
the storage firewall denies public access. The mount fails with a network error that looks
nothing like a DNS problem, and the private DNS zone looks perfectly healthy in the portal.

`ServiceEndpoint` mode has no DNS dependency and works with the on-prem resolver as-is.

> If you later want private endpoints anywhere in this subscription, fix the DNS path first:
> either add a conditional forwarder on the Gilbert DNS server for
> `privatelink.file.core.windows.net` → `168.63.129.16`, or deploy an Azure DNS Private
> Resolver in the vNet and point on-prem at it.

---

## 3. Command executed

```powershell
Connect-AzAccount   # or supply a token from an existing az CLI session
Connect-MgGraph -Scopes 'Application.ReadWrite.All','DelegatedPermissionGrant.ReadWrite.All'

./azure/Deploy-AzureFilesForCloudPC.ps1 `
  -SubscriptionId              '00000000-0000-0000-0000-000000000001' `
  -ResourceGroupName           'rg-cloudpc-files' `
  -Location                    'westus3' `
  -StorageAccountName          'examplestorageold' `
  -ShareName                   'cloudpc-data' `
  -Sku                         'Premium_ZRS' `
  -NetworkMode                 'ServiceEndpoint' `
  -AncVirtualNetworkResourceId '/subscriptions/.../virtualNetworks/MVN-W3-VNET' `
  -AncSubnetName               'AVDHosts' `
  -UserGroupObjectId           '00000000-264a-48bb-8591-1f9d17938917' `
  -DriveLetter 'X' -DriveLabel 'Company Files' `
  -EnableCloudOnlyGroupSids -GrantAdminConsent
```

Required modules: `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.Network`, `Az.PrivateDns`,
`Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`,
**`Microsoft.Graph.Identity.SignIns`** (the last one is needed for `-GrantAdminConsent`).

---

## 4. Result — verified against ARM and Graph

Every value below was read back from the ARM / Graph API, not from script output.

| Check | Result |
|---|---|
| Storage account | `examplestorageold`, Premium_ZRS / FileStorage, westus3, `Succeeded` |
| Identity source | `directoryServiceOptions = AADKERB` |
| Share | `cloudpc-data`, 1024 GiB, SMB, available |
| SMB versions | `SMB3.1.1` only |
| SMB auth | `Kerberos` only — NTLM fallback removed |
| Channel encryption | `AES-256-GCM` |
| Kerberos ticket encryption | `AES-256` |
| Share soft delete | enabled, 7 days |
| Service endpoint | `Microsoft.Storage` on `AVDHosts` (westus3, eastus) |
| Storage firewall | `defaultAction=Deny`, `bypass=AzureServices`, `AVDHosts` allowed |
| Share RBAC | `Storage File Data SMB Share Contributor` → `MVN - Mapp Network Drive Tesating` |
| Entra app | `[Storage Account] examplestorageold...` (`e04fe1ac-...`) |
| App tag | `kdc_enable_cloud_group_sids` |
| Admin consent | `AllPrincipals` — `openid profile User.Read` |

**UNC path:** `\\examplestorageold.file.core.windows.net\cloudpc-data`

### Verification gotcha worth knowing

`az storage account show --query networkAcls` reported `defaultAction: None` with no vNet
rules, while the ARM REST API for the same account reported `defaultAction: Deny` with the
rule present. **The CLI projection was wrong, not the resource.** Confirm firewall state
against the REST API before concluding a rule did not apply:

```bash
az rest --method get --url "https://management.azure.com/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<name>?api-version=2023-05-01" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['properties']['networkAcls'])"
```

---

## 5. Bugs found by executing (all fixed)

None were reachable by parsing, linting, or the offline tests. They required a live tenant.

1. **`-WhatIf` was impossible.** `Set-AzContext` honours ShouldProcess and returns nothing
   in that mode, so `$ctx.Tenant.Id` threw at step 1. The script could never be dry-run.

2. **Tenant ID could be silently wrong.** Both `$ctx.Tenant.Id` and
   `$ctx.Subscription.TenantId` reported `08495e34-…` while ARM and the auto-created Entra
   app both said `00000000-…`. That ID goes into `config.json` and the Kerberos
   identifierUris, so the damage would have surfaced much later as an unexplained mount
   failure. Now resolved from ARM, with a loud warning on mismatch.

3. **The cloud-group-SIDs tag crashed the entire app-config step.** `$tags = @($app.Tags)`
   collided with the script's `[hashtable] $Tags` parameter — PowerShell variable names are
   case-insensitive, so they are the same variable. Renamed to `$appTags`.

4. **Admin consent failed with "term not recognized".** `Get-MgOauth2PermissionGrant` lives
   in `Microsoft.Graph.Identity.SignIns`, which the module preflight did not require, so the
   script ran to the very last step before dying.

### Idempotency, proven

A full re-run after the fixes reported **every** step as already-correct — resource group,
storage account, Entra Kerberos, share, service endpoint, firewall rule, RBAC, app tag and
admin consent. The only step that re-executes unconditionally is the SMB hardening
(`Update-AzStorageFileServiceProperty` is a PUT with no cheap get-then-compare); it is
converging on the same values, so it is safe.

### Entra replication lag, observed

The first run reached step 9 before the storage account's Entra application had replicated,
and reported the app as not-found-yet — exactly as designed, with instructions to re-run. It
appeared roughly a minute later. This is normal, not a failure; budget for it, and do not
treat a single not-found as a broken deployment.

---

## 6. Remaining steps before the drive will actually map

The Azure side is complete and the Kerberos policy is deployed. **Nothing has yet been proven
on the Cloud PC itself** — no mount has been attempted, no Kerberos ticket obtained.

### Done — Intune Kerberos policy

```powershell
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'
./intune/Deploy-IntunePolicies.ps1 -GroupId '00000000-0000-0000-0000-0000000000b1' -SkipSessionLimits
```

| Item | Value |
|---|---|
| Policy | `Cloud PC - Entra Kerberos TGT Retrieval` (`00000000-0000-0000-0000-0000000000c1`) |
| Setting | `…kerberos_cloudkerberosticketretrievalenabled` = `…_1` (Enabled) |
| Assigned to | `SSO - Cloud PCs` (`00000000-…`) — dynamic device group |
| Verified | read back from Graph; re-run reports already-correct |

**Settings-catalog IDs must be verified, not assumed.** The Kerberos ID was correct first
time, but all three originally-assumed session-limit IDs were wrong — the real ones are
ADMX-backed under `admx_terminalserver`, not under any `remotedesktopservices` path. Confirm
any ID before building a policy body around it:

```powershell
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationSettings('<id>')"
```

Note that `configurationSettings` does **not** return an `@odata.nextLink`; it silently caps
at `$top`. Use `$top=5000` and filter client-side, or you will search a truncated catalog and
wrongly conclude a setting does not exist.

### Deferred — session time limits

Not deployed, pending a scoping decision. `SSO - Cloud PCs` is dynamic on
`(device.deviceModel -startsWith "Cloud PC") -or (device.displayName -contains "AVD-")`, so it
also contains five AVD session hosts (`MVN-AVD-PER-0/1`, `MVN-AVD-RA-0`, `AVD-W3-0`,
`MVN-AVD-01$`) and the hybrid Cloud PC `CPC-User-CCCCCC`. The Kerberos policy is harmless to
all of them; an 8-hour forced sign-out is not necessarily welcome on persistent AVD desktops.
Either scope session limits to a Cloud-PC-only group, or accept the blast radius deliberately.

### Still outstanding

1. **Conditional Access exclusion.** Exclude the app
   `[Storage Account] examplestorageold.file.core.windows.net` from every MFA-requiring
   policy. Without it, mounts fail with **error 1327**. Requires a security owner decision —
   deliberately not automated. Compensating controls are already in place: service-endpoint
   isolation with default-deny, share-level RBAC, and NTFS ACLs.
2. **NTFS ACLs + Win32 app.** Set root ACLs once from a pilot Cloud PC holding
   *Elevated Contributor*, then drop that role. Package `client/` and assign to the device
   group.

Then validate on `CPC-User-AAAAAA`:

```powershell
.\Test-DriveMapReadiness.ps1 -UncPath \\examplestorageold.file.core.windows.net\cloudpc-data
```

Note that share-level RBAC changes take up to ~30 minutes to propagate; test after that.

---

## 7. Teardown

```powershell
Remove-AzResourceGroup -Name 'rg-cloudpc-files' -Force
```

Two things the resource group does **not** cover, because they live outside it:

- The `Microsoft.Storage` service endpoint added to `MVN-Networking/MVN-W3-VNET/AVDHosts`.
  Harmless to leave; remove only if nothing else uses it.
- The auto-created Entra application `[Storage Account] examplestorageold...`
  (`appId 00000000-0000-0000-0000-0000000000e2`) and its service principal, plus the
  admin-consent grant. Delete via Entra admin center or
  `Remove-MgApplication -ApplicationId 00000000-0000-0000-0000-0000000000e1`.
- The Intune policy `Cloud PC - Entra Kerberos TGT Retrieval`:

  ```powershell
  Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('00000000-0000-0000-0000-0000000000c1')"
  ```

  Note this setting is otherwise harmless to leave in place — it only enables cloud TGT
  retrieval at logon and does not depend on the storage account existing.
