# Deployment record — second real deployment

Rebuild of the Azure side after a previous estate was torn down. Recorded because execution
found a defect in this repo's own idempotency check, and because the root cause of the final
mount failure generalises to any deployment of this solution.

Identifiers below are redacted; the structure and the failure modes are the point.

**Region:** westus3 · **Network mode:** ServiceEndpoint · **Auth mode:** `AADKERB`

---

## 1. Environment

| Item | Value |
|---|---|
| Subscription | `00000000-0000-0000-0000-000000000001` |
| Tenant | `00000000-0000-0000-0000-000000000000` |
| Resource group | `rg-cloudpc-files` (existing, westus3) |
| Storage account | `<storageaccount>`, Premium_ZRS / FileStorage |
| Share | `cloudpc-data`, 1024 GiB |
| ANC vNet / subnet | `<anc-vnet>` / `<anc-subnet>` |
| Network mode | `ServiceEndpoint` |
| Auth mode | `AADKERB` (Microsoft Entra Kerberos) |
| Share RBAC group | **Group A** — the data-access group (`aaaaaaaa-…`) |
| Policy assignment group | **Group B** — the Intune policy target (`bbbbbbbb-…`) |
| Pilot Cloud PC | `CPC-User-AAAAAA` — `trustType=AzureAd`, build 26200, NIC in the ANC subnet |

> **Group A and Group B are different groups.** That distinction is the whole of §4 — keep it
> in mind while reading.

### "Redeploy" was actually a fresh build

The repo's committed `client/config.json` named a storage account in `ADDS` mode. Neither
survived: the resource group held only an unrelated Recovery Services vault, and the account
did not exist in the subscription. **A repo's config file names the last deployment, not a
live one** — list the estate before planning, and confirm the auth mode with the operator
rather than inheriting the stale file. `directoryServiceOptions` is account-wide and one-of.

### ServiceEndpoint, again

The ANC vNet uses a custom on-premises DNS server. Unchanged from the previous deployment:
with a custom resolver and no conditional forwarder for `privatelink.file.core.windows.net`,
a private endpoint would resolve to the public IP while the firewall denies public access.

---

## 2. Result — verified against ARM and Graph

Every value read back from the API, not from script output.

| Check | Result |
|---|---|
| Storage account | Premium_ZRS / FileStorage, westus3, `Succeeded` |
| Identity source | `directoryServiceOptions = AADKERB` |
| Share | `cloudpc-data`, 1024 GiB, SMB, available |
| Service endpoint | `Microsoft.Storage` on the ANC subnet |
| Storage firewall | `defaultAction=Deny`, `bypass=AzureServices`, ANC subnet allowed |
| Share RBAC | `Storage File Data SMB Share Contributor` → **Group A** |
| Entra app | `[Storage Account] <acct>.file.core.windows.net` (appId and objectId are different values — see below) |
| App tag | `kdc_enable_cloud_group_sids` |
| Admin consent | `AllPrincipals` — `openid profile User.Read` |
| Intune policy | `Cloud PC - Entra Kerberos TGT Retrieval`, `…cloudkerberosticketretrievalenabled_1`, `windows10`/`mdm`, assigned to **Group B** |
| CA exclusions | Both enabled MFA policies exclude the storage account's app |

`publicNetworkAccess: Enabled` alongside `networkAcls.defaultAction: Deny` is **correct** for
ServiceEndpoint mode. The firewall is the control; it is not a hole to "fix".

> An application's `id` (object ID) is not its `appId`. A script that logs "Found app
> \<objectId\>" cannot have that value fed into `?$filter=appId eq '…'` — it returns an empty
> list, which reads like a missing app. Filter on `displayName` to get both.

---

## 3. Bug found by executing: the SPN case check silently passed

The deploy script reported `identifierUris correct (uppercase SPNs present) (already correct)`
while Graph showed **all six URIs lowercase** (`cifs/`, `host/`, `http/`).

PowerShell's `-contains` / `-notcontains` / `-eq` are **case-insensitive**, so the wanted
`CIFS/...` matched the existing `cifs/...`; both `$needsFix` and `$missing` came back empty and
the script declared success — on exactly the defect the block exists to catch.

Fixed in `84b2aab` by switching to `-cnotcontains`. The lesson generalises: **never trust a
deploy script's "already correct" on a case-sensitive value.** Read it back from the authority.

Had this shipped, the symptom would have been the misleading one: Entra issues a valid AES-256
CIFS ticket, 445 connects, and session setup surfaces as a credential prompt with no SMB
Security event.

---

## 4. Root cause of the mount failure: RBAC group ≠ NTFS ACL group

After the Azure build, the policy, and the CA exclusions were all verified correct, the mount
still prompted for credentials. Client-side evidence was clean:

- `CloudKerberosTicketRetrievalEnabled : 1` at `HKLM\SYSTEM\...\Lsa\Kerberos\Parameters`
- `krbtgt/KERBEROS.MICROSOFTONLINE.COM`, `Kdc Called: TicketSuppliedAtLogon`
- `CIFS/<acct>.file.core.windows.net` — **uppercase**, AES-256-CTS-HMAC-SHA1-96,
  via `KdcProxy:login.microsoftonline.com`

Reading the share root descriptor over REST found a single ACE:

```
O:SYG:SYD:(A;OICI;FA;;;S-1-12-1-<Group B SID>)S:NO_ACCESS_CONTROL
```

That SID decoded to **Group B** — the *Intune policy assignment* group. Share-level RBAC was
on **Group A**. Two valid gates naming different groups, so no principal cleared both. Every
individual check passed, which is exactly what made it hard to see.

Adding the RBAC group to the root ACL (keeping the existing ACE) fixed the mount:

```
O:SYG:SYD:(A;OICI;FA;;;S-1-12-1-<Group B SID>)(A;OICI;FA;;;S-1-12-1-<Group A SID>)S:NO_ACCESS_CONTROL
```

Decode every cloud-only ACE SID before drawing conclusions — `S-1-12-1-<w0>-<w1>-<w2>-<w3>` is
the object GUID as four little-endian uint32s:

```python
import uuid
w = [int(x) for x in sid.split('-')[4:]]
print(uuid.UUID(bytes_le=b''.join(x.to_bytes(4, 'little') for x in w)))
```

### Two assumptions that were wrong, and cost time

1. **"A new share root has no security descriptor."** True only of a genuinely new share. This
   root had a real descriptor *and* an existing directory in it. Read it before theorising;
   existing directories are the tell that the share is not new.
2. **Stale `activeDirectoryProperties` were the cause.** The account carried residue from the
   old `ADDS` config (`domainGuid`, `domainName` populated, other four fields blank) alongside
   `directoryServiceOptions: AADKERB`. Clearing it was harmless but **was not the fix**.

### Validator output that was not a finding

`Debug-AzStorageAccountAuth` reported two failures, both validator limitations with cloud-only
identities:

- **`CheckRBAC` — "User is a cloud-only user, cannot have RBAC access."** It looks for an
  `onPremisesSecurityIdentifier`. Entra Kerberos supports cloud-only users; that is what the
  `kdc_enable_cloud_group_sids` tag is for.
- **`CheckRegKey` — Failed**, while the client demonstrably held a CIFS ticket. It reads the
  PolicyManager CSP path, not the LSA path. A ticket cannot be obtained with cloud retrieval
  disabled, so the ticket outranks the check.

Everything that actually gates a mount passed: port 445, AAD connectivity, Entra object, admin
consent, Kerberos realm mapping, Entra join type.

---

## 5. A note on lowering SMB security

After the mount failure, "lower the SMB enforcement" was a tempting next move. It was the
wrong one, and the record is kept here because the reasoning generalises.

"Maximum compatibility" produces:

```
authenticationMethods    : NTLMv2;Kerberos;
channelEncryption        : AES-128-CCM;AES-128-GCM;AES-256-GCM;
kerberosTicketEncryption : RC4-HMAC;AES-256;
versions                 : SMB2.1;SMB3.0;SMB3.1.1;
```

- **NTLMv2 is enabled**, which bypasses Kerberos entirely. Any mount that then succeeds does
  **not** prove the Entra Kerberos path works — it may have fallen back to NTLM. Cloud-only
  and hybrid-user testing in this state is inconclusive on the question you are asking.
- **RC4-HMAC** ticket encryption is re-enabled.
- **SMB 2.1 / 3.0** are re-enabled. SMB 2.1 cannot work anyway while *Secure transfer
  required* is on.

The hardened profile is fully supported under `AADKERB` and is the recommended end state:

```
versions                 : SMB3.1.1
authenticationMethods    : Kerberos
channelEncryption        : AES-256-GCM
kerberosTicketEncryption : AES-256
```

The RC4 / `msDS-SupportedEncryptionTypes` trap that makes hardening a genuine suspect is an
**AD DS** failure mode and requires a computer object, which `AADKERB` does not have. If
`klist` already shows an AES-256 CIFS ticket, the account accepts that encryption by
definition.

If you do relax it as a diagnostic, change **one axis at a time** and retest the mount between
each, so the result stays attributable — and re-tighten afterwards.

---

## 6. Temporary access opened and reverted

Setting the root ACL over REST required access that did not exist by default. All three were
removed and the removal verified against ARM:

| Grant | Scope | Status |
|---|---|---|
| `Storage File Data Privileged Contributor` | storage account | **removed** |
| `Storage File Data SMB Share Elevated Contributor` | `cloudpc-data` share | **removed** |
| Storage firewall IP rule (operator's egress IP) | storage account | **removed** |

Final state: `ipRules: []`, `defaultAction: Deny`, only the ANC subnet vNet rule, and the sole
data-plane role assignment is `Storage File Data SMB Share Contributor` → Group A. The ACL
persists independently of these grants.

`Storage File Data SMB Share Elevated Contributor` is **not sufficient** for the REST
data-plane calls — they return `AuthorizationPermissionMismatch`. See
[`Set-RootAcl-RestApi.md`](Set-RootAcl-RestApi.md).

Track every such grant as you create it and revert it in the same session. A default-deny
account otherwise keeps an IP rule forever.

---

## 7. Client-side defects found after the Azure side was correct

Both were found by running the agent on a real Cloud PC, and neither was reachable by the
offline tests as they stood. Fixed in `548bf57` and `5191902`.

1. **The scheduled task exited `0x4` while manual runs worked.** `0x4` is the agent's own
   "required mapping failed" code, not a Task Scheduler fault. At an `-AtLogOn` trigger the
   agent ran before CloudAP had delivered the cloud TGT; four minutes later the next run
   mapped cleanly with no intervention. The agent now *waits* for the ticket, and reports this
   case as `0x6` (transient) so it is distinguishable from a real failure.

2. **The agent logged "Re-acquisition succeeded" immediately before the mount failed.** The
   success check accepted a ticket whose expiry could not be parsed. Worse, the whole
   re-acquisition path cannot work at logon: `dsregcmd /RefreshPrt` refreshes the Entra PRT,
   a different artefact that cannot mint a cloud TGT, which is `TicketSuppliedAtLogon`.

3. **The detection script could never report detected.** It read `package.json` via
   `$PSScriptRoot`, but Intune copies the script *content* elsewhere and runs it with nothing
   beside it — so the app reinstalled on every evaluation cycle. The expected version is now
   stamped into a generated `dist/Detect-DriveMapAgent.ps1` at build time.
