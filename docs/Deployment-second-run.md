# Deployment record — westus3, <org>

Rebuild of the Azure side after the previous estate (`<storageaccount-old>`) was torn down.
Recorded because execution found a defect in this repo's own idempotency check, and because
the root cause of the final mount failure generalises to any deployment of this solution.

**Executed:** 2026-10-08 / 09 · **Region:** westus3 · **Operator:** <operator-upn>

---

## 1. Environment

| Item | Value |
|---|---|
| Subscription | `<subscription>` (`00000000-0000-0000-0000-000000000001`) |
| Tenant | `00000000-0000-0000-0000-000000000000` (<org>) |
| Resource group | `rg-cloudpc-files` (existing, westus3) |
| Storage account | `<storageaccount>`, Premium_ZRS / FileStorage |
| Share | `cloudpc-data`, 1024 GiB |
| ANC vNet / subnet | `<anc-vnet>` (`<network-rg>`) / `<anc-subnet>` |
| Network mode | `ServiceEndpoint` |
| Auth mode | `AADKERB` (Microsoft Entra Kerberos) |
| Share RBAC group | `Group A (data-access group)` (`aaaaaaaa-0000-0000-0000-00000000000a`) |
| Policy assignment group | `Group B (policy assignment group)` (`bbbbbbbb-0000-0000-0000-00000000000b`) |
| Pilot Cloud PC | `CPC-User-AAAAAA` — `trustType=AzureAd`, build 26200, NIC `10.x.2.6` |

### "Redeploy" was actually a fresh build

The repo's committed `client/config.json` named `<storageaccount-old>` in `ADDS` mode. Neither
survived: the resource group held only a Recovery Services vault, and the account did not
exist in the subscription. **A repo's config file names the last deployment, not a live one** —
list the estate before planning, and confirm the auth mode with the operator rather than
inheriting the stale file. `directoryServiceOptions` is account-wide and one-of.

### ServiceEndpoint, again

`<anc-vnet>` DNS is `<on-prem-dns-ip>` (on-prem). Unchanged from the previous deployment: with a
custom resolver and no conditional forwarder for `privatelink.file.core.windows.net`, a
private endpoint would resolve to the public IP while the firewall denies public access.

---

## 2. Result — verified against ARM and Graph

Every value read back from the API, not from script output.

| Check | Result |
|---|---|
| Storage account | `<storageaccount>`, Premium_ZRS / FileStorage, westus3, `Succeeded` |
| Identity source | `directoryServiceOptions = AADKERB` |
| Share | `cloudpc-data`, 1024 GiB, SMB, available |
| Service endpoint | `Microsoft.Storage` on `<anc-subnet>` (westus3, eastus) |
| Storage firewall | `defaultAction=Deny`, `bypass=AzureServices`, `<anc-subnet>` allowed |
| Share RBAC | `Storage File Data SMB Share Contributor` → `Group A (data-access group)` |
| Entra app | `[Storage Account] <storageaccount>.file.core.windows.net` — appId `0000e2-…`, objectId `0000e1-…` |
| App tag | `kdc_enable_cloud_group_sids` |
| Admin consent | `AllPrincipals` — `openid profile User.Read` |
| Intune policy | `Cloud PC - Entra Kerberos TGT Retrieval` (`0000c1-…`), `…cloudkerberosticketretrievalenabled_1`, `windows10`/`mdm` |
| CA exclusions | `<ca-policy-mfa>` **and** `<ca-policy-legacy-auth>` both exclude `0000e2-…` |

**UNC path:** `\\<storageaccount>.file.core.windows.net\cloudpc-data`

`publicNetworkAccess: Enabled` alongside `networkAcls.defaultAction: Deny` is **correct** for
ServiceEndpoint mode. The firewall is the control; it is not a hole to "fix".

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
- `CIFS/<storageaccount>.file.core.windows.net` — **uppercase**, AES-256-CTS-HMAC-SHA1-96,
  via `KdcProxy:login.microsoftonline.com`

Reading the share root descriptor over REST found a single ACE:

```
O:SYG:SYD:(A;OICI;FA;;;S-1-12-1-<Group-B-SID>)S:NO_ACCESS_CONTROL
```

That SID decodes to `bbbbbbbb-…` = **`Group B (policy assignment group)`** — the *Intune policy
assignment* group. Share-level RBAC was on **`Group A (data-access group)`**
(`aaaaaaaa-…`). Two valid gates naming different groups, so no principal cleared both.

Adding the RBAC group to the root ACL (keeping the existing ACE) fixed the mount.

```
O:SYG:SYD:(A;OICI;FA;;;S-1-12-1-...bbbbbbbb)(A;OICI;FA;;;S-1-12-1-...aaaaaaaa)S:NO_ACCESS_CONTROL
```

### Two assumptions that were wrong, and cost time

1. **"A new share root has no security descriptor."** True only of a genuinely new share. This
   root had a real descriptor *and* an existing `<existing-dir>` directory. Read it before theorising.
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

## 5. Current state of SMB security settings ⚠️ TEMPORARY

**The account is currently on "Maximum compatibility", deliberately, pending further testing.**

```
authenticationMethods    : NTLMv2;Kerberos;
channelEncryption        : AES-128-CCM;AES-128-GCM;AES-256-GCM;
kerberosTicketEncryption : RC4-HMAC;AES-256;
versions                 : SMB2.1;SMB3.0;SMB3.1.1;
```

This is **not** the recommended end state and was not what fixed the mount — the ACL group
mismatch (§4) was. It is recorded here so the next person does not mistake it for a
deliberate baseline.

Why it matters while it stays this way:

- **NTLMv2 is enabled**, which bypasses Kerberos entirely. Any mount that now succeeds does
  **not** prove the Entra Kerberos path works — it may have fallen back to NTLM. Hybrid-user
  and cloud-only testing done in this state is inconclusive on that point.
- **RC4-HMAC** ticket encryption is re-enabled.
- **SMB 2.1 / 3.0** are re-enabled. Note SMB 2.1 cannot work anyway while *Secure transfer
  required* is on.

Target state to restore once testing concludes (all supported under `AADKERB`):

```
versions                 : SMB3.1.1
authenticationMethods    : Kerberos
channelEncryption        : AES-256-GCM
kerberosTicketEncryption : AES-256
```

Re-tighten **one axis at a time**, retesting the mount between each, so a regression stays
attributable.

---

## 6. Temporary access opened and reverted

Setting the root ACL over REST required access that did not exist by default. All three were
removed and the removal verified against ARM:

| Grant | Scope | Status |
|---|---|---|
| `Storage File Data Privileged Contributor` | storage account | **removed** |
| `Storage File Data SMB Share Elevated Contributor` | `cloudpc-data` share | **removed** |
| Storage firewall IP rule `<operator-egress-ip>` | storage account | **removed** |

Final state: `ipRules: []`, `defaultAction: Deny`, only the `<anc-subnet>` vNet rule, and the sole
data-plane role assignment is `Storage File Data SMB Share Contributor` → the RBAC group. The
ACL persists independently of these grants.

`Storage File Data SMB Share Elevated Contributor` is **not sufficient** for the REST
data-plane calls — they return `AuthorizationPermissionMismatch`. See
[`Set-RootAcl-RestApi.md`](Set-RootAcl-RestApi.md).

---

## 7. Outstanding

- [ ] **Restore SMB hardening** (§5) once testing concludes.
- [ ] **Rebuild `dist/Install-DriveMapAgent.intunewin`** — the committed artifact predates this
      deployment and points at the torn-down `<storageaccount-old>` account in `ADDS` mode.
      Verify by decrypting and reading the packaged `config.json` back; do not trust the
      build's own success output.
- [ ] **Assign the Win32 app** to a device group. Until then nothing maps the drive
      automatically — the successful mount recorded here was manual (`net use`).
- [ ] **Hybrid-user validation.** `AADKERB` supports cloud-only *and* hybrid users on an Entra
      joined device. All four members of the RBAC group are currently cloud-only (no
      `onPremisesSecurityIdentifier`). A hybrid user presents an `S-1-5-21-…` SID but still
      matches the cloud **group** ACEs via the `kdc_enable_cloud_group_sids` tag, provided they
      are a member of the RBAC group. Note this test is inconclusive while NTLMv2 is enabled.
