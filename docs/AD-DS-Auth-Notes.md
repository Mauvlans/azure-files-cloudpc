# AD DS (on-prem Kerberos) Azure Files — deployment notes

Companion to the Entra Kerberos (AADKERB) build. These two identity modes are
**mutually exclusive**: a storage account carries exactly one
`directoryServiceOptions` value. Switching modes invalidates all NTFS ACLs,
because the SIDs in them come from a different authority.

## Why AD DS instead of Entra Kerberos

Entra Kerberos cloud TGTs carry a hard ~10 hour lifetime that no client agent
can extend — the TGT is minted at logon (`Kdc Called: TicketSuppliedAtLogon`)
and cannot be re-requested mid-session. AD DS Kerberos has no such ceiling.

Cost of the switch: the client needs unimpeded network line of sight to a
domain controller on **every** mount, and users must be hybrid (synced from AD
to Entra). Cloud-only accounts cannot authenticate against AD DS at all.

Entra-joined (not domain-joined) devices **are** supported against AD DS-backed
Azure Files. Domain membership is not required — only DC reachability and a
synced user identity.

## Live deployment

| Field | Value |
|---|---|
| Storage account | `examplestorage` (FileStorage, PremiumV2_LRS, westus3) |
| Resource group | `rg-cloudpc-files` |
| Share | `cloudpc-data`, 1024 GiB, SMB |
| Domain | `corp.example.com` |
| NetBIOS name | `AD` |
| Domain GUID | `11111111-2222-3333-4444-555555555555` |
| Domain SID | `S-1-5-21-1111111111-2222222222-3333333333` |
| Storage computer object | `examplestorsvc01` (SID `…-1648`) |
| DC | `dc01.corp.example.com` (10.20.30.40) — PDC, GC, KDC, writable |

Note the estate has a **second** AD domain, `alt.example.com`
(`S-1-5-21-4444444444-5555555555-6666666666`). A storage account binds to one
domain only; users in the other domain cannot authenticate to this share.

## Reading domain facts without AD credentials

`Get-ADDomain` needs an authenticated bind. Where no domain credential is
available, anonymous CLDAP/RPC returns everything Azure needs:

```bash
net ads lookup -S <dc-ip>              # Domain GUID, forest, Pre-Win2k name, site
rpcclient -U "" -N <dc-ip> -c lsaquery # NetBIOS domain name + domain SID
ldapsearch -x -H ldap://<dc-ip> -s base -b "" \
  defaultNamingContext dnsHostName rootDomainNamingContext
```

Verified: the GUID from `net ads lookup` matched exactly what
`Join-AzStorageAccount` later wrote to Azure. Note it comes from the CLDAP
netlogon response rather than the domain object's `objectGUID` — if a join ever
fails on a GUID mismatch, re-check against `Get-ADDomain` first.

The domain object's `objectGUID` is **not** readable anonymously; RootDSE does
not expose it and a base search on the domain DN returns
`000004DC: LdapErr: … a successful bind must be completed`.

## Gotcha 1 — portal writes the FQDN into netBiosDomainName

The portal's AD DS join wrote:

```
netBiosDomainName: corp.example.com   # WRONG — that is the FQDN
```

The NetBIOS name is `AD` (confirmed by `rpcclient lsaquery` → `Domain Name: AD`
and `net ads lookup` → `Pre-Win2k Domain: AD`). A mismatch here is a known
cause of Kerberos failures in AD DS mode. Corrected via ARM PATCH and verified
by reading the property back.

**Always read this property back after any join** — do not trust the portal.

## Gotcha 2 — SMB "Maximum security" breaks AD DS mounts (RC4)

This hardening was applied *before* the first successful mount, and the mount
then prompted for credentials:

```
versions                 SMB3.1.1
authenticationMethods    Kerberos
kerberosTicketEncryption AES-256
channelEncryption        AES-256-GCM
```

Setting the account to **Maximum compatibility** made it work immediately:

```
versions                 SMB2.1;SMB3.0;SMB3.1.1;
authenticationMethods    NTLMv2;Kerberos;
kerberosTicketEncryption RC4-HMAC;AES-256;
channelEncryption        AES-128-CCM;AES-128-GCM;AES-256-GCM;
```

**Likely root cause (unconfirmed):** the computer object created by
`Join-AzStorageAccount` has no `msDS-SupportedEncryptionTypes` value, so the
KDC issues **RC4-HMAC** service tickets. An AES-256-only storage account
rejects them, and the failure surfaces as a credential prompt rather than a
Kerberos error. The proper fix is on the AD side, not by weakening the storage
account:

```powershell
Set-ADComputer examplestorsvc01 -KerberosEncryptionType AES256
# then re-tighten kerberosTicketEncryption to AES-256 and retest
```

"Maximum compatibility" is a real security regression, not a neutral default —
it re-enables NTLMv2 (bypassing Kerberos entirely), RC4-HMAC (deprecated), and
SMB 2.1/3.0 (no modern channel encryption). Treat it as a temporary state.

### Re-tightening safely

Change **one axis at a time** and retest the mount between each, so a failure
is attributable. Recommended order (lowest risk first):

1. Drop `NTLMv2` from `authenticationMethods` — biggest security win
2. Drop `SMB2.1;SMB3.0` from `versions`
3. Set `msDS-SupportedEncryptionTypes` on the computer object, then drop
   `RC4-HMAC` from `kerberosTicketEncryption`

If a step breaks the mount, revert that axis only and keep the rest.

## Process lesson

Establish a **working baseline first**, then harden one variable at a time.

On the previous (Entra Kerberos) account several changes were made against a
live deployment without retesting between them — SPN case, NTFS root ACL, a
direct user RBAC grant, `defaultSharePermission`, and a client-side registry
write. When the symptom moved, attribution became impossible and the cause was
never isolated.

Here the same mistake recurred in miniature: SMB hardening was applied before
the first mount was ever proven, and it was the hardening that blocked it.

Corollary: **a validator passing is not the same as the scenario working.**
`Debug-AzStorageAccountAuth` reported `CheckEntraObject Passed` on a
configuration that could not mount.

## Client requirements (AD DS mode)

- Windows **Entra-joined is fine** — domain join not required
- User must be **hybrid** (`onPremisesSyncEnabled: true`, on-prem SID present)
- Unimpeded network path to a DC (here: ANC vNet DNS → `10.20.30.40` over S2S VPN)
- **No** `CloudKerberosTicketRetrievalEnabled` registry key — that is Entra
  Kerberos only and is not used in AD DS mode
- Test mount **non-elevated**; Kerberos ticket caches are per-logon-session and
  an elevated prompt is a different session

```powershell
net use X: \\examplestorage.file.core.windows.net\cloudpc-data
```

Diagnostic that names the fault instead of prompting:

```powershell
klist get cifs/examplestorage.file.core.windows.net
```

## Outstanding

- [ ] NTFS root ACLs not yet set on `cloudpc-data`. On the previous account the
      share root had **no security descriptor at all** — verify rather than
      assume defaults.
- [ ] `ipRules` still contains the admin workstation IP `203.0.113.10` from
      the portal session; remove when no longer browsing.
- [ ] Share-level RBAC is granted to individual users (`User@`, `user2@`) for
      testing. Production should use a **synced AD group**, not direct grants.
- [ ] Re-tighten SMB settings per the staged plan above.
