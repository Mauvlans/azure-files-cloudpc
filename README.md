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
  Packaging-and-Assignment.md       Settings catalog policy, CA exclusion, Win32 app rules,
                                    session limits, monitoring event IDs.
tests/
  Test-AgentLogic.ps1               Offline tests for the purge guard and timing logic.
                                    No Windows or Azure needed: pwsh ./tests/Test-AgentLogic.ps1
```

## Order of operations

1. **Build Azure** — run `azure/Deploy-AzureFilesForCloudPC.ps1` against the region your
   ANC vNet lives in. It writes `client/config.json` for you.
2. **Exclude the storage app from MFA CA policies.** Mounts fail with error 1327 otherwise.
   See `intune/Packaging-and-Assignment.md`.
3. **Deploy the settings catalog policy** setting `CloudKerberosTicketRetrievalEnabled = 1`
   to the Cloud PC device group.
3b. **Deploy the session time limits policy** (9h max session with forced sign-out). This is
   the only deterministic answer to the TGT ceiling — do not defer it.
4. **Set NTFS ACLs** once from a pilot Cloud PC, signed in as a member of the admin group
   (which holds *Storage File Data SMB Share Elevated Contributor*). Then drop that role.
5. **Package and assign the Win32 app** to the Cloud PC device group.
6. **Validate** with `client/Test-DriveMapReadiness.ps1` on a pilot Cloud PC.

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
- Microsoft Graph: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`
- Azure: Owner, or Contributor + User Access Administrator
- Entra: Cloud Application Administrator or higher (to grant admin consent)
- Cloud PC image: Windows 11 Enterprise 24H2 (build 26100) or later, current CU

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
