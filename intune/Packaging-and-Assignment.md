# Intune packaging and assignment

Everything Intune needs to deliver this solution: one settings catalog policy, one Win32 app,
one Conditional Access exclusion.

---

## 1. Settings catalog policy — cloud Kerberos ticket retrieval

**Required.** Without it the client never requests a cloud TGT and every mount falls back to
NTLM, which Azure Files rejects.

> **Automated.** Run [`Deploy-IntunePolicies.ps1`](Deploy-IntunePolicies.ps1) to create and
> assign this policy (and optionally the session limits in §7) via Graph:
>
> ```powershell
> Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All'
> ./intune/Deploy-IntunePolicies.ps1 -GroupId '<cloud-pc-device-group>' -WhatIf
> ```
>
> Idempotent, supports `-WhatIf`, and **merges** assignments rather than overwriting them —
> important when targeting a shared device group. Use `-SkipSessionLimits` to deploy only
> the Kerberos policy. The table below documents what it creates, and remains the manual
> path if you prefer the portal.

| Field | Value |
|---|---|
| Platform | Windows 10 and later |
| Profile type | Settings catalog |
| Category | **Administrative Templates > System > Kerberos** |
| Setting | **Allow retrieving the Microsoft Entra Kerberos Ticket Granting Ticket during logon** |
| Value | **Enabled** |
| Policy CSP | `./Device/Vendor/MSFT/Policy/Config/Kerberos/CloudKerberosTicketRetrievalEnabled` = `1` |
| Assign to | Cloud PC **device** group |

> Use the **Settings catalog**, not a custom OMA-URI profile. Microsoft documents that the
> OMA-URI method does not work on multi-session hosts, and there is no reason to carry that
> risk on single-session Cloud PCs either.

**Optional companion setting** — if the estate also reaches AD DS-backed storage accounts,
add `Kerberos/HostToRealm` mappings so the client sends those hostnames to the right realm.
Realm names are case-sensitive and must be uppercase.

---

## 2. Conditional Access exclusion

**Required.** Not automatable, and it needs a security owner's sign-off.

1. Entra admin center → **Protection → Conditional Access**.
2. For every policy that requires MFA for all cloud apps, add an exclusion for the
   application named:

   ```
   [Storage Account] <storageAccountName>.file.core.windows.net
   ```

3. Confirm the exclusion is scoped to that one app, not broadened to all storage.

Skipping this produces **error 1327** on mount. Document the exception in your risk register:
the compensating controls are network isolation (private endpoint or service endpoint
default-deny), share-level RBAC, and NTFS ACLs — the share is not reachable from the internet
regardless of the CA exclusion.

---

## 3. Win32 app

### Build

```powershell
# From the repo root, with IntuneWinAppUtil.exe on PATH
IntuneWinAppUtil.exe -c .\client -s Install-DriveMapAgent.ps1 -o .\dist -q
```

**Cross-platform alternative (recommended).** `IntuneWinAppUtil.exe` is Windows-only.
`tools/Build-IntuneWinPackage.ps1` produces a byte-compatible package (ToolVersion 1.8.6.0)
on Linux, macOS or Windows:

```powershell
Install-Module SvRooij.ContentPrep.Cmdlet -Scope CurrentUser   # once
./tools/Build-IntuneWinPackage.ps1
```

It does three things the raw tool does not:

- **Stages only the six runtime files.** Pointing `IntuneWinAppUtil -c` at `client/` sweeps in
  whatever else is sitting there (`config.sample.json`, editor scratch files). The build
  script ships an explicit allow-list.
- **Refuses to package the placeholder tenant.** Shipping the unedited sample produces an app
  that installs cleanly and then never maps a drive — a slow, confusing failure.
- **Round-trips the package.** It decrypts the result and compares every file's SHA-256
  against the source. A package that cannot decrypt to identical bytes is one Intune rejects
  *after* upload, which is far harder to diagnose from the portal.

Each build produces a different SHA-256 even from identical inputs — every package gets a
fresh random AES-256 key and IV. That is expected, not a reproducibility defect.

Package the **whole** `client` folder — the installer copies `Invoke-DriveMapAgent.ps1` and
`config.json` out of it and fails fast if either is missing. `package.json` must be in the
package too: it is the single source of truth for version and task identity, read by the
installer, the detection script and the uninstaller alike.

### App settings

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-DriveMapAgent.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-DriveMapAgent.ps1` |
| Install behavior | **System** |
| Device restart behavior | No specific action |
| Return codes | `0` = Success, `1603` = Failed |

No `-PackageVersion` on the install command. Version comes from `package.json`, so there is
no second place to update and no way for the install command and the detection rule to
disagree.

### Requirements

| Field | Value |
|---|---|
| Architecture | 64-bit |
| Minimum OS | Windows 11 22H2 |
| Additional rule | Registry — `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuild` ≥ `26100` |

The build requirement matters: Entra Kerberos with **cloud-only identities** needs Windows 11
24H2 (build 26100) or later with the current cumulative update. Enforcing it as a requirement
rule rather than hoping the image is current stops the app landing on a Cloud PC that cannot
possibly authenticate.

### Detection

Use a **custom detection script**: `Detect-DriveMapAgent.ps1`, run as 64-bit, not as the
logged-on user. It checks the version stamp, the agent file, *and* the scheduled task, so a
Cloud PC whose task was wiped gets a reinstall instead of showing healthy.

The script takes no parameters — Intune runs detection scripts with no arguments, so a
parameter default would be the only value that ever applied. It reads the expected version
from the `package.json` packaged alongside it.

Simpler alternative if you prefer a rule over a script: registry, `HKLM\SOFTWARE\AzureFilesDriveMap`,
value `Version`, String comparison equals the `packageVersion` in `package.json`. It won't
catch a deleted task, and it reintroduces a value you have to keep in sync by hand.

### Assignment

Assign **Required** to the Cloud PC device group — the same group the ANC provisioning policy
targets. Device assignment, not user: the agent installs once per Cloud PC and then serves
whoever signs in.

### Versioning

Bump `packageVersion` in `client/package.json`. That is the only change required — the
installer stamps it and the detection script reads it from the same file, so the
"mismatched values leave every device reinstalling on a loop" failure is now structurally
impossible rather than merely documented against.

---

## 4. What the scheduled task looks like once installed

```
Task:       \AzureFilesDriveMap\AzureFilesDriveMap   (from package.json taskPath/taskName)
Run as:     BUILTIN\Users  (S-1-5-32-545), non-elevated, only when a user is logged on
Triggers:   At logon (30s delay)
            Once at install+5m, repeating every 30 minutes indefinitely
            On remote session connect   (Cloud PC reconnect)
            On workstation unlock
Action:     powershell.exe -File %ProgramData%\AzureFilesDriveMap\Invoke-DriveMapAgent.ps1
```

The 30 minute repetition is not arbitrary: it must be **shorter** than
`tgt.renewThresholdMinutes` (45) in `config.json`, or the agent can step straight over the
renewal window — a run at T‑50 sees "50 minutes left, nothing to do" and the next run lands
at T+10, already expired. The installer validates this relationship and refuses to install
if it does not hold.

Non-elevated is deliberate. A mapping made in an elevated token is invisible to Explorer in
the user's standard token unless `EnableLinkedConnections` is set — install with
`-EnableLinkedConnections` only if you specifically need elevated processes to see the drive.

---

## 5. Monitoring

The agent writes to the **Application** log under source `AzureFilesDriveMap`:

| Event ID | Meaning |
|---|---|
| 1001 | Drive mapped successfully |
| 2001 | Cloud TGT missing or near expiry — re-acquisition starting |
| 2002 | Re-acquisition succeeded |
| 2003 | Mapping existed but was not responding; rebuilt |
| 3001 | Re-acquisition produced no usable TGT |
| 3002/3003 | Mapping creation failed |
| 3004 | TCP 445 unreachable |
| 3005 | **TGT unrecoverable in-session — user told to sign out** |

Collect 3005 specifically. Its rate over a week is the single number that tells you whether
the 10-hour TGT ceiling is an annoyance or a blocker for this estate, and whether you need to
escalate to one of the mitigations in the spec.

Per-user file log: `%LOCALAPPDATA%\AzureFilesDriveMap\Logs\agent-YYYYMMDD.log` (14-day retention).

---

## 6. Uninstall caveat — stale mappings

`Uninstall-DriveMapAgent.ps1` runs as SYSTEM and can only clean the HKCU hives that are
**loaded** at the time, which in practice is the signed-in user. Profiles for users who are
not signed in keep their `X:` mapping and will see a dead drive letter with a red X at next
logon.

This is **provided as is** — no run-once or Active Setup cleanup is registered. If you are
retiring the share across an estate, clean up deliberately: reprovision the Cloud PCs, or
push a user-context script removing `HKCU:\Network\<letter>` and the matching `MountPoints2`
entry. On single-session Cloud PCs with one primary user this rarely bites; it is called out
so nobody discovers it during a decommission.

---

## 7. Bound the session length (recommended, ship with the pilot)

The agent mitigates the ~10h TGT ceiling on a best-effort basis; it cannot remove it. The
only deterministic control available to cloud-native Entra-only Cloud PCs is to keep sessions
shorter than the ticket:

| Setting | Value |
|---|---|
| Set time limit for active Remote Desktop Services sessions | **8 hours** |
| Set time limit for active but idle sessions | 2 hours |
| Set time limit for disconnected sessions | 1 hour |
| **End session when time limits are reached** | **Enabled** |

Delivered via settings catalog → *Administrative Templates > Windows Components > Remote
Desktop Services > Remote Desktop Session Host > Session Time Limits*, or automatically by
`Deploy-IntunePolicies.ps1`.

Two things that are easy to get wrong here, both verified against the live settings catalog:

1. **The limits are fixed enums, not free integers.** The catalog exposes a ladder
   (…1h, 2h, 3h, 6h, **8h**, 12h, 16h, 18h, 1 day…) and rejects anything else. **There is no
   9-hour option.** 8h is the correct choice: 12h exceeds the ~10h TGT lifetime and defeats
   the entire purpose of the policy.
2. **"End session when time limits are reached" must be Enabled**, as a separate setting.
   Without it, reaching the limit only *disconnects* the session — the logon session and its
   dead cloud TGT survive, the drive stays broken, and the policy achieves nothing. This is
   the single setting that makes the whole mitigation work.

The ADMX-backed setting IDs (`…admx_terminalserver_ts_sessions_limits_2` and friends) are
**not** under a `remotedesktopservices` policy path, which is where you would reasonably look
for them first.

The exchange this makes: an unpredictable mid-afternoon "access denied" that generates a
support ticket becomes a predictable, announceable daily sign-in. It also turns the agent
into the thing that makes reconnects seamless — a job it does reliably — instead of the thing
papering over a ceiling it cannot move. Ship it with the pilot rather than waiting on event
3005 volume to justify it.
