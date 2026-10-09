# Setting the share-root NTFS ACL over the Files REST API

No Windows box, no storage account key. Works from Linux/macOS with an `az login` bearer
token. Verified end to end against a live `AADKERB` premium share.

Use this when you need to set or repair the root security descriptor and you do not have a
pilot Cloud PC available to run `icacls` from.

---

## Prerequisites

### The role: Elevated Contributor is NOT enough

`Storage File Data SMB Share Elevated Contributor` governs the **SMB** path. REST data-plane
calls carrying `x-ms-file-request-intent: backup` return `403 AuthorizationPermissionMismatch`
under it.

Grant **`Storage File Data Privileged Contributor`** at the *storage account* scope and allow
~30–60 seconds for propagation:

```bash
az role assignment create \
  --assignee <your-object-id> \
  --role "Storage File Data Privileged Contributor" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<acct>"
```

If a call still fails, decode the token before blaming the role — a wrong audience looks
identical to a missing permission:

```bash
TOK=$(az account get-access-token --resource https://storage.azure.com/ --query accessToken -o tsv)
python3 -c "
import base64,json
t='$TOK'.split('.')[1]; t+='='*(-len(t)%4)
c=json.loads(base64.urlsafe_b64decode(t))
print({k:c.get(k) for k in ('aud','oid','upn','tid','scp')})"
```

### Network access

The storage firewall must admit the machine making these calls. On a default-deny account
that means a **temporary** IP rule:

```bash
curl -s ifconfig.me    # your egress IP
az storage account network-rule add -g <rg> --account-name <acct> --ip-address <your-ip>
```

Both the role and the IP rule are temporary. Track them and remove them in step 5.

### Common headers

Every call below needs:

```
-H "Authorization: Bearer $TOK"
-H "x-ms-version: 2022-11-02"
-H "x-ms-file-request-intent: backup"
```

---

## 1. Confirm access, and whether the share is really new

```bash
curl -s "https://<acct>.file.core.windows.net/<share>?restype=directory&comp=list" \
  -H "Authorization: Bearer $TOK" -H "x-ms-version: 2022-11-02" \
  -H "x-ms-file-request-intent: backup"
```

Existing directories in the listing mean the share has been used and almost certainly already
carries a root descriptor. **Do not assume an empty descriptor** — the "a new root has no
security descriptor at all" rule applies only to a genuinely new share.

## 2. Read the current root descriptor

The permission key comes back as a **response header**, not in the body:

```bash
curl -s -D /tmp/h.txt -o /dev/null \
  "https://<acct>.file.core.windows.net/<share>?restype=directory" \
  -H "Authorization: Bearer $TOK" -H "x-ms-version: 2022-11-02" \
  -H "x-ms-file-request-intent: backup"

KEY=$(grep -i x-ms-file-permission-key /tmp/h.txt | sed 's/.*: //' | tr -d '\r')

curl -s "https://<acct>.file.core.windows.net/<share>?restype=share&comp=filepermission" \
  -H "Authorization: Bearer $TOK" -H "x-ms-version: 2022-11-02" \
  -H "x-ms-file-permission-key: $KEY" -H "x-ms-file-request-intent: backup"
# -> {"permission":"O:SYG:SYD:(A;OICI;FA;;;S-1-12-1-...)S:NO_ACCESS_CONTROL"}
```

### Decode every ACE before deciding anything

A cloud-only SID is `S-1-12-1-<four little-endian uint32 words of the object GUID>`. Reverse
it to find out *which* group an ACE actually grants:

```python
import uuid
def sid_to_object_id(sid):
    w = [int(x) for x in sid.split('-')[4:]]
    return str(uuid.UUID(bytes_le=b''.join(x.to_bytes(4, 'little') for x in w)))
```

Then compare that object ID against the group holding the share-scope RBAC role:

```bash
az role assignment list \
  --scope ".../storageAccounts/<acct>/fileServices/default/fileshares/<share>" -o table
```

**If the two differ, that is your bug.** Each gate is individually valid, every diagnostic
passes, and the mount fails with an interactive credential prompt rather than access-denied.

## 3. Create the new permission, then apply its key

Build the SDDL by **adding** an ACE, preserving any existing one unless a replacement was
explicitly requested — the ACE already there may be another workflow's only access.
`OICI` = object + container inherit, `FA` = full access.

```bash
NEW='O:SYG:SYD:(A;OICI;FA;;;<existing-sid>)(A;OICI;FA;;;<new-sid>)S:NO_ACCESS_CONTROL'

# PUT share permission -> 201, new key arrives in the response header
curl -s -D /tmp/pk.txt \
  -X PUT "https://<acct>.file.core.windows.net/<share>?restype=share&comp=filepermission" \
  -H "Authorization: Bearer $TOK" -H "x-ms-version: 2022-11-02" \
  -H "x-ms-file-request-intent: backup" -H "Content-Type: application/json" \
  -d "{\"permission\":\"$NEW\"}"

NEWKEY=$(grep -i x-ms-file-permission-key /tmp/pk.txt | sed 's/.*: //' | tr -d '\r')

# PUT directory properties -> 200
curl -s -X PUT \
  "https://<acct>.file.core.windows.net/<share>?restype=directory&comp=properties" \
  -H "Authorization: Bearer $TOK" -H "x-ms-version: 2022-11-02" \
  -H "x-ms-file-request-intent: backup" \
  -H "x-ms-file-permission-key: $NEWKEY" \
  -H "x-ms-file-attributes: Directory" \
  -H "x-ms-file-creation-time: preserve" \
  -H "x-ms-file-last-write-time: preserve" \
  -H "Content-Length: 0"
```

> **`Content-Length: 0` is mandatory on that last call.** curl omits the header when there is
> no payload, and the service rejects the request with **HTTP 411 Length Required** — returned
> as a generic IIS HTML page rather than an Azure XML error, so it reads like a routing
> problem rather than a missing header.

`x-ms-file-attributes`, `x-ms-file-creation-time` and `x-ms-file-last-write-time` are all
required on the directory-properties call; `preserve` keeps the existing timestamps.

## 4. Verify by reading it back

Re-run step 2. The root's permission key should now equal `$NEWKEY`, and the SDDL should list
every ACE you intended. **The `200` from step 3 is not proof** — read the descriptor back.

## 5. Revert the temporary grants

The ACL persists independently of whatever you opened to write it. Remove all of it:

```bash
az role assignment delete --assignee <oid> \
  --role "Storage File Data Privileged Contributor" --scope ".../storageAccounts/<acct>"
az role assignment delete --assignee <oid> \
  --role "Storage File Data SMB Share Elevated Contributor" --scope ".../fileshares/<share>"
az storage account network-rule remove -g <rg> --account-name <acct> --ip-address <your-ip>
```

Then read `networkAcls` back from ARM and confirm `ipRules` is empty and `defaultAction` is
still `Deny`. A default-deny account otherwise keeps an IP rule forever.
