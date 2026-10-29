# Windows Server / Active Directory configuration

Every detection in [`/splunk`](splunk) depends on Windows actually generating these events. This
is every policy change made on `hackme.local` to produce them, applied as one GPO linked at the
domain root so it covers the DC and `DESKTOP-01` together.

## 1. Create and link the GPO

1. Open **Group Policy Management** (`gpmc.msc`).
2. Expand *Forest > Domains > hackme.local*.
3. Right-click **hackme.local > Create a GPO in this domain, and Link it here**.
4. Name it `SOC-Audit-Policy`.
5. Right-click it → **Edit**.

Linking at the domain root applies it everywhere; the Default Domain Controllers Policy only
conflicts if it sets the same subcategories, and step 3 below settles any conflict.

## 2. Advanced Audit Policy Configuration

*Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy
Configuration > Audit Policies*. For each subcategory, tick **Configure the following audit
events**, then **Success** and **Failure**:

| Category | Subcategory | Feeds |
|---|---|---|
| Account Logon | Audit Credential Validation | 4776, 4771 (spraying, NTLM) |
| Account Logon | Audit Kerberos Authentication Service | 4768 (AS-REP Roasting) |
| Account Logon | Audit Kerberos Service Ticket Operations | 4769 (Kerberoasting) |
| Account Management | Audit User Account Management | 4720 (account created) |
| Account Management | Audit Security Group Management | 4728, 4732 (group membership) |
| DS Access | Audit Directory Service Access | 4662 (DCSync) |
| DS Access | Audit Directory Service Changes | 4662 (DCSync) |
| Detailed Tracking | Audit Process Creation | 4688 |
| Logon/Logoff | Audit Logon | 4624, 4625 (Pass-the-Hash, spraying) |
| Logon/Logoff | Audit Special Logon | 4672 |
| Object Access | Audit Other Object Access Events | 4698 (scheduled task) |
| Object Access | Audit Detailed File Share | 5145 (remote hive access, PsExec) |
| Policy Change | Audit Audit Policy Change | — |

## 3. Force subcategory settings

*... > Local Policies > Security Options* → **Audit: Force audit policy subcategory settings
(Windows Vista or later) to override audit policy category settings** → **Enabled**.

Without this, legacy category-level audit settings can silently override everything in step 2.

## 4. Command-line logging

*... > Administrative Templates > System > Audit Process Creation* → **Include command line in
process creation events** → **Enabled**. Needed to see `-enc` PowerShell payloads and `schtasks`
arguments inside event 4688.

## 5. PowerShell Script Block Logging

*... > Administrative Templates > Windows Components > Windows PowerShell* → **Turn on PowerShell
Script Block Logging** → **Enabled**. Produces event 4104, used by the Encoded PowerShell
detection (T1059.001).

## 6. Bigger Security log

*... > Windows Settings > Security Settings > Event Log* → **Maximum security log size** →
`1048576` KB (1 GB). The default size is small enough that a busy attack run can overwrite
events before the Universal Forwarder ships them.

## 7. DCSync auditing (required for event 4662)

Event 4662 for replication only fires if the domain object itself has an audit entry — this is
separate from the Advanced Audit Policy above and easy to miss:

1. **Active Directory Users and Computers** → *View > Advanced Features*.
2. Right-click **hackme.local > Properties > Security > Advanced > Auditing > Add**.
3. Principal: **Everyone**. Type: **Success**. Applies to: **This object only**.
4. Tick **Replicating Directory Changes** and **Replicating Directory Changes All** → OK.

## 8. Apply and verify

On the DC and on `DESKTOP-01`, from an elevated prompt:

```powershell
gpupdate /force
auditpol /get /category:*
```

Every subcategory from step 2 should show **Success and Failure**, not "No Auditing". Confirm the
GPO actually reached each machine:

```powershell
gpresult /r /scope:computer
```

`SOC-Audit-Policy` should be listed under Applied GPOs.

## 9. Functional test

1. Log off/on as a test user on `DESKTOP-01`.
2. On the DC, Event Viewer → Windows Logs → Security → confirm **4624** and **4768/4769**.
3. In Splunk: `index=win_security | stats count by host, EventCode` — expect 4624/4769 on the DC,
   Sysmon 1/3/10/11 on both machines, and 4104 in the `powershell` index.

## Troubleshooting

| Symptom | Cause |
|---|---|
| GPO not in `gpresult` | Machine isn't domain-joined, DNS isn't pointing at the DC, or it hasn't refreshed — reboot and `gpupdate /force` again |
| `auditpol` shows "No Auditing" | Step 3 is missing, or another GPO overrides this one |
| Events missing on the endpoint | Endpoint isn't in the domain, or sits in an OU with blocked GPO inheritance |
| Events exist locally but not in Splunk | `inputs.conf` issue — see [`/splunk/inputs`](splunk/inputs) |

## Encryption-type fix for Kerberoasting (`svc_sql`)

The Kerberoasting detection (`01_kerberoasting_T1558.003.spl`) only fires reliably if the target
service account can actually be issued an RC4 ticket — the encryption type real Kerberoasting
tools request. Windows Server 2025 defaults new/clean accounts to AES, which won't trigger it.

Check the current value:

```powershell
Get-ADUser svc_sql -Properties msDS-SupportedEncryptionTypes, ServicePrincipalNames |
  Format-List Name, msDS-SupportedEncryptionTypes, ServicePrincipalNames
```

Set it to allow both RC4 and AES (`28` = RC4 + AES128 + AES256):

```powershell
Set-ADUser svc_sql -Replace @{'msDS-SupportedEncryptionTypes'=28}
```

RC4-only (`4`) is more realistic but can make the DC refuse to issue a ticket at all on a hardened
Server 2025 build (`0xE`, encryption type not supported) — use `28` unless you've also enabled RC4
under *Computer Configuration > Windows Settings > Security Settings > Local Policies > Security
Options > Network security: Configure encryption types allowed for Kerberos*. After changing the
value, purge cached tickets on the client before re-testing:

```powershell
klist purge
```

**This is a real misconfiguration, not just a lab quirk.** A Kerberoastable service account is an
account whose `msDS-SupportedEncryptionTypes` permits RC4 with a short or static password. The
production fix is the opposite of what makes this lab's detection easy to trigger: set the account
to AES-only (`Set-ADUser svc_sql -Replace @{'msDS-SupportedEncryptionTypes'=24}`), give it a long
random password or convert it to a gMSA, and keep the detection above running to catch anyone who
re-introduces a weak account later.

## Time sync

Kerberos fails outright once clock skew exceeds 5 minutes, which silently breaks attacks #1, #2
and #5 as well as the detections for them. On the DC:

```powershell
w32tm /config /syncfromflags:manual /manualpeerlist:"pool.ntp.org" /update
```
