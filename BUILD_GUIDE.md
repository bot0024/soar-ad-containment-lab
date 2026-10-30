# Build guide: step by step

This walks through building the whole lab from a blank hypervisor — installing every VM's OS —
through to all 10 detections containing automatically. It assumes no prior Splunk/Tines/Wazuh
experience.

**Time estimate:** a weekend for someone new to all three tools; a few hours if you already know
Splunk and Active Directory.

## What you'll have at the end

Five VMs on one private network, a real AD domain, centralized logging, 10 working detections,
and a SOAR pipeline that opens a Jira ticket and (after approval) disables an account, blocks an
IP, or isolates a host — automatically, based on what fired.

## Prerequisites

- [VirtualBox](https://www.virtualbox.org/) (this guide uses it; any hypervisor works the same
  way in principle).
- ISOs: Windows Server 2025, Windows 10, [Ubuntu Server](https://ubuntu.com/download/server) (for
  Splunk only), [Kali Linux](https://www.kali.org/get-kali/).
- The official [Wazuh virtual machine (OVA)](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html)
  — this lab imported the ready-built Wazuh appliance rather than installing the manager by hand
  on a generic Linux VM.
- Accounts: a free [Tines](https://www.tines.com/) tenant, a free
  [Jira Cloud](https://www.atlassian.com/software/jira) project, a
  [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) dev license.
- ~10 GB RAM and 150 GB disk free across the VMs is comfortable.

## Step 0 — Create the isolated network

Everything in this lab sits on one private network with no route to your real LAN or the
internet, except Wazuh's one outbound tunnel (step 7).

1. Open **VirtualBox Manager** → **Tools > Network Manager** (or **File > Tools > Network
   Manager** on older versions) → **NAT Networks** tab → **Create**.
2. Set the network to `10.0.0.0/24`. Leave **Enable DHCP** on — this lab reserved
   `10.0.0.20`–`10.0.0.100` for DHCP and used static addresses outside that range for every VM.
3. Note the network's name (e.g. `NatNetwork`) — every VM you create below gets its Adapter 1 set
   to **Attached to: NAT Network**, **Name:** this same network. Getting this wrong on even one
   VM is the single most common cause of "nothing can reach anything" later.

This lab's addressing:

| Host | IP | Role |
| --- | --- | --- |
| DC01 | `10.0.0.10` | Windows Server 2025, domain controller for `hackme.local` |
| DESKTOP-01 | `10.0.0.4` | Windows 10 endpoint, domain-joined |
| Kali | `10.0.0.8` | Attack box |
| Splunk | `10.0.0.7` | Ubuntu Server running Splunk Enterprise |
| Wazuh | `10.0.0.9` | Official Wazuh OVA appliance |

## Step 1 — Create and install the VMs

Repeat **New VM** in VirtualBox for each machine below, attach its ISO, and install the OS with
defaults unless noted. Attach **Adapter 1** of every VM to the NAT Network from step 0 before
first boot.

### 1a. DC01 — Windows Server 2025

1. **New** → Name `DC01`, Type Microsoft Windows, Version Windows Server 2025 (64-bit).
2. 4 GB+ RAM, 2 CPUs, 60 GB disk (dynamically allocated is fine).
3. Attach the Windows Server 2025 ISO, start the VM, and install **Windows Server 2025 (Desktop
   Experience)** — the Desktop Experience edition gives you a GUI for `dcpromo`/AD tools, much
   easier for a lab than Server Core.
4. After install: set a static IP (`10.0.0.10`, gateway `10.0.0.1`, DNS `127.0.0.1` for now — it
   becomes its own DNS server once promoted to a DC), rename the computer to `DC01`, and reboot.

### 1b. DESKTOP-01 — Windows 10

1. **New** → Name `DESKTOP-01`, Type Microsoft Windows, Version Windows 10 (64-bit).
2. 4 GB RAM, 2 CPUs, 50 GB disk.
3. Attach the Windows 10 ISO and install normally (local account is fine for now — it gets
   domain-joined in step 2).
4. Rename the computer to `DESKTOP-01`. DNS gets pointed at the DC once it exists (step 1d).

### 1c. Kali — attack box

1. **New** → Name `Kali`, Type Linux, Version Debian (64-bit).
2. 2 GB RAM, 2 CPUs, 40 GB disk.
3. Attach the Kali ISO (the installer image, not the live image, if you want it to persist) and
   install with defaults.
4. Set a static IP `10.0.0.8` once installed (`/etc/network/interfaces` or your desktop's network
   settings, depending on which Kali image you used), or just let DHCP assign one and note
   whatever it gets — Kali's address isn't referenced by anything else in this lab, unlike the
   servers.

### 1d. Splunk — Ubuntu Server

1. **New** → Name `Splunk`, Type Linux, Version Ubuntu (64-bit).
2. 4 GB+ RAM, 2 CPUs, 40 GB disk.
3. Attach the Ubuntu Server ISO and install with defaults (OpenSSH server selected is convenient).
4. Set a static IP, `10.0.0.7`, either in the installer's network step or afterwards via netplan.
5. This VM runs **Splunk only** — Wazuh is a separate, pre-built appliance (next step), not
   installed here.

### 1e. Wazuh — official OVA appliance

Unlike the other Linux VM, Wazuh here is **imported**, not installed from an ISO:

1. **File > Import Appliance**, select the downloaded Wazuh `.ova` file.
2. Rename it `Wazuh` in the import settings, and set its network adapter to the same NAT Network
   as everything else before finishing the import.
3. Boot it. Log in with the credentials the appliance's first-boot screen/documentation gives you,
   and change the default password immediately.
4. Set a static IP, `10.0.0.9`.
5. The appliance comes with the Wazuh manager, indexer, and dashboard already running — there's no
   separate "install wazuh-manager" step here, which is the main difference from a manual install
   on a generic Linux VM.

### Set DNS once DC01 exists

After DC01 is promoted to a domain controller (next step), go back and point **every other VM's**
DNS at `10.0.0.10` (Kali, Splunk and Wazuh via their network config; DESKTOP-01 gets this
automatically when it joins the domain). AD and Splunk's internal name resolution both depend on
this.

## Step 2 — Stand up Active Directory

On **DC01**:

1. Server Manager → **Add Roles and Features** → **Active Directory Domain Services** → install.
2. Click the notification flag → **Promote this server to a domain controller** → **Add a new
   forest** → root domain name `hackme.local`.
3. Accept the defaults for forest/domain functional level, leave DNS server checked, set a
   Directory Services Restore Mode (DSRM) password, finish the wizard, and let it reboot.
4. On **DESKTOP-01**: **Settings > System > About > Domain or workgroup** (or
   `System Properties > Computer Name > Change`) → join domain `hackme.local` → reboot → log in
   with a domain account.
5. **Create the four accounts this lab's attacks and detections use.** In **Active Directory
   Users and Computers** on DC01 (or PowerShell, below), create them in the default `Users`
   container:

   | Account | Type | Used for |
   | --- | --- | --- |
   | `lab_dip` | Ordinary domain user | The "attacker-controlled" identity for most attacks — this lab made it a Domain Admin so it also has the rights attack #9 needs (creating users, adding to Domain Admins); don't do this outside an isolated lab |
   | `svc_sql` | Service account | Target of the Kerberoasting detection — needs an SPN and a specific encryption-type setting |
   | `svc_lab` | Service account | Target of the DCSync detection — needs directory-replication rights delegated to it |
   | `Administrator` | Built-in | Target of the Pass-the-Hash attack — no setup needed, it already exists |

   PowerShell, run on DC01:

   ```powershell
   # ordinary attacker-controlled user, made a Domain Admin for lab convenience
   New-ADUser -Name "lab_dip" -SamAccountName "lab_dip" -AccountPassword (Read-Host -AsSecureString "Password") -Enabled $true
   Add-ADGroupMember -Identity "Domain Admins" -Members "lab_dip"

   # service accounts
   New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" -AccountPassword (Read-Host -AsSecureString "Password") -Enabled $true
   New-ADUser -Name "svc_lab" -SamAccountName "svc_lab" -AccountPassword (Read-Host -AsSecureString "Password") -Enabled $true
   ```

   Give `svc_sql` an SPN (makes it Kerberoastable) and the encryption types the attack/detection
   pair needs — full explanation in
   [`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md#encryption-type-fix-for-kerberoasting-svc_sql):

   ```powershell
   setspn -A HTTP/sql.hackme.local svc_sql
   Set-ADUser svc_sql -Replace @{'msDS-SupportedEncryptionTypes'=28}
   ```

   Delegate directory-replication rights to `svc_lab` (required for the DCSync attack and the
   4662 event the detection looks for) — **Active Directory Users and Computers** → *View >
   Advanced Features* → right-click **hackme.local > Properties > Security > Add** → add
   `svc_lab` → tick **Replicating Directory Changes** and **Replicating Directory Changes All**
   under Allow. (This is the same auditing dialog used in
   [`WINDOWS-AUDIT-POLICY.md` step 7](WINDOWS-AUDIT-POLICY.md#7-dcsync-auditing-required-for-event-4662)
   — here you're granting the *permission*, there you're adding the *audit entry* that logs its
   use; both go on the same object.)

6. Sync time on the DC (`w32tm`) — Kerberos breaks past 5 minutes of clock skew. Details in
   [`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md).

## Step 3 — Turn on the logging Windows needs

Apply the GPO audit policy, PowerShell Script Block Logging, command-line logging, the bigger
Security log, and the DCSync auditing entry on the domain object. This is the single most
important step — every detection downstream depends on it, and it's easy to get partially right
and not notice until a detection silently never fires.

Full steps, exact subcategories, and the verification commands (`auditpol`, `gpresult`):
**[`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md)**.

Then install Sysmon on both DC01 and DESKTOP-01, using Olaf Hartong's
[`sysmon-modular`](https://github.com/olafhartong/sysmon-modular) config (covers LSASS access,
needed for the credential-dumping detection):

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

## Step 4 — Stand up Splunk and ship logs to it

On the **Splunk** (Ubuntu) VM:

1. Download the Splunk Enterprise `.deb` and install it:
   ```bash
   sudo dpkg -i splunk-*.deb
   sudo /opt/splunk/bin/splunk start --accept-license
   ```
2. Enable receiving on port 9997: Splunk web UI → **Settings > Forwarding and receiving >
   Configure receiving > New Receiving Port** → `9997`.
3. Create four indexes (**Settings > Indexes > New Index**): `win_security`, `sysmon`,
   `powershell`, `wazuh`.
4. Install the **Splunk Add-on for Sysmon** and the **Splunk Add-on for Microsoft Windows** from
   Splunkbase (improves field extraction for the raw events).

On **both DC01 and DESKTOP-01**:

5. Install the **Splunk Universal Forwarder**, then drop in the matching `inputs.conf` from
   [`/splunk/inputs`](splunk/inputs) (rename to `inputs.conf`, place at
   `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`), and point it at the Splunk
   server:
   ```
   & "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" add forward-server 10.0.0.7:9997
   ```
   Restart the `SplunkForwarder` service.

6. Verify events are arriving before moving on (search these in Splunk web):
   ```spl
   index=win_security | stats count by host, EventCode
   index=sysmon       | stats count by host, EventCode
   index=powershell EventCode=4104 | stats count by host
   ```
   You should see 4624/4768/4769 on the DC, Sysmon events on both hosts, and 4104 events. Debug
   this now — chasing a missing detection on top of missing logs wastes far more time.

## Step 5 — Create the 10 detections

Create one scheduled Splunk saved search per technique using the queries in
[`/splunk`](splunk). For each one:

- **Schedule:** every 5 minutes (`*/5 * * * *`), searching the last 5 minutes.
- **Trigger:** once per result; throttle by the relevant field (e.g. `user`) for 10–15 minutes so
  one ongoing attack doesn't open dozens of duplicate tickets.
- **Alert action:** Webhook, pointed at your Tines story's webhook URL (you'll get this URL in
  step 6 — come back and fill it in once the story exists). Splunk posts the search results as
  JSON under `result`.

Each search already outputs the same normalized schema (`alert_name`, `mitre_id`, `severity`,
`user`, `host`, `src_ip`, `event_time`) — that consistency is what lets one Tines story handle all
10 without per-alert branching logic downstream of the webhook.

## Step 6 — Build the Tines story

Fastest path: import the finished story and adjust it to your tenant, rather than building node
by node.

1. In Tines, **Import** [`tines/your-first-story.json`](tines/your-first-story.json).
2. Create the credentials and resource it references — see the table in
   [`tines/README.md`](tines/README.md#the-exported-story): a Jira API token credential, a Wazuh
   basic-auth credential, VirusTotal/AbuseIPDB credentials for IP enrichment, and a `wazuh_base_url`
   resource pointing at your Wazuh API tunnel (built in step 7).
3. Set your own webhook secret on the Webhook node, and update the Jira domain/email placeholders
   in the Jira nodes. Your Jira project needs a `SOC` key (or edit the nodes to match yours) and
   two extra workflow statuses: **Containment Approved** and **Containment Rejected**.
4. Copy the Webhook's URL back into each Splunk alert action from step 5.
5. Full explanation of the story's logic — the `Set_Containment_Type` decision table, the approval
   gate, deduplication, and the dynamic Wazuh agent lookup — is in
   [`tines/README.md`](tines/README.md).

## Step 7 — Wire up Wazuh for containment

On the **Wazuh** appliance (via its dashboard or SSH):

1. Enroll DC01 and DESKTOP-01 as agents: in the Wazuh dashboard, **Agents > Deploy new agent**,
   pick Windows, copy the generated `agent-auth`/install one-liner, and run it on each Windows
   host. Confirm both show **Active** with `sudo /var/ossec/bin/agent_control -l` on the appliance.
2. Copy the six files in [`/wazuh/active-response`](wazuh/active-response) onto the agent that
   runs each one (DC01 for `disable-ad-user` and `block-ip`, DESKTOP-01 for `isolate-host`) at
   `C:\Program Files (x86)\ossec-agent\active-response\bin\`, then restart the Wazuh agent
   service.
3. Expose the Wazuh API (port 55000) to Tines without opening an inbound port on your network, by
   running a tunnel from the Wazuh appliance:
   ```bash
   cloudflared tunnel --url https://localhost:55000 --no-tls-verify
   ```
   Put the tunnel URL into the `wazuh_base_url` resource in Tines from step 6.
4. Full flow, the containment-type → command/agent mapping, and rollback commands:
   [`wazuh/README.md`](wazuh/README.md).

## Step 8 — Attack and verify

Run each technique from Kali (exact commands in [`ATTACKS.md`](ATTACKS.md)) and confirm, for each
one:

1. The Splunk search fires within 5 minutes.
2. A Jira ticket opens (or an existing one gets a comment, if you fire the same alert twice —
   that's the dedup logic working).
3. For `disable_user`/`isolate_host`: approve the ticket and confirm the action actually runs
   (check `active-responses.log` on the agent, or the account/firewall state in AD/Windows).
4. For `block_ip`: confirm it runs without waiting for approval.

Clean up between runs — see [`wazuh/README.md`](wazuh/README.md#rollback--cleanup) to re-enable
accounts and remove firewall rules, and remove any test accounts you created.

## Troubleshooting the network

Almost every "nothing works" problem in a lab like this traces back to one VM's network adapter.
If a host can't reach another:

- VirtualBox Manager → the VM → **Settings > Network > Adapter 1** → confirm **Enabled**,
  **Attached to: NAT Network**, and **Name** matches the exact same NAT Network every other VM
  uses (not plain `NAT`, which is per-VM isolated, and not `Bridged Adapter`).
- From the host machine (not inside any VM): `VBoxManage natnetwork list <name> -i` to confirm the
  NAT Network's built-in DHCP is actually running.
- Inside the VM: confirm its actual IP (`ipconfig` / `ip a`) matches what you expect — NAT Network
  DHCP can reassign addresses across reboots if you didn't set static ones.

## Done

At this point you have the same pipeline this repo documents: 10 real attacks, 10 hand-written
detections, one decision node routing all of them to the right containment action behind a human
approval gate, and a Jira ticket as the record of everything that happened. The full write-up,
with architecture, test results and lessons learned, is in [`/docs`](docs).
