# Build guide: step by step

This walks through building the whole lab from an empty hypervisor to all 10 detections
containing automatically. It assumes no prior Splunk/Tines/Wazuh experience. Where a step has its
own detailed doc, this guide links to it instead of repeating it.

**Time estimate:** a weekend for someone new to all three tools; a few hours if you already know
Splunk and Active Directory.

## What you'll have at the end

Five VMs on one private network, a real AD domain, centralized logging, 10 working detections,
and a SOAR pipeline that opens a Jira ticket and (after approval) disables an account, blocks an
IP, or isolates a host — automatically, based on what fired.

## Prerequisites

- A hypervisor with one isolated virtual network (this lab used VirtualBox + a NAT Network,
  `10.0.0.0/24`). Don't bridge this network to your real LAN.
- ISOs: Windows Server 2025, Windows 10, a Linux distro for Splunk/Wazuh (Ubuntu Server works),
  Kali Linux.
- Accounts: a free [Tines](https://www.tines.com/) tenant, a free
  [Jira Cloud](https://www.atlassian.com/software/jira) project, a
  [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) dev license.
- ~10 GB RAM and 150 GB disk free across the VMs is comfortable.

## Step 1 — Build the network and VMs

1. Create one isolated virtual network (`10.0.0.0/24` in this lab). Reserve a DHCP range
   (`10.0.0.20`–`10.0.0.100` here) and give every VM a static or static-reserved address outside
   it. This lab used:

   | Host | IP | Role |
   | --- | --- | --- |
   | DC01 | `10.0.0.10` | Windows Server 2025, domain controller for `hackme.local` |
   | DESKTOP-01 | `10.0.0.4` | Windows 10 endpoint, domain-joined |
   | Kali | `10.0.0.8` | Attack box |
   | Splunk | — | Linux VM running Splunk Enterprise |
   | Wazuh | `10.0.0.9` | Linux VM running the Wazuh manager |

2. Install all five VMs with their OS, attached only to the isolated network.
3. Set every VM's DNS to point at the future DC's IP (`10.0.0.10`) once step 2 is done — AD and
   Splunk forwarding both depend on working internal DNS.

## Step 2 — Stand up Active Directory

1. On the server VM, `Install-WindowsFeature AD-Domain-Services` then promote it to a new forest
   (e.g. `hackme.local`) with `Install-ADDSForest`.
2. Join the Windows 10 VM to the domain (**System > About > Domain or workgroup**), reboot, and
   log in with a domain account.
3. Create the accounts this lab's detections and attacks use: an ordinary domain user, and a
   service account with an SPN (used by the Kerberoasting detection — see
   [`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md) for the exact encryption-type setting it
   needs).
4. Sync time on the DC (`w32tm`) — Kerberos breaks past 5 minutes of clock skew. Details in
   [`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md).

## Step 3 — Turn on the logging Windows needs

Apply the GPO audit policy, PowerShell Script Block Logging, command-line logging, the bigger
Security log, and the DCSync auditing entry on the domain object. This is the single most
important step — every detection downstream depends on it, and it's easy to get partially right
and not notice until a detection silently never fires.

Full steps, exact subcategories, and the verification commands (`auditpol`, `gpresult`):
**[`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md)**.

Then install Sysmon on both the DC and the endpoint, using Olaf Hartong's
[`sysmon-modular`](https://github.com/olafhartong/sysmon-modular) config (covers LSASS access,
needed for the credential-dumping detection):

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

## Step 4 — Stand up Splunk and ship logs to it

1. Install Splunk Enterprise on its own Linux VM; enable receiving on port 9997
   (**Settings > Forwarding and receiving > Configure receiving**).
2. Create four indexes: `win_security`, `sysmon`, `powershell`, `wazuh`.
3. Install the **Splunk Add-on for Sysmon** and the **Splunk Add-on for Microsoft Windows** on the
   Splunk server (improves field extraction for the raw events).
4. On both DC01 and DESKTOP-01, install the **Splunk Universal Forwarder**, then drop in the
   matching `inputs.conf` from [`/splunk/inputs`](splunk/inputs) (rename to `inputs.conf`, place
   at `C:\Program Files\SplunkUniversalForwarder\etc\system\local\`), and point it at the Splunk
   server: `splunk add forward-server <splunk-ip>:9997`. Restart the forwarder service.
5. Verify events are arriving before moving on:
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

1. Install the Wazuh manager on its Linux VM and enroll both DC01 and DESKTOP-01 as agents
   (`/var/ossec/bin/manage_agents` on the manager, the agent installer on each Windows host).
   Confirm both show **Active** with `/var/ossec/bin/agent_control -l`.
2. Copy the six files in [`/wazuh/active-response`](wazuh/active-response) onto the agent that
   runs each one (DC01 for `disable-ad-user` and `block-ip`, DESKTOP-01 for `isolate-host`) at
   `C:\Program Files (x86)\ossec-agent\active-response\bin\`, then restart the Wazuh agent
   service.
3. Expose the Wazuh API (port 55000) to Tines without opening an inbound port on your network, by
   running a tunnel from the Wazuh VM:
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

## Done

At this point you have the same pipeline this repo documents: 10 real attacks, 10 hand-written
detections, one decision node routing all of them to the right containment action behind a human
approval gate, and a Jira ticket as the record of everything that happened. The full write-up,
with architecture, test results and lessons learned, is in [`/docs`](docs).
