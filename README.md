# SOAR + AD Attack Detection Lab

A home SOC lab: a real Active Directory domain is attacked with ten MITRE ATT&CK techniques,
detected by hand-written Splunk searches, and automatically contained through a Tines SOAR
pipeline wired to Wazuh active response. Full write-up: [`/docs`](docs).

![Architecture and network diagram](docs/architecture-network-diagram.png)

## What's in here

| Folder | Contents |
| --- | --- |
| [`/docs`](docs) | The full lab report (PDF) and the architecture/network diagram |
| [`ATTACKS.md`](ATTACKS.md) | The Kali Linux command used for each of the 10 attacks |
| [`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md) | The GPO audit policy, PowerShell logging and DCSync auditing config each detection depends on |
| [`BUILD_GUIDE.md`](BUILD_GUIDE.md) | Full step-by-step guide: build the entire lab from an empty hypervisor to all 10 detections containing automatically |
| [`/splunk`](splunk) | The final Splunk search (`.spl`) for each of the 10 detections, plus the Universal Forwarder `inputs.conf` files ([`/splunk/inputs`](splunk/inputs)) |
| [`/tines`](tines) | The Tines story structure, the `Set_Containment_Type` decision node, the sanitized story export, and before/after screenshots of the routing rebuild |
| [`/wazuh`](wazuh) | The Wazuh active-response scripts ([`/wazuh/active-response`](wazuh/active-response): `disable-ad-user`, `block-ip`, `isolate-host`) and how the API flow is wired |
| [`/screenshots`](screenshots) | Proof-of-work: the Tines story, Splunk detection results, and the Jira tickets it opened |
| [`/prototype`](prototype) | An early HTTP-listener containment prototype, superseded by the Wazuh scripts (reference only) |

## Architecture

| Layer | Component | Role |
| --- | --- | --- |
| Attack | Kali Linux (`10.0.0.8`) | Runs all 10 attacks (Impacket, mostly) against the domain |
| Targets | Windows Server 2025 DC — `hackme.local` (`10.0.0.10`) · Windows 10 `DESKTOP-01` (`10.0.0.4`) | Generate Security, Sysmon, PowerShell logs |
| Collection | Splunk Universal Forwarder on the DC and endpoint (`inputs.conf` in [`/splunk/inputs`](splunk/inputs)) + Sysmon (Olaf's modular config) | Ships Security, Sysmon and PowerShell logs into Splunk |
| Detection | Splunk Enterprise, indexes `win_security` / `sysmon` / `powershell` / `wazuh` | One scheduled search per technique, each posting a normalized alert to a webhook |
| Orchestration | Tines | Classifies the alert, opens/dedupes a Jira incident, decides containment in one decision node (`Set_Containment_Type`), with Jira-based approval and dedup |
| Containment | Wazuh active response (`10.0.0.9`), reached over a `cloudflared` tunnel | Executes `disable_user`, `block_ip`, or `isolate_host` |

Every VM (DC, endpoint, Kali, Splunk, Wazuh) sits on one isolated VirtualBox NAT network, `10.0.0.0/24` — this lab was
never exposed to a real network.

## The 10 techniques

Names match the saved searches exactly as they're titled in Splunk (**SOC - \<name\>**), all scheduled `*/5 * * * *`:

The exact Kali Linux command used for each attack is in [`ATTACKS.md`](ATTACKS.md).

| # | Splunk saved search | MITRE ID | Detection | Containment |
| --- | --- | --- | --- | --- |
| 1 | SOC - Kerberoasting | T1558.003 | [`splunk/01_kerberoasting_T1558.003.spl`](splunk/01_kerberoasting_T1558.003.spl) | `disable_user` |
| 2 | SOC - AS-REP Roasting | T1558.004 | [`splunk/02_asrep_roasting_T1558.004.spl`](splunk/02_asrep_roasting_T1558.004.spl) | `disable_user` |
| 3 | SOC - DCSync | T1003.006 | [`splunk/03_dcsync_T1003.006.spl`](splunk/03_dcsync_T1003.006.spl) | `disable_user` |
| 4 | SOC - Credential Dumping via Remote Registry | T1003.002 | [`splunk/04_credential_dumping_remote_registry_T1003.002.spl`](splunk/04_credential_dumping_remote_registry_T1003.002.spl) | `isolate_host` |
| 5 | SOC - Pass-the-Hash | T1550.002 | [`splunk/05_pass_the_hash_T1550.002.spl`](splunk/05_pass_the_hash_T1550.002.spl) | `isolate_host` |
| 6 | SOC - Encoded PowerShell Execution | T1059.001 | [`splunk/06_encoded_powershell_execution_T1059.001.spl`](splunk/06_encoded_powershell_execution_T1059.001.spl) | `isolate_host` |
| 7 | SOC - Scheduled Task Persistence | T1053.005 | [`splunk/07_scheduled_task_persistence_T1053.005.spl`](splunk/07_scheduled_task_persistence_T1053.005.spl) | `isolate_host` |
| 8 | SOC - Password Spraying | T1110.003 | [`splunk/08_password_spraying_T1110.003.spl`](splunk/08_password_spraying_T1110.003.spl) | `block_ip` |
| 9 | SOC - Rogue Privileged Account Creation | T1136.002 | [`splunk/09_rogue_privileged_account_creation_T1136.002.spl`](splunk/09_rogue_privileged_account_creation_T1136.002.spl) | `disable_user` |
| 10 | SOC - Lateral Movement via PsExec | T1021.002 | [`splunk/10_psexec_lateral_movement_T1021.002.spl`](splunk/10_psexec_lateral_movement_T1021.002.spl) | `isolate_host` |

Every search posts a normalized JSON payload to the same Tines webhook (`alert_name`,
`mitre_id`, `severity`, `user`, `host`, `src_ip`, `event_time`) — that shared schema is what
lets one decision node route all ten.

## The engineering story: regex lists → one decision node

The first version of the Tines story routed containment with a separate regex condition per
branch — adding an 11th detection meant editing several condition nodes and hoping none were
missed:

![Tines story before the rebuild](screenshots/02-tines-story-before-rebuild.png)

That was replaced with a single decision node, `Set_Containment_Type`, holding one table
(`alert_name → containment_type`) plus the list of protected accounts. Adding a detection to
containment now means adding one row in one place. See [`/tines`](tines) for the full
before/after, the node's formula and tables, and the sanitized story export. The same story also
gained human approval via Jira, duplicate-ticket detection and automatic Wazuh agent lookup.

![Tines story after the rebuild](screenshots/01-tines-story-after-rebuild.png)

The rebuild was verified with three live, end-to-end tests — real alerts through the real
pipeline, not synthetic Tines test events — covering all three containment types
(`disable_user`, `block_ip`, `isolate_host`). Full results in the report.

## Proof of work

| | |
| --- | --- |
| ![Splunk PsExec detection](screenshots/03-splunk-psexec-detection.png) | Splunk result: the PsExec lateral-movement detection firing on a real service-install event |
| ![Jira Kerberoasting alert](screenshots/04-jira-kerberoasting-alert.png) | The Jira incident Tines opened automatically for a Kerberoasting alert |
| ![Jira containment approval](screenshots/05-jira-containment-approval.png) | SOAR approval workflow: containment proposed, approved, and executed, all logged as Jira comments |
| ![Registry: HKLM hives](screenshots/06-registry-hklm-hives.png) / ![SAM hive access](screenshots/07-registry-sam-hive-access.png) | Evidence of the SAM/registry credential-dumping technique on the endpoint |
| ![Domain join](screenshots/08-domain-join-hackme-local.png) | `DESKTOP-01` joined to `hackme.local` |

## Build it yourself

**[`BUILD_GUIDE.md`](BUILD_GUIDE.md) has the full step-by-step walkthrough** — network/VM setup,
Active Directory, the Windows audit policy, Splunk, the Tines story, Wazuh, and end-to-end
testing. Short version:

### Prerequisites

- VirtualBox (or any hypervisor) with one isolated NAT Network shared by every VM
- Windows Server 2025 (Domain Controller) and Windows 10 (endpoint) ISOs
- Kali Linux (attack box)
- Splunk Enterprise (free dev license is enough)
- A Wazuh server (Linux) + `cloudflared`
- A Tines account (the free tier works)
- A Jira Cloud project (or swap in another ticketing tool)

### Steps

1. Stand up the domain and the network — [`BUILD_GUIDE.md` step 1–2](BUILD_GUIDE.md#step-1--build-the-network-and-vms).
2. Turn on logging: GPO audit policy, PowerShell logging, Sysmon — [`WINDOWS-AUDIT-POLICY.md`](WINDOWS-AUDIT-POLICY.md).
3. Stand up Splunk, ship logs with the Universal Forwarder — [`/splunk/inputs`](splunk/inputs).
4. Add the 10 detections — [`/splunk`](splunk).
5. Build the Tines story by importing [`tines/your-first-story.json`](tines/your-first-story.json) — [`/tines`](tines).
6. Wire Wazuh active response behind a `cloudflared` tunnel — [`/wazuh`](wazuh).
7. Attack from Kali and verify — [`ATTACKS.md`](ATTACKS.md).

### A note on secrets

Nothing in this repo contains live credentials, API keys, or the `cloudflared` tunnel URL — all
of those are placeholders (`<<WEBHOOK_SECRET>>`, `YOUR-TUNNEL.trycloudflare.com`,
`YOUR-DOMAIN.atlassian.net`, etc.). If you're adapting this for your own lab, generate your own
Tines/Jira/Wazuh credentials; nothing here is reusable as-is, which is the point.

## Full write-up

The complete report — architecture, all 10 detections, the routing rebuild in detail, test
results, and lessons learned — is in [`/docs`](docs) as a PDF. A narrative version will be published on Medium (link added here once it's live).

## License

[MIT](LICENSE) — copy, adapt, and build your own version of this lab.
