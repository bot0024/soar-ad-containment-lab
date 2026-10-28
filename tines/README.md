# Tines SOAR story

[`your-first-story.json`](your-first-story.json) is the full Tines story export, sanitized (see
[the exported story](#the-exported-story)). Import it into your own tenant, then follow
[Rebuilding / importing](#importing-it-into-your-own-tenant) to point it at your own Jira and Wazuh.

## Story flow

```
Webhook                                  (one URL, all 10 Splunk alerts)
  → 10 Condition nodes, one per alert_name
      (Is_Kerberoasting, Is_ASREP, Is_DCSync, Is_CredDumping, Is_PassTheHash,
       Is_EncodedPS, Is_ScheduledTaskPersist, Is_PasswordSpray, Is_RogueAdmin, Is_PsExecLateral)
  → Is_Public_IP / Is_Private_IP          (is the alert's src_ip internal?)
  → VirusTotal_IP → AbuseIPDB_IP          (threat-intel enrichment, public IPs only)
  → Build_Dedup_Key → Search_Open_Duplicate
      → Is_New_Incident → Create_Jira_Incident → Add Jira Comment (enrichment)
      → Is_Duplicate    → Comment_On_Existing_Ticket   (no second ticket for the same alert)
  → Set_Containment_Type                  (decision node, see below)
  → Should_Contain                        (skips protected accounts, never skips host isolation)
  → Requires_Approval
      ├─ containment_type ≠ block_ip → Request_Approval (comment on the Jira ticket)
      │     → Wait_For_Approval (60 s loop) → Get_Jira_Approval_Status
      │         → Is_Approved → Jira_Containment_Approved ─┐
      │         → Is_Rejected → Jira_Containment_Rejected   │
      │         → Still_Pending → back to Wait_For_Approval │
      │         → Approval_Timed_Out (4 h) → Jira_Approval_Timed_Out
      └─ containment_type = block_ip → straight through ────┤
                                                            ▼
  wazuh_auth → Wazuh_Auth_OK (else Jira_Wazuh_Auth_Failed)
      → Route_To_Disable_User → wazuh_disable_user ───────────────┐
      → Route_By_Attack_Type  → block_ip ─────────────────────────┤→ Jira_Containment_Result
      → Route_To_Isolate_Host → Lookup_Wazuh_Agent → Agent_Found ─┤
            → isolate_host  (else Jira_Agent_Not_Found)           ┘
```

Screenshots: [before the rebuild](../screenshots/02-tines-story-before-rebuild.png) (per-branch
regex routing), [after](../screenshots/01-tines-story-after-rebuild.png), and the
[Jira approval comment](../screenshots/05-jira-containment-approval.png).

## `Set_Containment_Type` (the decision node)

One Event Transformation node decides everything about containment, from a table kept in the
node's own `local` data (`options.local` in the export), not spread across condition nodes:

```js
containment_type = DEFAULT(
  FIND(LOCAL.containment_table, LAMBDA(r, r.alert = webhook.body.result.alert_name)).type,
  "disable_user")

protected_account = INCLUDES(LOCAL.protected_accounts,
                             DOWNCASE(DEFAULT(webhook.body.result.user, "")))

should_contain = IF(containment_type = "isolate_host", TRUE, NOT(protected_account))
```

```js
LOCAL.containment_table = [
  { alert: "Password Spraying",                                 type: "block_ip" },
  { alert: "Pass-the-Hash",                                     type: "isolate_host" },
  { alert: "LSASS/SAM Credential Dumping",                      type: "isolate_host" },
  { alert: "Suspicious Encoded/Download PowerShell",            type: "isolate_host" },
  { alert: "Suspicious Scheduled Task Created",                 type: "isolate_host" },
  { alert: "Suspicious Service Installation (Lateral Movement)", type: "isolate_host" }
]
LOCAL.protected_accounts = ["administrator", "krbtgt", "guest", "svc_sql", "svc_lab"]
```

| `alert_name` | `containment_type` |
| --- | --- |
| Password Spraying | `block_ip` |
| Pass-the-Hash, LSASS/SAM Credential Dumping, Encoded/Download PowerShell, Scheduled Task, Service Installation (PsExec) | `isolate_host` |
| Anything not in the table (Kerberoasting, AS-REP Roasting, DCSync, Rogue Privileged Account) | `disable_user` (default) |

Adding a detection to containment is one new row in `containment_table`; no new condition nodes.
Protected accounts are never disabled, but a host isolation still proceeds because it acts on the
machine, not the account.

## Safety controls in this story

- **Human approval.** Every `disable_user` and `isolate_host` waits for an analyst to move the Jira
  ticket to **Containment Approved** or **Containment Rejected**. No decision in 4 hours means no
  action. `block_ip` (password spraying from outside) skips approval.
- **Deduplication.** `Build_Dedup_Key` builds a key from alert + user + host; an open ticket with the same key
  gets a comment instead of a new ticket.
- **Dynamic agent lookup.** `Lookup_Wazuh_Agent` resolves the Wazuh agent ID from the alert's host
  name before isolating, and files a Jira note if the agent isn't found.
- **Failure reporting.** Wazuh auth failure, missing agent, rejection and timeout each write back to
  the Jira ticket instead of failing silently.
- Host-side guards live in the Wazuh scripts too ([`../wazuh`](../wazuh)).

## The exported story

`your-first-story.json` is the real export. Replaced with placeholders: the webhook secret
(`<<WEBHOOK_SECRET>>`), Jira domain (`YOUR-DOMAIN.atlassian.net`) and email (`<<YOUR_EMAIL>>`). The
`diagram_layout` and tenant-specific IDs are left as exported; Tines re-creates them on import.
Credentials and resources are referenced by name only, so create these in your tenant:

| Name | Type | Used for |
| --- | --- | --- |
| `jira_api_token` | Credential | Jira basic auth |
| `virustotal`, `abuseipdb` | Credentials | IP enrichment |
| `wazuh` | Credential | Value `Basic <base64 user:password>` for `/security/user/authenticate` |
| `wazuh_base_url` | Resource | `base_url` = your Wazuh API URL (the cloudflared tunnel, see [`../wazuh`](../wazuh)) |

## Importing it into your own tenant

1. Tines → Stories → Import, choose `your-first-story.json`.
2. Create the credentials and the resource in the table above.
3. In the Webhook action, set your own secret and copy its URL into the Splunk alert actions.
4. Replace `YOUR-DOMAIN.atlassian.net` and `<<YOUR_EMAIL>>` in the Jira nodes; the Jira project key
   is `SOC`, and its workflow needs the statuses **Containment Approved** and
   **Containment Rejected**.
5. `wazuh_disable_user` and `block_ip` target agent `001` (the domain controller); change it to
   match `agent_control -l` on your Wazuh manager.
