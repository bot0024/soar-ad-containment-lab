# Tines SOAR story

The full Tines export (`.json`) isn't included because it embeds live credentials and tunnel
URLs that can't be stripped cleanly from a story export. This folder documents the story's
structure instead, so it can be rebuilt node-for-node.

## Story flow

```
Webhook
  → 10 Condition nodes (one per alert_name: Is_Kerberoasting, Is_ASREP, Is_DCSync, Is_CredDumping,
    Is_PassTheHash, Is_EncodedPS, Is_ScheduledTaskPersist, Is_PasswordSpray, Is_RogueAdmin,
    Is_PsExecLateral)
  → Is_Public_IP / Is_Private_IP   (branches on whether the alert's src_ip is internal)
  → VirusTotal_IP, AbuseIPDB_IP    (threat-intel enrichment on public IPs only)
  → Build_Dedup_Key → Search_Open_Duplicate → Is_New_Incident / Is_Duplicate
  → Create_Jira_Incident  /  Comment_On_Existing_Ticket
  → Set_Containment_Type           (formula node — see below)
  → Should_Contain → Requires_Approval
      → Request_Approval → Wait_For_Approval → Is_Approved / Is_Rejected
  → wazuh_auth → Wazuh_Auth_OK
      → Route_To_Isolate_Host → isolate_host     → Jira_Containment_Result
      → Route_To_Disable_User → wazuh_disable_user → Jira_Containment_Result
      → Route_By_Attack_Type  → block_ip          → Jira_Containment_Result
```

See [`../screenshots/02-tines-story-before-rebuild.png`](../screenshots/02-tines-story-before-rebuild.png)
for the original story (separate `Bypass_For_PTH` / `Route_To_*` regex conditions per branch) and
[`../screenshots/01-tines-story-after-rebuild.png`](../screenshots/01-tines-story-after-rebuild.png)
for the rebuilt story after the `Set_Containment_Type` lookup table replaced them.

## `Set_Containment_Type` (the formula node)

```js
containment_type = FIND(LOCAL.containment_table, LAMBDA(r, r.alert = webhook.body.result.alert_name)).type
```

`LOCAL.containment_table` is a local array of `{alert, type}` rows, one per detection:

```js
LOCAL.containment_table = [
  { alert: "Kerberoasting", type: "disable_user" },
  { alert: "AS-REP Roasting", type: "disable_user" },
  { alert: "DCSync", type: "isolate_host" },
  { alert: "LSASS/SAM Credential Dumping", type: "isolate_host" },
  { alert: "Pass-the-Hash", type: "disable_user" },
  { alert: "Suspicious Encoded/Download PowerShell", type: "isolate_host" },
  { alert: "Suspicious Scheduled Task Created", type: "disable_user" },
  { alert: "Password Spraying", type: "block_ip" },
  { alert: "Rogue Admin Account Creation", type: "disable_user" },
  { alert: "Suspicious Service Installation (Lateral Movement)", type: "isolate_host" }
]
```

Unlisted alerts default to `disable_user`. Adding a new detection to containment is one new row
in this table — no new condition nodes, no edits to existing branches.

## Rebuilding this story in your own Tines tenant

1. Create a Webhook action and a Jira resource (and Slack/VirusTotal/AbuseIPDB resources if you
   want enrichment) in your own Tines workspace.
2. Add one Event Transform (formula) node named `Set_Containment_Type` with the formula above.
3. Wire `Webhook → Set_Containment_Type → Should_Contain → Requires_Approval → three containment
   branches`, each still reporting back to its own `Jira_Containment_Result` node.
4. Point the three containment HTTP Request nodes (`wazuh_disable_user`, `block_ip`,
   `isolate_host`) at your own Wazuh API tunnel (see [`../wazuh`](../wazuh)).
