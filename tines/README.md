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
for the rebuilt story after the `Set_Containment_Type` formula consolidated them.

## `Set_Containment_Type` (the formula node)

The exported story ([`your-first-story.json`](your-first-story.json)) implements it as one
Event Transformation node with a single nested `IF()` formula:

```
containment_type = IF(alert_name = "Password Spraying", "block_ip",
  IF(alert_name = "Pass-the-Hash"
     || alert_name = "LSASS/SAM Credential Dumping"
     || alert_name = "Suspicious Encoded/Download PowerShell"
     || alert_name = "Suspicious Scheduled Task Created"
     || alert_name = "Suspicious Service Installation (Lateral Movement)",
   "isolate_host",
   "disable_user"))
```

Resulting mapping (alert names are the exact `alert_name` strings the Splunk searches emit):

| `alert_name` | `containment_type` |
| --- | --- |
| Password Spraying | `block_ip` |
| Pass-the-Hash, LSASS/SAM Credential Dumping, Suspicious Encoded/Download PowerShell, Suspicious Scheduled Task Created, Suspicious Service Installation (Lateral Movement) | `isolate_host` |
| Everything else (Kerberoasting, AS-REP Roasting, DCSync, Rogue Privileged Account Creation) | `disable_user` (default) |

Anything not named explicitly falls through to `disable_user`, so a new detection that should
disable the user needs no change at all; one that needs a different action is a one-line edit to
this single formula instead of edits across several condition nodes.

## The exported story

[`your-first-story.json`](your-first-story.json) is the real Tines export, sanitized: the webhook
secret, `cloudflared` tunnel URL, Wazuh basic-auth value, Jira domain/email and Tines tenant URL
are replaced with `<<PLACEHOLDERS>>` / `YOUR-...` values, and the long `diagram_layout` string was
dropped (Tines re-lays out the nodes on import). Secrets that were already Tines credential
references (`<<CREDENTIAL.jira_api_token>>`, `<<CREDENTIAL.virustotal>>`,
`<<CREDENTIAL.abuseipdb>>`) are untouched — create credentials with those names in your own
tenant. Note that this snapshot still contains the original per-branch routing conditions
(`Route_To_Isolate_Host`, `Bypass_For_PTH`, ...) alongside `Set_Containment_Type`.

## Rebuilding this story in your own Tines tenant

1. Create a Webhook action and a Jira resource (and Slack/VirusTotal/AbuseIPDB resources if you
   want enrichment) in your own Tines workspace.
2. Add one Event Transform (formula) node named `Set_Containment_Type` with the formula above.
3. Wire `Webhook → Set_Containment_Type → Should_Contain → Requires_Approval → three containment
   branches`, each still reporting back to its own `Jira_Containment_Result` node.
4. Point the three containment HTTP Request nodes (`wazuh_disable_user`, `block_ip`,
   `isolate_host`) at your own Wazuh API tunnel (see [`../wazuh`](../wazuh)).
