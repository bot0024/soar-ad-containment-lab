# Wazuh active response

Wazuh runs on its own Linux VM (`10.0.0.9`) and exposes the Wazuh API behind a
[`cloudflared`](https://github.com/cloudflare/cloudflared) tunnel, so Tines (a cloud SaaS) can
reach it without opening any inbound port on the lab network:

```bash
cloudflared tunnel --url https://localhost:55000 --no-tls-verify
```

Tines authenticates against the Wazuh API (`PUT /active-response`) and calls one of three
active-response commands, resolved per-alert by the `Set_Containment_Type` lookup table in the
Tines story (see [`/tines`](../tines)):

| Containment type | What it runs | Where |
| --- | --- | --- |
| `disable_user` | `disable-ad-user.cmd` — disables the AD account named in the alert | Domain Controller |
| `block_ip` | A Windows Firewall block rule for the alert's source IP | Domain Controller / endpoint |
| `isolate_host` | `isolate-host.ps1` — drops a host-isolation firewall rule that blocks all outbound/inbound traffic except to the DC and Wazuh manager | Endpoint |

## Example request shape

This is the shape of the HTTP request Tines sends (values are placeholders — see the root
README's sanitization note):

```json
{
  "url": "https://YOUR-TUNNEL.trycloudflare.com/active-response?agents_list=001",
  "content_type": "json",
  "method": "put",
  "payload": {
    "command": "disable-ad-user0",
    "arguments": ["<<webhook.body.result.user>>"]
  },
  "headers": {
    "Authorization": "Bearer <<WAZUH_API_TOKEN>>"
  }
}
```

## Rollback / cleanup

Several attacks leave state that needs manual cleanup between test runs:

```powershell
# re-enable an account disabled by disable_user
Enable-ADAccount -Identity <account>

# remove isolate_host / block_ip firewall rules
Get-NetFirewallRule -DisplayName "SOC-Isolate*" | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName "SOC-Block-*" | Remove-NetFirewallRule
```

Only run the rollback for the account/rule the specific attack actually touched — see the main
report (`/docs`) for a note on why blindly re-running cleanup on every attack is a mistake.
