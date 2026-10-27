# Wazuh active response

Wazuh runs on its own Linux VM (`10.0.0.9`) and exposes the Wazuh API behind a
[`cloudflared`](https://github.com/cloudflare/cloudflared) tunnel, so Tines (a cloud SaaS) can
reach it without opening any inbound port on the lab network:

```bash
cloudflared tunnel --url https://localhost:55000 --no-tls-verify
```

## Flow

1. `wazuh_auth` (Tines) — `POST /user/authenticate` with HTTP Basic auth returns a JWT.
2. One of three containment nodes calls `PUT /active-response?agents_list=<id>` with
   `Authorization: Bearer <token>` and a command, chosen per-alert by the `Set_Containment_Type`
   formula node in the Tines story (see [`/tines`](../tines)).
3. The Wazuh manager forwards the command to the agent, which runs the matching script from
   [`active-response/`](active-response) on the Windows host and logs the result to
   `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`.

| Containment type | Tines command | Agent | What it does |
| --- | --- | --- | --- |
| `disable_user` | `!disable-ad-user.cmd` (arg: user) | `001` (DC) | `Disable-ADAccount` on the alert's user. Safety guard skips machine accounts (`*$`), `krbtgt` and `Administrator`. |
| `block_ip` | `!block-ip.cmd` (arg: source IP) | `001` (DC) | Adds inbound + outbound Windows Firewall block rules for the IP. Skips protected IPs (`10.0.0.10`, `10.0.0.4`, `127.0.0.1`). |
| `isolate_host` | `!isolate-host.cmd` | `003` (endpoint) | Blocks all inbound/outbound traffic and ICMP, with an allow rule for the DC and Wazuh manager (`10.0.0.10`, `10.0.0.9`) so the host stays manageable. |

The `.cmd` files are thin wrappers (Wazuh executes `.cmd`); each just calls the `.ps1` next to it,
which reads the Wazuh JSON payload from stdin.

## Install

Copy the six files in [`active-response/`](active-response) into
`C:\Program Files (x86)\ossec-agent\active-response\bin\` on the agent host that runs them
(the DC for `disable-ad-user` / `block-ip`, the endpoint for `isolate-host`), and restart the
Wazuh agent. Agent IDs (`001`, `003`) are specific to this lab — check yours with
`/var/ossec/bin/agent_control -l` on the manager.

## Example request shape

Values are placeholders — see the root README's note on secrets:

```json
{
  "url": "https://YOUR-TUNNEL.trycloudflare.com/active-response?agents_list=001",
  "content_type": "application_json",
  "method": "put",
  "payload": {
    "command": "!disable-ad-user.cmd",
    "arguments": ["<<webhook.body.result.user>>"]
  },
  "headers": {
    "Authorization": "Bearer <<wazuh_auth.body.data.token>>"
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

Only run the rollback for the account/rule the specific attack actually touched.
