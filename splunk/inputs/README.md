# Universal Forwarder inputs

`inputs.conf` for the Splunk Universal Forwarder on each Windows host. Place it at
`C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` and restart the
`SplunkForwarder` service. Forwarding to the Splunk indexer on port 9997 is configured separately
(`splunk add forward-server <splunk-ip>:9997`).

| File | Host | Collects |
| --- | --- | --- |
| [`inputs.conf.dc01`](inputs.conf.dc01) | Domain controller | Security, System, Application, Directory Service, PowerShell/Operational (`powershell` index), Sysmon (`sysmon` index) |
| [`inputs.conf.desktop01`](inputs.conf.desktop01) | `DESKTOP-01` endpoint | Security, System, Application, Sysmon |

Rename the file to `inputs.conf` when deploying. Create the `win_security`, `sysmon` and
`powershell` indexes on the Splunk server first.
