$inputJson = [Console]::In.ReadLine()
if (-not $inputJson) { exit }

$payload = $inputJson | ConvertFrom-Json
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log($msg) {
    try { Add-Content $log $msg -ErrorAction Stop }
    catch { }
}

if ($payload.command -eq "add") {
    try {
        if (-not (Get-NetFirewallRule -DisplayName "SOC-Isolate-Host-In" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName "SOC-Isolate-Host-In" -Direction Inbound -RemoteAddress Any -Action Block -ErrorAction Stop
            New-NetFirewallRule -DisplayName "SOC-Isolate-Host-Out" -Direction Outbound -RemoteAddress Any -Action Block -ErrorAction Stop
            New-NetFirewallRule -DisplayName "SOC-Isolate-Allow-Mgmt" -Direction Outbound -RemoteAddress 10.0.0.10,10.0.0.9 -Action Allow -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "SOC-Isolate-Block-ICMP-In" -Direction Inbound -Protocol ICMPv4 -Action Block -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "SOC-Isolate-Block-ICMP-Out" -Direction Outbound -Protocol ICMPv4 -Action Block -ErrorAction SilentlyContinue
            Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - CONTAINMENT SUCCESS: Host isolated (all traffic blocked except mgmt)"
        } else {
            Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED: Isolation rules already present"
        }
    } catch {
        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - CONTAINMENT FAILED: $_"
    }
}
