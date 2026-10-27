$inputJson = [Console]::In.ReadLine()
if (-not $inputJson) { exit }

$payload = $inputJson | ConvertFrom-Json
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log($msg) {
    try { Add-Content $log $msg -ErrorAction Stop }
    catch { } # don't let a locked log file break containment
}

if ($payload.command -eq "add") {
    $srcIp = $payload.parameters.extra_args[0]

    $protectedIps = @('10.0.0.10','10.0.0.4','127.0.0.1')
    if (-not $srcIp -or $srcIp -in $protectedIps) {
        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED: $srcIp"
        exit
    }

    try {
        New-NetFirewallRule -DisplayName "SOC-Block-$srcIp-In" -Direction Inbound -RemoteAddress $srcIp -Action Block -ErrorAction Stop
        New-NetFirewallRule -DisplayName "SOC-Block-$srcIp-Out" -Direction Outbound -RemoteAddress $srcIp -Action Block -ErrorAction Stop
        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - CONTAINMENT SUCCESS: Blocked IP: $srcIp"
    } catch {
        Write-Log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - CONTAINMENT FAILED: $srcIp : $_"
    }
}
