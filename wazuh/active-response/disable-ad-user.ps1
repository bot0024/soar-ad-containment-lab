$inputJson = [Console]::In.ReadLine()
if (-not $inputJson) { exit }

$payload = $inputJson | ConvertFrom-Json
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

if ($payload.command -eq "add") {
    $targetUser = $payload.parameters.extra_args[0].Split('@')[0]

    # Safety guard: never disable machine accounts or critical accounts
    if (-not $targetUser -or $targetUser -like '*$' -or $targetUser -in @('krbtgt','Administrator')) {
        Add-Content $log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED: $targetUser"
        exit
    }

    try {
        Import-Module ActiveDirectory
        Disable-ADAccount -Identity $targetUser -ErrorAction Stop
        Add-Content $log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - CONTAINMENT SUCCESS: Disabled AD Account: $targetUser"
    } catch {
        Add-Content $log "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - CONTAINMENT FAILED: $targetUser : $_"
    }
}
