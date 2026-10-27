# EARLY PROTOTYPE - superseded by the Wazuh active-response scripts in /wazuh/active-response.
# A bare HTTP listener on the domain controller that disables the AD account named in a POSTed
# Tines payload. Kept for reference only: it has no authentication, no protected-account guard,
# and no logging, so do not use it outside an isolated lab.

$port = 8080
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")
$listener.Start()
Write-Host "SOAR Listener active. Waiting for Tines containment requests on port $port..." -ForegroundColor Cyan

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request

    if ($request.HttpMethod -eq 'POST') {
        # Read the JSON payload from Tines
        $reader = New-Object System.IO.StreamReader($request.InputStream)
        $body = $reader.ReadToEnd()
        $json = $body | ConvertFrom-Json

        $targetUser = $json.TargetUserName.Split('@')[0]

        # Execute the Active Directory Containment
        Write-Host "CRITICAL ALERT: Received isolation request for user: $targetUser" -ForegroundColor Red
        Disable-ADAccount -Identity $targetUser
        Write-Host "[+] Account $targetUser has been successfully disabled in Active Directory!" -ForegroundColor Green

        # Send a success message back to Tines
        $response = $context.Response
        $buffer = [System.Text.Encoding]::UTF8.GetBytes("Containment Executed Successfully")
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.Close()
    }
}
