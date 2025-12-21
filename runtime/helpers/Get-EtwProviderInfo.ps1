param (
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$TargetId
)

# 1. Normalize the GUID (Replace underscores with hyphens)
$TargetId = $TargetId.Replace("_", "-")

# 2. Ensure it looks like a proper GUID: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
if ($TargetId -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
    $TargetId = "{$TargetId}"
}
# 1. Helper to find the Provider Name from the GUID using logman
function Get-ProviderNameFromGuid($guid) {
    # Remove braces if present to make searching easier
    $cleanGuid = $guid.Trim("{", "}")
    
    # Run logman to find the line containing the GUID
    $line = logman query providers | Select-String $cleanGuid
    
    if ($line) {
        # Split at the first opening brace and trim whitespace
        return $line.ToString().Split('{')[0].Trim()
    }
    return $null
}

# 2. Main Logic
Write-Host "[*] Searching for: $TargetId" -ForegroundColor Cyan

# Resolve Name
$providerName = Get-ProviderNameFromGuid $TargetId

if (-not $providerName) {
    # If logman fails, try using the ID directly (some providers register via ID)
    $providerName = $TargetId
}

try {
    $provider = Get-WinEvent -ListProvider $providerName -ErrorAction Stop
    Write-Host "[+] Found Provider: $($provider.Name)" -ForegroundColor Green
    Write-Host "------------------------------------------------------------"

    $results = foreach ($event in $provider.Events) {
        $fieldNames = @()
        if ($event.Template) {
            try {
                # Parse the XML Template to get field names for your Protobuf
                $xml = [xml]$event.Template
                $fieldNames = $xml.template.data.name
            } catch {
                $fieldNames = "N/A"
            }
        }

        [PSCustomObject]@{
            EID         = $event.Id
            Description = $event.Description
            Fields      = ($fieldNames -join ", ")
        }
    }

    # Display results
    $results | Format-Table -AutoSize -Wrap
    Write-Host "[!] Total Events Found: $($results.Count)" -ForegroundColor Gray
}
catch {
    Write-Host "[!] Error: Could not find manifest for '$providerName'." -ForegroundColor Red
    Write-Host "    Make sure you are running as Administrator." -ForegroundColor Yellow
}