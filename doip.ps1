# DigitalOcean API settings
$doApiToken = ""
$firewallName = ""
$apiBaseUrl = "https://api.digitalocean.com/v2/firewalls"

# Ports to update
$targetPorts = @("", "", "", "")

# Function to get the current public IP address of the machine
function Get-PublicIPv4 {
    try {
        # Using a public IP service
        return (Invoke-RestMethod -Uri "https://api.ipify.org")
    } catch {
        Write-Output "Error: Unable to retrieve public IP."
        return $null
    }
}

# Get current public IP
$currentIp = Get-PublicIPv4
if (-not $currentIp) {
    Write-Output "Error: Unable to continue without a valid IP."
    exit 1
}
Write-Output "Current public IP: $currentIp"

# Retrieve the firewall by name
$firewalls = Invoke-RestMethod -Uri $apiBaseUrl -Method Get -Headers @{
    "Authorization" = "Bearer $doApiToken"
}

# Find the firewall ID for the firewall name
$firewall = $firewalls.firewalls | Where-Object { $_.name -eq $firewallName }
if (-not $firewall) {
    Write-Output "Error: Firewall '$firewallName' not found."
    exit 1
}
$firewallId = $firewall.id
Write-Output "Found firewall '$firewallName' with ID: $firewallId"

# Update firewall rules to use the current IP for specified ports
$updatedRules = @()
foreach ($rule in $firewall.inbound_rules) {
    if ($rule.protocol -eq "tcp" -and $targetPorts -contains $rule.ports) {
        # Update only the sources for specified ports
        $rule.sources.addresses = @($currentIp)
    }
    $updatedRules += $rule
}

# Create payload with updated rules
$payload = @{
    name           = $firewallName
    inbound_rules  = $updatedRules
    outbound_rules = $firewall.outbound_rules
    droplet_ids    = $firewall.droplet_ids
    tags           = $firewall.tags
} | ConvertTo-Json -Depth 10

# Send the update request to DigitalOcean API
$response = Invoke-RestMethod -Uri "$apiBaseUrl/$firewallId" -Method Put -Headers @{
    "Authorization" = "Bearer $doApiToken"
    "Content-Type"  = "application/json"
} -Body $payload

if ($response -ne $null -and $response.status -eq "OK") {
    Write-Output "Firewall '$firewallName' updated successfully with IP: $currentIp for ports: $($targetPorts -join ', ')"
} else {
    Write-Output "Error updating firewall. Response: $($response | ConvertTo-Json)"
}
