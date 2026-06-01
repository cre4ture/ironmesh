param(
    [string]$ManifestPath,
    [string]$NodeLabel = "cluster-a",
    [string]$BaseUrl,
    [string]$FilterExpression
)

$ErrorActionPreference = "Stop"

$adminToken = $null

if (-not [string]::IsNullOrWhiteSpace($ManifestPath)) {
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest not found: $ManifestPath"
    }
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
    $adminToken = $manifest.admin_token
    if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
        $node = $manifest.nodes | Where-Object { $_.label -eq $NodeLabel } | Select-Object -First 1
        if ($null -eq $node) {
            throw "Node label '$NodeLabel' not found in manifest."
        }
        $BaseUrl = $node.public_base_url
    }
}

if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    throw "BaseUrl is required when ManifestPath is not provided."
}

if ([string]::IsNullOrWhiteSpace($adminToken)) {
    $adminToken = $env:IRONMESH_ADMIN_TOKEN
}
if ([string]::IsNullOrWhiteSpace($adminToken)) {
    throw "Admin token is required. Provide ManifestPath or set IRONMESH_ADMIN_TOKEN."
}

$uri = "$BaseUrl/api/v1/auth/logging/config"
$headers = @{ "x-ironmesh-admin-token" = $adminToken }

if ([string]::IsNullOrWhiteSpace($FilterExpression)) {
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
}
else {
    $body = @{
        filter_expression = $FilterExpression
    } | ConvertTo-Json
    $response = Invoke-RestMethod -Method Put -Uri $uri -Headers $headers -ContentType "application/json" -Body $body
}

$response | ConvertTo-Json -Depth 8
