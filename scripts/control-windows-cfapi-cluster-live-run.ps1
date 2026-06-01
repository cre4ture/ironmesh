param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestPath,
    [ValidateSet("Show", "Continue", "Cleanup")]
    [string]$Action = "Show"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath"
}

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

switch ($Action) {
    "Show" {
        Write-Host "Phase   : $($manifest.phase)"
        Write-Host "Status  : $($manifest.status)"
        Write-Host "Detail  : $($manifest.detail)"
        Write-Host "RunRoot : $($manifest.paths.run_root)"
        Write-Host "LogFile : $(Join-Path $manifest.paths.run_root 'driver.log')"
        Write-Host "Continue: $($manifest.continue_signal_path)"
        Write-Host "Cleanup : $($manifest.cleanup_signal_path)"
        Write-Host "Admin   : $($manifest.admin_token)"
        foreach ($node in $manifest.nodes) {
            Write-Host ""
            Write-Host "$($node.label)"
            Write-Host "  public   : $($node.public_base_url)"
            Write-Host "  internal : $($node.internal_base_url)"
            Write-Host "  pid      : $($node.server_pid)"
            Write-Host "  stdout   : $($node.stdout_log)"
            Write-Host "  stderr   : $($node.stderr_log)"
            Write-Host "  logs     : $($node.logs_endpoint)"
        }
    }
    "Continue" {
        $null = New-Item -ItemType File -Force -Path $manifest.continue_signal_path
        Write-Host "Continue signal written to $($manifest.continue_signal_path)"
    }
    "Cleanup" {
        $null = New-Item -ItemType File -Force -Path $manifest.cleanup_signal_path
        Write-Host "Cleanup signal written to $($manifest.cleanup_signal_path)"
    }
}
