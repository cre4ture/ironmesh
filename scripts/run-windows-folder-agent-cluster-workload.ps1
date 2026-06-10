param(
    [int]$FileCount = 4000,
    [int]$MinSizeMiB = 1,
    [int]$MaxSizeMiB = 5,
    [int]$VerifySampleCount = 24,
    [int]$SubdirCount = 80,
    [int]$MaxDirDepth = 4,
    [ValidateSet("before_copy", "after_copy")]
    [string]$StartMode = "before_copy",
    [int]$UploadTimeoutMinutes = 150,
    [int]$ReplicationTimeoutMinutes = 60,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

if ($MinSizeMiB -le 0) {
    throw "MinSizeMiB must be greater than zero."
}
if ($MaxSizeMiB -lt $MinSizeMiB) {
    throw "MaxSizeMiB must be greater than or equal to MinSizeMiB."
}
if ($FileCount -le 0) {
    throw "FileCount must be greater than zero."
}
if ($SubdirCount -le 0) {
    throw "SubdirCount must be greater than zero."
}
if ($MaxDirDepth -le 0) {
    throw "MaxDirDepth must be greater than zero."
}
if ($SubdirCount -gt $FileCount) {
    throw "SubdirCount must be less than or equal to FileCount."
}
if ($UploadTimeoutMinutes -le 0) {
    throw "UploadTimeoutMinutes must be greater than zero."
}
if ($ReplicationTimeoutMinutes -le 0) {
    throw "ReplicationTimeoutMinutes must be greater than zero."
}

$repoRoot = Split-Path -Parent $PSScriptRoot

$env:IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_FILE_COUNT = [string]$FileCount
$env:IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_MIN_BYTES = [string]($MinSizeMiB * 1MB)
$env:IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_MAX_BYTES = [string]($MaxSizeMiB * 1MB)
$env:IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_VERIFY_SAMPLE_COUNT = [string]$VerifySampleCount
$env:IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_SUBDIR_COUNT = [string]$SubdirCount
$env:IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_MAX_DIR_DEPTH = [string]$MaxDirDepth
$env:IRONMESH_WINDOWS_FOLDER_AGENT_START_MODE = $StartMode
$env:IRONMESH_WINDOWS_FOLDER_AGENT_UPLOAD_TIMEOUT_SECS = [string]($UploadTimeoutMinutes * 60)
$env:IRONMESH_WINDOWS_FOLDER_AGENT_REPLICATION_TIMEOUT_SECS = [string]($ReplicationTimeoutMinutes * 60)

Write-Host "Running Windows Folder Agent cluster workload"
Write-Host "  files          : $FileCount"
Write-Host "  size range MiB : $MinSizeMiB - $MaxSizeMiB"
Write-Host "  average MiB    : $([math]::Round(($MinSizeMiB + $MaxSizeMiB) / 2, 2))"
Write-Host "  sample checks  : $VerifySampleCount"
Write-Host "  subdirs        : $SubdirCount"
Write-Host "  max dir depth  : $MaxDirDepth"
Write-Host "  start mode     : $StartMode"
Write-Host "  upload timeout : $UploadTimeoutMinutes min"
Write-Host "  repl timeout   : $ReplicationTimeoutMinutes min"

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        cargo test --manifest-path tests\system-tests\Cargo.toml --no-run
    }

    cargo test `
        --manifest-path tests\system-tests\Cargo.toml `
        windows_folder_agent_cluster_upload_and_replication_workload `
        -- `
        --ignored `
        --nocapture
}
finally {
    Pop-Location
}
