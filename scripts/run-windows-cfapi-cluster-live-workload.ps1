param(
    [int]$FileCount = 4000,
    [int]$MinSizeMiB = 1,
    [int]$MaxSizeMiB = 5,
    [int]$VerifySampleCount = 24,
    [int]$SubdirCount = 80,
    [int]$MaxDirDepth = 4,
    [int]$CloseUploadConcurrency = 8,
    [int]$UploadTimeoutMinutes = 150,
    [int]$ReplicationTimeoutMinutes = 60,
    [bool]$HoldOnFailure = $true,
    [switch]$HoldAfterCopy,
    [switch]$HoldAfterUpload,
    [switch]$HoldAfterReplication,
    [string]$RunRoot,
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
if ($CloseUploadConcurrency -le 0) {
    throw "CloseUploadConcurrency must be greater than zero."
}
if ($UploadTimeoutMinutes -le 0) {
    throw "UploadTimeoutMinutes must be greater than zero."
}
if ($ReplicationTimeoutMinutes -le 0) {
    throw "ReplicationTimeoutMinutes must be greater than zero."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$liveRootBase = Join-Path $repoRoot "target\tmp\windows-cfapi-live"
if ([string]::IsNullOrWhiteSpace($RunRoot)) {
    $runId = "{0}-{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), ([guid]::NewGuid().ToString("N").Substring(0, 8))
    $RunRoot = Join-Path $liveRootBase $runId
}

$null = New-Item -ItemType Directory -Force -Path $RunRoot
$manifestPath = Join-Path $RunRoot "manifest.json"
$continueSignalPath = Join-Path $RunRoot "continue.signal"
$cleanupSignalPath = Join-Path $RunRoot "cleanup.signal"
$driverLogPath = Join-Path $RunRoot "driver.log"

function Resolve-DriverExecutable {
    param(
        [string]$RepoRoot
    )

    $searchRoots = @(
        (Join-Path $RepoRoot "target\debug"),
        (Join-Path $RepoRoot "tests\system-tests\target\debug")
    )

    foreach ($searchRoot in $searchRoots) {
        $directCandidate = Join-Path $searchRoot "windows_cfapi_cluster_workload_driver.exe"
        if (Test-Path -LiteralPath $directCandidate) {
            return Get-Item -LiteralPath $directCandidate
        }
    }

    $matches = @(foreach ($searchRoot in $searchRoots) {
        if (-not (Test-Path -LiteralPath $searchRoot)) {
            continue
        }

        Get-ChildItem `
            -Path $searchRoot `
            -Filter "windows_cfapi_cluster_workload_driver*.exe" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
    }) | Where-Object {
        $_.FullName -notmatch '\\deps\\'
    }

    return $matches |
        Sort-Object -Property LastWriteTime -Descending |
        Select-Object -First 1
}

if (-not $SkipBuild) {
    Push-Location $repoRoot
    try {
        cargo build --locked -p server-node --bin ironmesh-server-node
        cargo build --locked -p os-integration --bin ironmesh-os-integration
        cargo build --locked --manifest-path tests\system-tests\Cargo.toml --bin windows_cfapi_cluster_workload_driver
    }
    finally {
        Pop-Location
    }
}

$driverExeInfo = Resolve-DriverExecutable -RepoRoot $repoRoot
if ($null -eq $driverExeInfo) {
    throw "Driver executable not found under target\\debug or tests\\system-tests\\target\\debug."
}
$driverExe = $driverExeInfo.FullName

if (Test-Path -LiteralPath $driverLogPath) {
    Remove-Item -LiteralPath $driverLogPath -Force
}
if (Test-Path -LiteralPath $manifestPath) {
    Remove-Item -LiteralPath $manifestPath -Force
}
if (Test-Path -LiteralPath $continueSignalPath) {
    Remove-Item -LiteralPath $continueSignalPath -Force
}
if (Test-Path -LiteralPath $cleanupSignalPath) {
    Remove-Item -LiteralPath $cleanupSignalPath -Force
}

$inner = @(
    "set `"IRONMESH_WINDOWS_CFAPI_LOAD_FILE_COUNT=$FileCount`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LOAD_MIN_BYTES=$($MinSizeMiB * 1MB)`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LOAD_MAX_BYTES=$($MaxSizeMiB * 1MB)`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LOAD_VERIFY_SAMPLE_COUNT=$VerifySampleCount`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LOAD_SUBDIR_COUNT=$SubdirCount`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LOAD_MAX_DIR_DEPTH=$MaxDirDepth`"",
    "set `"IRONMESH_CFAPI_CLOSE_UPLOAD_MAX_CONCURRENCY=$CloseUploadConcurrency`"",
    "set `"IRONMESH_WINDOWS_CFAPI_UPLOAD_TIMEOUT_SECS=$($UploadTimeoutMinutes * 60)`"",
    "set `"IRONMESH_WINDOWS_CFAPI_REPLICATION_TIMEOUT_SECS=$($ReplicationTimeoutMinutes * 60)`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_MANIFEST_PATH=$manifestPath`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_CONTINUE_SIGNAL_PATH=$continueSignalPath`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_CLEANUP_SIGNAL_PATH=$cleanupSignalPath`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_AFTER_COPY=$($HoldAfterCopy.IsPresent.ToString().ToLowerInvariant())`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_AFTER_UPLOAD=$($HoldAfterUpload.IsPresent.ToString().ToLowerInvariant())`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_AFTER_REPLICATION=$($HoldAfterReplication.IsPresent.ToString().ToLowerInvariant())`"",
    "set `"IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_ON_FAILURE=$($HoldOnFailure.ToString().ToLowerInvariant())`"",
    "`"$driverExe`" > `"$driverLogPath`" 2>&1"
) -join " && "

$process = Start-Process `
    -FilePath "cmd.exe" `
    -ArgumentList @("/d", "/c", $inner) `
    -WorkingDirectory $repoRoot `
    -PassThru `
    -WindowStyle Hidden

Write-Output "PID=$($process.Id)"
Write-Output "RUN_ROOT=$RunRoot"
Write-Output "MANIFEST=$manifestPath"
Write-Output "LOG=$driverLogPath"
Write-Output "CONTINUE_SIGNAL=$continueSignalPath"
Write-Output "CLEANUP_SIGNAL=$cleanupSignalPath"
