param(
    [string]$RunRoot,
    [Parameter(Mandatory = $true)]
    [string]$ClusterAVolumeRoot,
    [int]$FileCount = 680,
    [int]$MinSizeMiB = 1,
    [int]$MaxSizeMiB = 5,
    [int]$VerifySampleCount = 16,
    [int]$SubdirCount = 80,
    [int]$MaxDirDepth = 4,
    [int]$CloseUploadConcurrency = 8,
    [int]$UploadTimeoutMinutes = 150,
    [int]$ReplicationTimeoutMinutes = 60,
    [int]$FailureDelayMinutes = 3,
    [int]$ObserveFullMinutes = 10,
    [int]$ReserveFreeMiB = 64,
    [int]$RecoveryWaitMinutes = 60,
    [string]$ClusterALogFilter = "warn,server_node_sdk=info,sync_core=info,transport_sdk=info",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

function Normalize-VolumeRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $candidate = $Path.Trim()
    if ($candidate.Length -eq 2 -and $candidate[1] -eq ':') {
        $candidate = "$candidate\"
    }

    if (-not (Test-Path -LiteralPath $candidate)) {
        throw "ClusterAVolumeRoot not found: $candidate"
    }

    $resolved = (Resolve-Path -LiteralPath $candidate).Path
    if (-not $resolved.EndsWith("\")) {
        $resolved = "$resolved\"
    }
    if ($resolved -notmatch '^[A-Za-z]:\\$') {
        throw "ClusterAVolumeRoot must be a mounted drive root like 'R:\'. Received: $resolved"
    }
    return $resolved
}

function New-ClusterAJunction {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunRoot,
        [Parameter(Mandatory = $true)]
        [string]$ClusterAVolumeRoot
    )

    $volumeRoot = Normalize-VolumeRoot -Path $ClusterAVolumeRoot
    $targetDir = Join-Path $volumeRoot "cluster-a-server"
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    Get-ChildItem -LiteralPath $targetDir -Force | ForEach-Object {
        Remove-Item -LiteralPath $_.FullName -Force -Recurse
    }

    $staleFillerPath = Join-Path $volumeRoot "volume-fill.bin"
    if (Test-Path -LiteralPath $staleFillerPath) {
        Remove-Item -LiteralPath $staleFillerPath -Force
    }

    $junctionPath = Join-Path $RunRoot "cluster-a-server"
    if (Test-Path -LiteralPath $junctionPath) {
        & cmd.exe /d /c "rmdir `"$junctionPath`"" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to remove pre-existing junction: $junctionPath"
        }
    }
    New-Item -ItemType Junction -Path $junctionPath -Target $targetDir | Out-Null

    return @{
        VolumeRoot = $volumeRoot
        TargetDir = $targetDir
        JunctionPath = $junctionPath
    }
}

function Remove-ClusterAJunction {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$VolumeInfo
    )

    if (Test-Path -LiteralPath $VolumeInfo.JunctionPath) {
        & cmd.exe /d /c "rmdir `"$($VolumeInfo.JunctionPath)`"" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to remove junction: $($VolumeInfo.JunctionPath)"
        }
    }
}

function Get-Manifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        return $null
    }

    return Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
}

function Wait-ForManifestPhase {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Phases,
        [Parameter(Mandatory = $true)]
        [int]$TimeoutMinutes
    )

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $lastSummary = ""

    while ((Get-Date) -lt $deadline) {
        $manifest = Get-Manifest -ManifestPath $ManifestPath
        if ($null -ne $manifest) {
            $summary = "phase=$($manifest.phase) status=$($manifest.status) detail=$($manifest.detail)"
            if ($summary -ne $lastSummary) {
                Write-Host "[manifest] $summary"
                $lastSummary = $summary
            }
            if ($Phases -contains $manifest.phase) {
                return $manifest
            }
        }
        Start-Sleep -Seconds 5
    }

    throw "Timed out waiting for manifest phase(s): $($Phases -join ', ')"
}

function Set-ClusterALogFilter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$FilterExpression
    )

    $scriptPath = Join-Path $RepoRoot "scripts\set-server-node-runtime-log-filter.ps1"
    & powershell -ExecutionPolicy Bypass -File $scriptPath `
        -ManifestPath $ManifestPath `
        -NodeLabel "cluster-a" `
        -FilterExpression $FilterExpression | Out-Null
}

function Get-NodeFileCount {
    param(
        [Parameter(Mandatory = $true)]
        $Manifest,
        [Parameter(Mandatory = $true)]
        [string]$NodeLabel
    )

    $node = $Manifest.nodes | Where-Object { $_.label -eq $NodeLabel } | Select-Object -First 1
    if ($null -eq $node) {
        throw "Node '$NodeLabel' not found in manifest."
    }

    $headers = @{ "x-ironmesh-admin-token" = $Manifest.admin_token }
    $uri = "$($node.public_base_url)/api/v1/auth/store/index?depth=8&synthesize_missing_folder_markers=false"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
    $files = @($response.entries | Where-Object { -not $_.path.EndsWith('/') })
    return @{
        file_count = $files.Count
        entry_count = $response.total_entry_count
    }
}

function New-FillerFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [UInt64]$ReserveFreeBytes
    )

    $drive = Split-Path -Qualifier $Path
    $driveName = $drive.TrimEnd('\').TrimEnd(':')
    $freeBytes = [UInt64](Get-PSDrive -Name $driveName).Free
    if ($freeBytes -le $ReserveFreeBytes) {
        throw "Drive $drive already has only $freeBytes bytes free."
    }

    $targetBytes = $freeBytes - $ReserveFreeBytes
    $stepBytes = [UInt64](16MB)
    while ($targetBytes -gt 0) {
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            try {
                $stream.SetLength([Int64]$targetBytes)
                if ($targetBytes -gt 0) {
                    $stream.Position = $targetBytes - 1
                    $stream.WriteByte(0)
                    $stream.Flush()
                }
            }
            finally {
                $stream.Dispose()
            }
            return $targetBytes
        }
        catch {
            if (Test-Path -LiteralPath $Path) {
                Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            }
            if ($targetBytes -le $stepBytes) {
                throw "Unable to allocate filler file on ${drive}: $($_.Exception.Message)"
            }
            $targetBytes -= $stepBytes
        }
    }

    throw "No room available to create a filler file on $drive."
}

function Write-Observation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObservationLog,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = "{0} {1}" -f (Get-Date -Format o), $Message
    Add-Content -LiteralPath $ObservationLog -Value $line
    Write-Host $line
}

function Wait-ForNodeProcessesToExit {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [int]$TimeoutSeconds = 90
    )

    $manifest = Get-Manifest -ManifestPath $ManifestPath
    if ($null -eq $manifest) {
        return
    }

    $pids = @()
    if ($null -ne $manifest.adapter -and $null -ne $manifest.adapter.pid) {
        $pids += [int]$manifest.adapter.pid
    }
    foreach ($node in @($manifest.nodes)) {
        if ($null -ne $node.server_pid) {
            $pids += [int]$node.server_pid
        }
    }
    $pids = $pids | Sort-Object -Unique
    if ($pids.Count -eq 0) {
        return
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $alive = @()
    foreach ($processId in $pids) {
        if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
            $alive += $processId
        }
    }
        if ($alive.Count -eq 0) {
            return
        }
        Start-Sleep -Seconds 3
    }
}

function Observe-Cluster {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ManifestPath,
        [Parameter(Mandatory = $true)]
        [string]$ObservationLog,
        [Parameter(Mandatory = $true)]
        [int]$Minutes,
        [Parameter(Mandatory = $true)]
        [string]$VolumeDriveLetter
    )

    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline) {
        $manifest = Get-Manifest -ManifestPath $ManifestPath
        if ($null -eq $manifest) {
            Write-Observation -ObservationLog $ObservationLog -Message "manifest unavailable during observation"
        }
        else {
            $a = Get-NodeFileCount -Manifest $manifest -NodeLabel "cluster-a"
            $b = Get-NodeFileCount -Manifest $manifest -NodeLabel "cluster-b"
            $c = Get-NodeFileCount -Manifest $manifest -NodeLabel "cluster-c"
            $driveName = $VolumeDriveLetter.TrimEnd(':')
            $freeGiB = [math]::Round((Get-PSDrive -Name $driveName).Free / 1GB, 3)
            Write-Observation `
                -ObservationLog $ObservationLog `
                -Message "phase=$($manifest.phase) status=$($manifest.status) free_gib=$freeGiB cluster-a=$($a.file_count)files/$($a.entry_count)entries cluster-b=$($b.file_count)files/$($b.entry_count)entries cluster-c=$($c.file_count)files/$($c.entry_count)entries"
        }
        Start-Sleep -Seconds 30
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$experimentRootBase = Join-Path $repoRoot "target\tmp\windows-cfapi-diskfull"
if ([string]::IsNullOrWhiteSpace($RunRoot)) {
    $runId = "{0}-{1}" -f (Get-Date -Format "yyyyMMdd-HHmmss"), ([guid]::NewGuid().ToString("N").Substring(0, 8))
    $RunRoot = Join-Path $experimentRootBase $runId
}

New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
$manifestPath = Join-Path $RunRoot "manifest.json"
$observationLog = Join-Path $RunRoot "diskfull-observation.log"
$fillerPath = $null
$volumeInfo = $null
$cleanupRequested = $false

try {
    $volumeInfo = New-ClusterAJunction -RunRoot $RunRoot -ClusterAVolumeRoot $ClusterAVolumeRoot
    Write-Host "cluster-a volume: $($volumeInfo.VolumeRoot) -> $($volumeInfo.TargetDir)"
    Write-Host "run root        : $RunRoot"

    $runnerScript = Join-Path $repoRoot "scripts\run-windows-cfapi-cluster-live-workload.ps1"
    $runnerOutput = & $runnerScript `
        -RunRoot $RunRoot `
        -FileCount $FileCount `
        -MinSizeMiB $MinSizeMiB `
        -MaxSizeMiB $MaxSizeMiB `
        -VerifySampleCount $VerifySampleCount `
        -SubdirCount $SubdirCount `
        -MaxDirDepth $MaxDirDepth `
        -CloseUploadConcurrency $CloseUploadConcurrency `
        -UploadTimeoutMinutes $UploadTimeoutMinutes `
        -ReplicationTimeoutMinutes $ReplicationTimeoutMinutes `
        -HoldOnFailure:$false `
        -SkipBuild:$SkipBuild
    $runnerOutput | ForEach-Object { Write-Host $_ }

    $manifest = Wait-ForManifestPhase -ManifestPath $manifestPath -Phases @("files_copied", "failed", "completed") -TimeoutMinutes 45
    if ($manifest.phase -ne "files_copied") {
        throw "Workload reached unexpected phase '$($manifest.phase)' before disk-full injection."
    }

    if (-not [string]::IsNullOrWhiteSpace($ClusterALogFilter)) {
        Set-ClusterALogFilter -RepoRoot $repoRoot -ManifestPath $manifestPath -FilterExpression $ClusterALogFilter
    }

    Write-Observation -ObservationLog $observationLog -Message "waiting $FailureDelayMinutes minute(s) before filling cluster-a volume"
    Start-Sleep -Seconds ($FailureDelayMinutes * 60)

    $fillerPath = Join-Path $volumeInfo.VolumeRoot "volume-fill.bin"
    $allocatedBytes = New-FillerFile -Path $fillerPath -ReserveFreeBytes ([UInt64]($ReserveFreeMiB * 1MB))
    Write-Observation -ObservationLog $observationLog -Message "allocated filler file $fillerPath bytes=$allocatedBytes reserve_free_mib=$ReserveFreeMiB"

    Observe-Cluster `
        -ManifestPath $manifestPath `
        -ObservationLog $observationLog `
        -Minutes $ObserveFullMinutes `
        -VolumeDriveLetter (Split-Path -Qualifier $volumeInfo.VolumeRoot)

    Remove-Item -LiteralPath $fillerPath -Force
    $fillerPath = $null
    Write-Observation -ObservationLog $observationLog -Message "removed filler file; waiting for recovery"

    $recoveryDeadline = (Get-Date).AddMinutes($RecoveryWaitMinutes)
    while ((Get-Date) -lt $recoveryDeadline) {
        $manifest = Get-Manifest -ManifestPath $manifestPath
        if ($null -ne $manifest) {
            Write-Observation -ObservationLog $observationLog -Message "manifest phase=$($manifest.phase) status=$($manifest.status) detail=$($manifest.detail)"
            if ($manifest.phase -eq "cleaned_up") {
                Write-Observation -ObservationLog $observationLog -Message "workload completed after space was restored"
                break
            }
            if ($manifest.phase -eq "failed") {
                throw "Workload failed after disk space was restored: $($manifest.detail)"
            }
        }
        Start-Sleep -Seconds 30
    }

    $manifest = Get-Manifest -ManifestPath $manifestPath
    if ($null -eq $manifest -or $manifest.phase -ne "cleaned_up") {
        throw "Timed out waiting for clean recovery after disk space was restored."
    }
}
catch {
    if (-not $cleanupRequested -and (Test-Path -LiteralPath $manifestPath)) {
        try {
            $controlScript = Join-Path $repoRoot "scripts\control-windows-cfapi-cluster-live-run.ps1"
            & powershell -ExecutionPolicy Bypass -File $controlScript -ManifestPath $manifestPath -Action Cleanup | Out-Null
            $cleanupRequested = $true
        }
        catch {
            Write-Warning "Failed to request live workload cleanup: $($_.Exception.Message)"
        }
    }
    throw
}
finally {
    if ($null -ne $fillerPath -and (Test-Path -LiteralPath $fillerPath)) {
        Remove-Item -LiteralPath $fillerPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $manifestPath) {
        Wait-ForNodeProcessesToExit -ManifestPath $manifestPath
    }
    if ($null -ne $volumeInfo) {
        Remove-ClusterAJunction -VolumeInfo $volumeInfo
    }
}
