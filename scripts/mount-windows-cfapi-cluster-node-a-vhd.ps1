param(
    [string]$VhdPath,
    [int]$VolumeSizeGiB = 4,
    [string]$DriveLetter = "R"
)

$ErrorActionPreference = "Stop"

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Normalize-DriveLetter {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Letter
    )

    $trimmed = $Letter.Trim().TrimEnd(':').TrimEnd('\')
    if ($trimmed.Length -ne 1 -or $trimmed -notmatch '^[A-Za-z]$') {
        throw "DriveLetter must be a single drive letter, for example 'R'."
    }
    return $trimmed.ToUpperInvariant()
}

function Invoke-DiskpartScript {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines,
        [Parameter(Mandatory = $true)]
        [string]$WorkingDir,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $scriptPath = Join-Path $WorkingDir "$Label.diskpart.txt"
    $stdoutPath = Join-Path $WorkingDir "$Label.diskpart.stdout.log"
    $stderrPath = Join-Path $WorkingDir "$Label.diskpart.stderr.log"

    $Lines | Set-Content -LiteralPath $scriptPath -Encoding ASCII
    if (Test-Path -LiteralPath $stdoutPath) {
        Remove-Item -LiteralPath $stdoutPath -Force
    }
    if (Test-Path -LiteralPath $stderrPath) {
        Remove-Item -LiteralPath $stderrPath -Force
    }

    $process = Start-Process `
        -FilePath diskpart.exe `
        -ArgumentList @("/s", $scriptPath) `
        -NoNewWindow `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $stdout = if (Test-Path -LiteralPath $stdoutPath) {
        Get-Content -LiteralPath $stdoutPath -Raw
    }
    else {
        ""
    }
    $stderr = if (Test-Path -LiteralPath $stderrPath) {
        Get-Content -LiteralPath $stderrPath -Raw
    }
    else {
        ""
    }

    if ($process.ExitCode -ne 0) {
        throw "diskpart step '$Label' failed with exit code $($process.ExitCode)`n--- stdout ---`n$stdout`n--- stderr ---`n$stderr"
    }

    return @{
        stdout = $stdout
        stderr = $stderr
    }
}

if (-not (Test-IsElevated)) {
    throw "This script requires an elevated PowerShell session because it uses diskpart to create and attach a VHD."
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($VhdPath)) {
    $VhdPath = Join-Path $repoRoot "target\tmp\windows-cfapi-diskfull\cluster-a-node-volume.vhd"
}

$DriveLetter = Normalize-DriveLetter -Letter $DriveLetter
$volumeRoot = "${DriveLetter}:\"
$workingDir = Split-Path -Parent $VhdPath
New-Item -ItemType Directory -Force -Path $workingDir | Out-Null

$markerPath = [System.IO.Path]::Combine($volumeRoot, "ironmesh-node-a-vhd.json")
if ([System.IO.Directory]::Exists($volumeRoot)) {
    if ([System.IO.File]::Exists($markerPath)) {
        $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
        Write-Output "VHD_PATH=$($marker.vhd_path)"
        Write-Output "VOLUME_ROOT=$($marker.volume_root)"
        Write-Output "NODE_A_DATA_DIR=$($marker.node_a_data_dir)"
        Write-Output "STATUS=already-mounted"
        exit 0
    }
    throw "Drive $volumeRoot already exists and is not marked as the cluster-a VHD volume."
}

$maximumMiB = $VolumeSizeGiB * 1024
if (Test-Path -LiteralPath $VhdPath) {
    Invoke-DiskpartScript -WorkingDir $workingDir -Label "attach-node-a-volume" -Lines @(
        "select vdisk file=""$VhdPath""",
        "attach vdisk",
        "assign letter=$DriveLetter"
    ) | Out-Null
    $status = "attached-existing"
}
else {
    Invoke-DiskpartScript -WorkingDir $workingDir -Label "create-node-a-volume" -Lines @(
        "create vdisk file=""$VhdPath"" maximum=$maximumMiB type=expandable",
        "select vdisk file=""$VhdPath""",
        "attach vdisk",
        "create partition primary",
        "format fs=ntfs quick label=ironmesh-node-a",
        "assign letter=$DriveLetter"
    ) | Out-Null
    $status = "created-and-mounted"
}

$nodeADataDir = [System.IO.Path]::Combine($volumeRoot, "cluster-a-server")
New-Item -ItemType Directory -Force -Path $nodeADataDir | Out-Null

$marker = @{
    vhd_path = (Resolve-Path -LiteralPath $VhdPath).Path
    volume_root = $volumeRoot
    node_a_data_dir = $nodeADataDir
    drive_letter = $DriveLetter
    status = $status
    updated_at = Get-Date -Format o
}
$marker | ConvertTo-Json | Set-Content -LiteralPath $markerPath -Encoding ASCII

Write-Output "VHD_PATH=$($marker.vhd_path)"
Write-Output "VOLUME_ROOT=$($marker.volume_root)"
Write-Output "NODE_A_DATA_DIR=$($marker.node_a_data_dir)"
Write-Output "STATUS=$status"
