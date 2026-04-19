<#
.SYNOPSIS
Builds, stages, optionally signs, and optionally installs the local IronMesh prototype MSIX package.

.DESCRIPTION
Run this script from the repository root when testing the packaged Windows prototype.

Common usage:

- Stage package contents only:
    powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -StageOnly

- Build, pack, sign, and install the debug prototype:
    powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Install

- Build, pack, sign, and install a release prototype:
    powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Configuration release -Install

- Override the package version explicitly:
    powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -PackageVersion 1.0.2.0 -Install

Notes:

- Rust/Cargo must be available.
- Full packing and signing require Windows SDK tools such as MakeAppx.exe and SignTool.exe.
- -Install may require an elevated PowerShell session so the development certificate can be imported into LocalMachine\TrustedPeople.
- After installation, launch the packaged IronMesh config app from the Start menu for the normal packaged-client flow.

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -StageOnly

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Install

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Configuration release -Install

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -PackageVersion 1.0.2.0 -Install
#>

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",
    [string]$Architecture = "x64",
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string]$PackageVersion,
    [switch]$StageOnly,
    [switch]$Install,
    [string]$CertificateSubject = "CN=53536D7F-3E42-40F5-ACA9-B14F636B5B21",
    [string]$CertificatePassword = "ironmesh-dev"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ("Command failed with exit code {0}: {1} {2}" -f $LASTEXITCODE, $FilePath, ($Arguments -join " "))
    }
}

function Test-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
}

function Get-WorkspaceCargoVersion {
    param([string]$RepoRoot)

    $workspaceManifestPath = Join-Path $RepoRoot 'Cargo.toml'
    $inWorkspacePackage = $false

    foreach ($line in Get-Content -Path $workspaceManifestPath) {
        if ($line -match '^\[workspace\.package\]\s*$') {
            $inWorkspacePackage = $true
            continue
        }

        if ($inWorkspacePackage -and $line -match '^\[') {
            break
        }

        if ($inWorkspacePackage -and $line -match '^\s*version\s*=\s*"([^"]+)"\s*$') {
            return $matches[1]
        }
    }

    throw "Unable to determine [workspace.package].version from $workspaceManifestPath"
}

function Convert-CargoVersionToPackageVersion {
    param([string]$CargoVersion)

    if ($CargoVersion -notmatch '^(\d+)\.(\d+)\.(\d+)$') {
        throw "Cargo workspace version '$CargoVersion' must be a plain semantic version like 0.1.0 to derive an MSIX package version automatically. Use -PackageVersion to override."
    }

    return "$($matches[1]).$($matches[2]).$($matches[3]).0"
}

function Save-StagedManifest {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$Version
    )

    [xml]$manifest = Get-Content -Raw -Path $SourcePath
    $manifest.Package.Identity.Version = $Version

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.IndentChars = '  '
    $settings.NewLineChars = "`r`n"
    $settings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)

    $writer = [System.Xml.XmlWriter]::Create($DestinationPath, $settings)
    try {
        $manifest.Save($writer)
    }
    finally {
        $writer.Dispose()
    }
}

function Find-WindowsSdkTool {
    param(
        [string]$ToolName,
        [string]$PreferredArchitecture = "x64"
    )

    $command = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $kitsRoot = "${env:ProgramFiles(x86)}\\Windows Kits\\10\\bin"
    if (-not (Test-Path $kitsRoot)) {
        return $null
    }

    $preferredPattern = Join-Path $kitsRoot "*\\$PreferredArchitecture\\$ToolName"
    $candidate = Get-ChildItem $preferredPattern -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($candidate) {
        return $candidate.FullName
    }

    $candidate = Get-ChildItem $kitsRoot -Recurse -Filter $ToolName -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($candidate) {
        return $candidate.FullName
    }

    return $null
}

function Ensure-CodeSigningCertificate {
    param(
        [string]$Subject,
        [string]$PfxPath,
        [string]$CerPath,
        [string]$Password
    )

    $existing = Get-ChildItem Cert:\\CurrentUser\\My |
        Where-Object { $_.Subject -eq $Subject } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $existing) {
        Write-Step "Creating self-signed code-signing certificate for $Subject"
        $existing = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $Subject `
            -KeyUsage DigitalSignature `
            -FriendlyName "Ironmesh Thumbnail Provider Dev" `
            -CertStoreLocation "Cert:\\CurrentUser\\My" `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")
    } else {
        Write-Step "Reusing existing certificate $($existing.Thumbprint)"
    }

    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

    Export-PfxCertificate -Cert $existing.PSPath -FilePath $PfxPath -Password $securePassword | Out-Null
    Export-Certificate -Cert $existing.PSPath -FilePath $CerPath | Out-Null

    $trusted = Get-ChildItem Cert:\\CurrentUser\\TrustedPeople |
        Where-Object { $_.Thumbprint -eq $existing.Thumbprint } |
        Select-Object -First 1
    if (-not $trusted) {
        Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\\CurrentUser\\TrustedPeople" | Out-Null
    }

    return $existing
}

function Ensure-LocalMachineTrustedPeopleCertificate {
    param(
        [string]$PfxPath,
        [string]$Password,
        [string]$Thumbprint
    )

    $existing = Get-ChildItem Cert:\\LocalMachine\\TrustedPeople -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $Thumbprint } |
        Select-Object -First 1
    if ($existing) {
        return
    }

    if (-not (Test-IsElevated)) {
        throw "Installing the MSIX package requires the signing certificate to be imported into Cert:\\LocalMachine\\TrustedPeople. Re-run this script from an elevated PowerShell when using -Install."
    }

    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    Import-PfxCertificate -FilePath $PfxPath -Password $securePassword -CertStoreLocation "Cert:\\LocalMachine\\TrustedPeople" | Out-Null
}

$repoRoot = Get-RepoRoot
$scriptDir = Split-Path -Parent $PSCommandPath
$manifestPath = Join-Path $scriptDir "AppxManifest.xml"
$assetsPath = Join-Path $scriptDir "Assets"
$outputRoot = Join-Path $scriptDir "out"
$stagePath = Join-Path $outputRoot "stage"
$cargoTargetDir = Join-Path $outputRoot "cargo-target"
$packageName = "IronMesh.msix"
$packagePath = Join-Path $outputRoot $packageName
$pfxPath = Join-Path $outputRoot "IronMesh.pfx"
$cerPath = Join-Path $outputRoot "IronMesh.cer"
$cargoVersion = Get-WorkspaceCargoVersion -RepoRoot $repoRoot
$resolvedPackageVersion = if ($PackageVersion) {
    $PackageVersion
} else {
    Convert-CargoVersionToPackageVersion -CargoVersion $cargoVersion
}

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
if (Test-Path $stagePath) {
    Remove-Item -Recurse -Force $stagePath
}
New-Item -ItemType Directory -Force -Path $stagePath | Out-Null

$cargoArgs = @(
    "build",
    "-p", "windows-thumbnail-provider",
    "-p", "os-integration",
    "-p", "ironmesh-folder-agent",
    "-p", "ironmesh-background-launcher",
    "-p", "ironmesh-config-app"
)
if ($Configuration -eq "release") {
    $cargoArgs += "--release"
}

Write-Step "Building windows-thumbnail-provider, os-integration, ironmesh-folder-agent, ironmesh-background-launcher, and ironmesh-config-app ($Configuration)"
if ($PackageVersion) {
    Write-Step "Using explicit package version $resolvedPackageVersion"
} else {
    Write-Step "Using package version $resolvedPackageVersion derived from workspace Cargo version $cargoVersion"
}
$env:CARGO_TARGET_DIR = $cargoTargetDir
Invoke-NativeChecked -FilePath "cargo" -Arguments $cargoArgs

$targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
$dllPath = Join-Path $cargoTargetDir "$targetDir\\windows_thumbnail_provider.dll"
$exePath = Join-Path $cargoTargetDir "$targetDir\\ironmesh-os-integration.exe"
$folderAgentPath = Join-Path $cargoTargetDir "$targetDir\\ironmesh-folder-agent.exe"
$backgroundLauncherPath = Join-Path $cargoTargetDir "$targetDir\ironmesh-background-launcher.exe"
$configAppPath = Join-Path $cargoTargetDir "$targetDir\ironmesh-config-app.exe"

if (-not (Test-Path $dllPath)) {
    throw "Expected DLL not found: $dllPath"
}
if (-not (Test-Path $exePath)) {
    throw "Expected EXE not found: $exePath"
}
if (-not (Test-Path $folderAgentPath)) {
    throw "Expected folder agent EXE not found: $folderAgentPath"
}
if (-not (Test-Path $backgroundLauncherPath)) {
    throw "Expected background launcher EXE not found: $backgroundLauncherPath"
}
if (-not (Test-Path $configAppPath)) {
    throw "Expected config app EXE not found: $configAppPath"
}

Write-Step "Staging package contents under $stagePath"
Save-StagedManifest -SourcePath $manifestPath -DestinationPath (Join-Path $stagePath "AppxManifest.xml") -Version $resolvedPackageVersion
Copy-Item $dllPath (Join-Path $stagePath "windows_thumbnail_provider.dll")
Copy-Item $exePath (Join-Path $stagePath "ironmesh-os-integration.exe")
Copy-Item $folderAgentPath (Join-Path $stagePath "ironmesh-folder-agent.exe")
Copy-Item $backgroundLauncherPath (Join-Path $stagePath "ironmesh-background-launcher.exe")
Copy-Item $configAppPath (Join-Path $stagePath "ironmesh-config-app.exe")
Copy-Item $assetsPath (Join-Path $stagePath "Assets") -Recurse

$makeAppx = Find-WindowsSdkTool -ToolName "MakeAppx.exe" -PreferredArchitecture $Architecture
$signTool = Find-WindowsSdkTool -ToolName "SignTool.exe" -PreferredArchitecture $Architecture

if ($StageOnly) {
    Write-Host ""
    Write-Host "Stage-only mode complete. Package contents are ready under:" -ForegroundColor Yellow
    Write-Host "  $stagePath"
    return
}

if (-not $makeAppx -or -not $signTool) {
    Write-Warning "SDK packaging tools are not fully available."
    Write-Host ""
    Write-Host "Staging complete. You can package manually from:" -ForegroundColor Yellow
    Write-Host "  $stagePath"
    Write-Host ""
    Write-Host "Missing tools:" -ForegroundColor Yellow
    if (-not $makeAppx) {
        Write-Host "  - MakeAppx.exe"
    }
    if (-not $signTool) {
        Write-Host "  - SignTool.exe"
    }
    Write-Host ""
    Write-Host "Install the Windows 10/11 SDK (MSIX packaging tools), then rerun this script without -StageOnly."
    return
}

if (Test-Path $packagePath) {
    Remove-Item -Force $packagePath
}

$certificate = Ensure-CodeSigningCertificate `
    -Subject $CertificateSubject `
    -PfxPath $pfxPath `
    -CerPath $cerPath `
    -Password $CertificatePassword

Write-Step "Packing MSIX with MakeAppx.exe"
Invoke-NativeChecked -FilePath $makeAppx -Arguments @("pack", "/o", "/h", "SHA256", "/d", $stagePath, "/p", $packagePath)

Write-Step "Signing package with SignTool.exe"
Invoke-NativeChecked -FilePath $signTool -Arguments @("sign", "/fd", "SHA256", "/f", $pfxPath, "/p", $CertificatePassword, $packagePath)

if ($Install) {
    Write-Step "Trusting development certificate for package installation"
    Ensure-LocalMachineTrustedPeopleCertificate `
        -PfxPath $pfxPath `
        -Password $CertificatePassword `
        -Thumbprint $certificate.Thumbprint

    Write-Step "Installing package"
    Add-AppxPackage -Path $packagePath -ForceApplicationShutdown
}

Write-Host ""
Write-Host "Package ready:" -ForegroundColor Green
Write-Host "  $packagePath"
Write-Host "Certificate:" -ForegroundColor Green
Write-Host "  $cerPath"
