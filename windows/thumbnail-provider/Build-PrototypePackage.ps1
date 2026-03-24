param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",
    [string]$Architecture = "x64",
    [switch]$StageOnly,
    [switch]$Install,
    [string]$CertificateSubject = "CN=Ironmesh Dev",
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

function Get-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir "..\\..")).Path
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
}

$repoRoot = Get-RepoRoot
$scriptDir = Split-Path -Parent $PSCommandPath
$manifestPath = Join-Path $scriptDir "AppxManifest.xml"
$assetsPath = Join-Path $scriptDir "Assets"
$outputRoot = Join-Path $scriptDir "out"
$stagePath = Join-Path $outputRoot "stage"
$cargoTargetDir = Join-Path $outputRoot "cargo-target"
$packageName = "IronmeshThumbnailProviderPrototype.msix"
$packagePath = Join-Path $outputRoot $packageName
$pfxPath = Join-Path $outputRoot "IronmeshThumbnailProviderPrototype.pfx"
$cerPath = Join-Path $outputRoot "IronmeshThumbnailProviderPrototype.cer"

New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null
if (Test-Path $stagePath) {
    Remove-Item -Recurse -Force $stagePath
}
New-Item -ItemType Directory -Force -Path $stagePath | Out-Null

$cargoArgs = @("build", "-p", "windows-thumbnail-provider", "-p", "os-integration")
if ($Configuration -eq "release") {
    $cargoArgs += "--release"
}

Write-Step "Building windows-thumbnail-provider and os-integration ($Configuration)"
$env:CARGO_TARGET_DIR = $cargoTargetDir
Invoke-NativeChecked -FilePath "cargo" -Arguments $cargoArgs

$targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
$dllPath = Join-Path $cargoTargetDir "$targetDir\\windows_thumbnail_provider.dll"
$exePath = Join-Path $cargoTargetDir "$targetDir\\os-integration.exe"

if (-not (Test-Path $dllPath)) {
    throw "Expected DLL not found: $dllPath"
}
if (-not (Test-Path $exePath)) {
    throw "Expected EXE not found: $exePath"
}

Write-Step "Staging package contents under $stagePath"
Copy-Item $manifestPath (Join-Path $stagePath "AppxManifest.xml")
Copy-Item $dllPath (Join-Path $stagePath "windows_thumbnail_provider.dll")
Copy-Item $exePath (Join-Path $stagePath "os-integration.exe")
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

Ensure-CodeSigningCertificate `
    -Subject $CertificateSubject `
    -PfxPath $pfxPath `
    -CerPath $cerPath `
    -Password $CertificatePassword

Write-Step "Packing MSIX with MakeAppx.exe"
Invoke-NativeChecked -FilePath $makeAppx -Arguments @("pack", "/o", "/h", "SHA256", "/d", $stagePath, "/p", $packagePath)

Write-Step "Signing package with SignTool.exe"
Invoke-NativeChecked -FilePath $signTool -Arguments @("sign", "/fd", "SHA256", "/f", $pfxPath, "/p", $CertificatePassword, $packagePath)

if ($Install) {
    Write-Step "Installing package"
    Add-AppxPackage -Path $packagePath
}

Write-Host ""
Write-Host "Package ready:" -ForegroundColor Green
Write-Host "  $packagePath"
Write-Host "Certificate:" -ForegroundColor Green
Write-Host "  $cerPath"
