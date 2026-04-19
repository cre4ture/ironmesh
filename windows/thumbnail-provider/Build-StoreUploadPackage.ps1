param(
    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string]$PackageVersion,
    [ValidateSet('x64')]
    [string]$Architecture = 'x64',
    [switch]$SkipSigning,
    [switch]$IncludePdbSymbols,
    [string]$CertificateSubject = 'CN=53536D7F-3E42-40F5-ACA9-B14F636B5B21',
    [string]$CertificatePassword = 'ironmesh-store-upload'
)

$ErrorActionPreference = 'Stop'
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
        throw ("Command failed with exit code {0}: {1} {2}" -f $LASTEXITCODE, $FilePath, ($Arguments -join ' '))
    }
}

function Get-RepoRoot {
    $scriptDir = Split-Path -Parent $PSCommandPath
    return (Resolve-Path (Join-Path $scriptDir '..\..')).Path
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
        throw "Cargo workspace version '$CargoVersion' must be a plain semantic version like 1.0.0 to derive an MSIX package version automatically. Use -PackageVersion to override."
    }

    return "$($matches[1]).$($matches[2]).$($matches[3]).0"
}

function Reset-Directory {
    param([string]$Path)

    if (Test-Path $Path) {
        Remove-Item -Recurse -Force $Path
    }

    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Find-WindowsSdkTool {
    param(
        [string]$ToolName,
        [string]$PreferredArchitecture = 'x64'
    )

    $command = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    if (-not (Test-Path $kitsRoot)) {
        return $null
    }

    $preferredPattern = Join-Path $kitsRoot "*\$PreferredArchitecture\$ToolName"
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

    $existing = Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $Subject } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if (-not $existing) {
        Write-Step "Creating self-signed code-signing certificate for $Subject"
        $existing = New-SelfSignedCertificate `
            -Type Custom `
            -Subject $Subject `
            -KeyUsage DigitalSignature `
            -FriendlyName 'IronMesh Store Upload Dev' `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3')
    }
    else {
        Write-Step "Reusing existing certificate $($existing.Thumbprint)"
    }

    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

    Export-PfxCertificate -Cert $existing.PSPath -FilePath $PfxPath -Password $securePassword | Out-Null
    Export-Certificate -Cert $existing.PSPath -FilePath $CerPath | Out-Null

    $trusted = Get-ChildItem Cert:\CurrentUser\TrustedPeople |
        Where-Object { $_.Thumbprint -eq $existing.Thumbprint } |
        Select-Object -First 1
    if (-not $trusted) {
        Import-Certificate -FilePath $CerPath -CertStoreLocation 'Cert:\CurrentUser\TrustedPeople' | Out-Null
    }

    return $existing
}

function Get-ManifestIdentity {
    param([string]$ManifestPath)

    [xml]$manifest = Get-Content -Raw -Path $ManifestPath
    return [pscustomobject]@{
        Name = [string]$manifest.Package.Identity.Name
        Publisher = [string]$manifest.Package.Identity.Publisher
        Version = [string]$manifest.Package.Identity.Version
        PublisherDisplayName = [string]$manifest.Package.Properties.PublisherDisplayName
    }
}

function Assert-StoreVersion {
    param([string]$Version)

    if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "Package version must have four numeric segments, for example 0.1.1.0"
    }

    $parts = $Version.Split('.') | ForEach-Object { [int]$_ }
    if ($parts.Count -ne 4) {
        throw "Package version must have four numeric segments"
    }

    if ($parts[0] -lt 1) {
        throw "Package version '$Version' is not Store-compatible. The first segment must be at least 1, for example 1.0.1.0"
    }

    foreach ($part in $parts) {
        if ($part -lt 0 -or $part -gt 65535) {
            throw "Each package version segment must be between 0 and 65535"
        }
    }

    if ($parts[3] -ne 0) {
        throw "Package version '$Version' is not Store-compatible. The fourth segment must be 0, for example 1.0.1.0"
    }
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

function Resolve-BuildArtifact {
    param(
        [string]$ReleaseDir,
        [string]$PrimaryFileName,
        [string[]]$FallbackPatterns = @()
    )

    $primaryPath = Join-Path $ReleaseDir $PrimaryFileName
    if (Test-Path $primaryPath) {
        return $primaryPath
    }

    $depsDir = Join-Path $ReleaseDir 'deps'
    if (-not (Test-Path $depsDir)) {
        return $null
    }

    foreach ($pattern in $FallbackPatterns) {
        $candidate = Get-ChildItem $depsDir -Filter $pattern -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1
        if ($candidate) {
            return $candidate.FullName
        }
    }

    return $null
}

function New-AppxSymArchive {
    param(
        [string[]]$PdbPaths,
        [string]$DestinationPath
    )

    if (-not $PdbPaths -or $PdbPaths.Count -eq 0) {
        return $false
    }

    $stagePath = Join-Path (Split-Path -Parent $DestinationPath) 'appxsym-stage'
    $zipPath = [System.IO.Path]::ChangeExtension($DestinationPath, '.zip')

    Reset-Directory -Path $stagePath
    foreach ($pdbPath in $PdbPaths) {
        Copy-Item $pdbPath $stagePath
    }

    if (Test-Path $zipPath) {
        Remove-Item -Force $zipPath
    }
    if (Test-Path $DestinationPath) {
        Remove-Item -Force $DestinationPath
    }

    Compress-Archive -Path (Join-Path $stagePath '*') -DestinationPath $zipPath -CompressionLevel Optimal
    Move-Item $zipPath $DestinationPath
    Remove-Item -Recurse -Force $stagePath
    return $true
}

function New-MsixUploadArchive {
    param(
        [string]$PackagePath,
        [string]$AppxSymPath,
        [string]$DestinationPath
    )

    $stagePath = Join-Path (Split-Path -Parent $DestinationPath) 'msixupload-stage'
    $zipPath = [System.IO.Path]::ChangeExtension($DestinationPath, '.zip')

    Reset-Directory -Path $stagePath
    Copy-Item $PackagePath $stagePath
    if ($AppxSymPath -and (Test-Path $AppxSymPath)) {
        Copy-Item $AppxSymPath $stagePath
    }

    if (Test-Path $zipPath) {
        Remove-Item -Force $zipPath
    }
    if (Test-Path $DestinationPath) {
        Remove-Item -Force $DestinationPath
    }

    Compress-Archive -Path (Join-Path $stagePath '*') -DestinationPath $zipPath -CompressionLevel Optimal
    Move-Item $zipPath $DestinationPath
    Remove-Item -Recurse -Force $stagePath
}

$repoRoot = Get-RepoRoot
$scriptDir = Split-Path -Parent $PSCommandPath
$manifestPath = Join-Path $scriptDir 'AppxManifest.xml'
$assetsPath = Join-Path $scriptDir 'Assets'
$identity = Get-ManifestIdentity -ManifestPath $manifestPath
$cargoVersion = Get-WorkspaceCargoVersion -RepoRoot $repoRoot
$defaultPackageVersion = Convert-CargoVersionToPackageVersion -CargoVersion $cargoVersion

$resolvedVersion = if ($PackageVersion) { $PackageVersion } else { $defaultPackageVersion }
if ($PackageVersion) {
    Write-Step "Using explicit package version $resolvedVersion"
    Assert-StoreVersion -Version $resolvedVersion
}
else {
    Write-Step "Using package version $resolvedVersion derived from workspace Cargo version $cargoVersion"
    try {
        Assert-StoreVersion -Version $resolvedVersion
    }
    catch {
        throw "Workspace Cargo version '$cargoVersion' maps to package version '$resolvedVersion'. $($_.Exception.Message) Either bump [workspace.package].version or pass -PackageVersion to override for Store upload packaging."
    }
}

$outputRoot = Join-Path $scriptDir 'out\store-upload'
$artifactName = '{0}_{1}_{2}' -f $identity.Name, $resolvedVersion, $Architecture
$artifactRoot = Join-Path $outputRoot $artifactName
$stagePath = Join-Path $artifactRoot 'stage'
$cargoTargetDir = Join-Path $artifactRoot ('cargo-target-' + [Guid]::NewGuid().ToString('N'))
$packagePath = Join-Path $artifactRoot ($artifactName + '.msix')
$uploadPath = Join-Path $artifactRoot ($artifactName + '.msixupload')
$appxSymPath = Join-Path $artifactRoot ($artifactName + '.appxsym')
$pfxPath = Join-Path $artifactRoot ($artifactName + '.pfx')
$cerPath = Join-Path $artifactRoot ($artifactName + '.cer')

New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
New-Item -ItemType Directory -Force -Path $cargoTargetDir | Out-Null
Reset-Directory -Path $stagePath

foreach ($path in @($packagePath, $uploadPath, $appxSymPath, $pfxPath, $cerPath)) {
    if (Test-Path $path) {
        Remove-Item -Force $path
    }
}

$makeAppx = Find-WindowsSdkTool -ToolName 'MakeAppx.exe' -PreferredArchitecture $Architecture
if (-not $makeAppx) {
    throw 'MakeAppx.exe was not found. Install the Windows 10/11 SDK MSIX packaging tools first.'
}

$signTool = $null
if (-not $SkipSigning) {
    $signTool = Find-WindowsSdkTool -ToolName 'SignTool.exe' -PreferredArchitecture $Architecture
    if (-not $signTool) {
        throw 'SignTool.exe was not found. Install the Windows 10/11 SDK or rerun with -SkipSigning if you only need an upload artifact.'
    }
}

Write-Step 'Building windows-thumbnail-provider, os-integration, ironmesh-folder-agent, ironmesh-background-launcher, and ironmesh-config-app (release)'
$env:CARGO_TARGET_DIR = $cargoTargetDir
Invoke-NativeChecked -FilePath 'cargo' -Arguments @('build', '-p', 'windows-thumbnail-provider', '-p', 'os-integration', '-p', 'ironmesh-folder-agent', '-p', 'ironmesh-background-launcher', '-p', 'ironmesh-config-app', '--release')

$releaseDir = Join-Path $cargoTargetDir 'release'
$dllPath = Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'windows_thumbnail_provider.dll' -FallbackPatterns @('windows_thumbnail_provider-*.dll')
$exePath = Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-os-integration.exe' -FallbackPatterns @('ironmesh_os_integration-*.exe', 'ironmesh-os-integration-*.exe')
$folderAgentPath = Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-folder-agent.exe' -FallbackPatterns @('ironmesh_folder_agent-*.exe', 'ironmesh-folder-agent-*.exe')
$backgroundLauncherPath = Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-background-launcher.exe' -FallbackPatterns @('ironmesh_background_launcher-*.exe', 'ironmesh-background-launcher-*.exe')
$configAppPath = Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-config-app.exe' -FallbackPatterns @('ironmesh_config_app-*.exe', 'ironmesh-config-app-*.exe')
$pdbCandidates = @(
    Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'windows_thumbnail_provider.pdb' -FallbackPatterns @('windows_thumbnail_provider-*.pdb')
    Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-os-integration.pdb' -FallbackPatterns @('ironmesh_os_integration-*.pdb', 'ironmesh-os-integration-*.pdb')
    Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-folder-agent.pdb' -FallbackPatterns @('ironmesh_folder_agent-*.pdb', 'ironmesh-folder-agent-*.pdb')
    Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-background-launcher.pdb' -FallbackPatterns @('ironmesh_background_launcher-*.pdb', 'ironmesh-background-launcher-*.pdb')
    Resolve-BuildArtifact -ReleaseDir $releaseDir -PrimaryFileName 'ironmesh-config-app.pdb' -FallbackPatterns @('ironmesh_config_app-*.pdb', 'ironmesh-config-app-*.pdb')
) | Where-Object { Test-Path $_ }

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

Write-Step 'Staging Store package contents'
Save-StagedManifest -SourcePath $manifestPath -DestinationPath (Join-Path $stagePath 'AppxManifest.xml') -Version $resolvedVersion
Copy-Item $dllPath (Join-Path $stagePath 'windows_thumbnail_provider.dll')
Copy-Item $exePath (Join-Path $stagePath 'ironmesh-os-integration.exe')
Copy-Item $folderAgentPath (Join-Path $stagePath 'ironmesh-folder-agent.exe')
Copy-Item $backgroundLauncherPath (Join-Path $stagePath 'ironmesh-background-launcher.exe')
Copy-Item $configAppPath (Join-Path $stagePath 'ironmesh-config-app.exe')
Copy-Item $assetsPath (Join-Path $stagePath 'Assets') -Recurse

Write-Step 'Packing MSIX with MakeAppx.exe'
Invoke-NativeChecked -FilePath $makeAppx -Arguments @('pack', '/o', '/h', 'SHA256', '/d', $stagePath, '/p', $packagePath)

if ($SkipSigning) {
    Write-Warning 'Skipping MSIX signing. The output is intended for Partner Center upload, not local installation.'
}
else {
    $null = Ensure-CodeSigningCertificate `
        -Subject $CertificateSubject `
        -PfxPath $pfxPath `
        -CerPath $cerPath `
        -Password $CertificatePassword

    Write-Step 'Signing MSIX with SignTool.exe'
    Invoke-NativeChecked -FilePath $signTool -Arguments @('sign', '/fd', 'SHA256', '/f', $pfxPath, '/p', $CertificatePassword, $packagePath)
}

$createdAppxSym = $false
if ($IncludePdbSymbols) {
    if ($pdbCandidates.Count -eq 0) {
        Write-Warning 'No PDB files were found in the release output. Skipping .appxsym generation.'
    }
    else {
        Write-Warning 'Including raw PDB files in .appxsym. This may expose private symbol information.'
        Write-Step 'Creating .appxsym archive from release PDBs'
        $createdAppxSym = New-AppxSymArchive -PdbPaths $pdbCandidates -DestinationPath $appxSymPath
    }
}

Write-Step 'Creating .msixupload archive'
New-MsixUploadArchive -PackagePath $packagePath -AppxSymPath $(if ($createdAppxSym) { $appxSymPath } else { $null }) -DestinationPath $uploadPath

Write-Host ''
Write-Host 'Store upload package ready:' -ForegroundColor Green
Write-Host "  $uploadPath"
Write-Host 'MSIX payload:' -ForegroundColor Green
Write-Host "  $packagePath"
if ($createdAppxSym) {
    Write-Host '.appxsym payload:' -ForegroundColor Green
    Write-Host "  $appxSymPath"
}
elseif ($IncludePdbSymbols) {
    Write-Host '.appxsym payload:' -ForegroundColor Yellow
    Write-Host '  requested but not created'
}

if ($SkipSigning) {
    Write-Host 'Signing:' -ForegroundColor Yellow
    Write-Host '  skipped for upload-only artifact generation'
}
else {
    Write-Host 'Signing certificate:' -ForegroundColor Green
    Write-Host "  $cerPath"
}

Write-Host ''
Write-Host 'Next steps:' -ForegroundColor Yellow
Write-Host '  1. Upload the .msixupload file to Partner Center.'
Write-Host '  2. Fill Store metadata, screenshots, privacy policy, and age rating.'
Write-Host '  3. Add certification notes for login, backend access, sync-root setup, and runFullTrust usage.'