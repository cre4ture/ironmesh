# Ironmesh Windows Thumbnail Provider Prototype

This folder holds the first packaged Explorer thumbnail-provider prototype for Ironmesh CFAPI placeholders.

Current status:

- the COM DLL implementation lives in `crates/windows-thumbnail-provider`
- it implements:
  - `IInitializeWithItem`
  - `IThumbnailProvider`
  - `IClassFactory`
- it now tries to fetch the real media thumbnail for the placeholder's remote object without hydrating the placeholder itself
- it uses the sync root registration plus per-sync-root state under `%LocalAppData%\Ironmesh\sync-roots\...` for the persisted connection bootstrap and client identity
- if the server has no thumbnail, the sync root is not fully configured, or the thumbnail request fails, it falls back to the fixed Ironmesh-branded bitmap
- the package scaffold in this folder is the Explorer/MSIX side of the prototype

## Files

- `AppxManifest.xml`
  - package manifest scaffold registering the thumbnail handler COM class and Cloud Files thumbnail-provider handler
- `Assets/`
  - minimal package logo assets for the prototype package

## Prototype CLSID

- `{D2E0FD2A-1D7B-4BE4-920A-8A6D019454CB}`

This must stay aligned with:

- `crates/windows-thumbnail-provider/src/lib.rs`

## Expected package layout

The prototype package root should contain at least:

- `AppxManifest.xml`
- `windows_thumbnail_provider.dll`
- `os-integration.exe`
- `Assets/SmallLogo.png`
- `Assets/StoreLogo.png`

The manifest currently points the `Application` executable at `os-integration.exe` because that binary already represents the Windows filesystem integration surface in this repo.

## Typical manual prototype flow

1. Build the DLL:
   - `cargo build -p windows-thumbnail-provider`
2. Build the host executable:
   - `cargo build -p os-integration`
3. Copy the outputs into a package staging folder next to `AppxManifest.xml`.
4. Register/install the package using your normal Windows packaging workflow.
5. Unregister any existing unpackaged Ironmesh sync root registration for the test root.
6. Re-register and serve the sync root using the packaged `os-integration.exe` from the installed package location, not the repo-local `target\debug\os-integration.exe`.
   - Example PowerShell:
     - `$pkg = Get-AppxPackage Ironmesh.ThumbnailProvider.Prototype`
     - `$exe = Join-Path $pkg.InstallLocation 'os-integration.exe'`
     - `& $exe serve --sync-root-id <id> --display-name <name> --root-path <path> --bootstrap-file <bootstrap-json>`
   - The first run uses `--bootstrap-file` to seed `%LocalAppData%\Ironmesh\sync-roots\...`.
   - Later runs for the same sync root can omit `--bootstrap-file`.
7. Restart Explorer.
8. Open an Ironmesh sync root in large-icon view and confirm that dehydrated placeholders use the real server thumbnail when available.
9. If a file type has no generated thumbnail yet, expect the fallback Ironmesh-branded bitmap instead.

Why this matters:

- the thumbnail handler is registered as a packaged Cloud Files extension
- installing the package does not retroactively convert an already-running unpackaged sync-root registration into a packaged one
- if the sync root is still being served by `target\debug\os-integration.exe`, Explorer may continue using the old unpackaged registration path and never call the prototype thumbnail provider

## Important note

This repo currently does not include a fully automated MSIX/sparse-package build pipeline for the prototype yet.

That is still intentionally incremental:

- Explorer must load the packaged thumbnail handler
- the handler should return real thumbnails for supported media without hydrating placeholders
- unsupported or unavailable thumbnails should degrade cleanly to the branded fallback
- packaging/install remains script-driven for now

## Helper script

There is now a PowerShell helper at `windows/thumbnail-provider/Build-PrototypePackage.ps1`.

Typical usage:

1. Stage only:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -StageOnly`
2. Build, pack, sign, and install:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Install`

The helper will:

- build `windows-thumbnail-provider`
- build `os-integration`
- stage `AppxManifest.xml`, `Assets`, `windows_thumbnail_provider.dll`, and `os-integration.exe`
- if the Windows SDK tools are installed, also:
  - create/reuse a self-signed developer certificate
  - generate an `.msix`
  - sign it
  - optionally install it with `Add-AppxPackage -ForceApplicationShutdown`

Notes:

- the helper auto-discovers `MakeAppx.exe` and `SignTool.exe` under `C:\Program Files (x86)\Windows Kits\10\bin` even if they are not on `PATH`
- `-StageOnly` is the safest way to verify the prototype package contents today
- full `.msix` packing and signing now work on a machine with the Windows SDK tools available
- `-Install` is optional and may require both the usual Windows developer/sideloading settings and an elevated PowerShell so the self-signed cert can be imported into `Cert:\LocalMachine\TrustedPeople`

## Install and Reinstall Workflow

Use this when iterating on the thumbnail provider DLL, the manifest, or the packaged `os-integration.exe`.

1. Build, pack, sign, and install from an elevated PowerShell:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Install`
2. Start the packaged host from the installed package location:
   - `$pkg = Get-AppxPackage Ironmesh.ThumbnailProvider.Prototype`
   - `$exe = Join-Path $pkg.InstallLocation 'os-integration.exe'`
   - `& $exe serve --sync-root-id <id> --display-name <name> --root-path <path> --bootstrap-file <bootstrap-json>`
   - After that first successful run, the packaged host will reuse the canonical `%LocalAppData%\Ironmesh\sync-roots\...` bootstrap and client identity for the same sync root.
3. If you changed any packaged content and Windows reports `0x80073CFB`, bump the package version in `windows/thumbnail-provider/AppxManifest.xml`:
   - update `<Identity ... Version="...">`
   - reinstall with the helper script
4. If Windows reports `0x80073D02`, the installed package is still loaded by Explorer, `dllhost.exe`, or the packaged `os-integration.exe`:
   - the helper now installs with `Add-AppxPackage -ForceApplicationShutdown`, which is usually enough
   - if that still fails, stop the packaged host if it is running, restart Explorer, and rerun the helper
   - example fallback:
     - `Stop-Process -Name explorer -Force`
     - `Start-Process explorer.exe`
5. After a successful reinstall, start the packaged `os-integration.exe` again from the installed package location before testing Explorer integration.

Why the version bump matters:

- Windows treats `Name + Publisher + Version` as the package identity
- reinstalling different contents under the same identity is blocked
- increasing the version is the normal way to publish the next local prototype build

## Diagnostics

The prototype DLL now writes a simple log file to:

- `%LocalAppData%\Ironmesh\thumbnail-provider.log`

Useful signals:

- if `GetThumbnail` appears there, Explorer is loading the packaged thumbnail handler
- if `thumbnail-fetch remote_key=...` appears there, the handler successfully resolved a sync root, built a client, and downloaded thumbnail bytes from the server
- if `GetThumbnail source=fallback ... error=...` appears there, the handler could not produce a real thumbnail and used the branded fallback instead
- if the log stays empty while browsing a dehydrated placeholder folder in large-icon view, the packaged handler is still not being invoked

## What you need installed for MSIX

Already available on most Windows developer machines:

- PowerShell `Add-AppxPackage`
- PowerShell certificate cmdlets like `New-SelfSignedCertificate`

Still required for packaging/signing if they are missing:

- Windows 10 or Windows 11 SDK
  - specifically the MSIX packaging tools:
    - `MakeAppx.exe`
    - `SignTool.exe`

Useful official docs:

- MakeAppx tool:
  - <https://learn.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool>
- Create a signing certificate:
  - <https://learn.microsoft.com/en-us/windows/msix/package/create-certificate-package-signing>

If the SDK tools are not installed yet, the helper still gives you a ready-to-package staging folder under `windows/thumbnail-provider/out/stage`.
