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
- if the server has no thumbnail or the request fails permanently, the provider now lets Explorer keep the normal file-type icon instead of replacing it with a dummy bitmap
- if the thumbnail request fails transiently, the provider returns a retry-later shell status so Explorer can ask again
- it also registers a Cloud Files Explorer context-menu verb named `Cancel Hydration` for active placeholder hydrations
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
- `ironmesh-config-app.exe`
- `ironmesh-background-launcher.exe`
- `windows_thumbnail_provider.dll`
- `ironmesh-os-integration.exe`
- `ironmesh-folder-agent.exe`
- `Assets/SmallLogo.png`
- `Assets/StoreLogo.png`

The manifest now exposes the packaged `ironmesh-config-app.exe` as the visible user-facing entry point, registers `ironmesh-background-launcher.exe` as the login-time startup task, and keeps `ironmesh-os-integration.exe` plus `ironmesh-folder-agent.exe` as hidden packaged full-trust entry points.

For normal packaged-client testing, start IronMesh through the packaged config app and define instances there first. The direct `ironmesh-os-integration.exe serve ...` flow below remains useful when you need low-level CFAPI or thumbnail-provider verification.

## Typical manual prototype flow

1. Build the DLL:
   - `cargo build -p windows-thumbnail-provider`
2. Build the host executable:
   - `cargo build -p os-integration`
3. Copy the outputs into a package staging folder next to `AppxManifest.xml`.
4. Register/install the package using your normal Windows packaging workflow.
5. Unregister any existing unpackaged Ironmesh sync root registration for the test root.
6. Re-register and serve the sync root using the packaged `ironmesh-os-integration.exe` from the installed package location, not the repo-local `target\debug\ironmesh-os-integration.exe`.
   - Example PowerShell:
   - `$pkg = Get-AppxPackage UlrichHornung.IronMesh`
   - `$exe = Join-Path $pkg.InstallLocation 'ironmesh-os-integration.exe'`
     - `& $exe serve --sync-root-id <id> --display-name <name> --root-path <path> --bootstrap-file <bootstrap-json>`
   - The first run uses `--bootstrap-file` to seed `%LocalAppData%\Ironmesh\sync-roots\...`.
   - Later runs for the same sync root can omit `--bootstrap-file`.
7. Restart Explorer.
8. Open an Ironmesh sync root in large-icon view and confirm that dehydrated placeholders use the real server thumbnail when available.
9. If a file type has no generated thumbnail yet, expect Explorer's normal file-type icon rather than an Ironmesh-branded fallback image.
10. If you intentionally trigger a long-running hydration for testing, right-click the active placeholder and use `Cancel Hydration`.

Why this matters:

- the thumbnail handler is registered as a packaged Cloud Files extension
- installing the package does not retroactively convert an already-running unpackaged sync-root registration into a packaged one
- if the sync root is still being served by `target\debug\ironmesh-os-integration.exe`, Explorer may continue using the old unpackaged registration path and never call the prototype thumbnail provider

## Important note

This repo currently does not include a fully automated MSIX/sparse-package build pipeline for the prototype yet.

For the planned production release and update path, see [../../docs/windows-msix-release-update-strategy.md](../../docs/windows-msix-release-update-strategy.md).

That is still intentionally incremental:

- Explorer must load the packaged thumbnail handler
- the handler should return real thumbnails for supported media without hydrating placeholders
- unsupported or unavailable thumbnails should degrade cleanly to Explorer's normal iconography
- packaging/install remains script-driven for now

## Helper script

There is now a PowerShell helper at `windows/thumbnail-provider/Build-PrototypePackage.ps1`.

Typical usage:

1. Stage only:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -StageOnly`
2. Build, pack, sign, and install:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Install`
3. Override the package version explicitly if needed:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -PackageVersion 1.0.2.0 -Install`

The helper will:

- build `windows-thumbnail-provider`
- build `os-integration`
- build `ironmesh-folder-agent`
- build `ironmesh-background-launcher`
- build `ironmesh-config-app`
- stage `AppxManifest.xml`, `Assets`, `windows_thumbnail_provider.dll`, `ironmesh-os-integration.exe`, `ironmesh-folder-agent.exe`, `ironmesh-background-launcher.exe`, and `ironmesh-config-app.exe`
- if the Windows SDK tools are installed, also:
  - create/reuse a self-signed developer certificate
  - generate an `.msix`
  - sign it
  - optionally install it with `Add-AppxPackage -ForceApplicationShutdown`
  - after `-Install`, start the packaged background launcher once so the config app owns desktop status immediately

Notes:

- the helper auto-discovers `MakeAppx.exe` and `SignTool.exe` under `C:\Program Files (x86)\Windows Kits\10\bin` even if they are not on `PATH`
- `-StageOnly` is the safest way to verify the prototype package contents today
- by default the helper derives the package version from `[workspace.package].version` in the repo-root `Cargo.toml` as `major.minor.patch.0`
- full `.msix` packing and signing now work on a machine with the Windows SDK tools available
- `-Install` is optional and may require both the usual Windows developer/sideloading settings and an elevated PowerShell so the self-signed cert can be imported into `Cert:\LocalMachine\TrustedPeople`
- pass `-NoStartAfterInstall` with `-Install` if you want to install the package without starting the background config app immediately

## Store upload helper

There is now a separate PowerShell helper for Partner Center upload packaging at `windows/thumbnail-provider/Build-StoreUploadPackage.ps1`.

Typical usage:

1. Build a Store upload package using the workspace Cargo version automatically:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-StoreUploadPackage.ps1`
2. Override the package version for a release build:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-StoreUploadPackage.ps1 -PackageVersion 1.0.2.0`
3. Also include raw PDBs in `.appxsym` for Partner Center crash analytics:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-StoreUploadPackage.ps1 -PackageVersion 1.0.2.0 -IncludePdbSymbols`

The helper will:

- build `windows-thumbnail-provider`, `os-integration`, `ironmesh-folder-agent`, `ironmesh-background-launcher`, and `ironmesh-config-app` in release mode
- stage the Store manifest, assets, DLL, and EXEs
- create an `.msix`
- sign the `.msix` with a local self-signed certificate matching the Store publisher by default
- create a `.msixupload` archive for Partner Center

Outputs land under `windows/thumbnail-provider/out/store-upload/<identity>_<version>_x64/`.

Notes:

- the script is focused on the current `x64` Store release path
- by default the helper derives the package version from `[workspace.package].version` in the repo-root `Cargo.toml` as `major.minor.patch.0`
- Store-compatible versioning must keep the first segment at `1` or higher and the fourth segment at `0`, for example `1.0.2.0`
- if the workspace Cargo version still starts with `0`, automatic Store upload packaging will fail until you either bump Cargo to `1.x.y` or pass `-PackageVersion`
- the script uses an isolated cargo target directory for each run so stale artifact locks do not block packaging
- `-SkipSigning` leaves the package unsigned for upload-only scenarios; local installation will not work until the package is signed
- `-IncludePdbSymbols` packages raw PDBs into `.appxsym`; use that only if you are comfortable uploading private symbol information
- the script prepares the upload artifact only; Partner Center metadata, screenshots, age ratings, privacy policy, and certification notes still have to be filled manually

## Install and Reinstall Workflow

Use this when iterating on the thumbnail provider DLL, the manifest, or the packaged `ironmesh-os-integration.exe`.

1. Build, pack, sign, and install from an elevated PowerShell:
   - `powershell -ExecutionPolicy Bypass -File .\windows\thumbnail-provider\Build-PrototypePackage.ps1 -Install`
2. The helper starts the packaged background launcher after install. To inspect or start the Explorer host manually from the installed package location:
   - `$pkg = Get-AppxPackage UlrichHornung.IronMesh`
   - `$exe = Join-Path $pkg.InstallLocation 'ironmesh-os-integration.exe'`
   - `& $exe serve --sync-root-id <id> --display-name <name> --root-path <path> --bootstrap-file <bootstrap-json>`
   - After that first successful run, the packaged host will reuse the canonical `%LocalAppData%\Ironmesh\sync-roots\...` bootstrap and client identity for the same sync root.
3. If you changed any packaged content and Windows reports `0x80073CFB`, bump the package version in `windows/thumbnail-provider/AppxManifest.xml`:
   - update `<Identity ... Version="...">` using Store-compatible versioning such as `0.1.1.0`
   - reinstall with the helper script
4. If Windows reports `0x80073D02`, the installed package is still loaded by Explorer, `dllhost.exe`, or the packaged `ironmesh-os-integration.exe`:
   - the helper now installs with `Add-AppxPackage -ForceApplicationShutdown`, which is usually enough
   - if that still fails, stop the packaged host if it is running, restart Explorer, and rerun the helper
   - example fallback:
     - `Stop-Process -Name explorer -Force`
     - `Start-Process explorer.exe`
5. After a successful reinstall, start the packaged `ironmesh-os-integration.exe` again from the installed package location before testing Explorer integration.
6. For manual hydration cancellation without Explorer, you can also use the packaged or local CLI:
   - `ironmesh-os-integration cancel-hydration --root-path <sync-root> --path <relative-or-absolute-path>`
   - the command succeeds only while that placeholder currently has an active hydration in flight

Why the version bump matters:

- Windows treats `Name + Publisher + Version` as the package identity
- reinstalling different contents under the same identity is blocked
- increasing the version is the normal way to publish the next local prototype build

## Diagnostics

The prototype DLL now writes a simple log file to:

- `%LocalAppData%\Ironmesh\thumbnail-provider.log`

Useful signals:

- if `thumbnail-provider version=... build_revision=...` appears there, you are looking at the current DLL build
- if `thumbnail-auth ... auth_mode=client-identity ...` appears there, the handler found and used a persisted client identity
- if `thumbnail-auth ... identity_state=missing auth_mode=anonymous ...` appears there, the handler did not find a persisted client identity and will likely fail against auth-required servers
- if `thumbnail-auth ... identity_state=load-error ...` appears there, the handler found an identity candidate but could not load it successfully
- if `GetThumbnail` appears there, Explorer is loading the packaged thumbnail handler
- if `thumbnail-fetch remote_key=...` appears there, the handler successfully resolved a sync root, built a client, and downloaded thumbnail bytes from the server
- if `GetThumbnail source=error ... error_kind=failed-extraction ...` appears there, the handler declined to provide a thumbnail and Explorer should keep the normal icon or other shell fallback
- if `GetThumbnail source=error ... error_kind=extraction-pending ...` appears there, the handler treated the failure as temporary and asked Explorer to retry later
- if `CancelHydration requested=... skipped=... failures=...` appears there, Explorer invoked the packaged context-menu verb and the handler attempted to raise cancel requests for the selected placeholders
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
