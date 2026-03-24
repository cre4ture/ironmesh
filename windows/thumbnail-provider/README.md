# Ironmesh Windows Thumbnail Provider Prototype

This folder holds the first packaged Explorer thumbnail-provider prototype for Ironmesh CFAPI placeholders.

Current status:

- the COM DLL implementation lives in `crates/windows-thumbnail-provider`
- it implements:
  - `IInitializeWithItem`
  - `IThumbnailProvider`
  - `IClassFactory`
- it currently returns a fixed Ironmesh-branded bitmap without hydrating the placeholder
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
5. Restart Explorer.
6. Open an Ironmesh sync root in large-icon view and confirm that dehydrated placeholders use the fixed thumbnail.

## Important note

This repo currently does not include a fully automated MSIX/sparse-package build pipeline for the prototype yet.

That is intentional for this first slice:

- first prove that Explorer loads the thumbnail handler at all,
- then wire in real Ironmesh thumbnail fetching,
- then automate packaging/install.
