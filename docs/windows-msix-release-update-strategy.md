# Windows MSIX Release And Update Strategy

Status: Proposed packaging and update architecture for the first consumer Windows release through Microsoft Store

Related notes:

- [Windows CFAPI Thumbnail Provider Plan](windows-cfapi-thumbnail-provider-plan.md)
- [Windows CFAPI Registration And Reconnect Strategy](windows-cfapi-registration-reconnect-strategy.md)

## Summary

- Ship the Windows desktop product as a Store-submitted MSIX package.
- Use Microsoft Store and Partner Center as the primary distribution and update channel.
- Treat direct sideload packaging as a development-only path, not the primary consumer install path.
- Keep mutable runtime state outside the package so package replacement is safe and predictable.
- Design explicitly for the fact that Explorer may keep packaged shell-extension DLLs loaded across a Store-delivered update until Explorer restarts.

## Goals

- Support Windows-native discovery, install, signing, and updates through Microsoft Store.
- Avoid buying or operating a separate CA-trusted code-signing pipeline for Store MSIX submission.
- Preserve sync roots, client identity, caches, and local configuration across updates.
- Keep packaged Shell and Cloud Files integration compatible with Windows package identity requirements.
- Reuse the existing prototype MSIX path already present in this repo.

## Non-goals

- Building a separate MSI-only production path for the first release.
- Supporting unpackaged Explorer shell integration as the main consumer install shape.
- Implementing a custom self-updater that patches binaries in place.
- Using `.appinstaller` as the primary public update mechanism for the first release.

## Current repo starting point

The current repo already has the core pieces of the packaging direction we should keep:

- `windows/thumbnail-provider/AppxManifest.xml`
  - current packaged prototype identity, Cloud Files extension registration, and COM registrations.
- `windows/thumbnail-provider/Build-PrototypePackage.ps1`
  - current build, stage, sign, and install helper for local MSIX iteration.
- `windows/thumbnail-provider/README.md`
  - current manual install and reinstall workflow for the packaged prototype.
- `docs/windows-cfapi-thumbnail-provider-plan.md`
  - already concludes that packaged Windows shell integration should use sparse-package or full-MSIX identity.

This note extends that direction from "prototype package works" to "production release and update path is coherent."

## Packaging model

### 1. Stable package identity

The reserved Partner Center identity for this repo is now:

- `Name`: `UlrichHornung.IronMesh`
- `Publisher`: `CN=53536D7F-3E42-40F5-ACA9-B14F636B5B21`
- `PublisherDisplayName`: `Ulrich Hornung`

These values should now be treated as fixed production identity.

Historical prototype values were:

- current prototype `Name`: `Ironmesh.ThumbnailProvider.Prototype`
- current prototype `Publisher`: `CN=Ironmesh Dev`

Important consequences:

- MSIX update continuity depends on package identity stability.
- Store submission depends on the package identity matching the reserved Partner Center product identity exactly.
- `Name`, `Publisher`, application IDs, and shell COM CLSIDs should be treated as part of the product contract.
- certificate rotation is acceptable only if the manifest `Publisher` string remains unchanged and the new certificate matches it.
- the package install location is versioned and must be treated as ephemeral.

We should not persist absolute paths into `C:\Program Files\WindowsApps\...` or assume the installed package path stays constant across releases.

For this repo, the manifest should now carry the exact Partner Center identity values above.

### 2. Package contents

The production package should include at least:

- `os-integration.exe`
  - packaged full-trust host for Windows filesystem integration and status surface.
- `ironmesh-folder-agent.exe`
  - packaged folder synchronization agent so Windows installs can reuse the same helper binary without a second installer.
- `windows_thumbnail_provider.dll`
  - packaged COM DLL for thumbnail and related Cloud Files handlers.
- packaged visual assets and manifest metadata.

If additional Windows-only helpers are required later, they should either live in the same package or in a deliberately versioned packaged companion path. The first release should avoid splitting the Windows desktop product across multiple independently updating installers.

### 3. Out-of-package mutable state

Package upgrades must not be the place where user state lives.

Persist mutable state in the existing external locations instead:

- `%LocalAppData%\Ironmesh\sync-roots\...`
  - per-sync-root bootstrap, client identity, and related runtime state.
- `%LocalAppData%\Ironmesh\thumbnail-cache`
  - packaged thumbnail cache.
- `%LocalAppData%\Ironmesh\thumbnail-provider.log`
  - current prototype diagnostics.
- Windows sync-root registration metadata
  - root ownership and reconnect identity, as described in the CFAPI reconnect note.

That separation is what makes package replacement viable. An update should replace packaged code and registration metadata, not rewrite per-user sync state.

## Release artifacts

### First public slice

For the first release, keep the artifact set small:

- versioned Store submission package, preferably `.msixupload`
- one or more `.msix` or `.msixbundle` files inside that upload package
- Store listing assets and submission metadata in Partner Center

### Later expansion

When Windows on ARM becomes a target, switch from a single-architecture `.msix` to a signed `.msixbundle` while keeping the same package identity.

## Install channels

### 1. Primary consumer path: Microsoft Store

Recommended user-facing flow:

1. The user discovers Ironmesh in Microsoft Store or via the Store web listing.
2. Microsoft Store installs the published MSIX package.
3. Later updates are delivered through Microsoft Store.

This removes the need for a custom bootstrapper in the primary path.

### 2. Developer and CI path

The current PowerShell prototype workflow should remain available for development:

- build and stage local package contents,
- sign with a local development certificate,
- install with `Add-AppxPackage` for prototype iteration.

That path is for local verification, not the final end-user experience.

## Default update mechanism

### Why Microsoft Store should own updates

Microsoft Store already solves the parts we would otherwise have to reimplement badly:

- package signing for published MSIX/AppX packages,
- version comparison and staged replacement,
- catalog distribution and customer acquisition,
- Windows-native update delivery,
- rollout controls inside Partner Center.

That is a better fit than a custom self-updater, especially because the product includes packaged shell extensions.

### Normal release-to-update sequence

1. CI builds the next release binaries.
2. The release job stages the next Store submission package.
3. The new submission is uploaded to Partner Center.
4. Microsoft certification runs preprocessing, malware/security checks, technical compliance checks, and content compliance checks.
5. After certification passes, Microsoft signs the published MSIX/AppX packages.
6. The submission is published immediately or per the configured schedule.
7. Microsoft Store offers the new package version to customers.
8. Customer machines receive the update through Store-managed package replacement.
9. The next Ironmesh launch runs from the new package location automatically.

The package manager owns the code replacement. Ironmesh only needs to be restart-friendly and state-safe.

## Microsoft Store upload requirements

### Account setup

Before the first upload:

1. Start at `storedeveloper.microsoft.com`.
2. Create either an individual or company developer account.
3. Complete identity verification.
4. Wait for Partner Center access to become active.

Current Microsoft guidance says the new onboarding flow is free for both:

- individual developers,
- company developers.

Important account-type rule:

- use a company account if Ironmesh is being published in relation to a business, trade, profession, or business entity name.

For company accounts, Microsoft currently requires:

- business verification using either a D-U-N-S number or official business documents,
- contact and employment verification,
- a work email associated with the organization domain where possible.

For individual accounts, Microsoft currently requires:

- government-issued ID,
- selfie-based identity verification.

### Product identity and manifest matching

Before packaging for upload:

1. Reserve the app name in Partner Center.
2. Open the product identity page in Partner Center.
3. copy the exact values for:
   - `Package/Identity/Name`
   - `Package/Identity/Publisher`
   - `Package/Properties/PublisherDisplayName`
4. update the manifest to match those values exactly.

The values are case-sensitive and punctuation-sensitive. A mismatch here is a direct submission failure risk.

### Package format

Partner Center accepts:

- `.msix`
- `.msixupload`
- `.msixbundle`
- `.appx`
- `.appxupload`
- `.appxbundle`

For Windows 10 and Windows 11 desktop submissions, Microsoft recommends uploading `.msixupload` rather than the raw package alone.

Practical implication for this repo:

- the current PowerShell helper produces `.msix`, which is uploadable,
- but a Store-oriented build path should preferably also generate `.msixupload`, especially if we want better crash analytics symbol handling.

### Signing

For Store MSIX/AppX submission:

- you do not need a CA-trusted code-signing certificate,
- you do not need to buy or provide production PFX/CER material for Store distribution,
- Microsoft re-signs the published MSIX/AppX package after certification.

Important boundary:

- this applies to MSIX/AppX Store distribution,
- it does not apply to MSI/EXE installer submissions,
- it does not apply to local sideloading outside the Store.

### Package requirements

At upload time, the package must satisfy the Microsoft Store MSIX package rules, including:

- correct manifest schema,
- supported target device family,
- supported language declarations,
- SHA-256 block map hashes,
- package size within Store limits,
- version numbering compatible with Store rules.

Repo-specific version issue:

- the old prototype manifest used `Version="0.1.0.14"`,
- the packaging helpers now derive the Windows package version automatically from `[workspace.package].version` in the repo-root `Cargo.toml` as `major.minor.patch.0`,
- Windows Store package versions cannot start with `0`,
- Microsoft’s package requirements for Windows 10/11 Store packages reserve the fourth version segment for Store use,
- while the workspace Cargo version remains `0.1.0`, the automatically derived package version is `0.1.0.0`, which is not Store-compatible,
- Store-targeted builds should use versions such as `1.0.0.0` or `1.0.1.0`, not `0.1.0.14`, `0.1.1.0`, or `0.1.0.0`.

### Submission metadata required in Partner Center

The submission itself requires more than the package file.

Required or practically required fields include:

- Markets
- Audience
- Discoverability
- Schedule
- Base price or Free
- Category
- Age rating questionnaire
- At least one app package
- Store listing description
- At least one screenshot

Conditionally required fields that matter for Ironmesh:

- Privacy policy URL
  - required if the app collects or transmits personal information
- Contact details
  - required for company accounts
- Restricted capability justification
  - required if the app declares restricted capabilities

For this repo, the privacy policy item should be treated as required because Ironmesh handles user files, account identity, and networked synchronization. The current package also declares `runFullTrust`, so the restricted-capability explanation path should be expected.

### Certification notes likely required for Ironmesh

Ironmesh should assume the `Notes for certification` field is required in practice, even if Partner Center labels it optional.

Reason:

- the app requires server connectivity,
- the app likely requires login or bootstrap material,
- the app has packaged shell integration that testers will not discover automatically,
- the app may rely on capabilities that need explanation.

The certification notes should include:

- working test credentials or a test bootstrap path,
- instructions for launching the packaged host,
- instructions for creating or attaching a sync root,
- instructions for verifying Explorer thumbnail behavior,
- any expected differences between local, relay, or authenticated environments,
- what changed in updates,
- justification for restricted capabilities.

If Microsoft cannot actually test the app because the required backend or credentials are unavailable, certification can fail.

## Update-time behavior inside Ironmesh

### 1. Package version detection

The packaged host should record the last launched package version under `%LocalAppData%\Ironmesh\...`.

On startup:

1. read the current installed package version,
2. compare it with the last launched version marker,
3. if the version changed, run post-update handling.

This gives the app a reliable way to distinguish:

- normal launch,
- first launch after update,
- first launch after repair or reinstall.

### 2. Host restart assumptions

The first production design should assume short downtime during upgrade is acceptable.

That means:

- `os-integration.exe` should be able to shut down cleanly,
- external state should be sufficient for reconnect on the next launch,
- the host should not rely on in-memory-only registration state that would be lost during update.

This aligns with the existing reconnect direction: root identity lives in Windows sync-root registration metadata and per-sync-root bootstrap state lives in `%LocalAppData%`.

### 3. Relaunch path

Because Ironmesh is a background-style desktop integration host, the Windows package needs a defined relaunch story after update.

The product should provide one of these packaged relaunch mechanisms before general release:

- a packaged startup entry that launches the host at sign-in, or
- a deliberate relaunch path triggered after update completion.

The main requirement is simple: an update must not leave the user with a silently stopped sync-root host until they discover the Start menu entry themselves.

## Explorer and shell-extension update handling

### Why this is the special case

The packaged thumbnail provider and related Cloud Files handlers are COM DLLs loaded by Explorer and `dllhost.exe`.

That creates a packaging edge case:

- a new package version can be installed,
- but Explorer may continue using already-loaded shell-extension code from the old version until Explorer restarts or the user signs out.

This is normal Windows shell behavior, but it must be part of the product update design.

### Proposed product behavior

On first launch after an update:

1. detect whether shell-extension-bearing package content changed,
2. if yes, show a notification that Explorer restart is recommended,
3. offer a user-initiated `Restart Explorer now` action,
4. if the user declines, keep the old shell code active until Explorer restarts naturally or the user signs out.

The first implementation can be explicit and conservative. It does not need a complex hot-reload story.

### Host-only vs shell-code updates

Not every update needs the same user interruption.

- If only `os-integration.exe` changes and the packaged shell DLLs do not, restarting the host is sufficient.
- If any packaged shell COM DLL changes, Explorer restart guidance should be shown.

That split gives us a better user experience than forcing the same restart guidance for every release.

## Signing and trust model

### Development

The current self-signed local certificate workflow is fine for development and prototype sideloading.

### Production

For the public Store release path:

- keep the manifest `Publisher` string aligned with the Store product identity,
- avoid shipping any public artifact under the development identity,
- rely on Microsoft Store signing for the distributed MSIX/AppX package.

An update must look like "the next version of the same product" to Windows. Stable publisher identity is part of that.

## Winget position

`winget` is still a useful secondary distribution channel, but it should not drive the first release architecture.

Recommended position:

- primary consumer update path: Microsoft Store,
- secondary power-user channel: consider `winget` after the Store path is stable.

## Release pipeline outline

1. Create the Partner Center account and reserve the product name.
2. Pull the exact Store product identity values into the manifest.
3. Build `os-integration` and Windows shell binaries in release mode.
4. Stage a Store submission package and generate `.msixupload`.
5. Fill the required Partner Center metadata: listing, screenshots, age rating, privacy policy, markets, pricing, and certification notes.
6. Submit to certification.
7. Smoke-test the first Store-published build on a clean machine.
8. Submit a follow-up update with a higher version and verify Store-driven upgrade behavior.
9. Verify that sync roots reconnect cleanly after update.
10. Verify whether the update needs host restart only or also Explorer restart guidance.

## Repo-specific implementation checklist

### Packaging foundation

- replace prototype package identity with stable production values,
- decide on the final package name and display name,
- keep CLSIDs and application IDs stable,
- generalize the current prototype packaging script into a Store submission build path,
- change the package version format so the fourth segment is `0` for Store builds.

### Store submission path

- add `.msixupload` generation,
- expose a build mode that swaps in the exact Partner Center identity values,
- keep a dedicated Store helper script separate from the local sideload helper,
- prepare Store listing assets and submission notes,
- define how release versions map to Partner Center submissions.

### Update coordination

- add package-version change detection in the packaged host,
- add graceful host shutdown for update windows,
- add post-update relaunch behavior,
- add Explorer restart guidance for shell-DLL updates.

### Validation

- test clean install,
- test Store-delivered update with the host running,
- test update while Explorer has loaded the thumbnail provider,
- test reconnect and thumbnail behavior after update,
- test that no code path depends on a version-specific package install path.

## Open decisions

- Whether the first public release should ship only `x64` or also `arm64`.
- Whether the first launch after update should offer automatic Explorer restart or only manual guidance.

## Recommended near-term order

1. Create the Store product and lock the final Partner Center identity.
2. Update the manifest and build pipeline for Store-compatible identity and versioning.
3. Add `.msixupload` generation and submission metadata preparation.
4. Add package-version detection and post-update UX in the packaged host.
5. Add `winget` only after the Store path has been proven end to end.