# Windows CFAPI Thumbnail Provider Plan

Status: Design note plus initial fixed-bitmap prototype scaffold for Explorer thumbnails on dehydrated Ironmesh placeholders

Related notes:

- [Nextcloud CFAPI Behavior Reference](others/nextcloud-cfapi-behavior.md)
- [Windows MSIX Release And Update Strategy](windows-msix-release-update-strategy.md)

## Goal

- Show thumbnails in Windows Explorer for dehydrated Ironmesh placeholders without hydrating the full file.
- Reuse the existing Ironmesh remote thumbnail service instead of inventing a second thumbnail pipeline.
- Keep the current CFAPI provider responsible for namespace, placeholder creation, hydration, pinning, and upload.

## Key conclusion

- `wincs` helps with CFAPI sync-root registration, session management, placeholder helpers, and progress reporting.
- `wincs` does not solve Explorer thumbnail rendering for dehydrated placeholders by itself.
- Explorer thumbnail rendering is a separate Shell integration problem:
  - a packaged COM thumbnail handler,
  - registered through package manifest extensions,
  - returning thumbnail bitmaps without forcing full-file hydration.

In other words:

- keep `wincs` for CFAPI sync-root mechanics where it already helps,
- add a separate packaged thumbnail-provider component for dehydrated placeholder thumbnails.

## Current repo pieces we can already reuse

### Windows sync-root side

- `crates/adapter-windows-cfapi/src/runtime.rs`
  - creates placeholders and currently stores placeholder file identity as:
    - `path=<remote path>`
    - `version=<remote version>`
- `crates/adapter-windows-cfapi/src/connection_config.rs`
  - persists `.ironmesh-connection.json` inside the sync root
- `crates/adapter-windows-cfapi/src/auth.rs`
  - persists `.ironmesh-client-identity.json` inside the sync root

### Remote thumbnail side

- `crates/server-node-sdk/src/lib.rs`
  - exposes `/media/thumbnail` and `/auth/media/thumbnail`
- `crates/web-ui-backend/src/lib.rs`
  - already proxies `/media/thumbnail`
- `apps/android-app/app/src/main/java/io/ironmesh/android/saf/IronmeshDocumentsProvider.kt`
  - already streams remote thumbnails without hydrating the full object

This means the missing part is not thumbnail generation. The missing part is Windows Explorer integration.

## Recommended architecture

### 1. Keep the current CFAPI provider as-is for namespace + hydration

The existing `adapter-windows-cfapi` remains the sync-root provider:

- sync-root registration,
- placeholder creation,
- fetch-data hydration,
- upload/writeback,
- pin state,
- progress reporting.

Do not try to overload the CFAPI fetch-data path to answer thumbnail requests. That would defeat the goal by encouraging full hydration just to render a preview.

### 2. Add a separate Windows thumbnail handler

Add a new packaged Shell component that implements the Explorer thumbnail-provider contract for Ironmesh placeholders.

Responsibilities:

- receive a shell item/path for the placeholder,
- determine the Ironmesh key and version for that placeholder,
- load the connection bootstrap and client identity for the owning sync root,
- fetch the thumbnail from Ironmesh,
- return a bitmap to Explorer,
- cache the result locally.

### 3. Package the thumbnail handler with package identity

Use Windows package identity for the thumbnail handler registration.

Recommended rollout:

1. Development / prototype:
   - sparse package
   - external-location binaries stay where they are
   - package contains the thumbnail handler registration and COM server metadata
2. Production:
   - full MSIX package, or keep the sparse-package path if it remains operationally simpler

This is the main reason the feature is separate from `wincs`: the thumbnail handler lives in Explorer/Shell integration land, not only in CFAPI callback land.

## Repo shape recommendation

### New Rust core crate

Add a reusable core crate for thumbnail fetch logic:

- `crates/windows-thumbnail-core`

Suggested responsibilities:

- discover the sync root from a file path,
- load `.ironmesh-connection.json`,
- load `.ironmesh-client-identity.json`,
- parse placeholder file identity or derive the remote key from the path,
- build an authenticated `IronMeshClient`,
- call the existing thumbnail endpoint,
- cache thumbnail bytes and decode them into a bitmap-friendly form,
- provide structured errors for the shell layer.

This keeps Ironmesh-specific logic in Rust and shared with tests.

### New shell component

Add a Windows shell thumbnail-provider project:

- recommended shape:
  - `windows/thumbnail-provider/`

Current prototype files now in place:

- package scaffold:
  - `windows/thumbnail-provider/AppxManifest.xml`
  - `windows/thumbnail-provider/README.md`
- Rust COM DLL prototype:
  - `crates/windows-thumbnail-provider`

Recommended implementation style:

- thin native COM DLL boundary,
- minimal shell-specific code,
- delegate Ironmesh logic into `crates/windows-thumbnail-core`.

Reasoning:

- Windows Shell thumbnail providers are COM DLLs and the official Explorer extension guidance is COM-oriented.
- A small native shim is the lowest-risk path for Explorer integration.
- Pure Rust COM is possible, but it is a riskier first slice than a tiny shell shim plus Rust core logic.

## Metadata needs

### Smallest viable prototype

The current placeholder file identity is enough for an MVP:

- `path`
- `version`

That is sufficient because the thumbnail service already supports key-based lookup and optional version-qualified reads.

### Recommended hardening

Before calling the format stable, upgrade the placeholder identity format from the current ad-hoc newline text to a versioned structured shape.

Suggested fields:

- `format_version`
- `path`
- `version`
- `media_thumbnail_profile` default `grid`
- optional `content_fingerprint`
- optional `mime`

Reason:

- thumbnails are a second consumer of placeholder identity,
- future shell features may want more than `path` and `version`,
- a versioned format avoids fragile parsing later.

## Authentication and connection model

The thumbnail handler should not invent a second auth story.

Use the same local sync-root artifacts the CFAPI provider already persists:

- `.ironmesh-connection.json`
- `.ironmesh-client-identity.json`

Flow:

1. Resolve the selected placeholder path to its owning sync root.
2. Load the persisted connection bootstrap.
3. Load the persisted client identity.
4. Build `IronMeshClient`.
5. Request the existing thumbnail route.

This keeps direct-vs-relay behavior consistent with the rest of the Windows integration.

## Explorer integration details

### Preferred initialization style

Prefer a path/item-based thumbnail handler initialization path, not a stream-based one.

Reasoning:

- the whole point is to avoid opening the full placeholder content stream,
- a stream-based thumbnail handler increases the risk of accidental hydration,
- a path/item-based handler can inspect placeholder state and fetch the remote thumbnail side-channel instead.

This is an implementation recommendation, not a repo constraint yet.

### Local caching

Add a thumbnail cache under the user profile, for example:

- `%LocalAppData%\\Ironmesh\\thumbnail-cache`

Cache key should include:

- cluster id,
- remote path,
- remote version,
- thumbnail profile,
- requested size bucket.

That gives:

- stable reuse,
- automatic invalidation on version change,
- less Explorer-induced network pressure.

### Failure behavior

If remote thumbnail fetch fails:

- return `no thumbnail` rather than hydrating the full file,
- optionally fall back to normal file-type icon,
- log the failure with a rate limit.

Do not silently download the full file just to satisfy a thumbnail request.

## Minimal viable prototype

### Phase 1: shell plumbing

- create packaged thumbnail-provider COM DLL,
- register it in the package manifest,
- make it activate for the Ironmesh sync-root placeholders,
- return a fixed test bitmap.

Success criterion:

- Explorer loads the handler for Ironmesh placeholders without hydrating the file.

### Phase 2: Ironmesh wiring

- add `crates/windows-thumbnail-core`,
- locate sync-root bootstrap + identity,
- parse placeholder identity,
- request `/media/thumbnail`,
- decode and return the real thumbnail.

Success criterion:

- dehydrated image placeholder shows the remote Ironmesh thumbnail.

### Phase 3: caching + diagnostics

- local thumbnail cache,
- better logging,
- timeout budget,
- size/profile normalization,
- version-driven invalidation.

### Phase 4: richer metadata

- versioned placeholder identity format,
- optional content fingerprint,
- optional MIME/media hints,
- future support for more preview classes if needed.

## Testing plan

### Unit tests

- `windows-thumbnail-core`
  - bootstrap discovery from file path,
  - identity loading,
  - cache-key generation,
  - thumbnail fetch request building,
  - failure classification.

### Integration tests

- package-installed thumbnail provider loads for a registered Ironmesh sync root,
- dehydrated placeholder still reports dehydrated state after thumbnail fetch,
- remote thumbnail is shown without full-file hydration,
- cache invalidates when placeholder version changes.

### Manual validation

1. Register and serve an Ironmesh CFAPI sync root.
2. Materialize dehydrated placeholders for image files.
3. Open the directory in Explorer large-icon mode.
4. Confirm:
   - no full hydration occurs,
   - thumbnail appears,
   - repeated view uses cache,
   - relay-backed and direct-backed roots both work.

## Open points

- Whether the first shell component should be pure Rust COM or a tiny native shim plus Rust core.
- Whether sparse package is sufficient for all target deployment modes or only for development.
- Whether placeholder identity alone is enough in practice, or if the handler should sometimes derive metadata from the relative path plus current sync-root state instead.
- Whether the same package should also later host Windows shell extras like context-menu verbs or custom columns.

## Recommended next implementation step

Do not change the current CFAPI runtime first.

Instead:

1. create the packaged thumbnail-provider prototype returning a fixed bitmap,
2. confirm Explorer loads it for Ironmesh placeholders,
3. only then wire in `windows-thumbnail-core` and the existing remote thumbnail endpoint.

That gives a clean risk split:

- first prove the Shell registration path,
- then connect Ironmesh transport/auth logic,
- then optimize caching and metadata.

## Reference links

- Windows Cloud Files manifest extension overview:
  - https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/desktop-to-uwp-extensions
- `ThumbnailProviderHandler` manifest element:
  - https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-cloudfiles-thumbnailproviderhandler
- `IThumbnailProvider`:
  - https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailprovider
- Packaged File Explorer / shell extension guidance:
  - https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/integrate-packaged-app-with-file-explorer
- `wincs`:
  - https://github.com/ok-nick/wincs
