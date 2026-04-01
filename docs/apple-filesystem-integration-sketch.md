# Apple filesystem integration sketch

## Purpose

This document is the implementation sketch for bringing IronMesh to Apple platforms, with:

1. `File Provider` on both macOS and iOS/iPadOS as the shared primary track.
2. `WebDAV` mount support on macOS as the secondary track.
3. `folder-agent + Finder Sync` as the lowest-priority fallback/MVP track.

This is intended as a handoff document for a macOS development machine running Codex Agent.

## Current repo state

- Existing Apple client stub:
  - `apps/ios-app/src/lib.rs`
- Existing shared transport and sync building blocks:
  - `crates/client-sdk`
  - `crates/sync-core`
  - `crates/sync-agent-core`
  - `apps/ironmesh-folder-agent`
- Existing platform integration patterns:
  - Android: `DocumentsProvider`
  - Linux: FUSE adapter
  - Windows: CFAPI adapter

The current `apps/ios-app` crate is already useful as a thin Rust-side API surface for Apple host apps. It accepts either direct base URLs or bootstrap JSON plus optional client identity material, which is the right starting point for Apple platform shells.

## Priority order

### Priority 1: File Provider

This is the main Apple-platform strategy.

This priority explicitly covers both macOS and iOS/iPadOS together. It is not intended to mean "macOS first, then iOS later as a lesser follow-up." The shared File Provider architecture across both Apple platforms is the primary deliverable.

Why this is first:

- It is the Apple-supported cloud-files integration model for both macOS and iOS/iPadOS.
- It is the closest Apple equivalent to IronMesh's existing Android `DocumentsProvider` and Windows CFAPI work.
- It supports the right UX class:
  - Finder / Files visibility
  - on-demand hydration
  - system-managed local copies and eviction
  - background upload/download scheduling
- It offers the best shared architecture across macOS and iOS.

What this should become:

- A native Apple host app for account/bootstrap setup.
- A File Provider extension using the modern replicated model.
- A thin native-to-Rust bridge so the extension can call shared IronMesh transport and sync logic.

Practical architecture:

1. Native Apple shell
   - Swift/SwiftUI host app.
   - Collect server/bootstrap config, trust roots, and client identity material.
   - Persist those settings in an app-group container shared with the extension.
   - Register one `NSFileProviderDomain` per configured IronMesh account/root.

2. File Provider extension
   - Use `NSFileProviderReplicatedExtension`.
   - Implement:
     - item enumeration
     - metadata lookup
     - fetch/hydrate on read
     - create/modify/delete
     - rename/move
     - remote refresh signaling
   - Keep extension logic thin; push transport/object operations into Rust.

3. Rust bridge layer
   - Reuse `client-sdk` for:
     - bootstrap-aware transport
     - object fetch/upload
     - remote index enumeration
   - Reuse `sync-core` concepts where they help with reconciliation and conflict policy.
   - Add a focused Apple-facing Rust facade rather than exposing low-level crate internals directly to Swift.

Suggested repo direction:

- Keep `apps/ios-app` as the Rust facade crate for Apple clients/extensions.
- Add Apple-facing methods for:
  - enumerate directory/prefix contents
  - stat one item
  - fetch object bytes or stream ranges
  - create/update/delete/move objects
  - report conflict-friendly metadata
- Keep native extension glue outside the Rust workspace if needed, in an Xcode project on the macOS machine.

### Priority 2: WebDAV mount on macOS

This is the secondary track, mainly for macOS.

Why this is second:

- Finder can mount WebDAV servers directly, which gives a familiar mount-style UX.
- It may be faster to get something usable on macOS than a full File Provider implementation.
- It is a good backup path if File Provider extension work is blocked by entitlement, lifecycle, or API complexity.

Why it is not first:

- It does not give a shared Apple-platform story with iOS the way File Provider does.
- It is a different UX class from Apple's modern cloud-file model.
- It is less aligned with IronMesh's existing placeholder/hydration-oriented adapter work.

What this should become:

- A small authenticated WebDAV frontend backed by IronMesh object/index APIs.
- A macOS Finder-connectable endpoint for browsing, opening, editing, renaming, and deleting files.

Suggested implementation shape:

1. Add a WebDAV server mode
   - Prefer a new Rust crate or a server module, for example:
     - `crates/webdav-server` or
     - `apps/os-integration` WebDAV mode
   - Map WebDAV methods onto existing IronMesh operations:
     - `PROPFIND` -> directory listing / metadata
     - `GET` -> object fetch
     - `PUT` -> upload/overwrite
     - `MKCOL` -> directory marker creation
     - `MOVE` -> rename/move
     - `DELETE` -> delete subtree/object

2. Authentication model
   - Reuse bootstrap/client identity material where practical.
   - Support a simple local authenticated endpoint first.
   - Decide whether the endpoint is:
     - local-only helper started by the app, or
     - remote-capable service exposure

3. macOS UX
   - Document Finder connection flow.
   - Validate behavior with larger files, save-in-place, package files, rename/move, and conflict cases.

Important scope note:

- Treat WebDAV as a macOS path unless iOS support is explicitly validated later.
- Do not let WebDAV dictate the core Apple architecture.

### Priority 3: Quick macOS MVP via `folder-agent + Finder Sync`

This is the lowest-priority track right now.

Why it stays on the list:

- It is likely the fastest way to ship a basic native-feeling macOS integration if both File Provider and WebDAV are blocked.
- It can reuse the existing `apps/ironmesh-folder-agent` work with relatively little backend change.

Why it is lowest priority:

- It is macOS-only.
- It does not provide true File Provider semantics.
- Finder Sync adds shell polish, not the cloud-files substrate itself.

What it would look like:

- Use `apps/ironmesh-folder-agent` to sync a normal local folder.
- Add a Finder Sync extension for:
  - badges
  - context menu actions
  - status affordances
- Accept that local disk usage, hydration, and placeholder behavior are much less elegant than File Provider.

## Recommended sequence

### Phase 1: Shared Apple File Provider foundation

1. Stand up Apple native project structure for both platforms:
   - macOS host app + File Provider extension
   - iOS host app + File Provider extension
   - shared app-group storage model where appropriate
2. Bridge both host apps/extensions to `apps/ios-app` Rust functionality.
3. Define one shared Apple-side config and Rust facade contract for both platforms.
4. Keep as much extension logic shared as practical, with only platform lifecycle glue split natively.

### Phase 2: File Provider read path on both platforms

1. Implement read-only namespace enumeration for macOS and iOS/iPadOS.
2. Implement on-demand fetch/hydration for both.
3. Validate:
   - Finder visibility and file open on macOS
   - Files app visibility and file open on iOS/iPadOS
4. Confirm the same Rust facade is serving both extension targets cleanly.

### Phase 3: File Provider write path on both platforms

1. Implement create/modify/delete.
2. Implement rename/move.
3. Add remote refresh integration.
4. Add conflict handling and progress/cancellation reporting.
5. Validate security-scoped URL workflows from other apps on iOS/iPadOS and normal Finder workflows on macOS.

### Phase 4: WebDAV backup path on macOS

1. Build a small local WebDAV frontend.
2. Validate Finder mount flow and file operations.
3. Keep it available as a fallback/debugging/degraded-access path.

### Phase 5: Finder Sync fallback only if needed

1. Pair folder-agent with a synced local root.
2. Add Finder badges and menu actions.
3. Use only if the higher-priority paths are blocked or delayed.

## Suggested first tasks on the macOS machine

1. Create the Apple host app + File Provider extension targets in Xcode for both macOS and iOS/iPadOS.
2. Confirm app-group persistence and Rust bridge loading for the shared Apple facade.
3. Extend `apps/ios-app` with a narrow facade for:
   - list children
   - stat item
   - fetch bytes
   - put bytes
   - delete item
   - move item
4. Get read-only File Provider enumeration and file open working on both macOS and iOS/iPadOS before tackling writes.

## Suggested Rust facade surface

The Apple extension should not need to understand the full server/client internals. Prefer a small facade with request/response structs tailored to extension work.

Example responsibilities:

- `connect(config)`
- `list(path_or_item_id)`
- `metadata(path_or_item_id)`
- `download(path, revision_hint)`
- `upload(path, bytes, expected_revision)`
- `mkdir(path)`
- `delete(path, expected_revision)`
- `move(from, to, expected_revision)`
- `poll_or_refresh(cursor)`

## Key design rules

- Keep Apple extension code thin and mostly native lifecycle glue.
- Keep transport, object operations, and conflict policy in Rust where possible.
- Prefer one shared Apple architecture across macOS and iOS.
- Treat File Provider support for macOS and iOS/iPadOS as one shared top-priority initiative.
- Do not optimize for a pure mount UX on macOS at the expense of the File Provider plan.
- Keep WebDAV clearly positioned as secondary.
- Keep Finder Sync clearly positioned as fallback-only.

## Open questions for implementation

- Exact Swift <-> Rust bridge mechanism:
  - static library via `cbindgen` / C ABI
  - uniffi
  - another FFI layer
- Whether to keep Apple native project files outside this repo initially or add them under `apps/apple-*`.
- Whether File Provider item identifiers should be path-derived or based on durable remote object IDs.
- How much of conflict state should be represented natively versus surfaced from Rust.
- Whether WebDAV should run as:
  - app-launched localhost service, or
  - reusable server-node mode

## Source notes

This priority order is based on current Apple platform guidance:

- `File Provider` is the modern Apple-supported model across macOS and iOS/iPadOS.
- Apple's iOS File Provider guidance explicitly builds on the macOS model and notes that the iOS sample extension is mostly unchanged from the macOS version.
- WebDAV remains useful on macOS as a mount-style fallback, but it is not the primary shared-platform strategy.

Relevant external references:

- Apple: `Sync files to the cloud with FileProvider on macOS`
- Apple: `Bring desktop class sync to iOS with FileProvider`
- Apple: `NSFileProviderReplicatedExtension`
- Apple: Finder WebDAV support documentation
