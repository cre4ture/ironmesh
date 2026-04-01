# Apple filesystem integration sketch

## Purpose

This document is the implementation sketch for bringing IronMesh to Apple platforms, with:

1. `File Provider` on both macOS and iOS/iPadOS as the shared primary track.
2. `folder-agent + Finder Sync` as the lowest-priority fallback/MVP track only if File Provider is blocked.

There is no active `WebDAV` track in the current Apple plan.

This is intended as an in-repo handoff document for a macOS development machine running Codex Agent.

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
- Existing object-identity direction:
  - Server-side `object_id` already exists in storage and version APIs.
  - Current `/store/index` / `StoreIndexEntry` responses are still path-centric and do not yet expose `object_id`.

The current `apps/ios-app` crate is already useful as a thin Rust-side API surface for Apple host apps. It accepts either direct base URLs or bootstrap JSON plus optional client identity material, which is the right starting point for Apple platform shells.

The existing Windows CFAPI adapter is also useful as an architectural precedent. It already covers several concerns that are similar in spirit to Apple File Provider work:

- sync planning and adapter action mapping
- live hydrator/uploader abstraction boundaries
- remote refresh via `client-sdk::RemoteSnapshotPoller`
- persisted bootstrap and client identity artifacts for an OS-facing integration

The CFAPI-specific shell callbacks and placeholder APIs are Windows-only, but the surrounding shape is relevant.

## Decided implementation direction

These decisions are already made for the Apple track:

- `File Provider` is the only active Apple integration track right now.
- Apple native/Xcode project files should live inside this repo, under `apps/apple-*` style paths rather than in an external-only Xcode workspace.
- The initial Swift <-> Rust bridge should use a static library with a manual C ABI and `cbindgen`.
- Do not use `UniFFI` in the initial Apple slice.
- File Provider item identity should be designed around durable remote object identity rather than treating path text as the long-term identifier model.
- Because current `/store/index` responses do not expose `object_id`, the Apple-facing metadata/list contract must be extended before the File Provider identifier scheme is finalized.
- For the initial Apple slice:
  - file item IDs should use durable remote file identity where available
  - directory item IDs may be path-derived temporarily
  - do not require directory-marker objects ending in `/` to exist as the source of directory identity

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
- Keep Apple native app/extension project files inside this repo under `apps/apple-*`.
- Add Apple-facing methods for:
  - enumerate directory/prefix contents
  - stat one item
  - fetch object bytes or stream ranges
  - create/update/delete/move objects
  - report conflict-friendly metadata, including durable identity where available
- Prefer a narrow manual C ABI boundary with a thin Objective-C/Swift wrapper rather than exposing low-level Rust internals directly to Swift.

### Priority 2: Quick macOS MVP via `folder-agent + Finder Sync`

This is the lowest-priority track right now.

Why it stays on the list:

- It is likely the fastest way to ship a basic native-feeling macOS integration if File Provider is blocked.
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

## Reuse from Windows CFAPI

The existing Windows adapter is similar enough to be useful, but only at the shared-service and adapter-shape level.

Reusable ideas and code patterns:

- sync planning and action mapping from `sync-core`
- thin OS adapter over shared Rust transport/object logic
- hydrator/uploader split with live `client-sdk` wiring
- remote refresh integration via `RemoteSnapshotPoller`
- persisted bootstrap and client identity handling for an OS-facing integration

Not reusable as-is:

- CFAPI registration/callback APIs
- Windows shell-specific placeholder/dehydrate/pin behavior
- the current Windows placeholder identity format (`path + version`) as the long-term Apple identity model

Treat the Windows adapter as a precedent for a thin native integration layer over shared Rust services, not as a source of Apple-specific shell code.

## Recommended sequence

### Phase 1: Shared Apple File Provider foundation

1. Stand up in-repo Apple native project structure for both platforms:
   - macOS host app + File Provider extension
   - iOS host app + File Provider extension
   - shared app-group storage model where appropriate
2. Add a static-library + C-ABI bridge from `apps/ios-app`, generated with `cbindgen`.
3. Define one shared Apple-side config and Rust facade contract for both platforms.
4. Extend the Apple-facing list/stat surface to expose file `object_id` before locking the File Provider item-identifier scheme.
5. Use path-derived IDs for directory entries temporarily, without depending on explicit directory-marker objects.
6. Keep as much extension logic shared as practical, with only platform lifecycle glue split natively.

### Phase 2: File Provider read path on both platforms

1. Implement read-only namespace enumeration for macOS and iOS/iPadOS.
2. Implement on-demand fetch/hydration for both.
3. Validate:
   - Finder visibility and file open on macOS
   - Files app visibility and file open on iOS/iPadOS
4. Confirm the same Rust facade and identity model are serving both extension targets cleanly.

### Phase 3: File Provider write path on both platforms

1. Implement create/modify/delete.
2. Implement rename/move.
3. Add remote refresh integration using the same `client-sdk` notification/polling patterns already proven in Linux and Windows where practical.
4. Add conflict handling and progress/cancellation reporting.
5. Validate security-scoped URL workflows from other apps on iOS/iPadOS and normal Finder workflows on macOS.

### Phase 4: Finder Sync fallback only if needed

1. Pair folder-agent with a synced local root.
2. Add Finder badges and menu actions.
3. Use only if the File Provider track is blocked or delayed.

## Suggested first tasks on the macOS machine

1. Create the in-repo Apple host app + File Provider extension targets for both macOS and iOS/iPadOS.
2. Confirm app-group persistence and Rust static-library loading for the shared Apple facade.
3. Add `cbindgen`-based header generation and a thin Objective-C/Swift wrapper layer.
4. Extend `apps/ios-app` with a narrow facade for:
   - list children
   - stat item
   - fetch bytes
   - put bytes
   - delete item
   - move item
   - return durable identity metadata needed for File Provider
5. Get read-only File Provider enumeration and file open working on both macOS and iOS/iPadOS before tackling writes.

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

Apple-facing metadata/list responses should carry the fields that the extension needs directly, rather than forcing Swift to reconstruct them from raw server payloads. In particular:

- path
- entry kind
- size / modified time
- revision/version hints
- durable file `object_id` when available
- temporary path-derived directory identifier
- conflict-friendly state metadata as needed for the extension UI, for example:
  - canonical state such as `clean`, `pending_upload`, or `conflicted`
  - conflict reason codes such as modify/modify or modify/delete
  - preferred revision/head information
  - optional alternate/conflicting revision identifiers
  - optional conflict-copy/reference path if IronMesh materializes one

## Key design rules

- Keep Apple extension code thin and mostly native lifecycle glue.
- Keep transport, object operations, and conflict policy in Rust where possible.
- Prefer one shared Apple architecture across macOS and iOS.
- Treat File Provider support for macOS and iOS/iPadOS as one shared top-priority initiative.
- Use a static library + manual C ABI with `cbindgen` for the initial Swift <-> Rust bridge.
- Keep Apple native project files inside this repo.
- Expose durable identity through the Apple-facing metadata/list contract instead of treating path text as the final File Provider identifier model.
- Accept temporary path-derived IDs for directories until the server exposes first-class durable directory identity.
- Keep conflict detection, authoritative conflict state, and conflict reason codes in Rust.
- Keep native Apple code responsible for presentation only:
  - badges
  - localized strings
  - File Provider-specific affordances
  - host-app / extension UI timing and rendering
- Reuse generic patterns from the Windows CFAPI adapter where they fit, but do not try to reuse Windows shell glue directly.
- Keep Finder Sync clearly positioned as fallback-only.

## Open questions for implementation

- Exact in-repo Apple project layout under `apps/apple-*`:
  - single Xcode project with shared packages/targets
  - or split macOS/iOS project structure with shared source packages

## Source notes

This priority order is based on current Apple platform guidance:

- `File Provider` is the modern Apple-supported model across macOS and iOS/iPadOS.
- Apple's iOS File Provider guidance explicitly builds on the macOS model and notes that the iOS sample extension is mostly unchanged from the macOS version.
- The existing Windows CFAPI adapter is a useful precedent for shared hydrator/uploader/refresh/config patterns, but not for Apple shell APIs directly.

Relevant external references:

- Apple: `Sync files to the cloud with FileProvider on macOS`
- Apple: `Bring desktop class sync to iOS with FileProvider`
- Apple: `NSFileProviderReplicatedExtension`
