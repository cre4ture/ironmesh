# Cross-platform filesystem integration strategy

## Goals

- Provide first-class file-manager integration on Windows, Ubuntu Linux, and Android.
- Reuse as much code as possible across platforms.
- Keep platform-specific code limited to OS API adapters.
- Support placeholder-first UX (on-demand hydration) where supported.

## Non-goals (MVP)

- Perfect parity of all OS-specific shell features in the first release.
- Bi-directional real-time sync with advanced conflict UI.
- Offline-first writeback queue with full resume semantics.

## Platform targets

### Windows

- Integration API: Cloud Files API (CFAPI) sync root.
- UX target: OneDrive-like placeholder files, hydration on open, pin/unpin semantics.
- Adapter responsibilities:
  - Register/unregister sync root.
  - Map CFAPI callbacks to core operations.
  - Report hydration/progress/status to shell.

### Ubuntu Linux

- Integration API: FUSE mount (primary).
- UX target: mountpoint visible to all apps and file managers.
- Adapter responsibilities:
  - Implement directory/file metadata operations.
  - Hydrate file data on read.
  - Route writes/renames/deletes to core engine.
- Future option: GNOME GVfs or KDE KIO backend for tighter shell UX.

### Android

- Integration API: `DocumentsProvider`.
- UX target: browse/open/save via system document picker.
- Adapter responsibilities:
  - Translate `query*` / `openDocument` operations.
  - Use shared base URL + auth configuration.
  - Route metadata and IO through shared core contracts.

## Clean code-reuse model

Use a layered architecture:

1. `sync-core` (platform-agnostic Rust crate)
   - Sync domain model.
   - Reconciliation planner.
   - Conflict policy.
   - Pin/hydration semantics.
2. `transport-client` (existing `client-sdk` + wrappers)
   - Remote object listing/metadata/content operations.
3. Platform adapters
   - `adapter-windows-cfapi` (future)
   - `adapter-linux-fuse` (future)
   - `adapter-android-docs` (existing Kotlin provider now, Rust bridge future)

### Design rule

If logic can be expressed without OS handles/callback types, it must live in `sync-core`.

## Functional requirements

- Stable namespace model (`path`, type, content hash/version, modified time).
- Deterministic reconciliation decisions from local + remote snapshots.
- Conflict detection (concurrent divergent local/remote versions).
- Pin state support:
  - `Unpinned` -> placeholder allowed.
  - `Pinned` -> keep hydrated locally.
- Hydration/dehydration planning independent of OS API.
- Explicit operation list output for adapters to execute.

## Non-functional requirements

- Deterministic planning for testability.
- No OS-specific dependencies in `sync-core`.
- Bounded memory use for large trees (streaming-friendly model in later phase).
- Structured errors with categories (`Conflict`, `Auth`, `Unavailable`, `InvalidState`).

## MVP scope

MVP focuses on a reusable planner and operation model.

Deliverables:

- New crate: `crates/sync-core`.
- Domain types for entries, local/remote snapshots, pin state, hydration state.
- Reconciliation planner producing generic sync operations.
- Unit tests for deterministic behavior and conflict paths.
- Documentation of adapter mapping strategy.

Out of scope for MVP:

- Windows CFAPI callback implementation.
- Linux FUSE mount implementation.
- Android Rust bridge wiring.

## Planned phase sequence

1. MVP (this change): shared planner + tests.
2. Linux pilot: `adapter-linux-fuse` read-only mount using planner metadata decisions.
3. Windows pilot: sync root registration + read/hydrate callback path.
4. Android alignment: map `DocumentsProvider` operations to the same planner contracts.
5. Shared writeback queue + conflict resolution UX.

## Adapter mapping notes

- `EnsurePlaceholder`:
  - Windows: cloud placeholder file metadata update.
  - Linux FUSE: represent as virtual inode with lazy read.
  - Android: metadata row with file entry; open triggers hydration.
- `Hydrate`:
  - Windows: `FETCH_DATA` callback fulfillment.
  - Linux: perform fetch during `read` path.
  - Android: fetch in `openDocument` for read.
- `Upload`:
  - Windows: upload on close/commit callback.
  - Linux: upload on flush/fsync boundary.
  - Android: upload pipe contents on write close.

## Acceptance criteria for MVP

- `sync-core` compiles on stable Rust.
- Planner output is deterministic for identical inputs.
- Tests cover:
  - Remote-only file -> hydrate/placeholder behavior.
  - Local-only file -> upload behavior.
  - Divergent local+remote -> conflict behavior.
  - Pin policy changes operation choice.

## Implementation status

- Completed:
  - `crates/sync-core` with deterministic reconciliation planner + unit tests.
  - `crates/adapter-linux-fuse` skeleton mapping `sync-core` operations to Linux/FUSE-oriented actions.
- Next step:
  - Replace skeleton action execution with concrete FUSE callback handling in a dedicated runtime crate/module.
