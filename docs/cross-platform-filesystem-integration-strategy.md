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
- Future shell enhancement track: packaged Explorer thumbnail provider for dehydrated placeholders.
  - See `docs/windows-cfapi-thumbnail-provider-plan.md`.
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
  - `adapter-windows-cfapi` (next)
  - `adapter-linux-fuse` (implemented MVP runtime)
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
2. Linux pilot: `adapter-linux-fuse` mount with live hydration, write-through, and local-edge support. ✅
3. Windows pilot: sync root registration + read/hydrate callback path. ✅
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
  - `crates/adapter-linux-fuse` runtime with Linux FUSE mount support.
  - Linux `os-integration` mount CLI with three modes:
    - `--snapshot-file` static snapshot mode.
    - `--server-base-url` live namespace/hydration/write-through mode via `server-node` APIs.
    - `--local-edge` embedded local-edge mode with persistent local storage and upstream sync.
  - CI artifact publication for Ubuntu mount binary (`linux-fuse-mount-binary-ubuntu`).
  - `crates/adapter-windows-cfapi` runtime with:
    - sync-root registration + placeholder creation,
    - fetch-data hydration callbacks backed by `server-node`,
    - periodic remote namespace refresh via `/store/index` polling.
  - Shared polling abstraction in `crates/client-sdk/src/remote_sync.rs`:
    - SDK-owned polling thread (`RemoteSnapshotPoller`),
    - callback contract on `changed_paths` + latest snapshot,
    - adapter-side callback applies platform action plans.
  - Server-driven remote-change notifications for live filesystem adapters:
    - `server-node` exposes `/store/index/changes/wait` long-poll wakeups,
    - Linux FUSE and Windows CFAPI now wait on server change notifications and then refresh snapshots,
    - periodic polling remains as a compatibility fallback for older servers.
  - `crates/adapter-linux-fuse` live mount now consumes the same polling abstraction to materialize remote additions without remounting.
  - `crates/sync-agent-core` with reusable local tree scanning, diffing, and remote index utilities.
  - `apps/ironmesh-folder-agent`:
    - OS-independent local-folder synchronization runtime,
    - initial remote materialization into a configured local root folder,
    - hybrid change detection: periodic local scans + native filesystem watcher events,
    - remote polling reuse via `client-sdk::RemoteSnapshotPoller`,
    - local file + directory-marker uploads to server,
    - local file deletion propagation to server (`/store/delete` via `client-sdk`).
  - `apps/android-app`:
    - configurable multi-profile folder sync settings (prefix + local folder),
    - periodic background sync execution via WorkManager,
    - manual "Sync Now" trigger from UI.
- Next step:
  - Align Android with the shared planner/contracts now that recursive directory deletion propagates through the shared `/store/delete` path for directory-marker keys.

## Folder agent usage (MVP)

```bash
mkdir -p /tmp/ironmesh-root
cargo run -p ironmesh-folder-agent -- \
  --root-dir /tmp/ironmesh-root \
  --server-base-url http://127.0.0.1:18080
```

Key options:

- `--local-scan-interval-ms`: periodic scan cadence for upload detection.
- `--remote-refresh-interval-ms`: server polling cadence for remote updates.
- `--prefix`: scope synchronization to a remote subtree; local root maps directly to that subtree.
- `--no-watch-local`: disable native local watcher and rely on scans only.
- `--run-once`: perform one bootstrap + local scan cycle and exit.

## Linux FUSE usage (current)

The Linux adapter currently ships through `os-integration`:

- Crate: `crates/adapter-linux-fuse`
- User-facing binary: `apps/os-integration`

Example snapshot file:

```json
{
  "local": [],
  "remote": [
    {
      "path": "docs/readme.txt",
      "kind": "File",
      "version": "v1",
      "content_hash": "h1"
    },
    {
      "path": "docs/nested",
      "kind": "Directory",
      "version": null,
      "content_hash": null
    }
  ]
}
```

Mount command:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p os-integration -- \
  --snapshot-file /tmp/snapshot.json \
  --mountpoint /tmp/ironmesh-mount
```

Snapshot mode behavior:

- Directories and placeholder files materialized from planned actions.
- File reads trigger demo hydration.
- Snapshot mode is for inspection/debugging, not persistent sync.

Direct server-node mode:

```bash
mkdir -p /tmp/ironmesh-mount-live
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --mountpoint /tmp/ironmesh-mount-live
```

- `--server-base-url` loads namespace entries from `/store/index`.
- File reads hydrate through live `GET /store/{key}` requests.
- Local writes, deletes, and renames are sent back to the server.
- `--remote-refresh-interval-ms` controls namespace polling while mounted.

Embedded local-edge mode:

```bash
mkdir -p /tmp/ironmesh-mount-edge
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --local-edge \
  --mountpoint /tmp/ironmesh-mount-edge
```

- `--local-edge` mounts against a spawned local edge node instead of the remote server directly.
- The local edge persists state on disk and can accept writes while the upstream is unavailable.
- By default, the local edge stores state under `$XDG_STATE_HOME/ironmesh/os-integration/local-edge/` or `~/.local/state/ironmesh/os-integration/local-edge/`.
- `--local-edge-data-dir` is the advanced override for choosing that storage path explicitly.
