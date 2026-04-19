# Cross-platform filesystem integration strategy

## Goals

- Provide first-class file-manager integration on Windows, Ubuntu Linux, and Android.
- Reuse as much code as possible across platforms.
- Keep platform-specific code limited to OS API adapters.
- Support placeholder-first UX (on-demand hydration) where supported.

## Non-goals (MVP)

- Perfect parity of all OS-specific shell features in the first release.
- Bi-directional real-time sync with advanced conflict UI.

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
- Status surfacing recommendation:
  - Expose lightweight sync state on the primary inode via read-only xattrs.
  - Mount remote-side conflict artifacts under `.ironmesh-conflicts/remote/...`.
  - Avoid sibling marker files next to user content because they pollute directory listings and
    confuse apps/indexers.
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
  - `adapter-windows-cfapi`
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
2. Linux pilot: `adapter-linux-fuse` mount with live hydration and client-rights edge sync. ✅
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

## Linux FUSE Status Surface

The Linux mount should use a hybrid status model:

- Primary files/directories stay in the normal namespace and expose state through read-only
  `user.ironmesh.*` xattrs.
- Conflict artifacts are mounted under `.ironmesh-conflicts/remote/...`.
- The internal `.ironmesh-conflicts` subtree is reserved and read-only from the mount.

Recommended xattrs:

- `user.ironmesh.state`
  - Comma-separated state flags such as `clean`, `placeholder`, `dirty`, `conflict`,
    `conflict-copy`, and `read-only`.
- `user.ironmesh.local_version`
- `user.ironmesh.remote_version`
- `user.ironmesh.conflict_reason`
- `user.ironmesh.conflict_copy`
  - Mount-relative path to the remote conflict artifact when present.
- `user.ironmesh.source_path`
  - For sidecar conflict copies, the original user-visible path they represent.

Current Linux FUSE interpretation:

- Runtime local modifications set `user.ironmesh.state=dirty` until upload succeeds on
  flush/release.
- Planner-provided `MarkConflict` actions surface both:
  - a user-visible conflicted file with conflict xattrs, and
  - a read-only remote-side artifact under `.ironmesh-conflicts/remote/...`.
- The conflict sidecar mirrors the remote object view. This keeps the primary namespace clean
  while preserving a discoverable place for remote conflict artifacts.

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
  - Linux `os-integration` mount CLI with:
    - `--snapshot-file` static snapshot mode.
    - live client-rights edge mode via `--server-base-url` or `--bootstrap-file`.
  - Linux direct/bootstrap mounts now persist:
    - the last successfully fetched remote snapshot,
    - a durable client-side mutation queue,
    - resumable upload state for queued large uploads,
    - an optional hydrated-object cache for remote reads.
  - CI artifact publication for Ubuntu mount binary (`linux-fuse-mount-binary-ubuntu`).
  - `crates/adapter-windows-cfapi` runtime with:
    - sync-root registration + placeholder creation,
    - fetch-data hydration callbacks backed by `server-node`,
    - registration helper implementation in `crates/adapter-windows-cfapi/src/register.rs`,
    - remote namespace refresh via server notifications first, with polling fallback.
  - Shared polling abstraction in `crates/client-sdk/src/remote_sync.rs`:
    - SDK-owned polling thread (`RemoteSnapshotPoller`),
    - callback contract on `changed_paths` + latest snapshot,
    - adapter-side callback applies platform action plans.
  - Server-driven remote-change notifications for live filesystem adapters:
    - `server-node` exposes `/store/index/changes/wait` long-poll wakeups,
    - Linux FUSE and Windows CFAPI now wait on server change notifications and then refresh snapshots,
    - periodic polling remains as a compatibility fallback for older servers.
  - CI now includes a Windows compile check lane for the CFAPI adapter.
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

Direct/bootstrap client-rights edge mode:

```bash
mkdir -p /tmp/ironmesh-mount-live
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --client-identity-file /path/to/client-identity.json \
  --mountpoint /tmp/ironmesh-mount-live
```

- `--server-base-url` loads namespace entries from `/store/index` and, when auth is required,
  should be paired with `--client-identity-file`.
- `--bootstrap-file` is the equivalent authenticated entrypoint when a client bootstrap bundle is
  preferred over a raw base URL. If `--client-identity-file` is omitted, the adapter also checks
  for a sibling `bootstrap.client-identity.json`.
- Local writes, deletes, and renames are captured into a durable local mutation queue first and
  then synchronized through client APIs.
- Offline restart replays the last cached snapshot plus queued local mutations.
- `--remote-refresh-interval-ms` controls namespace polling while mounted.
- `--client-edge-state-dir` overrides the default persisted state location.
- `--offline-object-cache` controls whether hydrated remote objects are cached locally for offline
  rereads.
- Remote placeholders and hydrated-object cache entries are keyed by remote `content_hash` when it
  is available from `/store/index`, so renamed/copied paths can reuse hydrated bytes safely.
- Even with `--offline-object-cache off`, the live mount keeps a small in-memory range chunk cache
  for repeated reads during the current mount session.

GNOME status integration:

```bash
cargo run -p os-integration -- \
  --mountpoint /tmp/placeholder \
  gnome install-extension

mkdir -p /tmp/ironmesh-mount-live
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --client-identity-file /path/to/client-identity.json \
  --mountpoint /tmp/ironmesh-mount-live \
  --publish-gnome-status
```

- `gnome print-status-path` prints the JSON path watched by the GNOME Shell extension.
- `--gnome-status-file` overrides the default `$XDG_RUNTIME_DIR/ironmesh/gnome-status.json`
  location.
- `--remote-status-poll-interval-ms` controls how often the GNOME surface refreshes authenticated
  connection and replication status; this is separate from `--remote-refresh-interval-ms`, which
  controls namespace refresh behavior for the mounted filesystem.
- Snapshot-mode mounts can publish GNOME status too, but they report static snapshot state instead
  of live connection/replication health.

Recommended same-device deployment:

```bash
mkdir -p /tmp/ironmesh-mount-live
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --offline-object-cache off \
  --mountpoint /tmp/ironmesh-mount-live
```

- Use `--offline-object-cache off` when the FUSE mount already runs on the same device as a
  regular `server-node` and a second hydrated-object cache would be redundant.
- This does not disable the durable mutation queue or snapshot cache required for client-rights
  offline sync semantics.
- This also does not disable the in-memory range chunk cache used to avoid refetching identical
  chunks within the same mounted session.

Obsolete path kept for design history:

- The old embedded Linux FUSE `--local-edge` helper is obsolete and has been removed.
- It is not being revived because it still required local `server-node` authority rather than a
  plain client identity.
- The rationale is preserved in `docs/client-rights-edge-sync-idea.md`.
