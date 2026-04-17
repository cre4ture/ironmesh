# Folder Agent Modification Log Proposal

## Goal

Persist every modification action performed by the folder agent and make that history visible in the Android app.

For this proposal, the history should include:

- completed file uploads,
- completed file downloads,
- delete-only reconciliation actions (`delete-local` and `delete-remote`),
- conflict-resolution-triggered operations in the same stream.

Directory marker uploads should stay out of scope because they are internal bookkeeping rather than user-meaningful file-data changes.

## Current Constraints

- The desktop folder agent already has a persistent state concept, but the default `StartupStateStore` root currently falls back to `std::env::temp_dir()`. That is a poor default for retained history because temp storage can be cleaned independently of the agent lifecycle.
- Android continuous folder sync currently puts its state root under the app cache directory. Cache is also the wrong durability class for an audit/history surface because Android may evict it under storage pressure.
- The runtime already has the right action boundaries for logging: uploads happen in `sync_local_changes`, and downloads happen in `download_remote_file` / `apply_remote_snapshot`.
- The Android app already has the right presentation path: Rust JNI bridge -> `IronmeshRepository` -> `MainViewModel` -> Compose in `MainActivity`.

## Recommended Storage Location

### Principle

Do not store the modification log inside the synced root.

Reasons:

- it becomes user-visible clutter,
- it risks syncing internal agent state back into Ironmesh,
- it can be deleted or moved as part of normal user file activity,
- it mixes operational state with customer data.

The log should live next to other agent-owned state under a durable, app-owned state root.

### Desktop / CLI folder agent

Use a persistent state root derived from XDG state, not temp space:

- preferred: `${XDG_STATE_HOME}/ironmesh/folder-agent/`
- fallback: `${HOME}/.local/state/ironmesh/folder-agent/`
- last resort only: `std::env::temp_dir()` when neither environment is available

Add a CLI override so tests and power users can pin it explicitly:

- `--state-root-dir <path>`

### Android

Use an app-internal durable directory, not `cacheDir`:

- preferred: `context.noBackupFilesDir/ironmesh/folder-sync-state/`
- acceptable fallback: `context.filesDir/ironmesh/folder-sync-state/`

`noBackupFilesDir` is the better default because this is runtime state/history, not user-authored content that should be restored onto a different device via OS backup.

### Per-profile layout

The log should be scoped the same way the baseline DB already is: by root directory, remote prefix, and connection target.

Recommended layout:

```text
<state-root>/
  profiles/
    <fingerprint>/
      baseline.sqlite
      modification-log.sqlite
```

Where `<fingerprint>` is derived from the same tuple already used by `StartupStateStore`:

- root dir
- remote prefix
- connection target

Because this is pre-release, move the baseline DB into this directory layout directly. Do not preserve the current flat baseline path.

## File Format

Even though the requirement says "logfile", I would not use a raw text log as the primary store.

Use SQLite as the canonical event log.

Reasons:

- bounded queries for Android are easy,
- retention and pruning are easy,
- concurrent reads are much easier than parsing a growing text file,
- we already use SQLite in folder-agent state and history-oriented storage elsewhere in the repo,
- crash recovery is better than ad hoc JSONL parsing.

If a human-readable export is still useful later, we can add a JSONL dump command, but the source of truth should stay queryable.

## Event Schema

One row per completed modification attempt.

Suggested table:

```sql
CREATE TABLE modification_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_unix_ms INTEGER NOT NULL,
    operation TEXT NOT NULL,
    outcome TEXT NOT NULL,
    phase TEXT NOT NULL,
    trigger_source TEXT NOT NULL,
    local_relative_path TEXT NOT NULL,
    remote_key TEXT NOT NULL,
    size_bytes INTEGER,
    content_hash TEXT,
    scope_label TEXT NOT NULL,
    root_dir TEXT NOT NULL,
    connection_target TEXT NOT NULL,
    error_text TEXT
);

CREATE INDEX idx_modification_actions_time
    ON modification_actions(occurred_unix_ms DESC, id DESC);

CREATE INDEX idx_modification_actions_operation
    ON modification_actions(operation, occurred_unix_ms DESC, id DESC);
```

Recommended enum values:

- `operation`: `upload` | `download` | `delete-local` | `delete-remote`
- `outcome`: `success` | `error`
- `phase`: `startup` | `steady-state` | `manual`
- `trigger_source`: `local-scan` | `local-watch` | `remote-refresh` | `startup-reconcile` | `conflict-resolution`

Notes:

- Log failures too, but still keep exactly one terminal row per attempt. Do not log `started` and `finished` as separate rows unless there is a product reason to show in-flight operations.
- `size_bytes` should be the local file size for uploads, the final downloaded size for downloads, and `NULL` for delete actions.
- `content_hash` should be present for uploads and downloads when available, and `NULL` for delete actions.
- Conflict-resolution-triggered uploads, downloads, and deletes should stay in this same table with `trigger_source = conflict-resolution`.

## Retention

This must be bounded.

Recommended default:

- age retention: 30 days
- row cap: 25,000 records per profile

Prune:

- once on startup,
- after append when the row count crosses the cap,
- using the same "retain by age and cap" pattern already used by server-side history features.

## Runtime Integration

### New core type

Add a `ModificationLogStore` in `sync-agent-core` beside `StartupStateStore`.

Responsibilities:

- derive per-profile log path,
- initialize schema,
- append rows,
- list rows with `limit` and optional cursor,
- prune retained history.

### Instrumented write helpers

Because this is pre-release, refactor the mutating helper layer instead of bolting logging onto each caller.

Thread a small logging context through the helper functions that already define the real write boundaries:

- `upload_local_file`
- `download_remote_file`
- `delete_remote_file`
- `remove_local_path`

That captures both steady-state sync and conflict-resolution flows cleanly, because `resolve_conflict_action` already reuses `upload_local_file`, `delete_remote_file`, and `remove_local_path`.

### Where to write rows

#### Uploads

In `upload_local_file`:

- after `upload_local_file(...)` succeeds, append one `upload/success` row,
- if `upload_local_file(...)` returns an error, append one `upload/error` row before returning the error upward.

That captures both regular sync uploads and conflict-resolution-triggered uploads without counting directory marker PUTs.

#### Downloads

In `download_remote_file`:

- after `download_file_resumable(...)` succeeds and the local file exists, append one `download/success` row,
- if the download fails, append one `download/error` row before returning the error.

Because all remote file materialization funnels through `download_remote_file`, this gives us one logging point for both startup sync and steady-state remote refreshes.

#### Deletes

In `delete_remote_file`:

- after `delete_path_blocking(...)` succeeds, append one `delete-remote/success` row,
- if it fails, append one `delete-remote/error` row before returning the error.

In `remove_local_path`:

- after the local path is removed, append one `delete-local/success` row,
- if local removal fails, append one `delete-local/error` row before returning the error.

That covers delete-only reconciliation and conflict-resolution-triggered deletes in the same history stream.

### Status payloads

Do not stuff the retained log into `FolderAgentRuntimeStatus` or the Android `FolderSyncServiceStatus` JSON.

Keep status as a lightweight summary surface and expose history through a separate query API.

## Desktop / Folder-Agent UI Surface

The existing folder-agent UI server already exposes `/api/info` and `/api/conflicts`. Add:

- `GET /api/modifications?limit=100&before_id=<cursor>&operation=upload|download|delete-local|delete-remote`

Response shape:

```json
{
  "records": [
    {
      "id": 123,
      "occurred_unix_ms": 1713300000000,
      "operation": "download",
      "outcome": "success",
      "phase": "steady-state",
      "trigger_source": "remote-refresh",
      "local_relative_path": "photos/IMG_0012.jpg",
      "remote_key": "photos/IMG_0012.jpg",
      "size_bytes": 4182731,
      "content_hash": "...",
      "error_text": null
    }
  ],
  "next_before_id": 122
}
```

That gives the desktop folder-agent UI parity with Android almost for free.

## Android Integration

### Rust bridge

Add a dedicated JNI method rather than overloading the current status JSON:

- `getFolderSyncModificationHistory(profileId: String, limit: Int, beforeId: Long?, operation: String?): String`

Rust side:

- add serializable types mirroring the core history response,
- teach `AndroidFolderSyncManager` to remember each running profile's `ModificationLogStore`, or enough information to rebuild it from `FolderAgentRuntimeOptions`,
- query the per-profile log store and return JSON.

Also add a durable path bridge in `RustPreferencesBridge`:

- `noBackupFilesDirPath()`

Then change Android folder sync state root construction to use that durable location instead of `cacheDirPath()`.

### Kotlin repository

Add data classes:

- `FolderSyncModificationRecord`
- `FolderSyncModificationHistory`

Add repository method:

- `fun getFolderSyncModificationHistory(profileId: String, limit: Int = 50, beforeId: Long? = null, operation: String? = null): FolderSyncModificationHistory`

This should decode the Rust JSON the same way `getContinuousFolderSyncStatus()` already does.

### View model

Extend `MainUiState` with:

- selected profile for history view,
- a small cache of recent history per profile,
- loading/error state,
- pagination cursor,
- optional operation filter.

Suggested behavior:

- only fetch history when the Folder Sync section is visible,
- fetch the latest page when a profile card is expanded or selected,
- optionally poll for new rows every 5 seconds while that profile is visible,
- keep the existing 2 second status polling only for summary/status.

That avoids sending a full retained log across JNI every time the status poll runs.

### Compose UI

Do not create a full new app section first, and do not build a combined cross-profile history view.

The lowest-friction UI is to extend each folder-sync profile card with a "Recent Activity" surface:

- a button or disclosure row: `Recent Activity`
- filter chips: `All`, `Uploads`, `Downloads`, `Deletes`
- a bounded list of recent rows
- a `Load more` button for pagination

Each row should show:

- operation badge (`Upload` / `Download` / `Delete local` / `Delete remote`)
- relative path
- timestamp
- size when present
- phase or trigger summary when useful
- error text when `outcome=error`

When `trigger_source = conflict-resolution`, show that explicitly in the secondary row text so the user can tell routine sync apart from manual resolution work.

That integrates naturally with the existing `FolderSyncControls` profile cards and keeps the history scoped to the profile the user already understands.

## Recommended Implementation Order

1. Move folder-agent state roots onto durable storage on desktop and Android.
2. Add `ModificationLogStore` and write rows for upload/download/delete success and failure.
3. Add query APIs in `sync-agent-core` and folder-agent UI.
4. Add Android JNI/repository/history models.
5. Extend the Compose profile card with a recent-activity view.

## Resolved Scope Decisions

- Record delete-only reconciliation in the same history stream.
- Include conflict-resolution-triggered uploads, downloads, and deletes in the same history stream.
- Keep the Android history view per-profile.

Because this is pre-release, take the direct shape now: durable per-profile state roots, a single per-profile SQLite history, and an action model that includes uploads, downloads, and delete reconciliation from the start.
