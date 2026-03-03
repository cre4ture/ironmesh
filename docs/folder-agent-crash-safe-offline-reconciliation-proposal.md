# Folder Agent Crash-Safe Offline Reconciliation Proposal (SQLite)

Status: In progress (partially implemented)

## 1. Summary
This proposal switches the local baseline store from a flat manifest file to a local SQLite database.
It combines:
- persistent SQLite baseline (instead of JSON manifest),
- selective local hashing for ambiguous/recovery paths,
- non-destructive conflict handling,
- server-side per-file content hashes in remote snapshot/index.

Goal: preserve offline local edits/additions across normal stop, crash, or power loss without silent data loss.

### 1.1 Current implementation status
Implemented so far:
- SQLite baseline store with schema versioning and startup migration (v1 -> v2), plus scope fingerprint validation.
- Runtime baseline persistence (not only on clean shutdown) for crash-safe restart behavior.
- Per-path recovery behavior when individual baseline rows are missing.
- Server `/store/index` now includes per-file `content_hash`.
- Folder-agent startup now uses remote hashes for missing-baseline paths:
  - if local hash matches remote hash, do not preserve/upload.
  - if hash differs or hash is unavailable, preserve local bytes (non-destructive default).
- Remote delete intent now wins for unchanged local files with valid baseline on restart.
- Startup conflict persistence in SQLite (`conflicts` table) for:
  - `add_delete_ambiguous_missing_baseline`
  - `modify_delete_conflict`
  - `dual_modify_missing_baseline`
- Incremental per-path baseline upserts/removals during startup/runtime apply/upload/delete flows to reduce crash windows.
- Crash-window system test coverage for abrupt kill during active sync writes, with restart reconciliation checks (local + remote changes).
- Server-side tombstone tooling scaffold:
  - `POST /maintenance/tombstones/compact`
  - `GET /maintenance/tombstones/archive`
  - `POST /maintenance/tombstones/archive/restore`
  - `POST /maintenance/tombstones/archive/purge`
  - token-based admin access control via `IRONMESH_ADMIN_TOKEN` + `x-ironmesh-admin-token`
  - explicit approval gate for destructive runs (`dry_run=false` requires `approve=true`)
  - persistent admin audit trail in `state/admin_audit.jsonl`
  - dry-run support
  - archival of compacted tombstoned version indexes into `state/tombstone_archive/*.jsonl`

Not implemented yet:
- Conflict lifecycle tooling (resolve/ack/clear workflows and user-facing surfacing).
- Full tombstone retention policy controls and richer restore/purge guardrails (RBAC role tiers, audit viewer APIs, tamper-evident archival).
- Telemetry counters for path/global recovery and conflict classes.
- Full transport/authn/authz security architecture implementation (documented in `docs/security-architecture.md`).

## 2. Decision Update
Chosen direction:
- Use SQLite as the local state store.
- Do not require global "full-tree recovery mode" when a few entries are missing.
- Apply recovery mode per-path by default.
- Set `max_offline_age = 0` (always apply long-offline rules).
- Set tombstone retention to infinite.
- Require strong tombstone compaction/archival and clear admin tooling.

## 3. Goals
- Preserve local offline edits/additions while agent was down.
- Work after ungraceful previous stop (crash/power loss).
- Avoid destructive auto-resolution when uncertainty exists.
- Keep steady-state overhead low.

## 4. Non-Goals
- Full CRDT/distributed merge system.
- Strong global ordering across multiple independent writers.

## 5. SQLite State Store
### 5.1 Scope identity
Use one SQLite database per `(root_dir, server_base_url, prefix)` scope.

### 5.2 Current schema target (v2, with v1 migration support)
- `meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`
  - `schema_version`
  - `scope_fingerprint`
  - optional agent metadata
- `files(path TEXT PRIMARY KEY, kind TEXT NOT NULL, size_bytes INTEGER, modified_unix_ms INTEGER, local_hash TEXT, remote_hash TEXT, state TEXT NOT NULL, last_seen_unix_ms INTEGER NOT NULL)`
- `conflicts(path TEXT PRIMARY KEY, reason TEXT NOT NULL, details_json TEXT, created_unix_ms INTEGER NOT NULL)`

Notes:
- `kind`: file|directory|tombstone
- `state`: synced|pending_upload|pending_delete|conflict

### 5.3 Durability and crash safety
Use DB guarantees instead of hand-rolled atomic file writes:
- transactions for multi-row updates,
- WAL journal mode,
- `synchronous=FULL` (or policy-controlled),
- `PRAGMA integrity_check` on suspicious startup failures.

## 6. Server Hash Requirement
Remote snapshot/index must include stable content hashes for files:
- content-derived only,
- unchanged when metadata-only updates happen,
- hash algorithm must be part of API contract.

## 7. Startup Reconciliation
### 7.1 Load phase
- Open SQLite DB for scope.
- Validate `schema_version` and scope metadata.
- If DB open/validation fails => `GLOBAL_RECOVERY_MODE`.

### 7.2 Collect phase
- Scan local tree metadata.
- Fetch remote snapshot with hashes.
- Load known DB entries for encountered paths.

### 7.3 Per-path mode selection
For each path, choose mode:
- `NORMAL`: DB row exists and is usable.
- `PATH_RECOVERY`: DB row missing/invalid for this path only.
- `GLOBAL_RECOVERY`: DB unavailable/corrupt, apply recovery logic to all paths.

This is the key adaptation: missing DB data for some files should not force whole-tree recovery.

### 7.4 Compare and classify
Per path (local + db + remote view):
- same hashes => synced,
- one side missing bytes => add/delete candidate,
- differing bytes => conflict candidate.

### 7.5 Hashing strategy
- Normal mode: metadata + DB fields first, no broad hashing.
- Path recovery mode: hash only that path if ambiguity remains.
- Global recovery mode: hash broadly, but skip obvious existence-only add/delete cases.

## 8. Conflict Policy (Non-Destructive)
Safety defaults:
- Never auto-delete when uncertain.
- "Bytes beat tombstones": keep content if other side is delete.
- For dual-modify, keep canonical path + write conflict copy.
- Persist unresolved conflicts in `conflicts` table.

## 9. Delete/Tombstone Semantics
Use soft-delete with infinite retention:
- track delete intent in DB (and optionally remote metadata),
- avoid hard-delete while conflict/uncertainty is unresolved,
- hard-delete only when certainty criteria pass or explicit resolution occurs.

### 9.1 Long-Offline Policy
With `max_offline_age = 0`, always apply this rule for delete intent:
- if local file is unchanged relative to DB baseline, remote delete intent wins,
- if local file changed, do not auto-delete; mark as conflict/pending resolution.

This prevents stale-file resurrection while still protecting real local edits.

### 9.2 Tombstone Compaction, Archival, and Tooling
Because retention is infinite, the system must include:
- strong tombstone compaction to keep hot working sets small,
- archival for old tombstones/history with integrity guarantees,
- clear admin tooling for inspection, restore, and controlled purge workflows.

## 10. DB Update Cadence
To support ungraceful-stop recovery, do not depend on clean shutdown writes.
Update DB during normal operation:
- after successful startup reconciliation,
- after each local sync cycle that changes tracked state,
- after applying remote updates that alter local tracked view,
- optionally periodic checkpoint/flush.

## 11. Failure Handling
- DB missing: create empty DB and run per-path recovery from filesystem+remote.
- DB partially populated: only missing rows go to path recovery.
- DB corrupt: rename/quarantine DB, rebuild in global recovery mode.

## 12. Performance Notes
- Index by `path` (primary key).
- Batch writes in transactions.
- Avoid full-table rewrites; update changed rows only.
- Hash only ambiguous paths unless in global recovery.

## 13. Test Plan
### 13.1 Unit tests
- schema init and migration guard,
- per-path recovery classification,
- conflict classifier (add/delete, modify/delete, dual-modify).

### 13.2 Integration tests
- DB row missing for subset of files -> only those paths enter recovery logic.
- DB corrupt -> global recovery fallback.
- startup reconciliation with existing-folder and new-folder offline additions.

### 13.3 System tests
- existing restart tests (remote/local offline changes),
- crash simulation: kill agent ungracefully, mutate local, restart, verify no data loss,
- verify no full-tree recovery when only a few rows are missing.

## 14. Experimental-Phase Implementation Strategy
- No staged rollout and no feature-flag gating are required at this phase.
- Land changes directly in mainline with test coverage.
- Keep migration/backward compatibility for developer environments (schema versioning and startup migration).
- Revisit staged rollout strategy only when a production-like environment exists.

## 15. Open Decisions
- SQLite pragmas default (`WAL`, `synchronous` level).
- Conflict-copy naming format.
- Recovery hashing budget limits for very large trees.
- Exact compaction/archival thresholds and retention tiers.
- Admin tooling surface (CLI commands, permissions, and audit logging format).

## 16. Acceptance Criteria
- Offline local edits/additions survive restart after crash/power loss.
- Missing DB rows trigger recovery only for affected paths.
- DB corruption does not cause destructive sync actions.
- No ambiguous add/delete conflict causes automatic data loss.
- For long-offline devices, unchanged local files follow remote delete intent; changed local files are preserved as conflicts.
- Infinite tombstone retention remains operationally manageable through compaction/archival and admin tooling.
