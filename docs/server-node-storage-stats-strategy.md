# Server-Node Storage Stats Strategy

## Goal

Expose per-node storage statistics that are cheap to read in the admin UI and still stay accurate
enough for operators:

- chunk store size on disk,
- metadata store size on disk,
- latest snapshot logical size,
- latest snapshot unique referenced chunk size.

The first rollout should prioritize:

- low request-time cost,
- correctness after restart,
- history suitable for simple charts in the admin UI,
- room for later Prometheus-style export.

## Current Storage Layout

The node currently stores data in separate on-disk areas:

- `chunks/` for content-addressed chunk payloads,
- `manifests/` for object manifests,
- `state/metadata.sqlite` or `state/metadata.turso.db` for metadata DB state,
- `state/media_cache/` for generated media metadata and thumbnails.

Because manifests are outside the SQLite file, "metadata size" should not be treated as just the
database file size. The implementation should report at least:

- `metadata_db_bytes`,
- `manifest_store_bytes`,
- `media_cache_bytes`.

## Recommended Model

Use a hybrid strategy instead of periodic full rescans as the primary mechanism.

### 1. Incremental counters where exact updates are cheap

- `chunk_store_bytes`
  - increment when a new chunk file is actually written,
  - decrement when chunk cleanup deletes a chunk file,
  - do not change on dedup hits.

This gives cheap exact accounting for the heaviest part of storage.

Current implementation status:

- implemented via a small persisted `storage_stats_state`,
- lazily seeded from a one-time chunk directory scan if the state is missing,
- updated incrementally on chunk ingest and orphan chunk cleanup.

### 2. Event-driven recomputation where full counters are expensive

- latest snapshot stats
  - recompute after a new snapshot is created,
  - derive from the latest snapshot's object map and referenced manifests,
  - sum:
    - logical bytes across the snapshot objects,
    - unique chunk bytes across all referenced manifests.

This work is more expensive than a counter but only needs to happen after namespace changes.

### 3. Cheap periodic file-metadata refresh for small local values

- `metadata_db_bytes`
  - file metadata on the DB path,
- `manifest_store_bytes`
  - recursive directory size,
- `media_cache_bytes`
  - recursive directory size.

These can run in the background on a slower schedule.

### 4. Slow reconciliation scan

Counters can drift after crashes, manual tampering, or future bugs. Add a slower full
reconciliation pass:

- once on startup,
- then every 30-60 minutes.

This pass should recompute all byte fields from disk and overwrite the stored values if needed.

Current implementation status:

- chunk-store state is reconciled in the background before sampling when its last reconciliation is
  older than the configured interval,
- the current default reconciliation interval is 1 hour.

## Scheduling

The worker should be driven by both namespace changes and a slower periodic timer.

### Event-driven trigger

- subscribe to the existing namespace-change watch channel,
- debounce updates for 10-30 seconds,
- recompute once after bursts of writes/renames/deletes/copies/repairs settle.

### Periodic trigger

- run a full refresh every 5-10 minutes for operator freshness,
- run a full reconciliation every 30-60 minutes.

## Persistence Model

Persist both the latest sample and a history table in the node metadata backend.

### Current sample

Used for fast admin reads.

Suggested fields:

- `collected_at_unix`
- `latest_snapshot_id`
- `latest_snapshot_created_at_unix`
- `chunk_store_bytes`
- `manifest_store_bytes`
- `metadata_db_bytes`
- `media_cache_bytes`
- `latest_snapshot_logical_bytes`
- `latest_snapshot_unique_chunk_bytes`

### History samples

Append one row per successful collection.

History does not need to be high resolution. A practical start:

- keep one sample per collection run,
- collect every few minutes,
- prune old samples after a retention window such as 30-90 days.

Current implementation status:

- implemented with history pruning during background collection,
- the current default retention window is 90 days.

## Admin/UI Shape

### Backend

Add node-local endpoints such as:

- `GET /storage/stats/current`
- `GET /storage/stats/history?limit=...`

### Frontend

The first UI slice can show:

- current values on the server-admin dashboard,
- a small per-node history chart on a detail card or dedicated storage section.

## External Observability

For these few node-local storage metrics, a built-in history table is simpler than requiring a full
Prometheus/Grafana deployment.

Later, if broader observability is wanted:

- export the same counters as Prometheus-compatible metrics,
- optionally feed them into an external time-series backend.

### GreptimeDB Note

GreptimeDB remains interesting as a future external observability backend, but it is not the right
frontend for the current storage-stats feature.

- The current storage-stats history is stored directly in the node metadata backend
  (`sqlite` / `turso`).
- GreptimeDB's dashboard/frontend is coupled to a running GreptimeDB instance and cannot simply be
  pointed at the existing Ironmesh SQLite or Turso data.
- Running one GreptimeDB instance per node would also not automatically produce a cluster-wide
  accumulated view. It would still require fan-in, cross-node querying, or a dedicated central
  GreptimeDB deployment.

Because of that, the current product direction stays:

- use the directly integrated basic visualization in `server-admin`,
- keep the node-local history in the existing metadata backend,
- treat richer external dashboards as a later feature.

If external dashboards are added later, the more realistic direction is:

- keep the current node-local stats collection,
- export the same values to a Prometheus-compatible sink,
- use Grafana for advanced filtering and visualization,
- optionally use GreptimeDB as a central time-series backend behind that flow.

## Rollout Plan

1. Document the strategy.
2. Add metadata-backend tables for current sample and history.
3. Implement storage-stat calculation helpers in `PersistentStore`.
4. Add a background worker in `server-node`.
5. Expose current/history admin endpoints.
6. Add server-admin UI cards and a simple history chart.
7. Add pruning and reconciliation policy.
8. Revisit external observability only after the integrated dashboard is sufficient for daily use.

The current codebase has completed steps 1-7 with a first pragmatic implementation:

- chunk-store bytes use incremental accounting plus periodic reconciliation,
- snapshot and small-directory values still use the background collector,
- history retention is enforced during successful sample persistence.

## Notes

- The latest snapshot size calculation should use manifest metadata, not file system walks over
  chunk files.
- "Metadata size" should stay explicitly split in the API so operators can tell whether growth is
  in the DB, manifests, or media cache.
- A future Prometheus exporter can reuse exactly the same collected values.
- GreptimeDB is considered a future backend option, not the current visualization layer.
