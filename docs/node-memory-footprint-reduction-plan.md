# Node Memory Footprint Reduction Plan

## Status

In progress (2026-07-06). Follows from an ad-hoc RAM analysis of server-node and the
desktop sync clients, confirmed against the current codebase. Landed so far: Slice 2b,
Slice 3, Slice 0, Slice 1a. Still open: Slice 1b, Slice 1c.

## Goal

Reduce the memory hotspots identified in the RAM analysis without changing on-disk formats
or client-visible behavior, and give operators visibility into *why* a node's RSS is what it
is, not just what it is.

## Confirmed Hotspots (ranked)

1. **FUSE hydrated file content (`FsNode.data: Vec<u8>`)** —
   `crates/adapter-linux-fuse/src/lib.rs:303-318,1454-1466,1590-1597`. Full file bytes stay
   resident in RAM once a file is hydrated, and are only released via `data.clear()` on
   re-placeholdering — which is skipped while a handle is open. RAM scales with the bytes of
   currently open/hydrated files, unbounded. This is the only place in the codebase where raw
   data volume, not file/object count, drives RSS.
2. **Server `CurrentState` double `HashMap<String,String>`** —
   `crates/server-node-sdk/src/storage/mod.rs:122-126`, loaded/rewritten wholesale in
   `crates/server-node-sdk/src/storage/sqlite_impl.rs:1003-1019`. Resident for the process
   lifetime, ~250-400 bytes/entry (path string + hash/id string + allocator overhead). Scales
   linearly with total file count across the node's namespace; the dominant baseline cost for
   large trees (multi-GB at millions of files) regardless of file size.
3. **GC's `load_all_manifests` full scan** —
   `crates/server-node-sdk/src/storage/mod.rs:7077-7098`. Builds a transient
   `HashMap<String, ObjectManifest>` covering every manifest in the store during each GC pass.
   Peak memory during GC scales with total manifest/chunk count.

Everything else surveyed (per-connection registries, per-peer relay sessions, mux channel
buffers, rendezvous presence, upload-session chunk refs, watch/notify channels, the Windows
CFAPI `RangeChunkCache`) is already bounded or small at realistic scale and is **out of scope**
for this plan — no action needed there.

## Non-goals

- No change to on-disk sqlite schemas (columns stay `TEXT`); only in-memory representations
  change.
- No change to client-visible APIs or file semantics.
- Not attempting a general rewrite of the FUSE adapter — reuse the staging/streaming pattern
  the Windows CFAPI adapter already uses (`crates/adapter-windows-cfapi/src/live.rs:163-229`,
  `common/src/range_chunk_cache.rs`) rather than inventing a new one.

## Architecture note: custom FUSE driver vs. a generic S3-FUSE gateway (2026-07-06)

With an S3 API for ironmesh in progress (separate PR), it's worth recording why this plan
keeps investing in the custom `adapter-linux-fuse` driver rather than dropping it in favor
of an existing FUSE-to-S3 mapping driver (s3fs-fuse, rclone mount, goofys, AWS's
`mountpoint-s3`):

- **Rename semantics.** S3 has no native rename; every generic S3-FUSE driver implements
  it as copy-then-delete, which is expensive and non-atomic for large files. Ironmesh's
  own metadata store can do a metadata-only rename (no data movement), which
  `adapter-linux-fuse` relies on today.
- **Placeholder/hydration/pinning UX.** The custom driver's placeholder-with-lazy-hydration
  model (this plan's Slice 1) gives parity with the Windows CFAPI adapter — online-only
  files, pinning, proactive eviction. A generic S3 gateway treats the mount as a plain
  object store with no concept of this; it either caches everything locally (unbounded, the
  same problem this plan is fixing) or has no offline-availability story at all.
- **Manifest/version awareness.** Rename tracking, provisional-version reconciliation,
  tombstones, and chunk-level dedup all live in ironmesh's manifest model, which a generic
  driver talking to a bare S3 API has no visibility into.
- **Counterpoint worth tracking.** AWS's `mountpoint-s3` (Rust, open source) has already
  solved a meaningful chunk of what Slice 1 is building here — bounded-memory streaming
  reads — so it's a useful reference implementation, and possibly a reasonable stopgap for
  simple read-mostly mirrors. It is not a candidate to replace `adapter-linux-fuse` wholesale
  given the rename/versioning gap above.

Conclusion: keep the custom driver; this plan's FUSE slices remain worth doing. Revisit
only if the S3 API PR reveals ironmesh doesn't actually need rename/version semantics for
some class of mounts (e.g. a read-only archive mirror), in which case a generic gateway
could be offered as an additional, simpler mount mode alongside the custom driver — not a
replacement for it.

## Slice 0: Observability — implemented (2026-07-06)

The dashboard already samples whole-process RSS (`ProcessStatsSample`,
`crates/server-node-sdk/src/lib.rs`, `spawn_process_stats_sampler`) and renders it in
[DashboardPage.tsx](web/apps/server-admin/src/pages/DashboardPage.tsx). Added a "Memory
attribution" card next to it, backed by a new `/process/stats/memory` endpoint
(`process_stats_memory` in `crates/server-node-sdk/src/lib.rs`, mounted alongside the
existing `/process/stats/current` and `/process/stats/history` routes):

- **Current-objects cache**: resident entry count vs. configured capacity
  (`PersistentStore::current_objects_cache_stats`, new `RangeChunkCache::len`/`capacity`
  in `crates/common/src/range_chunk_cache.rs`), an estimated resident-byte figure (rough
  per-entry constant, not a precise accounting), and the total live object count from
  sqlite (`count_current_objects`, now available outside tests). Reworked from the
  original "current_state entry count" bullet since Slice 2b replaced the resident
  `CurrentState` maps with this bounded cache — there's no full map left to size.
- **In-flight uploads**: session count and total bytes (`chunk_count × chunk_size_bytes`
  summed across open `UploadSessionRecord`s).
- **Last GC pass**: `retained_manifests_processed` and `peak_manifest_batch_size` (added
  to `CleanupReport` by Slice 3) plus deleted counts and dry-run flag, captured in
  `ServerState.storage.last_gc_pass` on every `/maintenance/cleanup` call (dry or not) so
  there's something to show without waiting for a real GC pass.
- **FUSE hydrated-bytes gauge: deferred.** Not implemented — `adapter-linux-fuse` runs in
  a separate client process (typically a different host) with no existing telemetry path
  to server-node's dashboard, and Slice 1 (which would track resident hydrated bytes in
  the first place) hasn't landed yet. Revisit once Slice 1 exists and a transport for
  client-side gauges is decided.

Additive, low-risk change with no effect on GC/cleanup behavior; the dashboard now shows
attribution for the two implemented hotspot fixes (Slices 2b and 3) and for in-flight
upload memory. Verified via `cargo test -p server-node-sdk` (300 tests) and
`--features turso-metadata` (439 tests), `cargo clippy` clean on both, and
`pnpm --filter @ironmesh/server-admin typecheck && build` clean.

## Slice 1: Bound FUSE hydrated memory

Clarification found while implementing 1a: `crates/adapter-linux-fuse/src/client_rights_edge.rs`
already implements the bounded `RangeChunkCache`-backed hydrator used for **range reads**
on read-only opens (`read_file_data`'s `hydrate_range` path never touches `FsNode.data` at
all, so it was never part of the unbounded-growth problem). The actual hotspot is narrower
than the original wording of 1c suggests: only `hydrate_if_needed` — the *eager, full-file*
hydration triggered by a write-intent `open()` or a size-changing `setattr` — reads the
whole file into `FsNode.data` and has no bound. 1c's "unify with `RangeChunkCache`" framing
should be read as "extend the existing bounded range-read path to also serve writes",
not "introduce range-based hydration for the first time."

### 1a — Global byte budget with eviction (low risk, do first) — implemented (2026-07-06)

- `IronmeshFuseFs` now tracks a `hydration_byte_budget: u64` (default 256 MiB, overridable
  via `IRONMESH_FUSE_HYDRATION_BUDGET_BYTES`), and `resident_hydrated_bytes()` sums
  `FsNode.data.len()` across all nodes on demand (computed only at hydration time, not
  incrementally — avoids a counter that could silently desync from direct `.data` writes in
  tests/other code paths).
- `hydrate_if_needed` (`crates/adapter-linux-fuse/src/lib.rs`) now calls
  `evict_hydrated_data_to_fit(additional_bytes)` before fetching the new file's bytes. This
  walks all nodes, filters to eligible candidates (regular file, non-empty `data`,
  `placeholder_content_hash.is_some()`, `sync_metadata.remote_version.is_some()`, no open
  handle), sorts by `modified_at` ascending (oldest-hydrated first, an approximation of LRU
  — see below), and clears `data` + restores `placeholder_version` on enough of them to fit
  the incoming file within budget.
- **Key correctness change**: `hydrate_if_needed` used to clear `placeholder_content_hash`
  after a successful hydration. It no longer does — the content hash is left in place as
  the "this file's resident bytes still match a known remote version" signal, and every
  mutation path that can make local content diverge from that remote version (`write`,
  `truncate_if_needed`, `upsert_file_local_only`) already independently clears
  `placeholder_content_hash` to `None` the moment it happens. So a node's
  `placeholder_content_hash.is_some()` after hydration is a reliable "safe to silently
  drop and re-fetch later" signal without adding a new field or dirty-tracking mechanism.
- "LRU" here is approximated by `modified_at`, which is already updated on each hydration
  and not touched by plain reads — i.e. recency-of-hydration, not recency-of-access. Chosen
  deliberately over adding a separate access-order queue (as `RangeChunkCache` uses) to
  keep the hot read path completely unchanged and reduce risk on this correctness-critical
  code.
- Verified: `hydration_budget_evicts_lru_clean_files_but_protects_open_handles`
  (`crates/adapter-linux-fuse/src/lib.rs`, `runtime::tests`) hydrates 3 synthetic 4 MiB
  files under a budget that fits only 2, with one file's handle held open; asserts the
  open-handled file survives eviction even though it wasn't the most recently hydrated,
  the LRU clean file gets correctly re-placeholdered, resident bytes stay within budget,
  and re-hydrating the evicted file afterward still returns correct content. Full existing
  suite (41 tests) passes unmodified; `cargo clippy` clean.
- No behavior change for small/typical workloads; only changes eviction *timing* under
  memory pressure — reads/writes/uploads are otherwise untouched.

### 1b — Disk-backed staging for large files (do second)

- For files above a size threshold (e.g. 8 MiB), hydrate directly into a per-mount stage
  file instead of a `Vec<u8>`, mirroring the CFAPI hydrator's
  `download_to_writer_resumable_staged` (`adapter-windows-cfapi/src/live.rs:151-159`).
  Serve `read()` via `pread` on the stage file; serve `upload_inode` by streaming from the
  stage file instead of cloning `node.data` wholesale (`lib.rs:1590-1597`).
- Small files keep the current in-memory path — no need to pay staging overhead for the
  common case.
- Not yet implemented.

### 1c — Range-based hydration for all sizes (optional, only if 1a/1b prove insufficient)

- Extend the write-intent (`hydrate_if_needed`) path to reuse the bounded `RangeChunkCache`
  model `client_rights_edge.rs` already uses for range reads, so no full-file read is ever
  required in memory even for writes. Larger effort; only pursue if Slice 0 telemetry shows
  1a/1b aren't enough in practice.
- Not yet implemented.

## Slice 2: Shrink `CurrentState` per-entry cost

- Replace hex-string manifest hashes and object IDs with fixed-size byte arrays
  (`[u8; 32]` for blake3 hashes, `[u8; 16]` for UUID-based object IDs) instead of `String`.
  This removes a separate heap allocation per value and roughly halves the per-entry cost,
  with no on-disk format change (encode/decode only at the sqlite TEXT boundary).
- Add round-trip tests for the encode/decode boundary before relying on it anywhere.
- Not yet implemented.

### Slice 2b — implemented directly (2026-07-06)

Originally gated behind Slice 0 telemetry; implemented unconditionally per direct request.
`PersistentStore.current_state: CurrentState` (two fully-resident `HashMap<String,String>`)
is gone. In its place:

- `MetadataStore` gained point operations backed by the existing `current_objects` table
  (schema unchanged): `get_current_object`, `upsert_current_object`, `remove_current_object`,
  `list_keys_for_object_id` (reverse lookup via the existing `object_id` index), plus
  `#[cfg(test)]`-only `count_current_objects`/`list_current_object_keys`. Implemented in both
  `SqliteMetadataStore` and `TursoMetadataStore`.
- `PersistentStore` holds `current_objects_cache: std::sync::Mutex<RangeChunkCache<String,
  CurrentObjectEntry>>` — the same bounded LRU already used by the Windows CFAPI adapter
  (`crates/common/src/range_chunk_cache.rs`, which gained a `remove` method for this use).
  Default capacity 100,000 entries, overridable via `IRONMESH_CURRENT_OBJECTS_CACHE_CAPACITY`.
- Startup no longer bulk-loads the table into memory; the cache starts empty and fills
  lazily on first touch per key, same per-key cost every other point-lookup metadata table
  already pays.
- The ~10 real mutation sites and ~66 read occurrences in `storage/mod.rs` were mechanical:
  reads funnel through `current_object_entry`/`object_id_for_key`/`current_state_binding`,
  writes through `upsert_current_object`/`remove_current_object`. The five full-scan
  consumers (`list_metadata_subjects`, `list_replication_subjects`,
  `StoreIndexInspector`/`DataScrubber`/`ReplicationSubjectInspector` construction, plus a
  few more found during implementation — `list_provisional_versions`, `tombstone_subtree`,
  `compact_tombstone_indexes`, snapshot creation) now fetch a fresh snapshot via
  `MetadataStore::load_current_state()` instead of reading a resident field.
- The old bulk `persist_current_state` (full `DELETE`+re-`INSERT` of the whole table on
  every single mutation) was removed entirely — dead code once every mutation is a point
  write. This also fixes a pre-existing write-amplification problem, not just memory.
- Verified: `current_objects_cache_stays_bounded_while_lookups_stay_correct` (new test,
  both metadata backends) seeds 5 keys with cache capacity 2 and asserts every key still
  resolves correctly and `object_count()`/`current_keys()` report the true total. Full
  existing suite (298 tests, 437 with `--features turso-metadata`) passes unmodified.

## Slice 3: Bound GC scan memory — implemented (2026-07-06)

`load_all_manifests` (the transient `HashMap<String, ObjectManifest>` covering every
manifest in the store) is gone. `PersistentStore::cleanup_unreferenced`
(`crates/server-node-sdk/src/storage/mod.rs`) now:

- Lists manifest hashes via `list_manifest_hashes`, a directory scan that reads file
  names only — no manifest JSON is parsed to find orphan candidates, only to inspect
  content that's actually retained.
- Determines the retained set (referenced manifests, plus any orphan still inside the
  retention window) without ever holding manifest content for the full store.
- Loads manifest content for the retained set only, one bounded batch at a time
  (`GC_MANIFEST_LOAD_BATCH_SIZE = 500`, overridable per-instance in tests via
  `set_gc_manifest_load_batch_size_for_test`), accumulating only `protected_chunks` and
  `protected_media_fingerprints` — the reference-count state GC actually needs — rather
  than materializing every manifest at once.
- Peak GC memory is now bounded by batch size and the size of the retained set, not by
  total manifest count on disk.
- Verified: `cleanup_unreferenced_processes_retained_manifests_across_batches` (new test,
  both metadata backends) forces the batch size down to 2 with 5 live objects and asserts
  every object's manifest and chunks survive cleanup and remain readable — a regression
  test for a batching bug that only processed the first batch. Full existing suite
  (300 tests) passes unmodified.

## Implementation Order

1. ~~Slice 0 (observability)~~ — done, see status above.
2. ~~Slice 1a (FUSE eviction budget)~~ — done, see status above.
3. ~~Slice 2 (compact `CurrentState` values)~~ — superseded by Slice 2b below, which
   replaces the resident map entirely rather than just shrinking its entries.
4. Slice 1b (FUSE disk-backed staging for large files) — still open.
5. ~~Slice 3 (GC batched scan)~~ — done, see status below.
6. Slice 1c — only if Slice 0 telemetry from real usage shows it's needed. Still open.
7. **Slice 2b — done** (see status below). Landed ahead of Slice 1 per direct request.
8. **Slice 3 — done** (see status below). Landed ahead of Slice 1 per direct request.
9. **Slice 0 — done** (see status above). Landed ahead of Slice 1a per direct request;
   its "GC pass peak manifest count" and "FUSE hydrated-bytes" gauges reflect the
   post-2b/3, pre-1a state at the time — the dashboard has no FUSE budget/eviction gauge
   yet even though 1a now exists (would be a natural follow-up, not yet done).
10. **Slice 1a — done** (see status above). Landed last of the FUSE work; 1b and 1c remain
    open, and Slice 1a's eviction activity is not yet surfaced on the Slice 0 dashboard.

## Test Plan

- **FUSE 1a (done)**: `hydration_budget_evicts_lru_clean_files_but_protects_open_handles` in
  `crates/adapter-linux-fuse/src/lib.rs` (`runtime::tests`) — 3 synthetic 4 MiB files under
  a budget fitting only 2, one handle held open; asserts the open-handled file survives
  eviction despite being hydrated earlier, the LRU clean file is evicted and correctly
  restored to a placeholder, resident bytes stay within budget, and re-hydrating the
  evicted file afterward returns correct content.
- **FUSE 1b**: large-file open/read/write/upload round-trip test; assert process RSS no
  longer grows proportionally with file size for files above the staging threshold.
- **`CurrentState` compaction**: round-trip encode/decode tests for the new fixed-size
  representations; a synthetic large-`current_objects` sqlite fixture (e.g. 500k rows) to
  compare server startup RSS before/after. (Superseded by Slice 2b below — not needed now
  that the map isn't resident at all.)
- **Slice 2b (done)**: `current_objects_cache_stays_bounded_while_lookups_stay_correct` in
  `storage_tests.rs` — seeds keys past a small forced cache capacity and asserts every key
  still resolves correctly via the sqlite fallback, and that `object_count()`/`current_keys()`
  report the true total regardless of cache size. Runs against both metadata backends.
- **GC batching (done)**: `cleanup_unreferenced_processes_retained_manifests_across_batches`
  in `storage_tests.rs` — forces `GC_MANIFEST_LOAD_BATCH_SIZE` down to 2 with 5 live objects
  (more than two batches' worth) and asserts every object's manifest/chunks survive cleanup
  and stay readable. Runs against both metadata backends. No dedicated large-scale RSS
  benchmark was run; the structural fix (no full-store `HashMap<String, ObjectManifest>`,
  bounded per-batch loads) removes the scaling factor by construction.
- Existing FUSE and server-node system tests must keep passing unmodified — none of these
  slices are meant to change client-visible read/write semantics.

## Risks

- Slice 1 touches the hot, correctness-critical FUSE read/write path; a bug here risks data
  loss or corruption, not just a performance regression. Needs careful test coverage and a
  conservative rollout (e.g. behind a config flag defaulting to the current behavior until
  proven).
  - **Slice 1a (done)**: mitigated by keeping the change narrow — eviction only triggers
    from `hydrate_if_needed`, reads/writes/uploads are untouched, and the "safe to evict"
    gate reuses an existing invariant (`placeholder_content_hash` cleared by every dirty-
    causing mutation) rather than adding new dirty-tracking that could itself have bugs.
    Still: this is the only slice-1a-shaped change in the codebase and has not been
    exercised under real multi-GB workloads or concurrent-access stress — the synthetic
    test covers the eviction algorithm's correctness, not production-scale timing/races.
- Slice 1b/1c change performance characteristics for large sequential reads/writes (e.g.
  video scrubbing, large project files) — needs benchmarking against real editing workflows
  to avoid regressing UX for the sake of RAM.
- Slice 2's fixed-size representation must be validated against every code path that
  currently assumes `String` hashes/IDs (serialization, logging, comparisons) — grep-audit
  before merging, not just unit-test the new type in isolation. Moot if Slice 2 is skipped
  in favor of the now-implemented Slice 2b.
- **Slice 2b (done)**: reintroduces sqlite read latency onto paths that used to assume
  in-memory O(1) lookup — every cache miss now costs one point query on the same
  `std::sync::Mutex`-guarded sqlite connection every other point-lookup metadata table
  already shares. No dedicated latency benchmark was run before landing this; worth
  watching under real load, especially for keys outside the default 100k-entry working set.

## Exit Criteria

- ~~FUSE process RSS stays within the configured hydration budget regardless of how much
  total data is synced~~ — done for the write-hydration path (1a): `hydrate_if_needed`
  proactively evicts LRU clean resident data before exceeding
  `IRONMESH_FUSE_HYDRATION_BUDGET_BYTES` (default 256 MiB), verified by the synthetic
  eviction test. Not yet true for every byte a mount touches — 1b/1c (still open) would
  extend the same bound to large-file staging and range-hydrated writes.
- ~~Server steady-state RSS attributable to `current_state` is measurably reduced at
  constant file count~~ — superseded: as of Slice 2b, this structure's resident size is
  bounded by cache capacity (default 100k entries) regardless of file count, not just
  "reduced." Slice 0's gauge would still be useful to confirm this in production but is no
  longer required to validate the fix.
- ~~GC pass peak RSS no longer scales with total manifest count~~ — done: `cleanup_unreferenced`
  no longer builds a full-store manifest map; retained-manifest content is loaded in
  bounded batches (default 500), so peak resident manifest data no longer scales with
  total manifest count on disk.
- ~~The admin dashboard shows per-structure memory attribution next to the existing
  whole-process RSS graph~~ — done for current-objects cache, in-flight uploads, and last
  GC pass (Slice 0); FUSE hydrated bytes remains unattributed until Slice 1 exists.
