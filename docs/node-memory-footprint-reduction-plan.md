# Node Memory Footprint Reduction Plan

## Status

Proposed. Not started. Follows from an ad-hoc RAM analysis of server-node and the desktop
sync clients (2026-07-06), confirmed against the current codebase.

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

## Slice 0: Observability

The dashboard already samples whole-process RSS (`ProcessStatsSample`,
`crates/server-node-sdk/src/lib.rs:1906-1913`, `spawn_process_stats_sampler` at
`lib.rs:6292`) and renders it in
[DashboardPage.tsx](web/apps/server-admin/src/pages/DashboardPage.tsx). What's missing is
attribution: knowing *why* RSS is high. Add, next to the existing process-stats panel:

- `current_state` entry count (cheap: `.len()` on both maps) and an estimated byte size.
- FUSE hydrated-bytes gauge: running total of resident `FsNode.data` bytes per mount.
- In-flight upload byte total (sum of `UploadSessionRecord` chunk counts × chunk size).
- Last GC pass peak manifest count (and, once Slice 3 lands, peak batch size instead).

This is additive, low-risk, and should land first so later slices can be measured
before/after rather than judged by guesswork.

## Slice 1: Bound FUSE hydrated memory

### 1a — Global byte budget with eviction (low risk, do first)

- Track total resident `FsNode.data` bytes for the mount.
- Before a `hydrate_if_needed` allocation would exceed a configured budget (default e.g.
  256 MiB), evict `data` from the least-recently-used *clean* nodes with no open handles —
  same precondition already required for the existing re-placeholder clear, just triggered
  proactively instead of only opportunistically.
- No behavior change for small/typical workloads; only changes eviction *timing* under
  memory pressure.

### 1b — Disk-backed staging for large files (do second)

- For files above a size threshold (e.g. 8 MiB), hydrate directly into a per-mount stage
  file instead of a `Vec<u8>`, mirroring the CFAPI hydrator's
  `download_to_writer_resumable_staged` (`adapter-windows-cfapi/src/live.rs:151-159`).
  Serve `read()` via `pread` on the stage file; serve `upload_inode` by streaming from the
  stage file instead of cloning `node.data` wholesale (`lib.rs:1590-1597`).
- Small files keep the current in-memory path — no need to pay staging overhead for the
  common case.

### 1c — Range-based hydration for all sizes (optional, only if 1a/1b prove insufficient)

- Unify Linux FUSE hydration with the bounded `RangeChunkCache` model already implemented
  and used by the Windows CFAPI adapter, so no full-file read is ever required in memory.
  Larger effort; only pursue if Slice 0 telemetry shows 1a/1b aren't enough in practice.

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

## Slice 3: Bound GC scan memory

- Change `load_all_manifests` from "collect every manifest into one `HashMap` up front" to
  a batched/streaming scan that accumulates only the reference-count state GC actually
  needs, processing manifests in bounded-size batches.
- Peak GC memory becomes bounded by batch size, not total manifest count.

## Implementation Order

1. Slice 0 (observability) — ships independently, unblocks measurement for everything else.
2. Slice 1a (FUSE eviction budget) — highest-ranked hotspot, lowest-risk fix.
3. ~~Slice 2 (compact `CurrentState` values)~~ — superseded by Slice 2b below, which
   replaces the resident map entirely rather than just shrinking its entries.
4. Slice 1b (FUSE disk-backed staging for large files).
5. Slice 3 (GC batched scan).
6. Slice 1c — only if Slice 0 telemetry from real usage shows it's needed.
7. **Slice 2b — done** (see status below). Landed ahead of Slices 0/1/3 per direct request;
   those remain open.

## Test Plan

- **FUSE 1a**: synthetic test mounting N files of size S, opening and holding handles past
  the configured budget; assert eviction keeps resident bytes bounded and reads of evicted-
  then-reopened files still return correct content.
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
- **GC batching**: large synthetic manifest count fixture; assert peak RSS during a GC pass
  stays roughly constant as manifest count grows, instead of scaling linearly.
- Existing FUSE and server-node system tests must keep passing unmodified — none of these
  slices are meant to change client-visible read/write semantics.

## Risks

- Slice 1 touches the hot, correctness-critical FUSE read/write path; a bug here risks data
  loss or corruption, not just a performance regression. Needs careful test coverage and a
  conservative rollout (e.g. behind a config flag defaulting to the current behavior until
  proven).
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

- FUSE process RSS stays within the configured hydration budget regardless of how much
  total data is synced, verified by the large-file-open synthetic test.
- ~~Server steady-state RSS attributable to `current_state` is measurably reduced at
  constant file count~~ — superseded: as of Slice 2b, this structure's resident size is
  bounded by cache capacity (default 100k entries) regardless of file count, not just
  "reduced." Slice 0's gauge would still be useful to confirm this in production but is no
  longer required to validate the fix.
- GC pass peak RSS no longer scales with total manifest count.
- The admin dashboard shows per-structure memory attribution next to the existing
  whole-process RSS graph, so operators can explain a node's memory use without guessing.
