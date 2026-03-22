# Persistent Storage Requirements and Strategy

## Requirements

1. **Corruption must be detectable**
   - Any stored payload corruption needs to be identified on read.

2. **No mandatory auto-repair**
   - Corrupted local data can be treated as unavailable.
   - Repair strategy is to re-download from another connected node.

3. **Automatic deduplication**
   - Duplicate content should not be stored repeatedly.

4. **Regular snapshots / time travel**
   - Capture full node state repeatedly.
   - Support reading older versions of stored data.

## Chosen Strategy

The node uses an on-disk **content-addressed object store** with immutable snapshot manifests.

### Identity and namespace model

- `object_id` is immutable identity of a logical file.
- `path` is a mutable namespace binding to an `object_id`.
- Version history is attached to `object_id`, not to path text.
- Rename updates only namespace bindings and keeps `object_id`.
- Copy creates a new `object_id` and records provenance on the first copied version:
  - `copied_from_object_id`
  - `copied_from_version_id`
  - optional `copied_from_path`

### 1) Content-addressed chunk storage

- Incoming object data is split into fixed-size chunks (currently 1 MiB).
- Each chunk is hashed with `BLAKE3`.
- Chunk file path is derived from the hash (`chunks/<prefix>/<hash>`).
- If a chunk hash already exists, the chunk is reused (dedup) instead of written again.

### 2) Object manifests

- Each stored object key maps to an immutable manifest containing:
  - chunk hashes in order,
  - expected chunk sizes,
  - total object size,
  - creation timestamp.
- Manifest files are also content-addressed by hash (`manifests/<hash>.json`).

### 3) Corruption detection

On every read:

- The node loads chunk files referenced by the manifest.
- For each chunk, it verifies:
  - file exists,
  - expected byte length,
  - expected `BLAKE3` hash.
- Any mismatch is reported as corruption and the read fails.

### 4) Snapshot model

- The node maintains mutable namespace state in `state/current.json`:
  - `path -> object_id` bindings,
  - `path -> head_manifest_hash` materialization for read/index compatibility.
- After each successful write, the node creates an immutable snapshot in `snapshots/`.
- A snapshot captures full namespace/materialized state at that point in time.
- Older versions are accessible by reading with a snapshot ID.

### 5) Branching / conflict model

- Concurrent writes to one logical document create multiple heads in the same `object_id` DAG.
- Preferred-head policy resolves default reads.
- Rename does not break branching continuity because identity remains `object_id`.
- Copy starts a new DAG rooted with provenance metadata to source history.

## API behavior

- `PUT /store/{key}`
  - Stores bytes into chunked, deduplicated persistent storage.
  - Automatically updates current state and creates a snapshot.
  - Best for smaller payloads where a single request body is acceptable.

- `POST /store-chunks/upload`
  - Uploads one content chunk and returns its `BLAKE3` hash plus dedup info.
  - Intended for chunked/resumable clients and large files.

- `POST /store/{key}?complete`
  - Finalizes an object version from previously uploaded chunk refs.
  - Automatically updates current state and creates a snapshot.
  - Supports the same versioning query options as `PUT /store/{key}` (`state`, `parent`, `version_id`, `internal_replication`).

- `GET /store/{key}`
  - Reads latest version from current state.

- `GET /store/{key}?snapshot=<id>`
  - Reads historical version from a specific snapshot.

- `GET /snapshots`
  - Lists available snapshots.

## Operational notes

- Default data directory: `./data/server-node`
- Override with: `IRONMESH_DATA_DIR=/path/to/node-data`
- Bind address override: `IRONMESH_SERVER_BIND=host:port`

## Future extensions

- Background anti-entropy that re-fetches missing/corrupt chunks from peers.
- Configurable chunking strategy (content-defined chunking for improved dedup).
- Refcount + garbage collection for unreferenced chunks.
- Signed snapshot manifests for stronger tamper evidence.
- Resumable upload session metadata persisted on disk (for crash-safe resume across restarts).
- Cluster-wide metadata visibility and read-through chunk caching for non-replica reads.
  See `docs/read-through-chunk-cache-proposal.md`.
