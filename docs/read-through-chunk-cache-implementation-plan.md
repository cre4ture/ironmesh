# Read-Through Chunk Cache Implementation Plan

## Status

Work in progress.

## Goal

Implement the proposal from `docs/read-through-chunk-cache-proposal.md` in slices that
deliver value early and keep the current replication planner correct throughout the rollout.

## Constraints

- Cluster-visible metadata must not make the cluster think every node is a full replica.
- Existing client APIs should stay unchanged.
- The first slice should improve cross-node namespace consistency before touching the read path.
- Tests must cover both metadata visibility and eventual read-through behavior.

## Slice 0: Documentation and Boundaries

- Document this implementation plan and link it from the proposal.
- Explicitly distinguish:
  - metadata-visible object,
  - fully readable local replica,
  - cached chunk.
- Keep replica-view synchronization based on fully readable local subjects only.

## Slice 1: Cluster-Wide Metadata Visibility

### Objective

Make directory trees and preferred-head metadata converge across all cluster nodes without
requiring full content replication.

### Design

- Add a metadata export/import path for:
  - current key metadata,
  - version metadata,
  - manifest bytes,
  - stable `object_id`,
  - version timestamps and ancestry.
- Import metadata without requiring local chunk presence.
- Persist imported manifests and version indexes locally.
- Materialize current namespace state from imported version metadata.
- Publish namespace changes after successful imports so local index watchers update.

### Important guardrail

- Replica-view synchronization must advertise only fully readable local subjects.
- Metadata-only imports must not call the existing `cluster.note_replica(...)` path.

### Expected result

- `GET /store/index` becomes consistent across nodes after metadata sync converges.
- Preferred-head reads resolve the same manifest hash across nodes.
- Actual object byte reads may still fail on non-replica nodes until Slice 2 lands.

## Slice 2: Synchronous Read-Through Chunk Fetch

### Objective

Allow a node that has metadata but lacks some chunks to serve reads by fetching only the needed
chunks from a replica node on demand.

### Design

- Extend local range planning so missing chunks trigger remote fetch instead of immediate failure.
- Choose a source node from cluster replica metadata.
- Fetch only the chunks needed for the requested range.
- Ingest fetched chunks into the existing content-addressed chunk store.
- Continue serving the client response from the now-local chunk files.

### First implementation target

- Keep the first read-through path blocking and simple.
- Do not add speculative prefetching yet.
- Favor correctness over maximal streaming overlap.

## Slice 3: Cache Accounting and Eviction

### Objective

Track which chunks are locally cached only because of read-through access and make those chunks
eligible for cleanup without affecting full replicas.

### Design

- Add cache-only metadata for chunk access tracking.
- Keep full-replica chunks protected by existing reachability rules.
- Evict cached-only chunks by policy such as LRU, TTL, or low-free-space pressure.

## Slice 4: Optimization and Observability

- Adjacent-chunk prefetch for sequential reads.
- Concurrent remote chunk fetch caps.
- Better source-node selection.
- Admin visibility for cache hit/miss and cache size.

## Implementation Order

1. Add metadata sync data structures and endpoints.
2. Add storage import helpers for metadata-only manifests and version records.
3. Change replica-view sync to report only fully readable local subjects.
4. Add focused tests for cross-node metadata visibility.
5. Add read-through chunk fetching on demand.
6. Add end-to-end system coverage for non-replica reads.
7. Add cache accounting and eviction.

## Test Plan

### Focused tests

- metadata-only imports do not mark a node as a full replica,
- imported metadata updates local `store/index` visibility,
- local replica-view sync excludes subjects whose chunks are missing,
- non-replica reads begin succeeding once read-through fetching is implemented.

### Required system test

The proposal already requires this system test and implementation should not be considered done
without it:

- 5 server-nodes,
- replication factor 3,
- upload one file through node 1,
- wait for metadata replication,
- read the same file from each node separately,
- require all reads to succeed, including on nodes that are not full replicas.

## Likely Risks

- Imported metadata must preserve stable `object_id` and version ancestry.
- Replica accounting can become incorrect if metadata-visible subjects leak into the replica view.
- Cross-node metadata import must remain idempotent.
- The first read-through implementation may need a small manifest/source-node lookup layer before
  it can stream successfully.

## Exit Criteria

The feature is functionally complete when:

- listings and preferred-head metadata converge across nodes,
- a non-replica node can serve a file by fetching only the missing chunks it needs,
- cached chunks are distinguishable from full replicas,
- the required 5-node system test passes.
