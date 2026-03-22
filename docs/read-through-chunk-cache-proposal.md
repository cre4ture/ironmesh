# Read-Through Chunk Cache and Cluster-Wide Metadata Proposal

## Status

Idea.

## Motivation

The current storage and replication model is optimized for full-object replicas:

- chunks are content-addressed and deduplicated,
- manifests describe full logical objects,
- replication transfers only missing chunks,
- reads are served from the local node's own manifest and chunk store.

This works well when the node serving a client is also a full replica for the requested object.
It breaks down for very large objects and sharded clusters:

- a node that does not hold a full replica cannot currently serve reads,
- a client connected to different nodes can observe different namespace visibility if metadata is not present everywhere,
- using a custom proxy per large-file use case would duplicate logic that should really live in the storage layer.

Examples:

- giant PMTiles archives,
- VM disk images,
- video files,
- backup archives,
- large scientific datasets.

## Current Behavior

### Data path

- A full replica stores:
  - manifest file,
  - version-index metadata,
  - current namespace bindings,
  - all chunks referenced by the preferred visible version.
- Replication is chunk-aware, but still results in a local full readable replica.
- Read planning fails when a referenced chunk is absent locally.

### Metadata path

- Namespace bindings and preferred-head materialization are stored in each node's local metadata store.
- Replica-manifest import updates the local version index and local current-state bindings on the importing node.
- Metadata commit currently provides a stronger local admission rule via quorum checks, but it does not by itself imply cluster-wide metadata fanout to every node.

### Consequence

Today, namespace visibility is effectively replica-local.

That means:

- if a key has only been replicated to a subset of nodes, only that subset is guaranteed to list and read it,
- differences between nodes can be temporary while asynchronous replication is still catching up,
- under real sharding, differences can become persistent unless metadata is distributed more broadly than object data.

This is in tension with the intended "globally visible preferred head" direction of the hybrid consistency model.

## Proposal

Introduce two related mechanisms:

1. cluster-wide metadata visibility,
2. read-through chunk caching on non-replica nodes.

These should be designed together, but they can be implemented in slices.

## Design Principles

### Distinguish cache from replica

A node may hold some chunks of an object without being a full replica.

We should model these separately:

- full replica:
  - manifest + version metadata + all referenced chunks needed for local object reads,
  - counts toward replication policy.
- metadata-visible object:
  - namespace binding and preferred-head metadata are known locally,
  - object may still require remote chunk fetches.
- cached chunks:
  - some subset of object chunks exist locally because of recent reads,
  - does not count as a replica.

### Reuse the existing chunk store

Fetched chunks should be written into the normal content-addressed chunk store.

Benefits:

- no second byte cache implementation,
- natural deduplication,
- all large-file reads benefit,
- repeated reads automatically get faster.

### Keep client API unchanged

Clients should continue to use the normal object GET and range GET interfaces.

The new behavior should be an internal server-node capability:

- if chunks are present locally, serve immediately,
- if some chunks are missing, fetch only what is needed and continue serving.

## Proposed Metadata Strategy

### Recommendation: distribute metadata cluster-wide

The recommended direction is:

- replicate namespace bindings, version indices, preferred-head decisions, tombstones, and manifests to all cluster nodes,
- keep chunk/object data placement subject to replication and sharding policy,
- let non-replica nodes perform read-through chunk fetches on demand.

Why:

- directory trees and object visibility become consistent across nodes,
- the node serving a client can resolve the requested object and its chunk plan without first needing a metadata miss path,
- this matches the intent that metadata has stronger consistency semantics than content replication.

### Why not keep metadata replica-local

Replica-local metadata would mean:

- clients connected to different nodes may see different directory trees and different object visibility,
- a non-replica node may not even know that a remote object exists,
- read-through chunk caching would need an additional remote metadata discovery path before each miss.

That can work, but it is harder to reason about and produces a more surprising product.

## Proposed Read Path

### High-level flow

1. Client requests `GET /store/{key}` or a byte range from node B.
2. Node B resolves the preferred visible manifest from local metadata.
3. Node B plans which chunks are needed for the requested byte range.
4. For each needed chunk:
   - if present locally, use it,
   - if absent, fetch it from a source node that is a full replica.
5. Node B stores fetched chunks in the normal chunk store.
6. Node B streams the response to the client.
7. Subsequent reads can reuse those cached chunks.

### Source selection

Node B should use cluster replica metadata to choose a source node that is expected to hold the full object.

Selection can later be improved using:

- latency,
- transport reachability,
- free space,
- recent success rates.

### Failure behavior

If no source node can provide a required chunk:

- return a read error,
- do not advertise the object as a full local replica,
- keep any successfully fetched chunks as cache unless policy says otherwise.

## Proposed Cache Metadata

In addition to the existing chunk files, maintain cache-only metadata for eviction and accounting.

Suggested fields:

- `chunk_hash`
- `size_bytes`
- `last_access_unix`
- `access_count`
- `last_source_node_id`
- `cache_class`
  - for example `read_through`
- optional `first_cached_unix`

This metadata should apply only to chunks that are not protected by local manifest reachability as part of a full local replica.

## Cleanup and Eviction

### Full replicas remain protected

Existing reachability-based cleanup should continue to protect:

- chunks referenced by locally retained manifests,
- manifests referenced by current state, snapshots, and retained history.

### Cached-only chunks become evictable

Chunks that exist only because of read-through caching should be evictable based on policy such as:

- LRU,
- TTL,
- target cache size,
- low-free-space pressure.

### Important rule

Cached-only chunks must not be treated as evidence that the node owns a full replica.

Eviction of cached-only chunks should not require replica-plan coordination, because they are not counted toward the replication factor.

## Proposed Implementation Slices

### Slice 1: metadata visibility

- distribute manifests and namespace/version metadata to all cluster nodes,
- make directory trees and preferred-head reads consistent across nodes,
- keep content reads local-only for now.

This slice is already valuable by itself because it fixes cross-node namespace divergence.

### Slice 2: blocking read-through cache

- when read planning encounters a missing chunk, fetch it synchronously from a source node,
- persist it into the local chunk store,
- continue streaming the response.

This enables generic large-object access through non-replica nodes.

### Slice 3: cache accounting and eviction

- add cache metadata,
- add size-aware cleanup,
- protect full-replica chunks from cache eviction logic.

### Slice 4: optimization

- prefetch adjacent chunks for sequential reads,
- cap concurrent remote chunk fetches,
- favor local or nearby source nodes,
- expose cache stats in admin UI.

## Required System Test Coverage

At minimum, implementation of cluster-wide metadata visibility plus read-through chunk caching
should include an end-to-end system test with this shape:

- 5 server-nodes,
- replication factor 3,
- upload one file through node 1,
- wait until metadata replication is complete across the cluster,
- read that same file from each of the 5 nodes separately,
- expect every read to succeed even when some nodes are not full data replicas.

This test is important because it validates both intended properties together:

- directory and object visibility no longer depends on which node the client hits,
- non-replica nodes can still satisfy reads by fetching only the missing chunks they need.

## Directory-Tree Consistency Implications

### Recommended end state

Clients should see the same directory tree and preferred visible contents regardless of which cluster node they connect to.

Differences should be temporary only while metadata propagation is still converging after a write or a partition heal.

### Why this matters

If metadata remains replica-local while data is sharded:

- one node may list a path while another does not,
- one node may show one preferred head while another has no visible head,
- web UIs and filesystem adapters become confusing and hard to trust.

For a storage product, that is usually the wrong default.

## Open Questions

1. Should metadata go to every node or only nodes marked client-facing?
Recommended: every cluster node, unless the product later introduces a distinct storage-only role.

2. Should manifest files themselves be distributed globally?
Recommended: yes. They are small compared to content and simplify read planning.

3. Should on-demand chunk fetch be strictly blocking in the first slice?
Recommended: yes for the first version, with later prefetch and background warming.

4. Should read-through chunks be promoted to full replicas automatically?
Recommended: no. Promotion should remain an explicit replication/placement decision.

5. Should partial cached chunks influence the replication planner?
Recommended: no. The planner should continue to reason in terms of full readable replicas.

## Summary

The preferred long-term architecture is:

- metadata visibility cluster-wide,
- content placement sharded by policy,
- missing chunks fetched on demand into the local chunk store,
- cached-only chunks tracked and evicted separately from full replicas.

This removes the need for one-off large-file proxy logic and turns partial, read-driven locality into a generic storage capability.
