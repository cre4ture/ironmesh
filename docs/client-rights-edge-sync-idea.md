# Client-Rights Edge Sync Idea

Status: Idea

## 1. Summary
This idea explores a least-privilege replacement for the current `LocalEdge` model.

Goal:
- keep offline-capable local caching and conflict handling close to the device,
- reuse as much of the existing client-side sync logic as possible,
- avoid granting the edge process cluster-node privileges.

Core principle:
- the edge should authenticate as a regular client device,
- not as a cluster node,
- and should therefore only use client-facing APIs.

## 2. Motivation
The current `LocalEdge` implementation reuses valuable server-node logic:
- persistent local object/chunk storage,
- version history,
- offline mutation capture,
- replication repair,
- reconciliation of provisional versions.

That reuse is attractive, but it comes with node-level trust.
Once the edge participates as a node, it can use peer transport and peer APIs, advertise presence, and take part in cluster replica bookkeeping.

For some deployments that trust level is broader than desired.
The edge is conceptually closer to:
- a powerful offline client,
- a local cache,
- a sync/conflict worker tied to one user or one device.

## 3. Proposal
Introduce a separate architecture path: `client-rights edge sync`.

This would not be a special `server-node` mode.
It would be a client-side sync agent that combines:
- a regular client identity,
- persistent local content-addressed cache,
- persistent local sync state,
- local conflict tracking and resolution,
- filesystem integration such as FUSE or folder sync.

## 4. Trust Model
The client-rights edge would have the same authority as a regular client:
- read objects,
- write objects,
- delete/rename/copy paths,
- inspect snapshots and store index,
- work with version history exposed by the client API.

It would not:
- register rendezvous presence as a node,
- receive node-to-node relay tickets,
- call peer replication endpoints,
- advertise itself as a replica placement target,
- participate in cluster heartbeat or replica repair as infrastructure.

## 5. Architecture Sketch
### 5.1 Local components
- `client-sdk` transport and auth for all remote access
- `content_addressed_client_cache` for persistent local bytes
- `sync-core` for change detection and conflict planning
- local SQLite state for baseline, pending work, conflicts, and crash recovery
- filesystem adapter layer such as FUSE or folder sync

### 5.2 Remote contract
The edge talks only to client-facing endpoints such as:
- `/snapshots`
- `/store/index`
- `/store/index/changes/wait`
- `/store/{key}`
- `/store/delete`
- `/store/rename`
- `/store/copy`
- `/store-chunks/upload`
- `/versions/{key}`
- `/versions/{key}/confirm/{version_id}`
- `/versions/{key}/commit/{version_id}`

### 5.3 Sync model
Remote changes:
- fetch remote snapshot or store index
- compare with local baseline and hydrated state
- plan placeholder creation, hydration, upload, or conflict handling

Local changes:
- persist bytes locally first
- record pending mutation in local durable state
- upload when connected
- keep conflict policy local to the edge agent

Conflicts:
- handled as client-visible sync conflicts rather than server-node reconciliation jobs
- preserve both sides by default
- require explicit resolution when ancestry is ambiguous

## 6. Important Difference From Current LocalEdge
This idea does not reuse the current peer replication engine unchanged.

The current repair/reconcile behavior depends on node-only concepts:
- peer transport,
- replication bundle export/import,
- chunk push between nodes,
- replica view synchronization,
- cluster replica bookkeeping,
- provisional reconciliation between nodes.

A client-rights edge would need its own sync loop built on client APIs.
That is the key tradeoff:
- lower privilege,
- but less reuse of the existing server-node peer logic.

## 7. What Can Be Reused
Reusable today:
- `sync-core` conflict planning
- persistent local client cache
- client auth and transport
- filesystem adapters that already consume client-style get/put operations
- versioned object storage semantics on the server

Likely reusable with extension:
- local crash-safe baseline/state patterns already explored for folder sync
- conflict persistence and resolution UI concepts
- client-side remote change polling via `/store/index/changes/wait`

## 8. Missing Pieces
To make this practical, the client-facing stack likely needs additional support.

### 8.1 Client SDK gaps
- first-class versioned write helpers that expose:
  - parent version ids
  - provisional vs confirmed state
- helpers for:
  - listing versions
  - confirming or committing versions
  - selecting provisional reads where needed

### 8.2 Durability / recovery gaps
- durable local mutation queue
- durable upload session tracking
- explicit restart recovery for in-flight large transfers
- temp artifact cleanup and retry policy

### 8.3 Transfer robustness gaps
- resumable uploads
- resumable downloads or ranged reads
- end-to-end streaming for very large downloads

## 9. Benefits
- least-privilege edge identity
- simpler security story
- easier mental model: this is a client with strong offline behavior, not cluster infrastructure
- avoids exposing peer APIs on edge devices

## 10. Costs
- cannot directly reuse current node replication repair as-is
- requires new client-side sync engine work
- may converge functionally with the folder-agent architecture
- durability semantics differ from a replica node:
  - local persistence exists on the device,
  - but the edge is not itself a cluster replica placement target

## 11. Recommendation
Treat this as a product/architecture branch, not a small refactor.

Good fit when:
- least privilege matters more than reuse of node replication internals
- the edge is conceptually one user/device cache and sync worker
- local offline behavior is more important than making the edge a true replica node

Poor fit when:
- the main goal is to reuse existing node replication, repair, and reconciliation with minimal new implementation work
- the edge must behave like a full storage peer in the cluster

## 12. Suggested Next Step
Prototype a small vertical slice:
- durable local cache
- durable mutation queue
- remote change polling
- conflict planning using `sync-core`
- upload/download through client APIs only

Related idea:
- `docs/client-rights-edge-resumable-transfer-proposal.md`

If that prototype feels good, it can become a separate edge architecture track next to the current node-backed local edge.
