# Multi-Node Requirements and Strategy

## Requirements (as provided)

- Data uploaded to one node should be replicated to other connected nodes automatically.
- Sharding must be supported so not every node stores every object.
- Replication can be asynchronous (minutes are acceptable).
- Priority is robust and efficient operation (traffic and performance overhead minimized).
- Replication policy verification must run automatically and repair missing replicas.
- Verification should run periodically (configurable), and ideally also on node-down events.
- Replication rules must support generic location awareness (data-center/rack, etc.).
- Over-replication cleanup should be manual and scheduled, with configurable retained overhead (e.g. 100 GB).
- Cleanup should prioritize nodes with lowest free space.
- Clients should connect to multiple nodes in parallel and prioritize best/fastest paths.
- Client ratings should be refreshed periodically by exploratory reads from non-primary nodes.
- Clients should not connect to all servers; choose nearest subset by location with configurable count.
- Clients should periodically retry reconnecting failed nodes.

## Strategy

### 1) Cluster metadata model (generic)

Represent each node with:

- `node_id`
- `public_url`
- `labels` (generic map, e.g. `region=eu`, `dc=fra-1`, `rack=r12`)
- `capacity_bytes`, `free_bytes`
- `last_heartbeat_unix`, status

This enables location-aware policy without hardcoding data-center/rack logic.

### 2) Deterministic sharding/placement

Use **Rendezvous hashing** on object key + node id for candidate ranking.

- Keeps placement stable across membership changes.
- Minimizes data movement on scale up/down.
- Supports sharding naturally.

Placement then applies policy constraints:

- replication factor
- label diversity constraints (e.g. min distinct `dc`, min distinct `rack`)

### 3) Async replication pipeline

Write path stores locally first, then enqueues replication intents.

- Missing replicas are repaired by background workers.
- Transfers are chunk-aware and content-addressed (only missing chunks copied).
- Eventual consistency is acceptable by requirement.

### 4) Verification and repair

A background **replication auditor** runs periodically (configurable) and can be triggered when nodes transition to offline.

- Computes desired replicas from placement policy.
- Compares against known replica map.
- Emits repair actions for under-replicated objects.

### 5) Over-replication cleanup

Separate cleanup planner (manual + scheduled daily):

- Never violate minimum replication policy.
- Keep configurable safety overhead.
- Prefer deletions from nodes with lowest free space first.

### 6) Client multi-node behavior

Client node pool should:

- maintain a configurable active subset (not all nodes), biased by location labels,
- keep parallel connections and rank by EWMA latency/throughput/failure rate,
- perform periodic exploratory reads to re-evaluate ranking,
- periodically retry failed nodes with backoff.

## Implementation phases

1. Cluster registry + heartbeats + node status transitions.
2. Placement engine + policy definitions.
3. Replication planner + periodic auditor API.
4. Replication executors (chunk transfer + retry/backoff).
5. Over-replication cleanup planner/executor.
6. Client multi-endpoint routing and adaptive ranking.

## What is implemented in this initial step

- Cluster metadata model and membership API.
- Deterministic placement with policy constraints.
- Replication audit planner endpoint + periodic audit task scaffold.
- Node-down transition detection hook to trigger immediate audit planning.

## What remains for later steps

- Actual inter-node replication transfer execution.
- Persistent replica index across restarts.
- Cleanup scheduling/automation policy tuning.
- Client-side multi-node adaptive routing implementation.

## Current implementation status (phased)

- **Phase A:** Completed — version DAG metadata primitives (`provisional`/`confirmed`, parent links, version listing).
- **Phase B:** Completed — metadata commit endpoint and quorum-gated commit mode.
- **Phase C:** Completed — provisional rejoin reconciliation with branch-preserving import.
- **Phase D:** Completed — deterministic preferred-head reads and explicit read modes.
- **Phase E.1:** Completed — replication auditing now includes version-head subjects (`key@version`).
- **Phase E.2:** Completed — retention-safe orphan cleanup endpoint with reachability guardrails.
- **Phase E.3:** Completed — reconciliation idempotency via persisted replay markers.
- **Next:** Phase E.4 documentation/UI stabilization and then executor-side replication transfer.

## Decision log

### Decision 1: Offline multi-client modifications and conflicts

**Status:** Decided

**Decision:**

- The system is offline-first and accepts concurrent file modifications from multiple clients.
- Conflicts must be **no-loss**: no version is overwritten or discarded.
- Conflicting updates are stored as separate branches in a per-file version graph (DAG).
- A default "preferred" head can be shown automatically (for convenience), but losing branches remain in history.
- Users must be notified when conflicts occur and can resolve conflicts manually by creating a merge version.

**Implications:**

- File history must support multiple heads (not only linear history).
- API and metadata need explicit version IDs and parent references.
- Merge operations create a new version with multiple parents.
- Optional latest-wins can be used only as a display preference, not as destructive conflict resolution.

### Decision 2: Consistency guarantees for metadata and reads

**Status:** Decided

**Decision:** Adopt **Hybrid consistency**.

- Content/chunk replication remains asynchronous and eventually consistent.
- File-version metadata (heads, branch links, merge commits, tombstones) follows stronger consistency semantics.
- Writes should still be accepted in partitioned/offline scenarios as provisional branch commits, then reconciled on rejoin.

**Partition behavior:**

- Majority/healthy control-plane path: metadata commits can be globally confirmed.
- Minority/disconnected path: writes remain possible as local provisional branches.
- After rejoin, provisional commits are synchronized and conflicts are preserved as branches (no-loss).

**Rationale:**

- Keeps offline-first availability and no-loss conflict handling.
- Reduces split-brain risk for globally visible "preferred head" metadata.
- Limits traffic and reconciliation overhead compared to pure eventual on all metadata.

## Next implementation checklist (Hybrid rollout)

1. **Phase A — Version graph metadata primitives**
	- Add per-file version IDs, parent links, branch heads, merge commits.
	- Distinguish `provisional` vs `confirmed` metadata state.

2. **Phase B — Metadata consistency path**
	- Add metadata commit API contract for confirmations.
	- Keep chunk/object transfer asynchronous.

3. **Phase C — Rejoin reconciliation**
	- Sync provisional commits after partition heal.
	- Build conflict branches automatically without data loss.

4. **Phase D — Preferred-head policy**
	- Add deterministic preferred-head selection for default reads.
	- Keep full branch visibility for manual merge workflows.

5. **Phase E — Verification and cleanup alignment**
	- Extend replication auditor to account for version DAG branches.
	- Schedule cleanup with safety margin and low-free-space prioritization.

### Decision 3: Delete semantics

**Status:** Decided (recommended default approved)

Options:

1. Hard delete immediately
2. Soft delete with tombstones (recommended)

Recommended default:

- Use tombstones replicated like metadata.
- Tombstone retention window: 30 days (configurable).
- Physical chunk cleanup only after retention and reachability checks.

### Decision 4: Version causality model

**Status:** Decided (recommended default approved)

Options:

1. Timestamp-only ordering
2. Version vectors / dotted version vectors (recommended)

Recommended default:

- Use dotted version vectors for conflict detection and causality.
- Use timestamps only for UI sorting, never as sole conflict authority.

### Decision 5: Preferred-head policy

**Status:** Decided (recommended default approved)

Options:

1. Latest timestamp always
2. Deterministic policy with confirmed/provisional precedence (recommended)

Recommended default:

- Default read head selection order:
	1) latest confirmed branch head,
	2) latest provisional head if no confirmed head exists,
	3) deterministic tie-break by version ID.

### Decision 6: Merge policy

**Status:** Decided (recommended default approved)

Options:

1. Manual merge only (recommended initially)
2. Optional auto-merge for known file types + manual fallback

Recommended default:

- Start manual-only merge commits with explicit parent versions.
- Add optional type-specific auto-merge later.

### Decision 7: Read consistency modes for clients

**Status:** Decided (recommended default approved)

Options:

1. Always read preferred head only
2. User-selectable modes (recommended)

Recommended default:

- Support explicit read mode:
	- `preferred` (deterministic preferred head; default)
	- `confirmed_only` (latest confirmed head only)
	- `provisional_allowed` (latest head, including provisional)
- Keep exact historical reads via `version=<version_id>` query selector.

### Decision 8: Membership authority

**Status:** Decided (recommended default approved)

Options:

1. Central coordinator/control plane (recommended for initial rollout)
2. Fully distributed gossip/lease model

Recommended default:

- Start with a control-plane authority for membership and policy.
- Keep node descriptors generic so migration to distributed membership remains possible.

### Decision 9: Security model

**Status:** Decided (recommended default approved)

Options:

1. Trust internal network only
2. Authenticated + encrypted node/client traffic (recommended)

Recommended default:

- Node-to-node mTLS.
- Client auth tokens/certs.
- Authorization scopes for metadata, replication, and admin endpoints.

### Decision 10: Metadata persistence engine

**Status:** Decided (recommended default approved)

Options:

1. JSON file sets only
2. Embedded transactional KV for metadata indices (recommended)

Recommended default:

- Keep chunk/manifests as files.
- Store DAG heads, tombstones, replica index, and audit state in embedded KV DB.

### Decision 11: Garbage collection and retention

**Status:** Decided (recommended default approved)

Options:

1. Immediate cleanup when unreferenced
2. Deferred policy-driven GC (recommended)

Recommended default:

- Mark-and-sweep GC with grace windows.
- Policy knobs:
	- minimum snapshot/version retention
	- tombstone retention
	- free-space emergency mode
	- daily scheduled cleanup + manual trigger

### Decision 12: Node bootstrap UX for runtime join

**Status:** Decided

**Decision:** Support both bootstrap paths:

1. **Prepackaged service + web pairing** (Option 2)
	- Node starts in `unpaired` mode.
	- Operator uses cluster UI to generate a pairing token/code.
	- Node local setup page consumes pairing token and joins.

2. **Cloud-init/config-file bootstrap** (Option 3)
	- Node starts with preseeded controller URL + bootstrap token/cert request config.
	- Node auto-enrolls without interactive local setup.

**Implementation note:**

- Both paths must use the same enrollment backend APIs and node-state machine (`unpaired -> pending -> joining -> online`).
- Security controls (token expiry, one-time use, approval policy, revocation, cert rotation) are identical for both paths.
- This keeps UX flexible while preserving a single trusted join protocol.
