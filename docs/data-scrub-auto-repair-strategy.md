# Data Scrub Auto-Repair Strategy

## Status

Implemented for the first conservative slice.

The current server-node runtime follows this strategy for scrub-triggered automatic repair.

## Goal

Define which data scrub findings may trigger automatic repair, which findings should remain
detect-only, and which repair path should be used for each class of issue.

The intent is to keep the first implementation conservative:

- prefer replacement from a healthy peer over local reconstruction,
- keep scrub primarily as a detector and scheduler of follow-on repair work,
- avoid destructive or metadata-rewriting behavior unless there is a clear authority source.

## Current Position

- The current scrub runtime detects corruption, records scrub history, degrades affected local
   subjects, and schedules follow-on local repair for the supported issue kinds.
- The current replication repair engine already knows how to:
  - pull a full bundle from a healthy peer to repair the local node,
  - push a healthy local bundle to another node,
  - track retries and backoff for repeated failures.
- The storage strategy already treats corrupted local data as unavailable and prefers re-download
  from another connected node over local guesswork.

## Safety Principles

1. A node should only auto-repair its own local data.
2. Byte-level corruption should be repaired by replacement from a healthy peer, not by patching
   suspect local files in place.
3. Metadata-only fixes need a stronger authority model than byte replacement.
4. If no healthy source exists, the node should degrade availability rather than invent data.
5. Scrub should queue or trigger a separate repair step instead of performing complex repair work
   inline inside the scrub pass.
6. Every automatic repair should be followed by targeted verification.
7. Every automatic repair attempt should be recorded in retained repair history.

## Authority Model

Automatic repair decisions should use the following authority order:

1. An online peer that can export a healthy replication bundle for the exact subject and version.
2. For metadata-only reconciliation, an online peer whose metadata bundle matches the expected
   `object_id`, `version_id`, lineage, and manifest hash for the subject.
3. If no such peer exists, no automatic repair should modify user-visible metadata or stored
   bytes.

For the first implementation, the safest rule is:

- byte and manifest corruption may auto-repair only by healthy-peer replacement,
- metadata path mismatches remain detect-only.

## Repair Matrix

| Scrub issue kind | Meaning | First automatic action | Preconditions | Fallback when preconditions fail | Notes |
| --- | --- | --- | --- | --- | --- |
| `manifest_missing` | Metadata references a manifest file that is absent locally. | Queue local replica rehydrate from a healthy peer. | At least one online peer can export the exact subject or versioned subject. | Leave issue open, mark the subject locally degraded, and surface it in scrub history. | Do not reconstruct the manifest from local chunks. |
| `manifest_unreadable` | Manifest file exists but could not be read from disk. | Retry local read in a bounded way, then queue local replica rehydrate if still failing. | A healthy peer export is available after the bounded local retry fails. | Leave issue open and treat the subject as unavailable locally. | Handles transient filesystem errors conservatively. |
| `manifest_invalid` | Manifest bytes are present but do not parse or violate format expectations. | Queue local replica rehydrate from a healthy peer. | Healthy peer export is available and passes normal import validation. | Leave issue open and degrade local readability for the subject. | Never attempt to synthesize a corrected manifest from the invalid local bytes. |
| `manifest_hash_mismatch` | Stored manifest bytes do not match the manifest hash referenced by metadata. | Queue local replica rehydrate from a healthy peer. | Healthy peer export is available. | Leave issue open and treat the subject as degraded locally. | Replace rather than rewrite the local file in place. |
| `manifest_key_mismatch` | Manifest key disagrees with the logical path derived from metadata. | Detect only in the first implementation. | A later metadata-only reconcile path would need a clearly authoritative peer metadata bundle with matching identity and lineage. | Leave issue open for operator review. | This can change user-visible namespace bindings and should not auto-heal by default. |
| `manifest_size_mismatch` | Manifest `total_size_bytes` disagrees with the sum of referenced chunk sizes. | Queue local replica rehydrate from a healthy peer. | Healthy peer export is available. | Leave issue open and degrade local readability for the subject. | Treat as manifest corruption, not as a chunk-only defect. |
| `chunk_missing` | Referenced chunk file is absent locally. | Queue local replica rehydrate from a healthy peer. | Healthy peer export is available. | Leave issue open, stop treating the subject as fully readable locally, and surface it for later repair. | A chunk-only fetch can be a later optimization. |
| `chunk_unreadable` | Chunk file exists but could not be read. | Retry local read in a bounded way, then queue local replica rehydrate if still failing. | Healthy peer export is available after bounded retry fails. | Leave issue open and degrade local readability for the subject. | Treat persistent unreadable chunks as corruption. |
| `chunk_size_mismatch` | Chunk length on disk differs from the manifest reference. | Queue local replica rehydrate from a healthy peer. | Healthy peer export is available. | Leave issue open and degrade local readability for the subject. | A chunk-only replacement can be added later, but the first slice should reuse bundle repair. |
| `chunk_hash_mismatch` | Chunk bytes on disk differ from the expected content hash. | Queue local replica rehydrate from a healthy peer. | Healthy peer export is available. | Leave issue open and degrade local readability for the subject. | This is the clearest case for peer replacement rather than local mutation. |

## Repair Strategy Details

### 1. Full Local Replica Rehydrate

This should be the default automatic repair path for all byte-level and manifest-level corruption
except `manifest_key_mismatch`.

### Why this is the preferred first slice

- It matches the existing persistent-storage rule that corruption should be repaired by
  re-download from another connected node.
- It reuses the current replication bundle import/export path instead of inventing new repair
  machinery.
- It avoids subtle local reconstruction bugs for manifests, chunks, and version metadata.

### Proposed flow

1. Scrub detects an issue on the local node.
2. Scrub records the issue in its history normally.
3. Scrub schedules a separate local repair task for the affected subject.
4. The repair task selects a healthy source node from current online replicas.
5. The repair task uses the existing replication repair path to rehydrate the local node.
6. After repair succeeds, the node runs targeted verification for the repaired subject.
7. Repair outcome is recorded in retained repair history.

### Important scope rule

Scrub-triggered auto-repair should be self-healing only:

- a node repairs its own local corruption,
- it does not directly initiate cross-node fanout repairs for other nodes based solely on its scrub
  findings.

### 2. Metadata-Only Reconciliation

This is the candidate strategy for issues like `manifest_key_mismatch`, but it should not be part
of the first implementation.

### Why it is higher risk

- It can change user-visible path bindings.
- It depends on a stronger authority model than byte replacement.
- A wrong metadata fix can make the namespace appear consistent while actually pointing at the
  wrong object or version.

### Requirements before enabling it

- A healthy peer must provide an authoritative metadata bundle for the exact subject.
- The metadata must match expected identity and lineage, not just path text.
- Conflict cases must remain detect-only.

### First-slice decision

- Keep `manifest_key_mismatch` as report-only.
- Do not automatically rewrite namespace bindings during scrub-triggered repair.

### 3. Quarantine and Degrade

When no healthy peer is available, automatic repair should not modify stored bytes or metadata.

Instead, the node should:

- treat the subject as not fully readable locally,
- avoid advertising it as a healthy local replica,
- keep the scrub finding visible to operators,
- allow later manual repair or a future successful peer-based repair.

This is safer than attempting to preserve availability by serving suspect bytes.

### 4. Chunk-Only Replacement as a Later Optimization

For chunk-specific findings such as `chunk_missing`, `chunk_size_mismatch`, and
`chunk_hash_mismatch`, a future optimization could replace only the affected chunks.

That should be deferred until after the first slice because:

- the current repair path is bundle-oriented and already works,
- chunk-only replacement adds new edge cases around manifest consistency and partial repair,
- the first slice should prioritize correctness over minimal transfer size.

## Post-Repair Verification

Every successful automatic repair should trigger a targeted verification step for the repaired
subject.

The verification should confirm:

- manifest presence and readability,
- manifest hash and structural validity,
- chunk existence, size, and hash,
- versioned subject readability where applicable.

If targeted verification fails, the repair should be treated as failed and follow the same retry
and backoff rules as other repair attempts.

## Observability Expectations

The implementation should preserve the distinction between:

- scrub history, which records what was detected,
- repair history, which records what corrective action was attempted and whether it worked.

Suggested behavior:

- scrub run remains `issues_detected` when it found corruption, even if a follow-on repair was
  scheduled,
- repair history records the actual correction attempt,
- UI can later link a scrub finding to the repair run that followed it.

## First Implementation Recommendation

The recommended first implementation scope is:

1. Allow scrub to schedule follow-on local replica rehydrate only for:
   - `manifest_missing`,
   - `manifest_unreadable`,
   - `manifest_invalid`,
   - `manifest_hash_mismatch`,
   - `manifest_size_mismatch`,
   - `chunk_missing`,
   - `chunk_unreadable`,
   - `chunk_size_mismatch`,
   - `chunk_hash_mismatch`.
2. Keep `manifest_key_mismatch` as detect-only.
3. Reuse the existing replication repair engine instead of introducing a separate scrub repair
   executor.
4. Repair exact versioned subjects as well as current preferred heads when scrub finds corruption
   in version indexes.
5. Run targeted post-repair verification for the repaired subject.
6. Keep chunk-only replacement and metadata-only reconcile out of the first slice.

## Explicit Non-Goals for the First Slice

- No local reconstruction of corrupt manifests.
- No automatic namespace rewrites.
- No destructive deletion of the only remaining local evidence.
- No chunk-only optimization path.
- No cross-node fanout repair driven directly by one node's scrub findings.

## Review Outcomes

### 1. Repair history and attempt backoff

Review outcome:

- the first slice should take the least-effort path,
- scrub-triggered repair should reuse the existing repair history and attempt-backoff model
   directly,
- if later needed, a scrub-specific repair trigger can be added without duplicating the repair
   state machine.

### 2. Bounded retry definition

For this note, "bounded retry" means:

- apply it only to local unreadable-file cases (`manifest_unreadable`, `chunk_unreadable`),
- do at most one immediate retry, or another very short retry inside the same scrub task,
- do not sleep for seconds or run a scrub-local backoff loop,
- if the retry still fails, record the issue and schedule follow-on repair.

Rationale:

- scrub should remain a detector and scheduler, not a long-wait recovery loop,
- long waits and retry backoff belong in the repair engine, not in the scrub verifier,
- an immediate retry is enough to absorb a narrow transient read failure without making scrub runs
   unpredictable.

### 3. UI linkage

Review outcome:

- the admin UI should link scrub findings and follow-on repair runs when that can be done with
   modest effort,
- the first slice can use lightweight correlation such as node, subject, and nearby timestamps,
- if that proves too weak later, an explicit link identifier can be added in retained history.

### 4. Current-head versus exact versioned subject repair

Review outcome:

- the first slice should repair exact versioned subjects as well as current preferred heads,
- corruption is expected to be rare enough that the added repair volume is acceptable,
- preserving historical and time-travel readability is worth the extra repair work.

Example:

- `docs/spec.txt` has version history `v1 -> v2 -> v3`,
- `v3` is the current preferred head, so plain reads of `docs/spec.txt` use `v3`,
- scrub may still discover corruption in the older historical version `docs/spec.txt@v1` because
   it scans version indexes as well as current heads.

Two possible policies:

- current-head-only repair:
   - auto-repair corruption only when it affects the current readable subject,
   - current reads keep working, but the broken historical version remains reported until later.
- exact-version repair:
   - auto-repair the specific historical subject such as `docs/spec.txt@v1`,
   - this preserves history and time-travel readability, but it can trigger more repair work.

Tradeoff:

- current-head-only is the simpler and lower-volume first slice,
- exact-version repair gives stronger historical guarantees.

First-slice decision:

- protect current readable namespace state and historical/versioned reads,
- if scrub finds corruption in a specific historical version such as `docs/spec.txt@v1`, queue
   repair for that exact versioned subject rather than leaving it as a later manual-only repair.
   