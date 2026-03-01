# Stable Object ID Model Decision

## Status

Accepted.

## Context

The current storage model treats the namespace path (`key`) as object identity:

- version graphs are stored per path,
- reads/writes are path-addressed end-to-end,
- rename/move is not a first-class metadata operation.

This makes rename semantics expensive or lossy:

- copy+delete breaks single-object history continuity,
- folder rename is effectively many independent path rewrites,
- identity is coupled to mutable naming.

Project constraints for this decision:

- experimental stage,
- no backwards-compatibility or migration-smoothing requirements.

## Decision

Adopt a stable-object-ID model for server-side object identity.

### Core rule

`object_id` is immutable identity.  
`path` is only a mutable namespace binding to an `object_id`.

### Data model changes

1. Version graphs are keyed by `object_id`, not by path.
2. Current namespace state stores:
   - `path -> object_id` binding,
   - `path -> head_manifest_hash` materialization for fast index/read compatibility.
3. File version records carry `object_id` as identity.
4. Rename updates bindings atomically and does not create content copies.
5. Copy creates a new `object_id` and preserves copy provenance metadata on the first copied version.

### API direction

Add first-class rename API:

- `POST /store/rename` with body:
  - `from_path`
  - `to_path`
  - `overwrite` (currently rejected when target exists)

Behavior:

- if source missing: `404`
- if target exists and overwrite disabled: `409`
- on success: binding is moved atomically and snapshot is created.

Add first-class copy API:

- `POST /store/copy` with body:
  - `from_path`
  - `to_path`
  - `overwrite` (currently rejected when target exists)

Behavior:

- creates a new `object_id` for `to_path`,
- initializes destination history from source head content,
- records provenance on destination root version,
- creates snapshot on success.

### Invariants

1. Every bound path maps to exactly one `object_id`.
2. A rename keeps the same `object_id`.
3. New versions after rename append to the same object’s version graph.
4. Tombstone of a bound path removes the path binding from namespace state.
5. A copy always creates a distinct `object_id`; source and destination histories diverge independently after copy.
6. Destination copy root version includes provenance fields:
   - `copied_from_object_id`
   - `copied_from_version_id`
   - optional `copied_from_path`
7. Conflict branches remain within the same `object_id` graph (multiple heads are allowed).

## Conflict and branch semantics

1. Content conflicts:
   - concurrent writes produce multiple heads in one `object_id` version DAG.
   - preferred head selection stays policy-driven; merge versions may reference multiple parents.
2. Namespace conflicts:
   - concurrent binding operations (rename/copy/create to same target path) are path-layer conflicts.
   - default behavior is reject with conflict status (`409`) unless explicit overwrite policy is enabled.

## Consequences

### Positive

- rename is metadata-only (constant data-path cost),
- version history continuity survives path changes,
- architecture aligns with long-term folder move semantics.

### Negative

- broader metadata responsibilities on server,
- more internal state coupling between bindings and version-index updates.

## Non-goals (this change set)

- No compatibility with old on-disk schema.
- No migration tooling.
- No adapter-side `rename` callback wiring yet (server and SDK foundations first).
- No folder-copy recursive orchestration yet (file copy semantics first).

## Follow-up work

1. Adapter runtime `rename` plumbing (Linux FUSE and Windows adapter).
2. Adapter runtime `copy` plumbing where platform APIs expose copy events.
3. Optional overwrite semantics for rename/copy.
4. Folder rename semantics over path-prefix bindings with conflict policy.
5. Folder copy semantics and provenance strategy for recursive copies.
