# Client-Rights Edge Resumable Transfer Proposal

Status: Idea

## 1. Summary
This proposal defines resumable large-file uploads and downloads for a client-rights edge architecture.

Goals:
- survive client restart, crash, or power loss,
- survive normal server-node restart with persistent data dir,
- avoid requiring node or peer privileges,
- keep large transfers bounded in memory,
- work for filesystem-backed clients such as FUSE and folder sync.

This proposal is intended to complement:
- `docs/client-rights-edge-sync-idea.md`

## 2. Problem Statement
Current large-transfer behavior is not restart-resumable.

Today:
- uploads larger than `1 MiB` are chunked client-side,
- each chunk is uploaded independently,
- the object becomes visible only after a final `complete` request,
- downloads stream only on the direct HTTP client path,
- relay-backed downloads buffer full responses,
- server reads currently assemble the full object in memory before responding.

Implications:
- if the client restarts mid-upload, the transfer restarts from the beginning,
- if the server restarts mid-upload, the client also restarts from the beginning,
- previously stored chunks may still exist on disk, but the client does not have durable upload progress,
- if a download is interrupted, it restarts from byte `0`,
- very large downloads are not handled with true end-to-end streaming.

## 3. Design Principles
1. Client-only authority
- no node identity,
- no peer replication routes,
- no rendezvous node presence.

2. Durable local progress
- client persists transfer state in local SQLite,
- restart recovery does not depend on clean shutdown.

3. Stable content identity
- resumability depends on stable object identity for the exact version being transferred,
- upload and download progress must be invalidated if the target content identity changes.

4. Bounded memory
- no full-object buffering for large direct downloads,
- relay path may still buffer per request, but each request must be size-bounded.

## 4. Proposal Overview
Use two different mechanisms:

### 4.1 Uploads
Use explicit server-side upload sessions plus durable client-side session state.

Why:
- avoids exposing a generic chunk-presence oracle,
- gives precise resume state after restart,
- works even when transfer lasts for hours,
- fits naturally with current content-addressed chunk storage.

### 4.2 Downloads
Use HTTP range-capable, manifest-backed streaming plus durable client-side partial-file state.

Why:
- download resume only needs byte-range restart,
- server does not need a server-side download session for the common case,
- direct HTTP can stream,
- relay can emulate resume using smaller fixed-size range pulls.

## 5. Upload Proposal
### 5.1 New client-facing API
- `POST /store/uploads/start`
  - request:
    - `key`
    - `total_size_bytes`
    - optional versioning fields:
      - `state`
      - `parent`
      - `version_id`
    - optional local file fingerprint
  - response:
    - `upload_id`
    - `chunk_size_bytes`
    - `expires_at_unix`

- `PUT /store/uploads/{upload_id}/chunk/{index}`
  - request body: raw chunk bytes
  - headers or query:
    - `hash`
    - `size_bytes`
  - response:
    - `stored`
    - `received_index`

- `GET /store/uploads/{upload_id}`
  - response:
    - `key`
    - `total_size_bytes`
    - `chunk_size_bytes`
    - `received_indexes`
    - `expires_at_unix`
    - `completed`

- `POST /store/uploads/{upload_id}/complete`
  - request:
    - ordered list of chunk refs
    - `total_size_bytes`
  - response:
    - created version metadata

- `DELETE /store/uploads/{upload_id}`
  - abort session

### 5.2 Server-side state
Persist upload session metadata on disk or in SQLite:
- `upload_id`
- client/device id
- target `key`
- transfer parameters
- chunk size
- total size
- ordered chunk metadata by index
- received bitmap or received index set
- created/updated/expiry timestamps
- completion state

Important:
- uploaded chunk bytes should still be written into the existing global content-addressed chunk store,
- session state only tracks which chunk indexes are attached to this upload,
- finalization reuses the current manifest/object creation logic.

### 5.3 Client-side state
Persist local upload session rows:
- local file path
- target remote key
- local file fingerprint
- file size
- chunk size
- upload id
- per-index hash list
- last-known server receipt state
- session expiry
- status:
  - pending
  - uploading
  - completing
  - completed
  - failed

### 5.4 Resume behavior
After restart:
1. load unfinished local upload sessions
2. re-stat the local file
3. verify local fingerprint still matches
4. query `GET /store/uploads/{upload_id}`
5. upload only missing chunk indexes
6. call `complete`

If the local file changed:
- abandon old session,
- start a new upload session,
- treat as a new local version.

If the server has expired the session:
- start a new upload session,
- reuse locally persisted chunk hashes to avoid recomputing if possible,
- re-upload needed chunks.

### 5.5 Why not only probe chunk presence by hash
A generic client endpoint like `POST /store-chunks/presence` would make resume simple,
but it also creates a content-existence oracle over the global deduplicated chunk store.

This proposal avoids that by:
- scoping progress to a server-managed upload session,
- returning only session receipt state,
- not exposing arbitrary global chunk presence checks to clients.

### 5.6 Server restart behavior
If the server restarts and keeps its data dir:
- chunk files remain,
- upload session rows remain,
- client resumes from exact missing chunk indexes.

If the server restarts with lost session state:
- client notices missing session,
- starts a new upload session,
- resumes from local durable state but must re-upload chunks into the new session.

### 5.7 Alternative considered: chunk existence probe
Alternative:
- do not persist upload session state on the server,
- let the client ask which chunk hashes already exist,
- upload only missing chunks,
- then call `complete`.

This is attractive because it appears simpler.
However, compared with upload sessions it has important tradeoffs.

Advantages of chunk existence probing:
- less server metadata,
- simpler server implementation in the short term,
- straightforward mental model for restart:
  - hash chunks,
  - ask what exists,
  - upload what does not.

Disadvantages of chunk existence probing:
- more request overhead, especially if done per chunk instead of in bulk,
- weaker semantics:
  - existence at check time does not reserve the chunk for later `complete`,
  - future unreferenced-chunk cleanup can race with completion,
- exposes a content-existence oracle over the deduplicated chunk store,
- weaker ownership and accounting story for quota, audit, and abuse control,
- harder to extend cleanly with expiry, cancellation, or per-transfer progress reporting.

Advantages of upload sessions:
- exact resume state after restart,
- clear ownership:
  - this device owns this in-progress upload,
- compatible with future chunk garbage collection because sessions can protect in-flight chunks,
- avoids exposing arbitrary chunk-presence checks,
- better foundation for progress UI, expiry, quotas, and cleanup.

Recommendation:
- prefer upload sessions as the primary design,
- if a probe-based design is ever revisited, prefer a bulk probe over per-chunk existence checks.

### 5.8 Deduplication scope under the session design
With the session design, storage deduplication still happens on the server:
- chunks are content-addressed,
- re-uploaded bytes with the same hash do not create duplicate stored chunks.

But bandwidth deduplication before upload is more limited.

Out of the box, the session design gives:
- resume deduplication within the same upload session:
  - the client asks which chunk indexes were already received,
  - only missing indexes are uploaded again.

It does not automatically give:
- global pre-upload deduplication against arbitrary chunks already present on the server from other files, older uploads, or other devices.

So the short answer is:
- yes, for the proposal as currently written, cross-object dedup before upload mostly remains server-side,
- while client-visible bandwidth savings mainly come from session resume, not from global remote chunk discovery.

Local client-side optimizations are still possible:
- avoid re-hashing unchanged local files by persisting local chunk hashes,
- avoid re-reading already hashed source data after restart,
- optionally detect duplicate chunks within the same local file.

Future extension if needed:
- add a session-scoped "attach known hash" optimization,
- the client would submit chunk hash metadata,
- the server could mark some indexes satisfied without re-uploading bytes if policy allows.

That would preserve the session model while adding pre-upload bandwidth dedup as an optimization layer.

## 6. Download Proposal
### 6.1 New or enhanced client-facing behavior
Enhance `GET /store/{key}` to support:
- `HEAD`
- `Range`
- `ETag`
- `If-Range`
- `Accept-Ranges: bytes`

Recommended identity:
- `ETag = manifest_hash`

Optional helper endpoint:
- `GET /store/{key}/metadata`
  - response:
    - `manifest_hash`
    - `content_length`
    - `version_id`
    - `content_hash`
    - optional mime type

This helper is optional because `HEAD` could already carry the required metadata.

### 6.2 Server read path
Replace full-object assembly for large reads with manifest-backed streaming:
- load manifest,
- skip chunks until the requested start offset,
- stream chunk slices directly to the response body,
- never assemble the entire object in memory for direct HTTP large reads.

This is the key server change for practical resumable downloads.

### 6.3 Client-side download state
Persist local download session rows:
- remote key
- selected snapshot/version if any
- target local path
- temp path such as `.ironmesh-part-*`
- `etag` / `manifest_hash`
- expected total size
- bytes_written
- last_verified_offset
- status

Bytes should be written to a temp file first and atomically renamed on completion.

### 6.4 Resume behavior
After restart:
1. find partial temp file plus download session row
2. issue `HEAD` or metadata request
3. compare `etag`
4. if unchanged, request `Range: bytes=<bytes_written>-`
5. append remaining bytes to temp file
6. finalize with rename after full size verification

If `etag` changed:
- discard or quarantine partial file,
- restart download from byte `0`,
- optionally record a conflict if the local consumer expected the old version.

### 6.5 Relay behavior
Current relay HTTP transport carries a fully buffered base64 body per request.
That makes true large streaming over relay a poor fit.

For relay-backed downloads, use segmented range requests:
- request small bounded windows, for example `4 MiB` or `8 MiB`,
- each relayed response may still buffer fully,
- but memory stays bounded by segment size,
- resume uses the last confirmed byte offset.

This gives resumability without requiring relay protocol streaming in the first phase.

## 7. Local State Model
Use SQLite tables conceptually like:

- `upload_sessions`
- `upload_session_chunks`
- `download_sessions`
- `transfer_failures`

Important durability rules:
- update progress during transfer, not only on clean shutdown,
- write progress after each confirmed chunk upload,
- write download progress after each flushed range segment,
- keep temp artifact cleanup explicit and restart-safe.

## 8. Failure Semantics
### 8.1 Client restart during upload
- upload session remains resumable,
- missing indexes are re-sent,
- completed indexes are not re-sent.

### 8.2 Server restart during upload
- resumable if upload session store persisted,
- otherwise client starts a new upload session.

### 8.3 Client restart during direct download
- partial temp file remains,
- client resumes using `Range` and `ETag`.

### 8.4 Server restart during direct download
- interrupted request fails,
- client retries from the last durable byte offset.

### 8.5 Relay interruption during download
- current request fails,
- client restarts from last durable segment boundary.

### 8.6 Remote object changes mid-download
- `ETag` mismatch invalidates resume,
- client restarts or records a version conflict depending on the caller contract.

## 9. Security Considerations
- all APIs remain client-authenticated
- no node-only or peer-only routes are exposed
- upload-session ownership must be bound to the authenticated device
- upload session IDs must be unguessable
- expired sessions must be garbage-collected
- direct chunk-presence probing should not be exposed as a generic client API

## 10. Compatibility and Rollout
### Phase 1
- add durable client-side transfer session state
- add upload session APIs
- add direct-download `HEAD` + `Range`
- add stream-based direct read path on the server

### Phase 2
- teach FUSE/folder sync adapters to use resumable transfer state
- add relay segmented-range downloads

### Phase 3
- optional upload-session renew/reattach workflow
- transfer progress UI
- retry backoff, rate control, and bandwidth policies

## 11. Non-Goals
- no node-style replication repair
- no peer chunk transfer
- no relay protocol streaming overhaul in the first phase
- no CRDT merge system for file contents

## 12. Open Questions
- upload session expiry defaults
- chunk size policy for very large files
- whether to persist per-chunk hashes locally before first upload or compute lazily
- how much metadata to expose via `HEAD` versus a dedicated metadata endpoint
- whether relay should gain true streaming later or remain segmented-request based

## 13. Recommendation
Build uploads first.

Why:
- current server storage model already fits chunk-by-chunk persistence,
- resumable upload sessions align with earlier storage strategy notes,
- uploads are the higher-risk operation for local offline edits,
- direct-download range support can follow as a focused server read-path improvement.
