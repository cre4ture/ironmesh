# S3-Compatible Front End Design

Status: proposal

## Summary

Add an optional S3-compatible HTTP surface to `ironmesh-server-node` so standard
S3 SDKs and tools can read, write, list, copy, and multipart-upload objects
without speaking the native Ironmesh API.

This design keeps the existing Ironmesh storage engine as the source of truth:

- bytes still land in the normal chunk store,
- manifests and version graphs stay in the current Ironmesh model,
- replication, deduplication, media cache, and read-through chunk fetches stay
  unchanged below the compatibility layer.

The S3 surface is a protocol adapter plus:

- generic per-version object metadata that is worth making first-class in the
  shared core, and
- a small amount of truly S3-specific compatibility metadata

It is not a replacement for the native Ironmesh API.

## Goals

- Support common S3 object workflows from existing clients and SDKs.
- Reuse the current Ironmesh chunk store, version store, and read path.
- Keep the native Ironmesh API unchanged.
- Keep the first implementation small enough to land in slices.
- Preserve Ironmesh's existing byte-level deduplication and clustered read path.

## Non-goals

The first design does not aim for full AWS parity.

Out of scope for the first implementation:

- IAM-compatible policy language
- ACLs and bucket policies
- STS session tokens
- presigned URLs
- virtual-hosted-style buckets
- object lock / legal hold / retention
- SSE-S3 / SSE-KMS
- event notifications
- website hosting
- lifecycle rules
- SelectObjectContent

These can be layered on later if the base object API proves useful.

## Current Constraints From Ironmesh

Ironmesh is not an S3-shaped storage engine today.

Important current properties:

- Object bytes are stored as fixed-size content-addressed chunks.
- Logical paths map to versioned object identities.
- Object history is a DAG, not a strictly linear version chain.
- The current HTTP API is path-oriented, not bucket-oriented.
- The primary store does not currently persist S3-style HTTP object metadata such
  as `Content-Type`, `Cache-Control`, or user metadata headers.
- The existing chunked upload flow is not S3 multipart upload; it uses fixed
  internal chunk refs and a separate finalize step.

That means the S3 surface needs its own compatibility decisions in four places:

1. bucket mapping
2. auth
3. linear object semantics
4. generic object metadata vs S3-specific compatibility metadata

## Recommended Deployment Model

### Dedicated S3 listener

Expose the S3 surface on a separate listener instead of mixing it into the
existing public API router.

New env vars:

- `IRONMESH_S3_BIND`
- `IRONMESH_S3_PUBLIC_URL`
- `IRONMESH_S3_TLS_CERT`
- `IRONMESH_S3_TLS_KEY`

Defaults:

- the S3 listener is disabled unless `IRONMESH_S3_BIND` is set
- if explicit S3 TLS files are not set, reuse the normal public TLS identity

Why a separate listener:

- S3 clients expect bucket paths at the root path, not under `/api/v1/...`
- it avoids route collisions with the native Ironmesh API
- it keeps S3-specific auth, XML errors, and protocol quirks isolated

### Cluster-wide S3 availability from the first implementation

The implementation should not assume one designated S3 ingress node.

Target behavior:

- every server node can expose an S3 listener
- every node has the same bucket registry and S3 access-key state
- every node can validate S3 requests locally
- every node can serve reads from local data or by using the existing
  read-through chunk fetch path when needed

This requires S3 control-plane metadata to be part of the first implementation,
not a later extension.

Required replicated control-plane state:

- `s3_buckets`
- `s3_access_keys`

Required replicated object-scoped metadata:

- `object_version_metadata`
- `s3_object_versions`

Recommendation:

- replicate those records through the same cluster metadata fanout direction as
  the rest of the cluster-visible metadata model
- subject bucket and access-key mutations to the same metadata commit policy
  that the deployment chooses for cluster metadata
- treat a node as S3-ready only after the replicated S3 control-plane state is
  loaded locally

This gives us one coherent model: any node can answer S3, and the choice of
front-door node is a routing concern rather than a control-plane ownership
concern.

### Rendezvous / relay-backed S3 access

Direct public S3 listeners are not enough for all deployments because some nodes
will only be reachable through the existing rendezvous/relay transport.

Standard S3 clients cannot speak Ironmesh's rendezvous or multiplex transport
protocols directly, so the recommended design is an S3 gateway that translates
normal HTTPS S3 requests into Ironmesh transport requests.

Recommended component:

- `ironmesh-s3-gateway`

Possible product shapes:

- a standalone binary
- a mode of the existing CLI/client app such as `ironmesh serve-s3`
- a deployable edge service in front of private nodes

Gateway behavior:

- accepts standard HTTPS S3 requests from ordinary S3 clients
- forwards the raw method, path, query, headers, and body through Ironmesh's
  direct or relay-capable transport session layer
- targets any cluster node that has the replicated S3 control-plane metadata
- lets the remote node perform the authoritative SigV4 validation using the
  replicated `s3_access_keys` data
- streams request and response bodies instead of buffering large uploads or
  downloads fully in memory

Security model:

- the external S3 client authenticates with S3 access keys
- the gateway authenticates to Ironmesh as a normal client or service identity
  over direct or relay transport
- the gateway does not become the source of truth for bucket or access-key
  metadata

Why this is preferable:

- the rendezvous/relay service stays focused on transport and session pairing
- standard S3 clients remain unchanged
- private clusters can still expose an S3-compatible entrypoint even when no
  node has a directly reachable public S3 listener
- the same gateway can choose direct transport when available and relay
  transport when required

## Bucket Model

### First-class bucket registry

Add an S3 bucket registry separate from the existing path namespace.

Proposed table: `s3_buckets`

Fields:

- `bucket_name`
- `root_prefix`
- `versioning_status`
  - `disabled`
  - `enabled`
- `read_only`
- `created_at_unix`
- `updated_at_unix`
- `created_by`

### Bucket to Ironmesh mapping

Each bucket maps to a prefix in the normal Ironmesh namespace.

Example:

- bucket `photos`
- `root_prefix = s3/photos/`
- S3 object `2025/cat.jpg`
- Ironmesh key `s3/photos/2025/cat.jpg`

Why prefix mapping instead of true bucket-native storage:

- it lets the S3 layer reuse the current path-based store without changing the
  underlying object model
- it keeps bucket delete/list logic simple
- it gives administrators an explicit namespace boundary for S3-managed data

### Prefix ownership rule

An S3 bucket should be treated as the owner of its mapped Ironmesh prefix.

Recommendation:

- objects under an S3 bucket prefix should be mutated through either:
  - the S3 surface, or
  - a native Ironmesh path API mode that explicitly opts into S3-compatible
    semantics for that prefix

Plain native path writes should not be allowed to bypass those semantics for
S3-managed prefixes.

Reason:

- S3-compatible writes need linear-head protection plus metadata maintenance
- the current generic native path writes do not preserve those guarantees by
  default

### Native S3-compatible mode

The stricter requirement is not "must pass through the S3 router." The real
requirement is "must preserve S3-compatible semantics."

That means the native path API can participate too, but only through an explicit
mode for S3-managed prefixes.

Possible shapes:

- dedicated native routes such as `/auth/s3-compat/store/...`
- an explicit compatibility flag on native write requests
- bucket-prefix policy that switches matching native writes into S3-compatible
  handling automatically

Required behavior for that mode:

- resolve and write against the current confirmed head only
- use CAS-style expected-current-version checks before creating a new visible
  head
- persist or update generic object metadata plus any S3-specific compatibility
  metadata when the write changes visible object state
- reject provisional writes for S3-managed prefixes
- reject explicit multi-parent writes for S3-managed prefixes
- reject further writes if the destination key is already in a multi-head state
  until repaired

This keeps the design open to native interoperability without claiming that the
current generic path API is already S3-safe.

## Auth Model

### Separate S3 credentials

Do not try to reuse Ironmesh client request signatures as S3 credentials.

Instead, add a separate S3 access-key store.

Proposed table: `s3_access_keys`

Fields:

- `access_key_id`
- `secret_hash`
- `description`
- `bucket_scope_json`
- `prefix_scope_json`
- `allow_list`
- `allow_read`
- `allow_write`
- `allow_delete`
- `created_at_unix`
- `last_used_at_unix`
- `revoked_at_unix`

`secret_hash` should use Argon2id. The plaintext secret should only be returned
once at creation time.

### Signature support

Support AWS Signature Version 4 header auth in the first slice:

- `Authorization: AWS4-HMAC-SHA256 ...`
- `x-amz-date`
- `x-amz-content-sha256`

Explicitly defer:

- query-string presigning
- chunked streaming SigV4 payload signing

This is enough for most SDK and CLI use when talking directly to the endpoint
over TLS.

### Request identity

Introduce a dedicated request identity type for the S3 router:

```rust
struct S3RequestIdentity {
    access_key_id: String,
    description: Option<String>,
    allowed_buckets: Vec<String>,
    allowed_prefixes: Vec<String>,
    allow_list: bool,
    allow_read: bool,
    allow_write: bool,
    allow_delete: bool,
}
```

This identity should never be translated into an admin request. It should map to
normal object-scoped operations only.

## API Surface

### Target route set

Implement a path-style S3 surface only:

- `GET /` -> `ListBuckets`
- `PUT /{bucket}` -> `CreateBucket`
- `DELETE /{bucket}` -> `DeleteBucket`
- `HEAD /{bucket}` -> `HeadBucket`
- `GET /{bucket}?list-type=2` -> `ListObjectsV2`
- `GET /{bucket}/{key...}` -> `GetObject`
- `HEAD /{bucket}/{key...}` -> `HeadObject`
- `PUT /{bucket}/{key...}` -> `PutObject`
- `DELETE /{bucket}/{key...}` -> `DeleteObject`
- `PUT /{bucket}/{key...}` with `x-amz-copy-source` -> `CopyObject`
- `POST /{bucket}/{key...}?uploads` -> `CreateMultipartUpload`
- `PUT /{bucket}/{key...}?partNumber=N&uploadId=...` -> `UploadPart`
- `POST /{bucket}/{key...}?uploadId=...` -> `CompleteMultipartUpload`
- `DELETE /{bucket}/{key...}?uploadId=...` -> `AbortMultipartUpload`
- `GET /{bucket}/{key...}?uploadId=...` -> `ListParts`

Later versioning route:

- `GET /{bucket}?versions` -> `ListObjectVersions`

### Explicitly unsupported initially

Return `NotImplemented` XML errors for:

- bucket policy operations
- tagging operations
- ACL operations
- object lock operations
- restore-from-archive flows

## Object Semantics

### Read mode

The S3 surface should read Ironmesh objects with `confirmed_only` semantics.

Reason:

- S3 clients expect the stable committed object view
- Ironmesh provisional versions should not leak through the compatibility layer

This implies the S3 layer needs storage helpers that can:

- resolve the current confirmed head version for a key
- list confirmed visible objects under a prefix

The existing generic store index path is not sufficient by itself because it is
based on the current preferred namespace view and may include provisional heads.

### Linear-write contract

S3 keys should behave like a linear object history even though Ironmesh
internally supports branching version graphs.

To make that reliable, add compare-and-swap style storage helpers:

- `put_object_if_current_version(...)`
- `put_object_from_chunks_if_current_version(...)`
- `tombstone_object_if_current_version(...)`
- `copy_object_if_current_version(...)`

Each helper takes:

- the expected current confirmed head version for the destination key
- `None` when the caller expects the key not to exist

If the destination head changed after the S3 gateway resolved it, the helper
must fail with a conflict instead of silently creating a branch.

Recommended S3 error mapping:

- `409 OperationAborted` for head races
- `412 PreconditionFailed` for failed `If-Match` / `If-None-Match`

Without this CAS layer, the S3 front end cannot honestly claim linear object
semantics.

The same CAS contract should be reused by any native S3-compatible write mode
for S3-managed prefixes. The compatibility boundary is semantic, not purely
transport-specific.

### External mutation rule

If plain native Ironmesh APIs bypass S3-compatible mode and create multi-head
history for an S3-managed key, the S3 surface and any native S3-compatible mode
should:

- keep reads on the current confirmed preferred head
- reject further writes to that key with `409 OperationAborted`
- emit an admin-visible warning that the key is no longer S3-linear

That keeps the failure mode explicit instead of silently exposing an arbitrary
branch to S3 clients.

## Object Metadata and S3 Compatibility Metadata

### Why a metadata split is required

Ironmesh manifests currently describe:

- logical key
- ordered chunk refs
- total size

They do not persist HTTP object presentation metadata such as content type,
cache policy, or user metadata.

That does not automatically mean everything should live in an S3-only sidecar.

The stronger design is:

- promote generic per-version object metadata into the shared core metadata
  model
- keep only truly S3-specific protocol compatibility artifacts in a thin
  sidecar

This makes the metadata model more broadly useful for native Ironmesh APIs too.

### Promote generic object metadata into shared per-version metadata

Recommended shared table:

`object_version_metadata`

Fields:

- `version_id`
- `content_type`
- `content_encoding`
- `content_language`
- `cache_control`
- `content_disposition`
- `user_metadata_json`
- `checksum_sha256`
- `checksum_crc32c`
- `updated_at_unix`

Notes:

- this is keyed by `version_id`, because these values describe how one visible
  object version should be presented
- this metadata is not inherently S3-specific
- native S3-compatible writes and the S3 adapter should both maintain it
- native non-S3 APIs can remain unaware of it initially, but it is part of the
  shared storage model rather than an adapter-only bolt-on

### Keep only S3-specific artifacts in a compatibility sidecar

`s3_object_versions`

Fields:

- `bucket_name`
- `ironmesh_key`
- `version_id`
- `etag`
- `multipart_part_count`
- `created_at_unix`

This record is keyed by `(bucket_name, version_id)`.

### Metadata behavior

`PutObject`:

- captures request metadata headers
- stores generic object metadata in `object_version_metadata` after the
  Ironmesh write returns a version id
- stores S3-specific compatibility artifacts in `s3_object_versions`

Native S3-compatible `PUT` / copy / delete / rename style mutations should
follow the same rule. If they change the visible state of an S3-managed key,
they must also maintain:

- shared per-version object metadata, and
- any S3-specific compatibility metadata for the affected visible version(s)

`CopyObject`:

- `x-amz-metadata-directive=COPY` copies the shared object metadata from the
  source version
- `x-amz-metadata-directive=REPLACE` uses request headers for the shared object
  metadata
- the S3 compatibility record is then rebuilt for the destination version

`GetObject` and `HeadObject`:

- resolve the exact Ironmesh version
- load shared object metadata for that version
- load S3 compatibility metadata for that version
- render standard S3 response headers

If a version exists without an S3 compatibility record, the gateway may
synthesize:

- `ETag` from the manifest hash

If a version exists without shared object metadata, the gateway may synthesize:

- `Content-Type` from path-based sniffing or `application/octet-stream`

That fallback is acceptable for recovery, but normal S3-managed objects should
always have:

- shared object metadata where applicable, and
- S3 compatibility metadata when the S3 surface is expected to expose the
  version cleanly

## ETag Strategy

The S3 surface should not expose the native Ironmesh manifest hash as the normal
object `ETag`.

Recommended behavior:

- single-part `PutObject`: compute and return the MD5 hex ETag that common S3
  clients expect
- multipart uploads: compute the normal S3 multipart ETag
  `md5(concat(part_md5_bytes)) + "-" + part_count`
- persist that ETag in `s3_object_versions`

The native Ironmesh API should continue to use manifest-hash ETags on `/store/*`
routes.

This split is important because:

- many S3 clients treat ETag as MD5-like compatibility data
- Ironmesh manifest hashes include storage-model details that are not part of
  normal S3 expectations

## Multipart Upload Design

### Hybrid approach: improve the native staged-upload core

The current design should not assume a pure adapter-only multipart subsystem.

Ironmesh's native finalize path is already close to what S3 multipart needs:

- the storage layer can already finalize an object from an arbitrary ordered
  list of `UploadChunkRef` values
- the chunk store and deduplication path already do the right thing for staged
  payload ingestion
- persisted upload-session state already exists and can be evolved instead of
  replaced

The main mismatch is the current upload-session orchestration layer, which is
still modeled as:

- one fixed expected request-body size per uploaded index
- one uploaded request body producing one stored `UploadChunkRef`
- one contiguous sequence of indexes rather than user-defined logical parts

S3 multipart uploads instead require:

- user-chosen part boundaries
- part numbers `1..=10000`
- part ETags
- out-of-order part upload
- explicit multipart completion XML

The recommended direction is therefore:

- improve the native staged-upload core so it can assemble an object from
  logical parts, where each logical part may expand to multiple internal
  `UploadChunkRef` values
- keep the existing native `/store/uploads/*` flow as one profile of that core
- add S3 adapter logic only for the parts that are truly S3-specific

### Proposed native staged-upload changes

Evolve `UploadSessionRecord` from a fixed chunk-grid model into a generic staged
upload model.

Recommended additions:

- `assembly_mode`
  - `fixed_sequence`
  - `multipart`
- `total_size_bytes`
  - optional during staging
  - required before finalization
- `parts`
  - ordered logical parts keyed by ordinal or part number
- per-part payload represented as `Vec<UploadChunkRef>`, not a single
  `UploadChunkRef`

Recommended generic part record:

```rust
struct StagedUploadPart {
    part_number: u32,
    size_bytes: u64,
    chunk_refs: Vec<UploadChunkRef>,
    client_etag: Option<String>,
    checksum_sha256: Option<String>,
    created_at_unix: u64,
}
```

Recommended generic session shape:

```rust
enum UploadAssemblyMode {
    FixedSequence,
    Multipart,
}

struct UploadSessionRecord {
    upload_id: String,
    key: String,
    assembly_mode: UploadAssemblyMode,
    total_size_bytes: Option<u64>,
    parts: BTreeMap<u32, StagedUploadPart>,
    // existing version/state/expiry fields stay
}
```

### Native ingest helper

Add a native helper below the HTTP adapter layer:

```rust
ingest_payload_to_chunk_refs(payload: &[u8]) -> Result<Vec<UploadChunkRef>>
```

Behavior:

- split the uploaded payload into the normal internal Ironmesh chunk size
- ingest each internal chunk into the content-addressed chunk store
- return the ordered `UploadChunkRef` list for that uploaded payload

This is the main native improvement that makes the hybrid design worthwhile.

Benefits:

- S3 multipart can reuse the native chunk-ingest and finalize path
- future native resumable uploads no longer need to be tightly coupled to one
  uploaded request body equaling one internal chunk
- the adapter layer only has to map S3 requests into native staged-upload
  primitives instead of reimplementing them

### Keep the current native upload API as a profile

The existing `/store/uploads/*` API can remain valid as a `fixed_sequence`
profile of the generalized core.

Behavior:

- uploaded index `N` maps to logical part `N`
- the existing expected-size checks can stay for that mode
- most native uploads will still produce one internal chunk ref per uploaded
  body, but the core no longer requires that invariant globally

This keeps backward-compatible native behavior while making the underlying
staging model more capable.

### S3-specific overlay metadata

Once the native staged-upload core is generalized, the remaining S3-only state
is relatively small.

Recommended S3 overlay record:

`s3_multipart_uploads`

- `upload_id`
- `bucket_name`
- `ironmesh_key`
- `expected_current_version_id`
- `content_type`
- `content_encoding`
- `content_language`
- `cache_control`
- `content_disposition`
- `user_metadata_json`
- `created_at_unix`
- `updated_at_unix`
- `expires_at_unix`

This overlay should not duplicate the full part assembly state if the native
session core already stores parts. It should only hold S3-specific request
semantics and response metadata.

### UploadPart flow

For each `UploadPart` request:

1. resolve or create the staged upload session in `multipart` mode
2. pass the payload through `ingest_payload_to_chunk_refs(...)`
3. compute the S3 part MD5 ETag
4. store one logical part record with:
   - `part_number`
   - `size_bytes`
   - `chunk_refs`
   - `client_etag`
5. persist or refresh the S3 overlay metadata
6. return the part ETag

No temporary user-visible Ironmesh object is created for a part.

### CompleteMultipartUpload flow

1. load the persisted parts in the client-supplied order
2. verify all referenced part numbers exist and ETags match
3. flatten each part's `chunk_refs` into one final ordered chunk-ref list
4. compute the final total size from the selected parts
5. call the native CAS-style finalizer on the Ironmesh store
6. persist the final shared object metadata plus S3 compatibility metadata
7. delete the staged upload session and S3 overlay metadata

This should reuse the normal chunk store and deduplication path; no byte copy is
required beyond the original part ingest.

### AbortMultipartUpload flow

Abort removes:

- the staged upload session state
- the S3 multipart overlay metadata

Uploaded chunk data stays in the chunk store until normal unreferenced cleanup
removes it. This is acceptable because the chunk store is already content
addressed and deduplicated.

### Why this hybrid is preferable

Compared with a pure adapter-only multipart subsystem, this hybrid approach:

- reuses the native persisted upload-session machinery instead of bypassing it
- strengthens the native upload path in a way that is independently useful
- keeps the final object-assembly path shared between native and S3 uploads
- limits S3-specific code to:
  - SigV4 auth
  - XML request/response handling
  - bucket/key mapping
  - multipart part-number and ETag semantics
  - S3 compatibility metadata

That is the right split between shared core capability and protocol adapter.

## Listing Design

### Hybrid approach: improve the native listing core

Do not solve S3 listing by building a completely separate paginator while the
native `/store/index` path keeps its current offset-based pagination model.

Instead, improve the native listing core so it can support stable cursor-based
pagination for both:

- native Ironmesh listing use cases
- the S3 adapter's `ListObjectsV2` and later `ListObjectVersions`

The S3 layer can then be the first consumer of that improved listing core
without making it S3-exclusive.

### Why the current model is a poor base

Today the native listing flow is effectively:

- collect and sort all matching keys
- derive visible entries
- decorate entries with metadata and media summaries
- apply `offset` / `limit` at the end

That is workable for small views, but it has two weaknesses:

- offset pagination is unstable under concurrent writes
- the server still does most of the listing work before dropping earlier pages
- S3 continuation tokens are expected to be opaque but stable across lexicographic
  scans

Improving this is useful even without S3 because it helps:

- large native CLI listings
- web explorer pagination
- admin browsing
- future filesystem-adapter namespace refresh workflows that need stable paging

### Recommended shared listing split

Add a shared native listing core with two layers:

1. a stable raw lexicographic scan layer
2. derived presentation layers built on top of it

The raw scan layer should become the canonical pagination primitive. S3 should
use it first, but native `/store/index` should be able to use it too.

### Shared raw scan helper

Add a dedicated storage/listing helper that is not S3-specific:

```rust
list_objects_for_prefix_cursor(
    root_prefix: Option<&str>,
    prefix: &str,
    read_visibility: ListVisibilityMode,
    delimiter: Option<&str>,
    cursor: Option<&OpaqueListCursor>,
    page_size: usize,
) -> Result<ListPage>
```

Properties:

- supports lexicographic forward scans
- supports stable opaque cursor continuation
- supports delimiter-aware prefix collapsing
- can operate against current state first
- can later be extended to snapshot-aware scans
- can support multiple visibility modes
  - `preferred`
  - `confirmed_only`
  - later possibly S3-specific versioned listing modes

Recommended page shape:

```rust
struct ListPage {
    entries: Vec<ListPageEntry>,
    next_cursor: Option<String>,
    has_more: bool,
}
```

Recommended entry shape:

```rust
enum ListPageEntry {
    Object { logical_path: String },
    CommonPrefix { logical_prefix: String },
}
```

### Cursor design

Continuation state should be opaque base64-encoded JSON, but the underlying
cursor model should be shared by native and S3 callers.

Suggested cursor contents:

- effective root prefix
- effective user prefix
- delimiter
- visibility mode
- last returned object key
- last returned common prefix

For S3:

- the S3 layer can wrap or translate this opaque cursor into S3 continuation
  tokens directly

For native `/store/index`:

- expose the same continuation token as a `cursor` parameter
- return `next_cursor` in the JSON response
- keep `offset` / `limit` as compatibility mode for now, but prefer `cursor`
  for large or correctness-sensitive listings

### Native API evolution

Extend the native store-index API with cursor pagination instead of replacing it
abruptly.

Recommended additions to `/store/index`:

- `cursor`
- `page_size`
- optional `pagination_mode`
  - `offset`
  - `cursor`

Recommended behavior:

- keep current `offset` / `limit` support for backward compatibility
- use cursor pagination as the preferred mode for raw lexicographic listings
- if a request uses tree collapsing, media sorting, or other derived views that
  cannot yet page cleanly at the raw scan layer, either:
  - keep them on compatibility pagination initially, or
  - explicitly constrain which sort/view combinations support cursor mode first

This lets the repo adopt the stronger primitive incrementally instead of waiting
for every presentation mode to be reworked at once.

### S3-first adoption path

The S3 adapter should be the first production consumer of the new raw cursor
scan helper because its requirements are narrow and strict:

- lexicographic order
- delimiter support
- opaque continuation token
- no need for the current native tree-view collapse behavior

That gives us a focused first implementation while still improving the shared
native core.

### How native `/store/index` can reuse it

The native API does not have to match S3's exact response shape to benefit from
the same underlying primitive.

Recommended reuse path:

1. use the shared raw cursor scan for `view=raw` and `sort=path_asc`
2. expose `next_cursor` in `StoreIndexResponse`
3. keep `offset` / `limit` for existing clients and for more complex derived
   views during the transition
4. later move more native listing modes onto the shared cursor scan where it
   remains semantically clean

### Why this hybrid is preferable

Compared with a S3-only listing subsystem, this shared approach:

- gives S3 the stable continuation semantics it needs
- fixes a real weakness in native pagination too
- avoids duplicating prefix-scan and delimiter logic
- creates one authoritative lexicographic listing primitive for the whole server
- lets the native API evolve gradually instead of forcing a one-shot pagination
  migration

### Bucket list implementation

`ListBuckets` should read from `s3_buckets`, not infer buckets from namespace
contents.

## Delete and Versioning Semantics

### Bucket versioning modes

Expose two S3 bucket modes:

- `disabled`
- `enabled`

Under the hood Ironmesh still retains historical versions in both modes. The S3
surface decides how much of that history it exposes.

### Versioning disabled

Behavior:

- `PutObject` replaces the visible current object through a CAS write
- `DeleteObject` creates an Ironmesh tombstone but does not expose a public S3
  delete-marker history surface
- normal `GetObject` reads the latest confirmed visible object only

This gives the external behavior most S3 clients expect while preserving
Ironmesh's internal no-loss history.

### Versioning enabled

Behavior:

- S3 `VersionId` maps directly to Ironmesh `version_id`
- `GetObject?versionId=...` reads the exact Ironmesh version
- `DeleteObject` creates a tombstone version and returns delete-marker fields
- `ListObjectVersions` translates the linearized S3-managed history into S3 XML

This mapping is only valid for keys that stayed on the S3-linear contract.

## CopyObject Design

`CopyObject` should reuse Ironmesh's copy primitives for zero-reupload server-side
copy.

Required additions:

- destination CAS guard
- shared object metadata copy/replace handling
- S3 compatibility metadata rebuild/update handling
- optional exact-version source reads when the source request names a `versionId`

Flow:

1. resolve the source bucket/key/version
2. resolve the destination current version
3. call `copy_object_if_current_version(...)`
4. persist destination shared object metadata
5. persist destination S3 compatibility metadata
6. return copy result XML

## Bucket Administration

### Admin API

Add admin-only endpoints on the native API surface for bucket and access-key
management.

Suggested routes:

- `GET /auth/s3/buckets`
- `POST /auth/s3/buckets`
- `DELETE /auth/s3/buckets/{bucket}`
- `GET /auth/s3/access-keys`
- `POST /auth/s3/access-keys`
- `POST /auth/s3/access-keys/{access_key_id}/revoke`

These routes should use the existing admin token/session model, not S3 auth.

### UI integration

The server-admin UI is a required part of the implementation plan, not an
optional follow-up.

Required admin tasks in the UI:

- bucket list
- bucket creation and deletion
- bucket prefix mapping
- versioning status
- read-only flag
- access key creation
- access key revocation
- recent use timestamps
- per-node S3 listener status
- S3 control-plane replication status or last-applied metadata generation
- direct S3 endpoint information
- relay/gateway access guidance for non-direct deployments

Recommendation:

- land the minimum usable admin UI in the same milestone as the initial bucket
  and access-key backend support
- extend that UI in later milestones as versioning, relay access, and advanced
  diagnostics come online

## Proposed Code Layout

Add a new module group under `crates/server-node-sdk/src/`:

- `s3_frontend/mod.rs`
- `s3_frontend/router.rs`
- `s3_frontend/auth.rs`
- `s3_frontend/xml.rs`
- `s3_frontend/errors.rs`
- `s3_frontend/multipart.rs`
- `s3_frontend/metadata.rs`

Storage-layer additions likely touch:

- `storage/mod.rs`
- `storage/sqlite_impl.rs`
- `storage/turso_impl.rs`

Server wiring likely touches:

- `lib.rs`
- `transport_service.rs` only if we later decide S3 should share the multiplexed
  internal execution path

Relay/gateway access likely also adds one of:

- a new standalone app such as `apps/s3-gateway`
- or a new mode in `apps/cli-client`

That gateway should primarily reuse:

- `crates/client-sdk`
- `crates/transport-sdk`

## Error Mapping

Implement explicit S3 XML error bodies instead of plain HTTP status-only
responses.

Core mappings:

- `NoSuchBucket`
- `BucketAlreadyExists`
- `BucketNotEmpty`
- `NoSuchKey`
- `NoSuchUpload`
- `InvalidPart`
- `InvalidPartOrder`
- `AccessDenied`
- `SignatureDoesNotMatch`
- `InvalidArgument`
- `NotImplemented`
- `OperationAborted`
- `PreconditionFailed`
- `InternalError`

## Interaction With Existing Ironmesh Features

### Replication and deduplication

No S3-specific byte storage is introduced.

Benefits:

- writes still deduplicate into the existing chunk store
- replicas stay compatible with existing replication bundles
- read-through chunk hydration keeps working for large object reads from the S3
  serving node

### Media cache

Objects uploaded through the S3 surface still become normal Ironmesh objects, so
existing media metadata warming and thumbnail logic can continue to operate on
their paths if those paths look like media files.

### Native clients

Native Ironmesh clients should continue to ignore the S3-specific compatibility
metadata. The S3 front end is an adapter, not the new canonical data model.

However, the shared per-version object metadata is a good candidate to become
part of the canonical storage model over time because it is useful beyond S3.

That said, native path APIs can still participate in S3-managed prefixes through
the explicit S3-compatible mode described above. In that mode, they become
another entrypoint to the same compatibility contract rather than a bypass
around it.

## Implementation Slices

### Slice 1: Cluster-wide control plane, admin UI, direct S3 CRUD

- add dedicated S3 listener
- add SigV4 header auth
- add bucket registry tables
- add S3 access-key tables
- replicate S3 control-plane metadata to all nodes
- add admin endpoints
- land the minimum required server-admin UI for bucket and access-key
  management
- add path-style bucket routing
- implement:
  - `ListBuckets`
  - `CreateBucket`
  - `DeleteBucket`
  - `HeadBucket`
  - `GetObject`
  - `HeadObject`
  - `PutObject`
  - `DeleteObject`
- add shared per-version object metadata table
- add S3 compatibility metadata table
- add CAS write helpers

Verification:

- multi-node replication coverage proving bucket and access-key changes become
  visible on every node
- direct S3 CRUD coverage against at least two different nodes in the same
  cluster
- server-admin UI coverage for bucket and access-key management
- unit tests for SigV4 canonical request verification
- request tests for XML errors
- end-to-end `aws s3api put-object/get-object/head-object/delete-object`

### Slice 2: Stable listing, copy, and cluster-wide S3 routing

- add shared lexicographic cursor-scan helper for native and S3 listing
- extend native `/store/index` with cursor-based pagination for the simplest
  compatible listing modes
- implement `ListObjectsV2`
- implement `CopyObject`
- implement metadata-directive handling
- surface per-node S3 listener status and replicated S3 control-plane health in
  the admin UI

Verification:

- native cursor pagination coverage for `/store/index`
- end-to-end `aws s3 ls`
- delimiter and continuation-token coverage
- copy across buckets

### Slice 3: Relay and gateway-backed S3 access

- add an `ironmesh-s3-gateway` or equivalent gateway mode
- let the gateway route over direct transport when available
- let the gateway fall back to rendezvous/relay transport when direct transport
  is unavailable
- forward raw S3 request semantics to a remote node for authoritative handling
- stream large request and response bodies through the transport layer
- add admin UI guidance for relay/gateway endpoint usage

Verification:

- end-to-end `aws s3api` CRUD through the gateway over direct transport
- end-to-end `aws s3api` CRUD through the gateway over relay transport
- mixed large upload/download coverage through relay-backed S3 access

### Slice 4: Multipart uploads

- generalize the native upload-session core from fixed chunk slots to logical
  staged parts
- add `ingest_payload_to_chunk_refs(...)` or equivalent native helper
- add S3 multipart overlay metadata
- implement `CreateMultipartUpload`
- implement `UploadPart`
- implement `ListParts`
- implement `CompleteMultipartUpload`
- implement `AbortMultipartUpload`

Verification:

- end-to-end multipart upload with AWS SDK
- resume after process restart
- invalid-part and invalid-order coverage

### Slice 5: Public versioning surface

- implement bucket versioning config
- implement `GetObject?versionId=...`
- implement `ListObjectVersions`
- expose S3 delete markers for versioned buckets

Verification:

- versioned put/delete/get flows
- copy from older version

### Slice 6: Optional compatibility extensions

- presigned URLs
- virtual-hosted-style bucket routing
- richer relay/gateway deployment packaging

## Open Questions

### Should the relay-backed S3 gateway ship as a standalone binary or a CLI mode?

Both are viable:

- standalone binary is cleaner for server/edge deployment
- CLI mode is faster to ship and can reuse existing bootstrap and transport
  wiring

The protocol design should keep this choice open.

### Should the S3 listener support browser presigned uploads early?

Probably not in the first slice. It is useful, but it expands the auth matrix
substantially and is not required for standard CLI/SDK direct use.

### Should bucket creation be allowed over the S3 API?

Yes, but only when the S3 access key carries an explicit management capability.
Otherwise the gateway should reject it with `AccessDenied`.

## Recommendation

Build the S3 surface as:

- an in-process compatibility listener on every server node,
- backed by cluster-wide replicated S3 control-plane metadata, and
- complemented by a relay-capable S3 gateway for deployments where direct S3
  listeners are not reachable.

That gives Ironmesh a practical interoperability story for:

- existing backup tools
- `aws s3api` / `aws s3`
- language SDKs
- migration bridges from S3-shaped applications
- private or NATed clusters that need relay-backed access

without forcing the core storage engine to become S3-native.

The critical design requirement is the CAS-style linear-write helper layer plus
cluster-wide metadata maintenance for S3-managed prefixes. Once that exists, the
rest of the front end is mostly protocol translation, cluster-wide metadata
replication, multipart bookkeeping, admin UX, and relay/direct entrypoints that
reuse the same compatibility contract.
