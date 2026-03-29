# Server-Node Media Cache

`server-node` now maintains a server-side cache for image metadata and thumbnails so mobile and web clients can list media-heavy directories without downloading original objects first.

## Goals

- Keep the primary object store immutable and version-oriented.
- Cache image-specific derivatives separately from object manifests.
- Let clients fetch directory metadata from `GET /store/index` and thumbnails from a dedicated endpoint.
- Reuse cached derivatives across different keys when the underlying bytes are identical.

## Storage Model

Primary object/version state remains unchanged:

- object payloads are chunked and content-addressed
- object manifests live under `manifests/`
- current/snapshot/path state still points to manifest hashes

Media derivatives are stored separately under:

- `state/media_cache/metadata/<content_fingerprint>.json`
- `state/media_cache/thumbnails/<content_fingerprint>/grid.jpg`

The cache is keyed by `content_fingerprint`, not by path.

## Why `content_fingerprint` Exists

`GET /store/index` historically returned `content_hash`, but in the current implementation that value is the active manifest hash, not a pure hash of object bytes.

That matters because manifests currently include the object key/path. Two keys can therefore reference identical bytes but still produce different manifest hashes.

To avoid duplicating thumbnails and metadata for byte-identical objects, `server-node` computes:

- `content_fingerprint = blake3(total_size_bytes + ordered chunk hashes + ordered chunk sizes)`

This excludes the key/path and is therefore stable across:

- copies
- renames
- re-uploads of identical bytes under a different key

## Supported Derivatives

Current implementation:

- image detection for common formats handled by the Rust `image` crate
- cached dimensions
- EXIF orientation when available
- EXIF GPS coordinates when available
- one JPEG thumbnail profile: `grid` with a maximum dimension of 256 px

Unsupported or undecodable media still get a cache record with status:

- `unsupported`
- `failed`

This prevents repeated expensive decode attempts on every listing.

Related design note:

- `docs/gallery-map-view-design-note.md`

## API

### `GET /store/index`

File entries may now include:

```json
{
  "path": "gallery/cat.png",
  "entry_type": "key",
  "content_hash": "manifest-hash",
  "content_fingerprint": "cfp-...",
  "media": {
    "status": "ready",
    "content_fingerprint": "cfp-...",
    "media_type": "image",
    "mime_type": "image/png",
    "width": 4032,
    "height": 3024,
    "orientation": 1,
    "taken_at_unix": null,
    "gps": {
      "latitude": 52.52,
      "longitude": 13.40
    },
    "thumbnail": {
      "url": "/media/thumbnail?key=gallery%2Fcat.png",
      "profile": "grid",
      "width": 256,
      "height": 192,
      "format": "jpeg",
      "size_bytes": 12458
    },
    "error": null
  }
}
```

When the object looks like an image but no cache record exists yet, the response uses:

- `media.status = "pending"`

The client can still request the thumbnail URL; the server will generate the cache on demand.

### `GET /media/thumbnail`

Query parameters:

- `key` (required)
- `snapshot` (optional)
- `version` (optional)
- `read_mode` (optional: `preferred`, `confirmed_only`, `provisional_allowed`)

Behavior:

- resolves the selected manifest for the requested object state
- generates the media cache on demand when missing
- returns the cached `grid` thumbnail as `image/jpeg`

Example:

```text
/media/thumbnail?key=gallery%2Fcat.png
```

## Cache Warming

New writes trigger asynchronous cache warming after successful upload/finalization. That covers:

- `PUT /store/{key}`
- chunked upload finalization via `POST /store/{key}?complete`

Existing objects created before this feature are still handled lazily:

- `GET /store/index` exposes `pending`
- the first thumbnail request generates the cache

## Cleanup

`cleanup_unreferenced` now also removes unreferenced media-cache metadata and thumbnail directories when the associated content fingerprint is no longer reachable from retained manifests.

## Client Guidance

For gallery-style UIs:

1. call `GET /store/index`
2. render file entries from the `media` block when present
3. load `media.thumbnail.url` instead of downloading the original object
4. fall back to the original object only when the user opens the full image

## Current Limits

- one thumbnail profile only: `grid`
- `taken_at_unix` is reserved in the response but not yet populated
- EXIF extraction is best-effort and format-dependent
- video/audio derivatives are not implemented yet

## Proposed Video Thumbnail Pipeline

Status:

- review draft only
- not implemented yet

### Goals

- add video thumbnails with broad format support
- avoid duplicating large objects into temporary files
- keep the existing media-cache API contract stable for clients
- keep the first implementation operationally simple

### Decision Summary

- use external `ffprobe` and `ffmpeg` processes for video inspection and thumbnail extraction
- keep image handling on the existing pure-Rust path
- for the first implementation, use `concatf:` as the only video input path
- assume all chunk files referenced by the manifest are already present locally
- keep storing video thumbnails in the existing cache layout under `state/media_cache/thumbnails/<content_fingerprint>/grid.jpg`
- keep exposing the result through the existing `media.thumbnail` block in `GET /store/index`

### Why External Tools

The main driver is codec and container coverage.

- `ffmpeg`/`ffprobe` support far more real-world formats than the currently available pure-Rust video options
- this keeps the thumbnailing path efficient and widely compatible without embedding a large decoding stack into `server-node`

### Input Strategy

The first implementation should use one input path only.

#### Fully Local Objects

When every chunk referenced by the manifest is already present on the current node:

- generate a tiny temporary `concatf` file containing the ordered local chunk paths
- pass that `concatf:` URL to `ffprobe` / `ffmpeg`

This avoids creating a second full copy of the original object, even for very large videos.

This also keeps the first implementation simpler because it avoids introducing an internal HTTP serving path just for thumbnail generation.

#### Objects That Are Not Fully Local

Support for partially local objects is explicitly out of scope for the first iteration.

- the first implementation assumes the required chunk files are already local
- if that assumption is not true, the video-thumbnail path should not attempt a remote-aware fallback
- handling partially local objects can be added in a later iteration if needed

### Deferred Follow-Up

If partially local video objects need thumbnail generation later, a follow-up design can revisit:

- an internal loopback HTTP helper with `Range` support
- token-based request authorization for that helper
- on-demand remote chunk fetches during FFmpeg seeks

### Thumbnail Generation Flow

For videos, the proposed flow is:

1. resolve the selected manifest and compute `content_fingerprint`
2. detect whether the payload is image or video
3. for video, inspect the first video stream with `ffprobe`
4. capture dimensions, codec/container details, and duration when available
5. choose a capture position based on duration, for example a clamped percentage into the file rather than frame zero
6. run `ffmpeg` to extract one representative frame
7. scale that frame to the existing `grid` thumbnail profile and encode as JPEG
8. persist the thumbnail and metadata through the existing media-cache record

### Expected Metadata

Initial video support is expected to populate:

- `media_type = "video"`
- `mime_type` when detectable
- `width`
- `height`
- `thumbnail`

The first implementation does not require new client-facing response fields beyond the existing media block.

### Failure Behavior

The media cache should remain best-effort.

- unsupported or undecodable videos should continue to produce `unsupported` or `failed` records without a thumbnail
- a missing `ffmpeg` / `ffprobe` binary should be recorded as a clear failure reason
- failures should be cached so the server does not repeatedly spawn expensive decode jobs for the same object

### Efficiency Notes

- avoid writing the full video to a temporary file
- use `concatf:` so FFmpeg reads the existing chunk files directly
- impose timeouts and concurrency limits around external-process execution
- keep the thumbnail profile unchanged for the first implementation to minimize cache growth

### Scope for the First Iteration

- video thumbnails only
- one thumbnail profile only: `grid`
- no audio waveforms or audio poster derivatives
- no scene-analysis service beyond what `ffmpeg` already provides
- no client API changes required
- auto-detect `ffmpeg` / `ffprobe` from `PATH`
- attempt all formats supported by the installed FFmpeg build
- no dedicated configuration flag to disable video thumbnail generation
- assume the manifest is fully local on the node performing thumbnail generation
