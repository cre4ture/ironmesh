# Server-Node Media Cache

`server-node` now maintains a server-side cache for image and video metadata plus thumbnails so mobile and web clients can list media-heavy directories without downloading original objects first.

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
- video inspection and thumbnail extraction handled by external `ffprobe` / `ffmpeg`
- cached dimensions
- EXIF orientation when available
- EXIF GPS coordinates when available
- one JPEG thumbnail profile: `grid` with a maximum dimension of 256 px
- local video thumbnails built through a `concatf:` list of chunk files

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

When the object looks like an image or video but no cache record exists yet, the response uses:

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
4. fall back to the original object only when the user opens the full image or movie

## Current Limits

- one thumbnail profile only: `grid`
- `taken_at_unix` is reserved in the response but not yet populated
- EXIF extraction is best-effort and format-dependent
- video thumbnails require `ffprobe` and `ffmpeg` to be available on `PATH`
- video thumbnail generation currently assumes all chunk files for the manifest are already local on the node performing the work
- objects that are not fully local do not yet use a remote-aware fallback path for video thumbnails
- audio derivatives are not implemented yet
