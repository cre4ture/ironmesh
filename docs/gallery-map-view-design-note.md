# Gallery Map View Design Note

## Status

Idea, not implemented.

This note assumes the general storage-layer solution for cluster-wide metadata visibility and
read-through chunk caching is already the accepted foundation for large self-hosted map data.

See:

- `docs/read-through-chunk-cache-proposal.md`
- `docs/read-through-chunk-cache-implementation-plan.md`

This document is therefore intentionally limited to gallery-map-specific product and UI decisions.

## Feature Goal

Add a switch in the shared web gallery that changes the current thumbnail grid into a world-map
view.

Requirements:

- use the existing shared web gallery surface,
- only place images that actually have GPS metadata,
- show thumbnails on the map,
- keep the basemap self-hostable on Ironmesh-operated infrastructure,
- keep the normal grid view available as the default fallback.

## Existing Foundation

The media pipeline already exposes the metadata needed by a future map view:

- image classification,
- thumbnail URLs,
- optional EXIF GPS coordinates.

See:

- `docs/server-node-media-cache.md`

The general storage-layer work is documented separately and should not be redesigned here:

- cluster-wide metadata visibility,
- read-through chunk caching for large objects,
- non-replica reads for large self-hosted basemap data.

## Map Stack Choice

### Browser-side map rendering

`MapLibre GL JS` remains the preferred browser-side map library.

Why:

- open and self-hostable,
- good fit for a web gallery with a custom thumbnail marker layer,
- flexible enough for marker clustering, popups, and selection sync with the lightbox.

### Basemap serving

The current preference remains:

- self-hosted `PMTiles` when a simple static basemap is sufficient,
- `Martin` only if Ironmesh later needs a more standard or more dynamic tile-service setup.

This note assumes the storage layer can already serve large basemap assets through the general
read-through path when needed.

## Transitional Split-MBTiles Packaging

For the currently prepared `maptiler-satellite-2017-11-02-planet.mbtiles` dataset, a practical
transitional packaging is:

- keep the already uploaded split files under `sys/maps/`,
- add one JSON manifest next to them,
- let the eventual map-serving layer treat that manifest as the authoritative logical-file layout.

This does not change the longer-term map-serving choice. It is only a packaging and discovery
format for a manually distributed large basemap artifact.

### Immediate cluster location proposal

For the dataset already uploaded to the cluster, store the manifest at:

- `sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json`

Keep the existing part objects as they are:

- `sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles-part-aa`
- `sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles-part-ab`
- ...
- `sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles-part-as`

An example manifest matching the current uploaded files is included in the repo at:

- `docs/examples/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json`

### Preferred long-term layout

For future large map artifacts, prefer a dedicated logical directory instead of a flat file set:

- `sys/maps/<map-id>/manifest.json`
- `sys/maps/<map-id>/parts/<part-id>`

For example:

- `sys/maps/maptiler-satellite-2017-11-02-planet/manifest.json`
- `sys/maps/maptiler-satellite-2017-11-02-planet/parts/aa`
- `sys/maps/maptiler-satellite-2017-11-02-planet/parts/ab`

Why:

- cleaner discovery,
- easier coexistence of multiple basemaps,
- easier to attach additional metadata later such as attribution, bounds, preferred zooms, or
  alternate profiles.

### Manifest structure

The split-file manifest should minimally contain:

- manifest version,
- logical format, for example `mbtiles`,
- logical object key,
- total logical byte size,
- regular part size,
- ordered list of parts with:
  - stable `part_id`,
  - cluster object key,
  - logical byte offset,
  - part size.

The map-serving layer should use the manifest rather than infer part membership by directory
listing or filename guessing.

### Important note

`MapLibre GL JS` does not directly consume a set of split MBTiles files in the browser.

This packaging therefore implies one additional service layer that reconstructs a logical MBTiles
file or otherwise serves map tiles from the manifest-defined parts. The manifest is only the
storage-side description of the split artifact.

## Remaining Map-Specific Decisions

The main open questions are now product and UI questions rather than storage questions:

- how the gallery switches between `Grid` and `Map`,
- whether the map opens at the global view or auto-fits the current visible images,
- how thumbnail markers should look at different zoom levels,
- when to switch from single thumbnails to clustering,
- how marker selection interacts with the existing fullscreen image view,
- how prefix/depth filtering in the gallery should affect the visible marker set,
- what the first self-hosted basemap profile should be.

## Recommended First Implementation

1. Add a `Grid` / `Map` switch to the shared gallery surface.
2. Show only GPS-bearing images on the map.
3. Reuse existing thumbnail URLs for marker visuals and preview popups.
4. Keep selection synchronized between map markers and the existing fullscreen image viewer.
5. Start with a basic self-hosted basemap and add clustering once the interaction model feels
   right.

## Current Recommendation

Treat the storage-layer foundation as an existing dependency, not as part of this feature note.

The next design and implementation work for the gallery map should focus on:

- shared gallery UX,
- marker rendering and clustering,
- fullscreen-view integration,
- practical basemap packaging and deployment for self-hosted use,
- the service layer that consumes the split-manifest format when a large basemap is manually
  distributed across the cluster.
