import {
  getBinaryObjectStreamUrl,
  listSnapshots,
  listStoreEntries,
  retryStoreMediaCacheEntry
} from "@ironmesh/api";
import {
  GallerySurface,
  PageHeader,
  type GalleryBasemapConfig,
  type GalleryEntry,
  type GalleryLoadEntriesOptions,
  type GalleryMediaRequests
} from "@ironmesh/ui";
import { useCallback } from "react";

const CLIENT_GALLERY_BASEMAP_MANIFEST_KEY =
  "sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json";
const CLIENT_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY =
  "sys/maps/maptiler-osm-2020-02-10-v3.11-planet.mbtiles.manifest.json";
const CLIENT_GALLERY_BASEMAPS: GalleryBasemapConfig[] = [
  {
    id: "satellite",
    kind: "raster",
    modeLabel: "Satellite",
    logicalFileUrl: logicalMapFileUrl(CLIENT_GALLERY_BASEMAP_MANIFEST_KEY),
    metadataUrl: logicalMapMetadataUrl(CLIENT_GALLERY_BASEMAP_MANIFEST_KEY),
    tileUrlTemplate: logicalMapTileUrlTemplate(CLIENT_GALLERY_BASEMAP_MANIFEST_KEY),
    label: "MapTiler Satellite 2017-11-02 Planet",
    attribution:
      "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors."
  },
  {
    id: "hybrid",
    kind: "hybrid",
    modeLabel: "Hybrid",
    rasterMetadataUrl: logicalMapMetadataUrl(CLIENT_GALLERY_BASEMAP_MANIFEST_KEY),
    rasterTileUrlTemplate: logicalMapTileUrlTemplate(CLIENT_GALLERY_BASEMAP_MANIFEST_KEY),
    vectorMetadataUrl: logicalMapMetadataUrl(CLIENT_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    vectorTileUrlTemplate: logicalMapVectorTileUrlTemplate(CLIENT_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    glyphsUrlTemplate: logicalMapGlyphUrlTemplate(),
    label: "Satellite with city and border overlay",
    attribution:
      "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors."
  },
  {
    id: "street",
    kind: "vector",
    modeLabel: "Street",
    metadataUrl: logicalMapMetadataUrl(CLIENT_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    vectorTileUrlTemplate: logicalMapVectorTileUrlTemplate(CLIENT_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    glyphsUrlTemplate: logicalMapGlyphUrlTemplate(),
    label: "OpenMapTiles Street 2020-02-10 v3.11 Planet",
    attribution: "Data Copyright OpenStreetMap contributors."
  }
];

export function GalleryPage() {
  const loadSnapshots = useCallback(() => listSnapshots(), []);
  const loadEntries = useCallback(
    (
      prefix: string,
      depth: number,
      snapshotId: string | null,
      options?: GalleryLoadEntriesOptions
    ) => listStoreEntries(prefix, depth, snapshotId, options),
    []
  );
  const getMediaRequests = useCallback(
    (entry: GalleryEntry, snapshotId: string | null): GalleryMediaRequests => ({
      thumbnail: entry.media?.thumbnail?.url
        ? {
            url: entry.media.thumbnail.url
          }
        : null,
      original: {
        url: binaryMediaUrl(entry.path, snapshotId)
      }
    }),
    []
  );
  const retryMediaEntry = useCallback(
    (entry: GalleryEntry, snapshotId: string | null) =>
      retryStoreMediaCacheEntry(entry.path, {
        snapshot: snapshotId,
        version: typeof entry.version === "string" ? entry.version : null
      }),
    []
  );

  return (
    <>
      <PageHeader
        title="Gallery"
        description="Browse photo and movie objects through the client web backend with shared media-aware gallery tooling."
      />
      <GallerySurface
        previewHint="Only indexed thumbnail URLs are used for gallery cards and movie posters. Missing thumbnails stay visible in the UI so pending or failed media processing is obvious."
        allowedMediaKinds={["image", "video"]}
        basemaps={CLIENT_GALLERY_BASEMAPS}
        loadSnapshots={loadSnapshots}
        loadEntries={loadEntries}
        getMediaRequests={getMediaRequests}
        retryMediaEntry={retryMediaEntry}
      />
    </>
  );
}

function binaryMediaUrl(key: string, snapshotId: string | null): string {
  return getBinaryObjectStreamUrl(key, snapshotId);
}

function logicalMapFileUrl(manifestKey: string): string {
  const query = new URLSearchParams({ manifest_key: manifestKey });
  return `/api/v1/maps/logical-file?${query.toString()}`;
}

function logicalMapMetadataUrl(manifestKey: string): string {
  const query = new URLSearchParams({ manifest_key: manifestKey });
  return `/api/v1/maps/mbtiles-metadata?${query.toString()}`;
}

function logicalMapTileUrlTemplate(manifestKey: string): string {
  const query = new URLSearchParams({ manifest_key: manifestKey });
  return `/api/v1/maps/tiles/{z}/{x}/{y}?${query.toString()}`;
}

function logicalMapVectorTileUrlTemplate(manifestKey: string): string {
  const query = new URLSearchParams({ manifest_key: manifestKey });
  return `/api/v1/maps/vector-tiles/{z}/{x}/{y}?${query.toString()}`;
}

function logicalMapGlyphUrlTemplate(): string {
  return "/api/v1/maps/fonts/{fontstack}/{range}.pbf";
}
