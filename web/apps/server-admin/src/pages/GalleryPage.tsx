import {
  getAdminVersionGraph,
  listAdminSnapshots,
  listAdminStoreEntries,
  restoreAdminStoreVersion,
  retryAdminMediaCacheEntry
} from "@ironmesh/api";
import {
  GallerySurface,
  type GalleryBasemapConfig,
  type GalleryEntry,
  type GalleryLoadEntriesOptions,
  type GalleryMediaRequests
} from "@ironmesh/ui";
import { useCallback } from "react";
const ADMIN_GALLERY_BASEMAP_MANIFEST_KEY =
  "sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json";
const ADMIN_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY =
  "sys/maps/maptiler-osm-2020-02-10-v3.11-planet.mbtiles.manifest.json";
const ADMIN_GALLERY_BASEMAPS: GalleryBasemapConfig[] = [
  {
    id: "satellite",
    kind: "raster",
    modeLabel: "Satellite",
    logicalFileUrl: logicalMapFileUrl(ADMIN_GALLERY_BASEMAP_MANIFEST_KEY),
    metadataUrl: logicalMapMetadataUrl(ADMIN_GALLERY_BASEMAP_MANIFEST_KEY),
    tileUrlTemplate: logicalMapTileUrlTemplate(ADMIN_GALLERY_BASEMAP_MANIFEST_KEY),
    label: "MapTiler Satellite 2017-11-02 Planet",
    attribution:
      "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors."
  },
  {
    id: "hybrid",
    kind: "hybrid",
    modeLabel: "Hybrid",
    rasterMetadataUrl: logicalMapMetadataUrl(ADMIN_GALLERY_BASEMAP_MANIFEST_KEY),
    rasterTileUrlTemplate: logicalMapTileUrlTemplate(ADMIN_GALLERY_BASEMAP_MANIFEST_KEY),
    vectorMetadataUrl: logicalMapMetadataUrl(ADMIN_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    vectorTileUrlTemplate: logicalMapVectorTileUrlTemplate(ADMIN_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    glyphsUrlTemplate: logicalMapGlyphUrlTemplate(),
    label: "Satellite with city and border overlay",
    attribution:
      "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors."
  },
  {
    id: "street",
    kind: "vector",
    modeLabel: "Street",
    metadataUrl: logicalMapMetadataUrl(ADMIN_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    vectorTileUrlTemplate: logicalMapVectorTileUrlTemplate(ADMIN_GALLERY_VECTOR_BASEMAP_MANIFEST_KEY),
    glyphsUrlTemplate: logicalMapGlyphUrlTemplate(),
    label: "OpenMapTiles Street 2020-02-10 v3.11 Planet",
    attribution: "Data Copyright OpenStreetMap contributors."
  }
];

export function GalleryPage() {
  const loadSnapshots = useCallback(() => listAdminSnapshots(), []);
  const loadEntries = useCallback(
    (
      prefix: string,
      depth: number,
      snapshotId: string | null,
      options?: GalleryLoadEntriesOptions
    ) => listAdminStoreEntries(prefix, depth, snapshotId, undefined, options),
    []
  );
  const loadVersions = useCallback((key: string) => getAdminVersionGraph(key), []);
  const getMediaRequests = useCallback(
    (
      entry: GalleryEntry,
      snapshotId: string | null,
      versionId?: string | null
    ): GalleryMediaRequests => {
      const original = {
        url: adminBinaryObjectUrl(entry.path, snapshotId, versionId)
      };

      return {
        thumbnail: entry.media?.thumbnail?.url
          ? {
              url: entry.media.thumbnail.url
            }
          : null,
        original
      };
    },
    []
  );
  const retryMediaEntry = useCallback(
    (entry: GalleryEntry, snapshotId: string | null) =>
      retryAdminMediaCacheEntry(entry.path, undefined, {
        snapshot: snapshotId,
        version: typeof entry.version === "string" ? entry.version : null
      }),
    []
  );

  return (
    <GallerySurface
      intro="Browse the node-side store index through admin-authenticated snapshot, index, and media routes. The gallery stays shared with the client surface and uses the current admin session for protected previews."
      previewHint="Only indexed thumbnail URLs are used for gallery cards and movie posters. Missing thumbnails stay visible in the UI so pending or failed media processing is obvious."
      allowedMediaKinds={["image", "video"]}
      basemaps={ADMIN_GALLERY_BASEMAPS}
      loadSnapshots={loadSnapshots}
      loadEntries={loadEntries}
      getMediaRequests={getMediaRequests}
      loadVersions={loadVersions}
      restoreVersion={(key, versionId, targetPath) =>
        restoreAdminStoreVersion(key, versionId, targetPath)
      }
      retryMediaEntry={retryMediaEntry}
    />
  );
}

function adminBinaryObjectUrl(
  key: string,
  snapshotId: string | null,
  versionId?: string | null
): string {
  const query = new URLSearchParams();
  if (snapshotId) {
    query.set("snapshot", snapshotId);
  }
  if (versionId?.trim()) {
    query.set("version", versionId.trim());
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return `/api/v1/auth/store/${encodeURIComponent(key)}${suffix}`;
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
