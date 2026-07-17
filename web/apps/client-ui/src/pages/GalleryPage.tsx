import {
  getBinaryObjectStreamUrl,
  getVersionGraph,
  listSnapshots,
  listStoreEntries,
  restoreStoreVersion,
  retryStoreMediaCacheEntry
} from "@ironmesh/api";
import {
  GallerySurface,
  PageHeader,
  type GalleryBasemapConfig,
  type GalleryEntry,
  type GalleryLoadEntriesOptions,
  type GalleryMediaRequests,
  type GallerySurfaceViewMode
} from "@ironmesh/ui";
import { useCallback } from "react";

const MOBILE_VIEWER_THUMBNAIL_PROFILE = "mobile_viewer";

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

type GalleryPageProps = {
  initialViewMode?: GallerySurfaceViewMode;
};

export function GalleryPage({ initialViewMode }: GalleryPageProps = {}) {
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
    (entry: GalleryEntry, snapshotId: string | null, versionId?: string | null): GalleryMediaRequests => {
      const thumbnailUrl = entry.media?.thumbnail?.url ?? null;
      return {
        thumbnail: thumbnailUrl
          ? {
              url: thumbnailUrl
            }
          : null,
        fullscreen:
          thumbnailUrl && entry.media?.media_type !== "video"
            ? {
                url: withThumbnailProfile(thumbnailUrl, MOBILE_VIEWER_THUMBNAIL_PROFILE)
              }
            : null,
        original: {
          url: binaryMediaUrl(entry.path, snapshotId, versionId)
        }
      };
    },
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
        initialViewMode={initialViewMode}
        allowedMediaKinds={["image", "video"]}
        basemaps={CLIENT_GALLERY_BASEMAPS}
        loadSnapshots={loadSnapshots}
        loadEntries={loadEntries}
        getMediaRequests={getMediaRequests}
        loadVersions={getVersionGraph}
        restoreVersion={(key, versionId, targetPath) =>
          restoreStoreVersion(key, versionId, targetPath)
        }
        retryMediaEntry={retryMediaEntry}
      />
    </>
  );
}

function binaryMediaUrl(
  key: string,
  snapshotId: string | null,
  versionId?: string | null
): string {
  return getBinaryObjectStreamUrl(key, snapshotId, versionId);
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

function withThumbnailProfile(url: string, profile: string): string {
  const baseOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  const resolved = new URL(url, baseOrigin);
  resolved.searchParams.set("profile", profile);
  return `${resolved.pathname}${resolved.search}${resolved.hash}`;
}
