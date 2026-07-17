import {
  getClientGalleryMapConfiguration,
  getBinaryObjectStreamUrl,
  getVersionGraph,
  listSnapshots,
  listStoreEntries,
  restoreStoreVersion,
  retryStoreMediaCacheEntry
} from "@ironmesh/api";
import {
  GallerySurface,
  galleryBasemapsFromConfiguration,
  PageHeader,
  type GalleryEntry,
  type GalleryLoadEntriesOptions,
  type GalleryMediaRequests,
  type GallerySurfaceViewMode
} from "@ironmesh/ui";
import { useCallback, useEffect, useMemo, useState } from "react";

const MOBILE_VIEWER_THUMBNAIL_PROFILE = "mobile_viewer";

type GalleryPageProps = {
  initialViewMode?: GallerySurfaceViewMode;
};

export function GalleryPage({ initialViewMode }: GalleryPageProps = {}) {
  const [mapConfiguration, setMapConfiguration] = useState<
    Awaited<ReturnType<typeof getClientGalleryMapConfiguration>> | null
  >(null);
  useEffect(() => {
    let cancelled = false;
    const refresh = async () => {
      try {
        const next = await getClientGalleryMapConfiguration();
        if (!cancelled) {
          setMapConfiguration(next);
        }
      } catch {
        // The gallery remains usable while a transient node or replication hop
        // is unavailable. The next refresh picks up the shared setting.
      }
    };
    void refresh();
    const interval = window.setInterval(() => void refresh(), 15_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);
  const basemaps = useMemo(
    () => galleryBasemapsFromConfiguration(mapConfiguration?.configuration.variants ?? []),
    [mapConfiguration]
  );
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
        basemaps={basemaps}
        preferredBasemapId={mapConfiguration?.configuration.active_variant_id}
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

function withThumbnailProfile(url: string, profile: string): string {
  const baseOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  const resolved = new URL(url, baseOrigin);
  resolved.searchParams.set("profile", profile);
  return `${resolved.pathname}${resolved.search}${resolved.hash}`;
}
