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
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const MOBILE_VIEWER_THUMBNAIL_PROFILE = "mobile_viewer";

type GalleryPageProps = {
  initialViewMode?: GallerySurfaceViewMode;
};

export function GalleryPage({ initialViewMode }: GalleryPageProps = {}) {
  const [mapConfiguration, setMapConfiguration] = useState<
    Awaited<ReturnType<typeof getClientGalleryMapConfiguration>> | null
  >(null);
  const [mapConfigurationLoading, setMapConfigurationLoading] = useState(true);
  const [mapConfigurationError, setMapConfigurationError] = useState<string | null>(null);
  const mapConfigurationMountedRef = useRef(true);
  const mapConfigurationRequestVersionRef = useRef(0);

  useEffect(() => {
    mapConfigurationMountedRef.current = true;
    return () => {
      mapConfigurationMountedRef.current = false;
    };
  }, []);

  const refreshMapConfiguration = useCallback(async () => {
    if (!mapConfigurationMountedRef.current) {
      return;
    }
    const requestVersion = mapConfigurationRequestVersionRef.current + 1;
    mapConfigurationRequestVersionRef.current = requestVersion;
    setMapConfigurationLoading(true);
    try {
      const next = await getClientGalleryMapConfiguration();
      if (
        !mapConfigurationMountedRef.current ||
        requestVersion !== mapConfigurationRequestVersionRef.current
      ) {
        return;
      }
      // Polling must not replace an equivalent response: `basemaps` then
      // keeps its identity and the map does not get recreated every 15s.
      setMapConfiguration((current) =>
        sameMapConfiguration(current, next) ? current : next
      );
      setMapConfigurationError(null);
    } catch (error) {
      if (
        mapConfigurationMountedRef.current &&
        requestVersion === mapConfigurationRequestVersionRef.current
      ) {
        setMapConfigurationError(mapConfigurationErrorMessage(error));
      }
    } finally {
      if (
        mapConfigurationMountedRef.current &&
        requestVersion === mapConfigurationRequestVersionRef.current
      ) {
        setMapConfigurationLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    void refreshMapConfiguration();
    const interval = window.setInterval(() => void refreshMapConfiguration(), 15_000);
    return () => {
      window.clearInterval(interval);
    };
  }, [refreshMapConfiguration]);
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
        basemapConfigurationLoading={mapConfigurationLoading}
        basemapConfigurationError={mapConfigurationError}
        retryBasemapConfiguration={() => void refreshMapConfiguration()}
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

function mapConfigurationErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }

  return "The gallery map configuration could not be loaded.";
}

function sameMapConfiguration(
  current: Awaited<ReturnType<typeof getClientGalleryMapConfiguration>> | null,
  next: Awaited<ReturnType<typeof getClientGalleryMapConfiguration>>
): boolean {
  // `stored` communicates server-side initialization state only; it has no
  // effect on gallery rendering. The API serializes configuration fields in a
  // stable order, so this also compares nested variants without an additional
  // dependency for deep equality.
  return (
    current !== null &&
    JSON.stringify(current.configuration) === JSON.stringify(next.configuration)
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
