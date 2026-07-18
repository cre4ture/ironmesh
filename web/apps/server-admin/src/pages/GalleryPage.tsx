import {
  getAdminGalleryMapConfiguration,
  getAdminVersionGraph,
  listAdminSnapshots,
  listAdminStoreEntries,
  restoreAdminStoreVersion,
  retryAdminMediaCacheEntry
} from "@ironmesh/api";
import {
  GallerySurface,
  galleryBasemapsFromConfiguration,
  type GalleryEntry,
  type GalleryLoadEntriesOptions,
  type GalleryMediaRequests
} from "@ironmesh/ui";
import { Stack } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { useCallback } from "react";
import { MapDatasetImportCard } from "../components/MapDatasetImportCard";
import { MapVariantConfigurationCard } from "../components/MapVariantConfigurationCard";
import { useAdminAccess } from "../lib/admin-access";

const MOBILE_VIEWER_THUMBNAIL_PROFILE = "mobile_viewer";

export function GalleryPage() {
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectMapConfiguration =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);
  const mapConfigurationQuery = useQuery({
    queryKey: ["gallery-page", "map-configuration", normalizedAdminTokenOverride],
    queryFn: () => getAdminGalleryMapConfiguration(normalizedAdminTokenOverride || undefined),
    enabled: canInspectMapConfiguration,
    staleTime: 5_000
  });
  const mapConfiguration = mapConfigurationQuery.data ?? null;
  const basemaps = galleryBasemapsFromConfiguration(
    mapConfiguration?.configuration.variants ?? []
  );

  const loadSnapshots = useCallback(
    () => listAdminSnapshots(normalizedAdminTokenOverride || undefined),
    [normalizedAdminTokenOverride]
  );
  const loadEntries = useCallback(
    (
      prefix: string,
      depth: number,
      snapshotId: string | null,
      options?: GalleryLoadEntriesOptions
    ) =>
      listAdminStoreEntries(
        prefix,
        depth,
        snapshotId,
        normalizedAdminTokenOverride || undefined,
        options
      ),
    [normalizedAdminTokenOverride]
  );
  const loadVersions = useCallback(
    (key: string) => getAdminVersionGraph(key, normalizedAdminTokenOverride || undefined),
    [normalizedAdminTokenOverride]
  );
  const getMediaRequests = useCallback(
    (
      entry: GalleryEntry,
      snapshotId: string | null,
      versionId?: string | null
    ): GalleryMediaRequests => {
      const thumbnailUrl = entry.media?.thumbnail?.url ?? null;
      const original = {
        url: adminBinaryObjectUrl(entry.path, snapshotId, versionId)
      };

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
        original
      };
    },
    []
  );
  const retryMediaEntry = useCallback(
    (entry: GalleryEntry, snapshotId: string | null) =>
      retryAdminMediaCacheEntry(entry.path, normalizedAdminTokenOverride || undefined, {
        snapshot: snapshotId,
        version: typeof entry.version === "string" ? entry.version : null
      }),
    [normalizedAdminTokenOverride]
  );
  return (
    <Stack gap="lg">
      <MapVariantConfigurationCard
        configuration={mapConfiguration?.configuration ?? null}
        stored={mapConfiguration?.stored ?? null}
        loading={mapConfigurationQuery.isLoading}
        error={mapConfigurationQuery.error}
      />
      <MapDatasetImportCard />

      <GallerySurface
        intro="Browse the node-side store index through admin-authenticated snapshot, index, and media routes. The gallery stays shared with the client surface and uses the current admin session for protected previews."
        previewHint="Only indexed thumbnail URLs are used for gallery cards and movie posters. Missing thumbnails stay visible in the UI so pending or failed media processing is obvious."
        allowedMediaKinds={["image", "video"]}
        basemaps={basemaps}
        preferredBasemapId={mapConfiguration?.configuration.active_variant_id}
        loadSnapshots={loadSnapshots}
        loadEntries={loadEntries}
        getMediaRequests={getMediaRequests}
        loadVersions={loadVersions}
        restoreVersion={(key, versionId, targetPath) =>
          restoreAdminStoreVersion(key, versionId, targetPath)
        }
        retryMediaEntry={retryMediaEntry}
      />
    </Stack>
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

function withThumbnailProfile(url: string, profile: string): string {
  const baseOrigin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  const resolved = new URL(url, baseOrigin);
  resolved.searchParams.set("profile", profile);
  return `${resolved.pathname}${resolved.search}${resolved.hash}`;
}
