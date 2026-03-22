import { listAdminSnapshots, listAdminStoreEntries } from "@ironmesh/api";
import {
  GallerySurface,
  type GalleryEntry,
  type GalleryImageRequests
} from "@ironmesh/ui";
import { useCallback } from "react";
import { useAdminAccess } from "../lib/admin-access";

const ADMIN_TOKEN_HEADER = "x-ironmesh-admin-token";

export function GalleryPage() {
  const { adminTokenOverride } = useAdminAccess();
  const previewHeaders = adminTokenOverride.trim()
    ? { [ADMIN_TOKEN_HEADER]: adminTokenOverride.trim() }
    : undefined;

  const loadSnapshots = useCallback(
    () => listAdminSnapshots(adminTokenOverride),
    [adminTokenOverride]
  );
  const loadEntries = useCallback(
    (prefix: string, depth: number, snapshotId: string | null) =>
      listAdminStoreEntries(prefix, depth, snapshotId, adminTokenOverride),
    [adminTokenOverride]
  );
  const getImageRequests = useCallback(
    (entry: GalleryEntry, snapshotId: string | null): GalleryImageRequests => ({
      thumbnail: {
        url: entry.media?.thumbnail?.url || adminBinaryObjectUrl(entry.path, snapshotId),
        headers: previewHeaders
      },
      original: {
        url: adminBinaryObjectUrl(entry.path, snapshotId),
        headers: previewHeaders
      }
    }),
    [previewHeaders]
  );

  return (
    <GallerySurface
      intro="Browse the node-side store index through admin-authenticated snapshot, index, and media routes. The gallery stays shared with the client surface, while this wrapper carries the admin session or advanced token override when previews need authenticated fetches."
      previewHint="Admin thumbnail URLs are preferred when indexed media is ready, with authenticated full-object fetches as a fallback."
      loadSnapshots={loadSnapshots}
      loadEntries={loadEntries}
      getImageRequests={getImageRequests}
    />
  );
}

function adminBinaryObjectUrl(key: string, snapshotId: string | null): string {
  const query = new URLSearchParams();
  if (snapshotId) {
    query.set("snapshot", snapshotId);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return `/auth/store/${encodeURIComponent(key)}${suffix}`;
}
