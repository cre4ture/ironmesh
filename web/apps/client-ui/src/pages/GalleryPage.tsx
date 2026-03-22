import { listSnapshots, listStoreEntries } from "@ironmesh/api";
import {
  GallerySurface,
  PageHeader,
  type GalleryEntry,
  type GalleryImageRequests
} from "@ironmesh/ui";
import { useCallback } from "react";

export function GalleryPage() {
  const loadSnapshots = useCallback(() => listSnapshots(), []);
  const loadEntries = useCallback(
    (prefix: string, depth: number, snapshotId: string | null) =>
      listStoreEntries(prefix, depth, snapshotId),
    []
  );
  const getImageRequests = useCallback(
    (entry: GalleryEntry, snapshotId: string | null): GalleryImageRequests => ({
      thumbnail: {
        url: entry.media?.thumbnail?.url || binaryObjectUrl(entry.path, snapshotId)
      },
      original: {
        url: binaryObjectUrl(entry.path, snapshotId)
      }
    }),
    []
  );

  return (
    <>
      <PageHeader
        title="Gallery"
        description="A first shared web gallery surface for browsing image objects through the client web backend."
      />
      <GallerySurface
        previewHint="Thumbnail URLs are used when the media index provides them, with full-object downloads as a fallback."
        loadSnapshots={loadSnapshots}
        loadEntries={loadEntries}
        getImageRequests={getImageRequests}
      />
    </>
  );
}

function binaryObjectUrl(key: string, snapshotId: string | null): string {
  const query = new URLSearchParams({ key });
  if (snapshotId) {
    query.set("snapshot", snapshotId);
  }
  return `/api/store/get-binary?${query.toString()}`;
}
