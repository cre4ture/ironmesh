import { listSnapshots, listStoreEntries } from "@ironmesh/api";
import {
  GallerySurface,
  PageHeader,
  type GalleryBasemapConfig,
  type GalleryEntry,
  type GalleryImageRequests
} from "@ironmesh/ui";
import { useCallback } from "react";

const CLIENT_GALLERY_BASEMAP_MANIFEST_KEY =
  "sys/maps/maptiler-satellite-2017-11-02-planet.mbtiles.manifest.json";
const CLIENT_GALLERY_BASEMAP: GalleryBasemapConfig = {
  logicalFileUrl: logicalMapFileUrl(CLIENT_GALLERY_BASEMAP_MANIFEST_KEY),
  label: "MapTiler Satellite 2017-11-02 Planet",
  attribution:
    "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors."
};

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
        basemap={CLIENT_GALLERY_BASEMAP}
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

function logicalMapFileUrl(manifestKey: string): string {
  const query = new URLSearchParams({ manifest_key: manifestKey });
  return `/api/maps/logical-file?${query.toString()}`;
}
