import {
  deleteStoreValue,
  getBinaryObjectDownloadUrl,
  getStoreValue,
  getVersionGraph,
  listSnapshots,
  listStoreEntries,
  putStoreValue,
  renameStorePath,
  restoreStorePathFromSnapshot
} from "@ironmesh/api";
import { ExplorerSurface, PageHeader } from "@ironmesh/ui";
import { useCallback } from "react";

type ExplorerPageProps = {
  queueFilesToPrefix: (files: File[], targetPrefix: string) => boolean;
  onOpenStore: () => void;
};

export function ExplorerPage({ queueFilesToPrefix, onOpenStore }: ExplorerPageProps) {
  const loadSnapshots = useCallback(() => listSnapshots(), []);
  const loadEntries = useCallback(
    (
      prefix: string,
      depth: number,
      snapshotId: string | null,
      view: "raw" | "tree" = "tree"
    ) => listStoreEntries(prefix, depth, snapshotId, view),
    []
  );
  const readValue = useCallback(
    (key: string, snapshotId: string | null, versionId: string | null, previewBytes: number) =>
      getStoreValue(key, snapshotId, versionId, previewBytes),
    []
  );
  const queueFiles = useCallback(
    (files: File[], targetPrefix: string) => {
      const queued = queueFilesToPrefix(files, targetPrefix);
      if (queued) {
        onOpenStore();
      }
      return queued;
    },
    [onOpenStore, queueFilesToPrefix]
  );

  return (
    <>
      <PageHeader
        title="Explorer"
        description="Inspect prefixes, snapshots, and version history through the same backend APIs exposed by serve-web and Android."
      />
      <ExplorerSurface
        loadSnapshots={loadSnapshots}
        loadEntries={loadEntries}
        readValue={readValue}
        getDownloadUrl={(key, snapshotId, versionId) =>
          getBinaryObjectDownloadUrl(key, snapshotId, versionId)
        }
        loadVersions={getVersionGraph}
        mutations={{
          createFolderMarker: (markerKey) => putStoreValue(markerKey, ""),
          deletePath: deleteStoreValue,
          renamePath: (fromPath, toPath) => renameStorePath(fromPath, toPath),
          restoreSnapshotPath: restoreStorePathFromSnapshot
        }}
        quickUpload={{
          queueFiles
        }}
      />
    </>
  );
}
