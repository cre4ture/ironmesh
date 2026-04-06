import {
  deleteAdminStorePath,
  getAdminStoreDownloadUrl,
  getAdminStoreValue,
  getAdminVersionGraph,
  listAdminSnapshots,
  listAdminStoreEntries,
  renameAdminStorePath
} from "@ironmesh/api";
import { ExplorerSurface } from "@ironmesh/ui";
import { useCallback } from "react";
import { useAdminAccess } from "../lib/admin-access";

export function ExplorerPage() {
  const { adminTokenOverride } = useAdminAccess();

  const loadSnapshots = useCallback(
    () => listAdminSnapshots(adminTokenOverride),
    [adminTokenOverride]
  );
  const loadEntries = useCallback(
    (
      prefix: string,
      depth: number,
      snapshotId: string | null,
      view: "raw" | "tree" = "tree"
    ) => listAdminStoreEntries(prefix, depth, snapshotId, adminTokenOverride, view),
    [adminTokenOverride]
  );
  const readValue = useCallback(
    (key: string, snapshotId: string | null, versionId: string | null, previewBytes: number) =>
      getAdminStoreValue(key, snapshotId, versionId, previewBytes, adminTokenOverride),
    [adminTokenOverride]
  );
  const loadVersions = useCallback(
    (key: string) => getAdminVersionGraph(key, adminTokenOverride),
    [adminTokenOverride]
  );

  return (
    <ExplorerSurface
      intro="Browse the node-side object index with the same shared explorer surface used by the client UI. The admin wrapper uses authenticated snapshot, object, and version routes, and it enables rename and delete against current data while leaving upload and folder creation disabled."
      loadSnapshots={loadSnapshots}
      loadEntries={loadEntries}
      readValue={readValue}
      getDownloadUrl={(key, snapshotId, versionId) =>
        getAdminStoreDownloadUrl(key, snapshotId, versionId)
      }
      loadVersions={loadVersions}
      mutations={{
        deletePath: (path) => deleteAdminStorePath(path, adminTokenOverride),
        renamePath: (fromPath, toPath) =>
          renameAdminStorePath(fromPath, toPath, false, adminTokenOverride)
      }}
    />
  );
}
