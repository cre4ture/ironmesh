import {
  Alert,
  Button,
  Card,
  Code,
  Divider,
  Drawer,
  Grid,
  Group,
  NumberInput,
  Select,
  Stack,
  Switch,
  Table,
  Text,
  TextInput,
  UnstyledButton
} from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { JsonBlock } from "../JsonBlock/JsonBlock";
import {
  MediaLightboxModal,
  MediaThumbnailPreview,
  resolveMediaKind,
  type MediaKind,
  type MediaLightboxItem,
  type MediaPreviewRequest
} from "../MediaViewer/MediaViewer";
import {
  normalizeStorePath,
  normalizeStorePrefix,
  parentStorePrefix,
  storeEntryName
} from "../store-paths";

const DEFAULT_EXPLORER_PREVIEW_BYTES = 1024;
const EXPLORER_RENAME_SCAN_DEPTH = 1024;

export type ExplorerSnapshot = {
  id: string;
} & Record<string, unknown>;

export type ExplorerEntry = {
  path: string;
  entry_type: string;
  version?: string | null;
  content_hash?: string | null;
  size_bytes?: number | null;
  modified_at_unix?: number | null;
  content_fingerprint?: string | null;
  media?: Record<string, unknown> | null;
};

export type ExplorerListView = "raw" | "tree";

export type ExplorerListResponse = {
  prefix: string;
  depth: number;
  entry_count: number;
  entries: ExplorerEntry[];
};

export type ExplorerValueResponse = {
  key: string;
  snapshot?: string | null;
  version?: string | null;
  value: string;
  truncated?: boolean;
  total_size_bytes?: number;
  preview_size_bytes?: number | null;
} & Record<string, unknown>;

export type ExplorerVersionEntry = {
  version_id: string;
  entry_type?: string;
  size_bytes?: number | null;
  modified_at_unix?: number | null;
  created_at_unix?: number | null;
  content_fingerprint?: string | null;
  media?: Record<string, unknown> | null;
} & Record<string, unknown>;

export type ExplorerVersionGraph = {
  key?: string;
  preferred_head_version_id?: string | null;
  versions: ExplorerVersionEntry[];
} & Record<string, unknown>;

export type ExplorerMutationConfig = {
  createFolderMarker?: (markerKey: string) => Promise<unknown>;
  deletePath?: (path: string) => Promise<unknown>;
  renamePath?: (fromPath: string, toPath: string) => Promise<unknown>;
  restoreVersion?: (key: string, versionId: string, targetPath: string) => Promise<unknown>;
  restoreSnapshotPath?: (
    snapshotId: string,
    sourcePath: string,
    targetPath: string,
    recursive: boolean
  ) => Promise<unknown>;
};

export type ExplorerQuickUploadConfig = {
  queueFiles: (files: File[], targetPrefix: string) => boolean | void;
  buttonLabel?: string;
  onQueued?: () => void;
};

export type ExplorerSurfaceProps = {
  intro?: string;
  previewBytes?: number;
  loadSnapshots: () => Promise<ExplorerSnapshot[]>;
  loadEntries: (
    prefix: string,
    depth: number,
    snapshotId: string | null,
    view?: ExplorerListView
  ) => Promise<ExplorerListResponse>;
  readValue: (
    key: string,
    snapshotId: string | null,
    versionId: string | null,
    previewBytes: number
  ) => Promise<ExplorerValueResponse | Record<string, unknown>>;
  getDownloadUrl?: (
    key: string,
    snapshotId: string | null,
    versionId?: string | null
  ) => string | null;
  loadVersions?: (key: string) => Promise<ExplorerVersionGraph>;
  mutations?: ExplorerMutationConfig;
  quickUpload?: ExplorerQuickUploadConfig;
  showEntriesPayload?: boolean;
  currentDataHint?: string;
  snapshotHint?: string;
  readOnlyHint?: string;
};

type ExplorerSortField = "path" | "type" | "size" | "modified";
type ExplorerSortDirection = "asc" | "desc";
type ExplorerMediaViewerSource = "browser" | "versions";
type ExplorerMediaViewerState = {
  source: ExplorerMediaViewerSource;
  index: number;
};

export function ExplorerSurface({
  intro,
  previewBytes = DEFAULT_EXPLORER_PREVIEW_BYTES,
  loadSnapshots,
  loadEntries,
  readValue,
  getDownloadUrl,
  loadVersions,
  mutations,
  quickUpload,
  showEntriesPayload = true,
  currentDataHint = "Delete on a prefix removes that whole subtree from current data. Rename on a prefix rewrites each stored path under it, and entering a full target path can move data.",
  snapshotHint = "Restore copies the selected snapshot item into current data. Create, rename, and delete stay disabled while browsing a historical snapshot.",
  readOnlyHint = "This surface is read-only. Use it to browse prefixes, inspect object payloads, and verify version history."
}: ExplorerSurfaceProps) {
  const [prefix, setPrefix] = useState("");
  const [depth, setDepth] = useState(1);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<ExplorerSnapshot[]>([]);
  const [entriesPayload, setEntriesPayload] = useState<ExplorerListResponse | null>(null);
  const [selectedPayload, setSelectedPayload] = useState<unknown>({
    message: "Select an object or version to preview it."
  });
  const [newFolderName, setNewFolderName] = useState("");
  const [versionKey, setVersionKey] = useState("");
  const [versionsPayload, setVersionsPayload] = useState<ExplorerVersionGraph | null>(null);
  const [versionHistoryOpened, setVersionHistoryOpened] = useState(false);
  const [mediaViewerState, setMediaViewerState] = useState<ExplorerMediaViewerState | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sortField, setSortField] = useState<ExplorerSortField>("path");
  const [sortDirection, setSortDirection] = useState<ExplorerSortDirection>("asc");
  const [showThumbnails, setShowThumbnails] = useState(false);
  const quickUploadInputRef = useRef<HTMLInputElement | null>(null);
  const canCreateFolder = snapshotId == null && mutations?.createFolderMarker != null;
  const canDeleteCurrentStore = snapshotId == null && mutations?.deletePath != null;
  const canRenameCurrentStore = snapshotId == null && mutations?.renamePath != null;
  const hasCurrentDataActions =
    snapshotId == null &&
    (canCreateFolder || canDeleteCurrentStore || canRenameCurrentStore || quickUpload != null);
  const canRestoreVersion = snapshotId == null && mutations?.restoreVersion != null;
  const canRestoreSnapshot = snapshotId != null && mutations?.restoreSnapshotPath != null;

  const sortedEntries = useMemo(() => {
    const entries = (entriesPayload?.entries ?? []).filter((entry) =>
      shouldDisplayExplorerEntry(entry, prefix)
    );
    entries.sort((left, right) =>
      compareExplorerEntries(left, right, sortField, sortDirection, prefix)
    );
    return entries;
  }, [entriesPayload, prefix, sortDirection, sortField]);

  useEffect(() => {
    void refreshSnapshots();
    void refreshEntries();
  }, [loadEntries, loadSnapshots]);

  async function refreshSnapshots() {
    setLoading("snapshots");
    setError(null);
    try {
      const payload = await loadSnapshots();
      setSnapshots(payload);
      setSnapshotId((current) =>
        current && payload.some((snapshot) => snapshot.id === current) ? current : null
      );
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed to load snapshots");
    } finally {
      setLoading(null);
    }
  }

  async function refreshEntries(nextPrefix?: string) {
    setLoading("entries");
    setError(null);
    const targetPrefix = nextPrefix ?? prefix;
    try {
      const payload = await loadEntries(targetPrefix.trim(), depth, snapshotId);
      setEntriesPayload(payload);
      if (typeof nextPrefix === "string") {
        setPrefix(nextPrefix);
      }
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed to load store entries");
    } finally {
      setLoading(null);
    }
  }

  async function readEntry(entry: ExplorerEntry) {
    if (entry.entry_type === "prefix" || entry.path.endsWith("/")) {
      await refreshEntries(entry.path);
      return;
    }

    setLoading(`read-entry:${entry.path}`);
    setError(null);
    try {
      const payload = await readValue(entry.path, snapshotId, null, previewBytes);
      setSelectedPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed reading object");
    } finally {
      setLoading(null);
    }
  }

  function downloadEntry(entry: ExplorerEntry) {
    if (entry.entry_type === "prefix" || entry.path.endsWith("/")) {
      return;
    }

    const downloadUrl = getDownloadUrl?.(entry.path, snapshotId, null);
    if (!downloadUrl) {
      return;
    }

    setError(null);
    triggerBrowserDownloadFromUrl(downloadUrl);
  }

  async function restoreEntry(entry: ExplorerEntry) {
    const currentSnapshotId = snapshotId;
    if (!currentSnapshotId || !mutations?.restoreSnapshotPath) {
      setError("Restore is not available on this surface.");
      return;
    }

    const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
    const sourcePath = normalizeExplorerPath(entry.path, isPrefix);
    if (!sourcePath) {
      setError("Path must not be empty.");
      return;
    }

    const requestedTargetPath =
      typeof window === "undefined"
        ? sourcePath
        : window.prompt(
            isPrefix
              ? `Restore snapshot folder "${sourcePath}" into current data at path:`
              : `Restore snapshot object "${sourcePath}" into current data at path:`,
            sourcePath
          );
    if (requestedTargetPath == null) {
      return;
    }

    const targetPath = normalizeExplorerPath(requestedTargetPath, isPrefix);
    if (!targetPath) {
      setError("Target path must not be empty.");
      return;
    }
    if (!isPrefix && targetPath.endsWith("/")) {
      setError("Restore target for an object must not end with '/'.");
      return;
    }

    setLoading(`restore-entry:${sourcePath}`);
    setError(null);
    try {
      const response = await mutations.restoreSnapshotPath(
        currentSnapshotId,
        sourcePath,
        targetPath,
        isPrefix
      );
      setSelectedPayload({
        action: isPrefix ? "restored_snapshot_prefix" : "restored_snapshot_path",
        snapshot: currentSnapshotId,
        source_path: sourcePath,
        target_path: targetPath,
        response
      });
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed restoring snapshot entry");
    } finally {
      setLoading(null);
    }
  }

  async function createFolder() {
    if (!canCreateFolder || !mutations?.createFolderMarker) {
      setError("Folder creation is not available on this surface.");
      return;
    }

    const folderPath = joinExplorerPath(prefix, newFolderName);
    const markerKey = folderMarkerKey(folderPath);
    if (!markerKey) {
      setError("Folder name must not be empty.");
      return;
    }

    setLoading("create-folder");
    setError(null);
    try {
      const payload = await mutations.createFolderMarker(markerKey);
      setNewFolderName("");
      setSelectedPayload({
        action: "created_folder_marker",
        folder_path: normalizeExplorerPath(markerKey, true),
        marker_key: markerKey,
        response: payload
      });
      await refreshEntries();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed creating folder");
    } finally {
      setLoading(null);
    }
  }

  function queueFilesToCurrentPrefix(files: File[]) {
    if (snapshotId != null) {
      setError("Switch Snapshot to Current data before uploading files.");
      return;
    }
    if (!quickUpload) {
      setError("Quick upload is not available on this surface.");
      return;
    }
    if (files.length === 0) {
      return;
    }

    setError(null);
    const targetPrefix = normalizeExplorerPrefix(prefix);
    const queued = quickUpload.queueFiles(files, targetPrefix);
    if (queued === false) {
      return;
    }
    quickUpload.onQueued?.();
  }

  function openQuickUploadPicker() {
    if (snapshotId != null) {
      setError("Switch Snapshot to Current data before uploading files.");
      return;
    }
    if (!quickUpload) {
      setError("Quick upload is not available on this surface.");
      return;
    }

    quickUploadInputRef.current?.click();
  }

  async function deleteEntry(entry: ExplorerEntry) {
    if (!canDeleteCurrentStore || !mutations?.deletePath) {
      setError("Delete is not available on this surface.");
      return;
    }

    const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
    const targetKey = isPrefix
      ? normalizeExplorerPath(entry.path, true)
      : normalizeExplorerPath(entry.path, false);
    if (!targetKey) {
      setError("Path must not be empty.");
      return;
    }

    const confirmed =
      typeof window === "undefined" ||
      window.confirm(
        isPrefix
          ? `Delete "${targetKey}" and everything under it from current data?`
          : `Delete "${targetKey}" from current data?`
      );
    if (!confirmed) {
      return;
    }

    setLoading(`delete-entry:${targetKey}`);
    setError(null);
    try {
      const payload = await mutations.deletePath(targetKey);
      setSelectedPayload({
        action: "deleted_path",
        path: targetKey,
        recursive: isPrefix,
        response: payload
      });
      await refreshEntries();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed deleting entry");
    } finally {
      setLoading(null);
    }
  }

  async function renamePrefixSubtree(fromPath: string, toPath: string): Promise<number> {
    const sourcePayload = await loadEntries(fromPath, EXPLORER_RENAME_SCAN_DEPTH, null, "raw");
    const concreteSourcePaths = sourcePayload.entries
      .filter((candidate) => candidate.entry_type !== "prefix")
      .map((candidate) => normalizeExplorerPath(candidate.path, candidate.path.endsWith("/")))
      .filter((candidatePath) => candidatePath === fromPath || candidatePath.startsWith(fromPath))
      .sort((left, right) => left.length - right.length);
    if (concreteSourcePaths.length === 0) {
      throw new Error(`No stored objects were found under "${fromPath}" to rename.`);
    }

    const targetPayload = await loadEntries(toPath, EXPLORER_RENAME_SCAN_DEPTH, null, "raw");
    const blockingTargetPaths = targetPayload.entries
      .filter((candidate) => candidate.entry_type !== "prefix")
      .map((candidate) => normalizeExplorerPath(candidate.path, candidate.path.endsWith("/")))
      .filter((candidatePath) => candidatePath === toPath || candidatePath.startsWith(toPath));
    if (blockingTargetPaths.length > 0) {
      throw new Error(`Target prefix "${toPath}" already contains data.`);
    }

    for (const candidatePath of concreteSourcePaths) {
      const suffix = candidatePath.slice(fromPath.length);
      await mutations!.renamePath!(candidatePath, suffix ? `${toPath}${suffix}` : toPath);
    }
    return concreteSourcePaths.length;
  }

  async function renameEntry(entry: ExplorerEntry) {
    if (!canRenameCurrentStore || !mutations?.renamePath) {
      setError("Rename is not available on this surface.");
      return;
    }

    const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
    const fromPath = normalizeExplorerPath(entry.path, isPrefix);
    if (!fromPath) {
      setError("Path must not be empty.");
      return;
    }

    const currentName = explorerEntryName(entry.path, isPrefix);
    const requestedTarget =
      typeof window === "undefined"
        ? currentName
        : window.prompt(
            isPrefix
              ? `Rename or move folder "${currentName}". Use a full path to move it:`
              : `Rename or move "${currentName}". Use a full path to move it:`,
            currentName
          );
    if (requestedTarget == null) {
      return;
    }

    const requestedTargetPath = requestedTarget.trim();
    const targetParent = parentPrefix(fromPath);
    const toPath = requestedTargetPath.includes("/")
      ? normalizeExplorerPath(requestedTargetPath, isPrefix)
      : isPrefix
        ? folderMarkerKey(joinExplorerPath(targetParent, requestedTargetPath))
        : joinExplorerPath(targetParent, requestedTargetPath);
    if (!toPath) {
      setError("Target path must not be empty.");
      return;
    }
    if (!isPrefix && toPath.endsWith("/")) {
      setError("Target path for an object must not end with '/'.");
      return;
    }
    if (toPath === fromPath) {
      return;
    }

    const confirmed =
      !isPrefix ||
      typeof window === "undefined" ||
      window.confirm(
        `Rename or move "${fromPath}" to "${toPath}"? This rewrites each stored path under that prefix.`
      );
    if (!confirmed) {
      return;
    }

    setLoading(`rename-entry:${fromPath}`);
    setError(null);
    try {
      if (isPrefix) {
        const renamedCount = await renamePrefixSubtree(fromPath, toPath);
        setSelectedPayload({
          action: "renamed_prefix",
          from_path: fromPath,
          to_path: toPath,
          renamed_count: renamedCount
        });
      } else {
        const response = await mutations.renamePath(fromPath, toPath);
        setSelectedPayload({
          action: "renamed_path",
          from_path: fromPath,
          to_path: toPath,
          renamed_count: 1,
          response
        });
      }
      await refreshEntries();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed renaming entry");
    } finally {
      setLoading(null);
    }
  }

  async function loadVersionGraph(nextKey?: string) {
    if (!loadVersions) {
      setError("Version history is not available on this surface.");
      return;
    }
    const targetKey = (nextKey ?? versionKey).trim();
    if (!targetKey) {
      setError("Enter a key to load version history.");
      return;
    }

    setLoading("versions");
    setError(null);
    setVersionKey(targetKey);
    try {
      const payload = await loadVersions(targetKey);
      setVersionsPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading versions");
    } finally {
      setLoading(null);
    }
  }

  async function openVersionHistoryDrawer(targetKey: string) {
    const normalizedTargetKey = targetKey.trim();
    if (!normalizedTargetKey) {
      setError("Path must not be empty.");
      return;
    }

    setVersionHistoryOpened(true);
    await loadVersionGraph(normalizedTargetKey);
  }

  async function showEntryHistory(entry: ExplorerEntry) {
    if (!loadVersions) {
      setError("Version history is not available on this surface.");
      return;
    }

    const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
    const targetKey = normalizeExplorerPath(entry.path, isPrefix);
    if (!targetKey) {
      setError("Path must not be empty.");
      return;
    }

    await openVersionHistoryDrawer(targetKey);
  }

  async function readVersion(versionId: string) {
    if (!versionKey.trim()) {
      setError("Enter a key before reading a version.");
      return;
    }

    setLoading("read-version");
    setError(null);
    try {
      const payload = await readValue(versionKey.trim(), null, versionId, previewBytes);
      setSelectedPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed reading version");
    } finally {
      setLoading(null);
    }
  }

  async function restoreVersion(version: ExplorerVersionEntry) {
    const sourceKey = (versionsPayload?.key ?? versionKey).trim();
    if (!canRestoreVersion || !mutations?.restoreVersion) {
      setError("Version restore is not available on this surface.");
      return;
    }
    if (!sourceKey) {
      setError("Enter a key before restoring a version.");
      return;
    }

    const requestedTargetPath =
      typeof window === "undefined"
        ? sourceKey
        : window.prompt(
            `Restore version "${version.version_id}" into current data at path:`,
            sourceKey
          );
    if (requestedTargetPath == null) {
      return;
    }

    const targetPath = normalizeExplorerPath(requestedTargetPath, false);
    if (!targetPath) {
      setError("Target path must not be empty.");
      return;
    }
    if (targetPath.endsWith("/")) {
      setError("Target path for a version restore must not end with '/'.");
      return;
    }

    setLoading(`restore-version:${version.version_id}`);
    setError(null);
    try {
      const response = await mutations.restoreVersion(sourceKey, version.version_id, targetPath);
      setSelectedPayload({
        action: "restored_version",
        key: sourceKey,
        version_id: version.version_id,
        target_path: targetPath,
        response
      });
      await refreshEntries();
      await loadVersionGraph(sourceKey);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed restoring version");
    } finally {
      setLoading(null);
    }
  }

  function toggleSort(field: ExplorerSortField) {
    if (sortField === field) {
      setSortDirection((current) => (current === "asc" ? "desc" : "asc"));
      return;
    }
    setSortField(field);
    setSortDirection(field === "size" || field === "modified" ? "desc" : "asc");
  }

  const helperText = snapshotId
    ? canRestoreSnapshot
      ? snapshotHint
      : readOnlyHint
    : hasCurrentDataActions
      ? currentDataHint
      : readOnlyHint;
  const currentVersionId = versionsPayload?.preferred_head_version_id?.trim() || null;
  const versionEntries = versionsPayload?.versions ?? [];
  const versionSourceKey = (versionsPayload?.key ?? versionKey).trim();
  const browserMediaItems = useMemo(
    () =>
      sortedEntries.flatMap((entry) => {
        const item = buildExplorerEntryLightboxItem(entry, snapshotId, getDownloadUrl);
        return item ? [item] : [];
      }),
    [getDownloadUrl, snapshotId, sortedEntries]
  );
  const browserMediaIndexByPath = useMemo(
    () => new Map(browserMediaItems.map((item, index) => [item.key, index] as const)),
    [browserMediaItems]
  );
  const versionMediaItems = useMemo(
    () =>
      versionEntries.flatMap((version) => {
        const item = buildExplorerVersionLightboxItem(version, versionSourceKey, getDownloadUrl);
        return item ? [item] : [];
      }),
    [getDownloadUrl, versionEntries, versionSourceKey]
  );
  const versionMediaIndexById = useMemo(
    () => new Map(versionMediaItems.map((item, index) => [item.key, index] as const)),
    [versionMediaItems]
  );
  const activeMediaItems = mediaViewerState?.source === "versions" ? versionMediaItems : browserMediaItems;
  const activeMediaItem = mediaViewerState ? activeMediaItems[mediaViewerState.index] ?? null : null;
  const activeMediaHistoryKey =
    mediaViewerState?.source === "versions"
      ? versionSourceKey || null
      : mediaViewerState?.source === "browser" && activeMediaItem
        ? normalizeExplorerPath(activeMediaItem.key, false)
        : null;

  useEffect(() => {
    if (mediaViewerState && !activeMediaItem) {
      setMediaViewerState(null);
    }
  }, [activeMediaItem, mediaViewerState]);

  function openBrowserMediaViewer(path: string) {
    const mediaIndex = browserMediaIndexByPath.get(path);
    if (typeof mediaIndex === "number") {
      setMediaViewerState({ source: "browser", index: mediaIndex });
    }
  }

  function openVersionMediaViewer(versionId: string) {
    const mediaIndex = versionMediaIndexById.get(versionId);
    if (typeof mediaIndex === "number") {
      setMediaViewerState({ source: "versions", index: mediaIndex });
    }
  }

  return (
    <>
      <Stack gap="lg">
      {intro ? (
        <Text c="dimmed" size="sm">
          {intro}
        </Text>
      ) : null}

      {error ? <Alert color="red">{error}</Alert> : null}

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Group justify="space-between" align="flex-start">
            <Text fw={700}>Object browser</Text>
            <Group gap="sm">
              {loadVersions ? (
                <Button variant="default" onClick={() => setVersionHistoryOpened(true)}>
                  Version history
                </Button>
              ) : null}
              <Button
                variant="default"
                loading={loading === "snapshots"}
                onClick={() => void refreshSnapshots()}
              >
                Refresh snapshots
              </Button>
              <Button
                leftSection={<IconRefresh size={16} />}
                loading={loading === "entries"}
                onClick={() => void refreshEntries()}
              >
                Refresh entries
              </Button>
            </Group>
          </Group>
          <Grid>
            <Grid.Col span={{ base: 12, md: 6 }}>
              <TextInput
                label="Prefix"
                value={prefix}
                onChange={(event) => setPrefix(event.currentTarget.value)}
                placeholder="docs/"
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, md: 3 }}>
              <NumberInput
                label="Depth"
                min={1}
                value={depth}
                onChange={(value) => setDepth(typeof value === "number" && value > 0 ? value : 1)}
              />
            </Grid.Col>
            <Grid.Col span={{ base: 12, md: 3 }}>
              <Select
                label="Snapshot"
                data={[
                  { value: "", label: "Current data" },
                  ...snapshots.map((snapshot) => ({
                    value: snapshot.id,
                    label: snapshot.id
                  }))
                ]}
                value={snapshotId ?? ""}
                onChange={(value) => setSnapshotId(value || null)}
              />
            </Grid.Col>
          </Grid>
          <Group justify="space-between" align="center">
            <Group gap="sm">
              <Button onClick={() => void refreshEntries()}>Load entries</Button>
              <Button variant="default" onClick={() => void refreshEntries(parentPrefix(prefix))}>
                Up one prefix
              </Button>
              <Button variant="subtle" onClick={() => void refreshEntries("")}>
                Root
              </Button>
            </Group>
            <Switch
              label="Show thumbnails"
              checked={showThumbnails}
              onChange={(event) => setShowThumbnails(event.currentTarget.checked)}
            />
          </Group>
          {canCreateFolder || quickUpload ? (
            <Grid>
              <Grid.Col span={{ base: 12, md: 8 }}>
                <TextInput
                  label="New folder name"
                  value={newFolderName}
                  onChange={(event) => setNewFolderName(event.currentTarget.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      if (canCreateFolder) {
                        void createFolder();
                      }
                    }
                  }}
                  placeholder="new-folder"
                  disabled={!canCreateFolder}
                />
              </Grid.Col>
              <Grid.Col span={{ base: 12, md: 4 }}>
                <Group grow wrap="nowrap" mt="xl">
                  {canCreateFolder ? (
                    <Button
                      loading={loading === "create-folder"}
                      disabled={!canCreateFolder}
                      onClick={() => void createFolder()}
                    >
                      New folder
                    </Button>
                  ) : null}
                  {quickUpload ? (
                    <Button
                      size="sm"
                      variant="default"
                      disabled={snapshotId != null}
                      onClick={openQuickUploadPicker}
                    >
                      {quickUpload.buttonLabel ?? "Upload"}
                    </Button>
                  ) : null}
                </Group>
                {quickUpload ? (
                  <input
                    ref={quickUploadInputRef}
                    type="file"
                    multiple
                    hidden
                    data-explorer-upload-input="true"
                    onChange={(event) => {
                      const files = Array.from(event.currentTarget.files ?? []);
                      event.currentTarget.value = "";
                      queueFilesToCurrentPrefix(files);
                    }}
                  />
                ) : null}
              </Grid.Col>
            </Grid>
          ) : null}
          <Text c="dimmed" size="sm">
            {helperText}
          </Text>
          <Table.ScrollContainer minWidth={720}>
            <Table striped highlightOnHover withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  {showThumbnails ? <Table.Th>Thumb</Table.Th> : null}
                  <Table.Th>
                    {renderExplorerHeader("Path", "path", sortField, sortDirection, toggleSort)}
                  </Table.Th>
                  <Table.Th>
                    {renderExplorerHeader("Type", "type", sortField, sortDirection, toggleSort)}
                  </Table.Th>
                  <Table.Th>
                    {renderExplorerHeader("Size", "size", sortField, sortDirection, toggleSort)}
                  </Table.Th>
                  <Table.Th>
                    {renderExplorerHeader(
                      "Modified",
                      "modified",
                      sortField,
                      sortDirection,
                      toggleSort
                    )}
                  </Table.Th>
                  <Table.Th>Action</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sortedEntries.map((entry) => {
                  const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
                  const displayPath = explorerDisplayPath(entry, prefix);
                  const historyTargetKey = normalizeExplorerPath(entry.path, isPrefix);
                  const browserMediaIndex = isPrefix ? null : browserMediaIndexByPath.get(entry.path) ?? null;
                  const browserMediaItem =
                    browserMediaIndex === null ? null : browserMediaItems[browserMediaIndex] ?? null;
                  return (
                    <Table.Tr key={entry.path}>
                      {showThumbnails ? (
                        <Table.Td>
                          <ExplorerThumbnailCell
                            item={browserMediaItem}
                            label={`Thumbnail for ${displayPath}`}
                            onClick={
                              browserMediaIndex === null
                                ? undefined
                                : () => openBrowserMediaViewer(entry.path)
                            }
                          />
                        </Table.Td>
                      ) : null}
                      <Table.Td>
                        <Code>{displayPath}</Code>
                      </Table.Td>
                      <Table.Td>{isPrefix ? "prefix" : entry.entry_type}</Table.Td>
                      <Table.Td>{formatExplorerSize(isPrefix ? null : entry.size_bytes)}</Table.Td>
                      <Table.Td>{formatExplorerModifiedAt(entry.modified_at_unix)}</Table.Td>
                      <Table.Td>
                        {isPrefix ? (
                          <Group gap="xs" wrap="nowrap">
                            <Button size="xs" variant="light" onClick={() => void readEntry(entry)}>
                              Open
                            </Button>
                            {loadVersions ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === "versions" && versionKey === historyTargetKey}
                                onClick={() => void showEntryHistory(entry)}
                              >
                                History
                              </Button>
                            ) : null}
                            {canRestoreSnapshot ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === `restore-entry:${normalizeExplorerPath(entry.path, true)}`}
                                onClick={() => void restoreEntry(entry)}
                              >
                                Restore...
                              </Button>
                            ) : null}
                            {canRenameCurrentStore ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === `rename-entry:${normalizeExplorerPath(entry.path, true)}`}
                                onClick={() => void renameEntry(entry)}
                              >
                                Rename
                              </Button>
                            ) : null}
                            {canDeleteCurrentStore ? (
                              <Button
                                size="xs"
                                color="red"
                                variant="default"
                                loading={loading === `delete-entry:${normalizeExplorerPath(entry.path, true)}`}
                                onClick={() => void deleteEntry(entry)}
                              >
                                Delete
                              </Button>
                            ) : null}
                          </Group>
                        ) : (
                          <Group gap="xs" wrap="nowrap">
                            <Button
                              size="xs"
                              variant="light"
                              loading={loading === `read-entry:${entry.path}`}
                              onClick={() => void readEntry(entry)}
                            >
                              Read
                            </Button>
                            {getDownloadUrl ? (
                              <Button size="xs" variant="default" onClick={() => downloadEntry(entry)}>
                                Download
                              </Button>
                            ) : null}
                            {loadVersions ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === "versions" && versionKey === historyTargetKey}
                                onClick={() => void showEntryHistory(entry)}
                              >
                                History
                              </Button>
                            ) : null}
                            {canRestoreSnapshot ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === `restore-entry:${normalizeExplorerPath(entry.path, false)}`}
                                onClick={() => void restoreEntry(entry)}
                              >
                                Restore...
                              </Button>
                            ) : null}
                            {canRenameCurrentStore ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === `rename-entry:${normalizeExplorerPath(entry.path, false)}`}
                                onClick={() => void renameEntry(entry)}
                              >
                                Rename
                              </Button>
                            ) : null}
                            {canDeleteCurrentStore ? (
                              <Button
                                size="xs"
                                color="red"
                                variant="default"
                                loading={loading === `delete-entry:${normalizeExplorerPath(entry.path, false)}`}
                                onClick={() => void deleteEntry(entry)}
                              >
                                Delete
                              </Button>
                            ) : null}
                          </Group>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
          {showEntriesPayload && entriesPayload ? <JsonBlock value={entriesPayload} /> : null}
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>Selected payload</Text>
          <JsonBlock value={selectedPayload} />
        </Stack>
      </Card>
      </Stack>

      {loadVersions ? (
        <Drawer
          opened={versionHistoryOpened}
          onClose={() => setVersionHistoryOpened(false)}
          position="right"
          title="Version history"
          size="xl"
          zIndex={400}
        >
          <Stack gap="sm">
            <TextInput
              label="Key"
              value={versionKey}
              onChange={(event) => setVersionKey(event.currentTarget.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  void loadVersionGraph();
                }
              }}
              placeholder="docs/readme.txt"
            />
            <Button loading={loading === "versions"} onClick={() => void loadVersionGraph()}>
              Load versions
            </Button>
            <Table.ScrollContainer minWidth={720}>
              <Table striped highlightOnHover withTableBorder>
                <Table.Thead>
                  <Table.Tr>
                    {showThumbnails ? <Table.Th>Thumb</Table.Th> : null}
                    <Table.Th>Version ID</Table.Th>
                    <Table.Th>Type</Table.Th>
                    <Table.Th>Size</Table.Th>
                    <Table.Th>Modified</Table.Th>
                    <Table.Th>Action</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {versionEntries.map((version) => {
                    const versionMediaIndex = versionMediaIndexById.get(version.version_id) ?? null;
                    const versionMediaItem =
                      versionMediaIndex === null ? null : versionMediaItems[versionMediaIndex] ?? null;

                    return (
                      <Table.Tr key={version.version_id}>
                        {showThumbnails ? (
                          <Table.Td>
                            <ExplorerThumbnailCell
                              item={versionMediaItem}
                              label={`Thumbnail for version ${version.version_id}`}
                              onClick={
                                versionMediaIndex === null
                                  ? undefined
                                  : () => openVersionMediaViewer(version.version_id)
                              }
                            />
                          </Table.Td>
                        ) : null}
                        <Table.Td>
                          <Code>{version.version_id}</Code>
                        </Table.Td>
                        <Table.Td>{normalizeExplorerVersionType(version)}</Table.Td>
                        <Table.Td>{formatExplorerSize(version.size_bytes)}</Table.Td>
                        <Table.Td>
                          {formatExplorerModifiedAt(version.modified_at_unix ?? version.created_at_unix)}
                        </Table.Td>
                        <Table.Td>
                          <Group gap="xs" wrap="nowrap">
                            <Button size="xs" variant="light" onClick={() => void readVersion(version.version_id)}>
                              Read
                            </Button>
                            {canRestoreVersion &&
                            currentVersionId != null &&
                            version.version_id !== currentVersionId ? (
                              <Button
                                size="xs"
                                variant="default"
                                loading={loading === `restore-version:${version.version_id}`}
                                onClick={() => void restoreVersion(version)}
                              >
                                Restore
                              </Button>
                            ) : null}
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
            <Divider />
            <JsonBlock value={versionsPayload ?? { message: "No version graph loaded yet." }} />
          </Stack>
        </Drawer>
      ) : null}

      <MediaLightboxModal
        opened={activeMediaItem !== null}
        onClose={() => setMediaViewerState(null)}
        itemCount={activeMediaItems.length}
        selectedIndex={mediaViewerState?.index ?? -1}
        selectedItem={activeMediaItem}
        getItemAtIndex={(index) => activeMediaItems[index] ?? null}
        onSelectIndex={(index) => {
          setMediaViewerState((current) =>
            current
              ? {
                  ...current,
                  index
                }
              : current
          );
        }}
        extraActions={
          loadVersions && activeMediaHistoryKey ? (
            <Button
              variant="default"
              size="xs"
              onClick={() => void openVersionHistoryDrawer(activeMediaHistoryKey)}
            >
              Version history
            </Button>
          ) : null
        }
      />
    </>
  );
}

function renderExplorerHeader(
  label: string,
  field: ExplorerSortField,
  activeField: ExplorerSortField,
  direction: ExplorerSortDirection,
  onToggle: (field: ExplorerSortField) => void
) {
  const indicator = activeField === field ? (direction === "asc" ? "↑" : "↓") : "↕";

  return (
    <UnstyledButton onClick={() => onToggle(field)}>
      <Group gap={6} wrap="nowrap">
        <Text fw={600} size="sm">
          {label}
        </Text>
        <Text c="dimmed" size="xs">
          {indicator}
        </Text>
      </Group>
    </UnstyledButton>
  );
}

function compareExplorerEntries(
  left: ExplorerEntry,
  right: ExplorerEntry,
  field: ExplorerSortField,
  direction: ExplorerSortDirection,
  prefix: string
): number {
  const leftIsPrefix = left.entry_type === "prefix" || left.path.endsWith("/");
  const rightIsPrefix = right.entry_type === "prefix" || right.path.endsWith("/");
  const leftDisplayPath = explorerDisplayPath(left, prefix);
  const rightDisplayPath = explorerDisplayPath(right, prefix);

  let result = 0;
  switch (field) {
    case "path":
      result = leftDisplayPath.localeCompare(rightDisplayPath);
      break;
    case "type":
      result = normalizeExplorerType(left).localeCompare(normalizeExplorerType(right));
      if (result === 0) {
        result = leftDisplayPath.localeCompare(rightDisplayPath);
      }
      break;
    case "size":
      result = compareNullableNumbers(
        leftIsPrefix ? null : left.size_bytes,
        rightIsPrefix ? null : right.size_bytes,
        direction
      );
      if (result === 0) {
        result = leftDisplayPath.localeCompare(rightDisplayPath);
      }
      break;
    case "modified":
      result = compareNullableNumbers(left.modified_at_unix, right.modified_at_unix, direction);
      if (result === 0) {
        result = leftDisplayPath.localeCompare(rightDisplayPath);
      }
      break;
  }

  return field === "size" || field === "modified"
    ? result
    : direction === "asc"
      ? result
      : -result;
}

function shouldDisplayExplorerEntry(entry: ExplorerEntry, prefix: string): boolean {
  const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
  const normalizedPrefix = normalizeExplorerPrefix(prefix);
  if (!normalizedPrefix) {
    return true;
  }

  const normalizedPath = normalizeExplorerPath(entry.path, isPrefix);
  if (!normalizedPath) {
    return false;
  }
  if (normalizedPath === normalizedPrefix) {
    return false;
  }
  if (isPrefix && normalizedPrefix.startsWith(normalizedPath)) {
    return false;
  }
  if (!normalizedPath.startsWith(normalizedPrefix)) {
    return false;
  }

  return normalizedPath.slice(normalizedPrefix.length).length > 0;
}

function explorerDisplayPath(entry: ExplorerEntry, prefix: string): string {
  const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
  const normalizedPrefix = normalizeExplorerPrefix(prefix);
  const normalizedPath = normalizeExplorerPath(entry.path, isPrefix);

  if (!normalizedPrefix || !normalizedPath.startsWith(normalizedPrefix)) {
    return normalizedPath || entry.path;
  }

  const relativePath = normalizedPath.slice(normalizedPrefix.length);
  return relativePath || normalizedPath;
}

function explorerEntryName(path: string, isPrefix: boolean): string {
  return storeEntryName(path, isPrefix);
}

function normalizeExplorerPrefix(prefix: string): string {
  return normalizeStorePrefix(prefix);
}

function normalizeExplorerPath(path: string, isPrefix: boolean): string {
  return normalizeStorePath(path, isPrefix);
}

function compareNullableNumbers(
  left: number | null | undefined,
  right: number | null | undefined,
  direction: ExplorerSortDirection
): number {
  if (left == null && right == null) {
    return 0;
  }
  if (left == null) {
    return 1;
  }
  if (right == null) {
    return -1;
  }
  return direction === "asc" ? left - right : right - left;
}

function normalizeExplorerType(entry: ExplorerEntry): string {
  return entry.entry_type === "prefix" || entry.path.endsWith("/") ? "prefix" : entry.entry_type;
}

function normalizeExplorerVersionType(version: ExplorerVersionEntry): string {
  if (typeof version.entry_type === "string" && version.entry_type.trim()) {
    return version.entry_type.trim();
  }
  return "key";
}

function formatExplorerModifiedAt(value: number | null | undefined): string {
  if (!value) {
    return "—";
  }
  return new Date(value * 1000).toLocaleString();
}

function formatExplorerSize(value: number | null | undefined): string {
  if (value === null || value === undefined) {
    return "—";
  }
  if (value < 1024) {
    return `${value} B`;
  }

  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const rounded = size >= 10 ? size.toFixed(0) : size.toFixed(1);
  return `${rounded} ${units[unitIndex]}`;
}

function thumbnailUrlForExplorerMedia(media: Record<string, unknown> | null | undefined): string | null {
  if (!media || typeof media !== "object") {
    return null;
  }

  const thumbnail = media.thumbnail;
  if (!thumbnail || typeof thumbnail !== "object") {
    return null;
  }

  const url = (thumbnail as Record<string, unknown>).url;
  return typeof url === "string" && url.trim() ? url : null;
}

function ExplorerThumbnailCell({
  item,
  label,
  onClick
}: {
  item: MediaLightboxItem | null;
  label: string;
  onClick?: () => void;
}) {
  const content = item ? (
    <MediaThumbnailPreview
      kind={item.kind}
      request={item.requests.thumbnail ?? null}
      alt={label}
      missingThumbnailInfo={item.missingThumbnailInfo}
    />
  ) : (
    <Text size="xs" c="dimmed">
      —
    </Text>
  );

  const sharedStyle = {
    width: 52,
    height: 52,
    borderRadius: 8,
    overflow: "hidden",
    background: "var(--mantine-color-gray-0)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center"
  } as const;

  if (!item || !onClick) {
    return <div style={sharedStyle}>{content}</div>;
  }

  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      style={{
        ...sharedStyle,
        padding: 0,
        border: 0,
        cursor: "pointer"
      }}
    >
      {content}
    </button>
  );
}

function buildExplorerEntryLightboxItem(
  entry: ExplorerEntry,
  snapshotId: string | null,
  getDownloadUrl:
    | ((key: string, snapshotId: string | null, versionId?: string | null) => string | null)
    | undefined
): MediaLightboxItem | null {
  if (!getDownloadUrl || entry.entry_type === "prefix" || entry.path.endsWith("/")) {
    return null;
  }

  const kind = explorerMediaKind(entry.path, entry.media);
  if (!kind) {
    return null;
  }

  const originalUrl = getDownloadUrl(entry.path, snapshotId, null);
  if (!originalUrl) {
    return null;
  }

  return {
    key: entry.path,
    title: storeEntryName(entry.path, false),
    description: entry.path,
    alt: entry.path,
    kind,
    requests: {
      thumbnail: thumbnailRequestForExplorerMedia(entry.media),
      original: { url: originalUrl }
    },
    status: explorerMediaString(entry.media, "status"),
    mimeType: explorerMediaString(entry.media, "mime_type"),
    width: explorerMediaNumber(entry.media, "width"),
    height: explorerMediaNumber(entry.media, "height"),
    takenAtUnix: explorerMediaNumber(entry.media, "taken_at_unix")
  };
}

function buildExplorerVersionLightboxItem(
  version: ExplorerVersionEntry,
  sourceKey: string,
  getDownloadUrl:
    | ((key: string, snapshotId: string | null, versionId?: string | null) => string | null)
    | undefined
): MediaLightboxItem | null {
  if (!getDownloadUrl || !sourceKey) {
    return null;
  }

  const kind = explorerMediaKind(sourceKey, version.media);
  if (!kind) {
    return null;
  }

  const originalUrl = getDownloadUrl(sourceKey, null, version.version_id);
  if (!originalUrl) {
    return null;
  }

  return {
    key: version.version_id,
    title: version.version_id,
    description: sourceKey,
    alt: `${sourceKey} ${version.version_id}`,
    kind,
    requests: {
      thumbnail: thumbnailRequestForExplorerMedia(version.media),
      original: { url: originalUrl }
    },
    status: explorerMediaString(version.media, "status"),
    mimeType: explorerMediaString(version.media, "mime_type"),
    width: explorerMediaNumber(version.media, "width"),
    height: explorerMediaNumber(version.media, "height"),
    takenAtUnix: version.modified_at_unix ?? version.created_at_unix ?? null
  };
}

function thumbnailRequestForExplorerMedia(
  media: Record<string, unknown> | null | undefined
): MediaPreviewRequest | null {
  const url = thumbnailUrlForExplorerMedia(media);
  return url ? { url } : null;
}

function explorerMediaKind(
  path: string,
  media: Record<string, unknown> | null | undefined
): MediaKind | null {
  return resolveMediaKind(
    path,
    explorerMediaString(media, "media_type"),
    explorerMediaString(media, "mime_type")
  );
}

function explorerMediaString(
  media: Record<string, unknown> | null | undefined,
  key: string
): string | null {
  if (!media || typeof media !== "object") {
    return null;
  }

  const value = media[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function explorerMediaNumber(
  media: Record<string, unknown> | null | undefined,
  key: string
): number | null {
  if (!media || typeof media !== "object") {
    return null;
  }

  const value = media[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function parentPrefix(path: string): string {
  return parentStorePrefix(path);
}

function normalizeExplorerSegments(path: string): string {
  return path
    .split("/")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join("/");
}

function joinExplorerPath(basePath: string, childPath: string): string {
  const base = normalizeExplorerSegments(basePath);
  const child = normalizeExplorerSegments(childPath);
  if (!base) {
    return child;
  }
  if (!child) {
    return base;
  }
  return `${base}/${child}`;
}

function folderMarkerKey(path: string): string {
  const normalized = normalizeExplorerSegments(path);
  return normalized ? `${normalized}/` : "";
}

function triggerBrowserDownloadFromUrl(url: string) {
  const anchor = document.createElement("a");
  anchor.href = url;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}
