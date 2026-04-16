import {
  Alert,
  Button,
  Card,
  Code,
  Divider,
  Grid,
  Group,
  NumberInput,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  UnstyledButton
} from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { JsonBlock } from "../JsonBlock/JsonBlock";
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

export type ExplorerVersionGraph = {
  key?: string;
  versions: Array<{
    version_id: string;
  } & Record<string, unknown>>;
} & Record<string, unknown>;

export type ExplorerMutationConfig = {
  createFolderMarker?: (markerKey: string) => Promise<unknown>;
  deletePath?: (path: string) => Promise<unknown>;
  renamePath?: (fromPath: string, toPath: string) => Promise<unknown>;
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
  currentDataHint = "Delete on a prefix removes that whole subtree from current data. Rename on a prefix rewrites each stored path under it.",
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
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sortField, setSortField] = useState<ExplorerSortField>("path");
  const [sortDirection, setSortDirection] = useState<ExplorerSortDirection>("asc");
  const quickUploadInputRef = useRef<HTMLInputElement | null>(null);
  const canCreateFolder = snapshotId == null && mutations?.createFolderMarker != null;
  const canDeleteCurrentStore = snapshotId == null && mutations?.deletePath != null;
  const canRenameCurrentStore = snapshotId == null && mutations?.renamePath != null;
  const hasCurrentDataActions =
    snapshotId == null &&
    (canCreateFolder || canDeleteCurrentStore || canRenameCurrentStore || quickUpload != null);
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
    const requestedName =
      typeof window === "undefined"
        ? currentName
        : window.prompt(
            isPrefix ? `Rename folder "${currentName}" to:` : `Rename "${currentName}" to:`,
            currentName
          );
    if (requestedName == null) {
      return;
    }

    const nextName = normalizeExplorerSegments(requestedName);
    if (!nextName) {
      setError("Name must not be empty.");
      return;
    }
    if (nextName.includes("/")) {
      setError("Rename expects a single new name, not a full path.");
      return;
    }

    const targetParent = parentPrefix(fromPath);
    const toPath = isPrefix
      ? folderMarkerKey(joinExplorerPath(targetParent, nextName))
      : joinExplorerPath(targetParent, nextName);
    if (!toPath) {
      setError("Name must not be empty.");
      return;
    }
    if (toPath === fromPath) {
      return;
    }

    const confirmed =
      !isPrefix ||
      typeof window === "undefined" ||
      window.confirm(
        `Rename "${fromPath}" to "${toPath}"? This rewrites each stored path under that prefix.`
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

  async function loadVersionGraph() {
    if (!loadVersions) {
      setError("Version history is not available on this surface.");
      return;
    }
    if (!versionKey.trim()) {
      setError("Enter a key to load version history.");
      return;
    }

    setLoading("versions");
    setError(null);
    try {
      const payload = await loadVersions(versionKey.trim());
      setVersionsPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading versions");
    } finally {
      setLoading(null);
    }
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

  return (
    <Stack gap="lg">
      {intro ? (
        <Text c="dimmed" size="sm">
          {intro}
        </Text>
      ) : null}

      {error ? <Alert color="red">{error}</Alert> : null}

      <Grid>
        <Grid.Col span={{ base: 12, xl: 7 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Group justify="space-between" align="flex-start">
                <Text fw={700}>Object browser</Text>
                <Group gap="sm">
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
                    onChange={(value) =>
                      setDepth(typeof value === "number" && value > 0 ? value : 1)
                    }
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
              <Group gap="sm">
                <Button onClick={() => void refreshEntries()}>Load entries</Button>
                <Button variant="default" onClick={() => void refreshEntries(parentPrefix(prefix))}>
                  Up one prefix
                </Button>
                <Button variant="subtle" onClick={() => void refreshEntries("")}>
                  Root
                </Button>
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
                      return (
                        <Table.Tr key={entry.path}>
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
                                {canRestoreSnapshot ? (
                                  <Button
                                    size="xs"
                                    variant="default"
                                    loading={
                                      loading ===
                                      `restore-entry:${normalizeExplorerPath(entry.path, true)}`
                                    }
                                    onClick={() => void restoreEntry(entry)}
                                  >
                                    Restore...
                                  </Button>
                                ) : null}
                                {canRenameCurrentStore ? (
                                  <Button
                                    size="xs"
                                    variant="default"
                                    loading={
                                      loading ===
                                      `rename-entry:${normalizeExplorerPath(entry.path, true)}`
                                    }
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
                                    loading={
                                      loading ===
                                      `delete-entry:${normalizeExplorerPath(entry.path, true)}`
                                    }
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
                                {canRestoreSnapshot ? (
                                  <Button
                                    size="xs"
                                    variant="default"
                                    loading={
                                      loading ===
                                      `restore-entry:${normalizeExplorerPath(entry.path, false)}`
                                    }
                                    onClick={() => void restoreEntry(entry)}
                                  >
                                    Restore...
                                  </Button>
                                ) : null}
                                {canRenameCurrentStore ? (
                                  <Button
                                    size="xs"
                                    variant="default"
                                    loading={
                                      loading ===
                                      `rename-entry:${normalizeExplorerPath(entry.path, false)}`
                                    }
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
                                    loading={
                                      loading ===
                                      `delete-entry:${normalizeExplorerPath(entry.path, false)}`
                                    }
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
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 5 }}>
          <Stack gap="lg">
            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Text fw={700}>Selected payload</Text>
                <JsonBlock value={selectedPayload} />
              </Stack>
            </Card>

            {loadVersions ? (
              <Card withBorder radius="md" padding="lg">
                <Stack gap="sm">
                  <Text fw={700}>Version history</Text>
                  <TextInput
                    label="Key"
                    value={versionKey}
                    onChange={(event) => setVersionKey(event.currentTarget.value)}
                    placeholder="docs/readme.txt"
                  />
                  <Button loading={loading === "versions"} onClick={() => void loadVersionGraph()}>
                    Load versions
                  </Button>
                  <Table.ScrollContainer minWidth={520}>
                    <Table striped highlightOnHover withTableBorder>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Version ID</Table.Th>
                          <Table.Th>Action</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {(versionsPayload?.versions ?? []).map((version) => (
                          <Table.Tr key={version.version_id}>
                            <Table.Td>
                              <Code>{version.version_id}</Code>
                            </Table.Td>
                            <Table.Td>
                              <Button
                                size="xs"
                                variant="light"
                                onClick={() => void readVersion(version.version_id)}
                              >
                                Read
                              </Button>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                  <Divider />
                  <JsonBlock value={versionsPayload ?? { message: "No version graph loaded yet." }} />
                </Stack>
              </Card>
            ) : null}
          </Stack>
        </Grid.Col>
      </Grid>
    </Stack>
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
