import {
  Alert,
  AppShell,
  Badge,
  Burger,
  Button,
  Card,
  Code,
  Divider,
  FileInput,
  Grid,
  Group,
  NavLink,
  NumberInput,
  Progress,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea,
  UnstyledButton
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconFiles,
  IconFolder,
  IconPlugConnected,
  IconPhoto,
  IconRefresh,
  IconServer
} from "@tabler/icons-react";
import {
  IronmeshBrand,
  JsonBlock,
  PageHeader,
  StatCard
} from "@ironmesh/ui";
import {
  deleteStoreValue,
  getBinaryObjectDownloadUrl,
  getClientHealth,
  getClientClusterNodes,
  getClientClusterStatus,
  getClientRendezvous,
  getClientReplicationPlan,
  getClientPing,
  getStoreValue,
  getVersionGraph,
  listSnapshots,
  listStoreEntries,
  putBinaryObject,
  putStoreValue,
  refreshClientRendezvous,
  updateClientRendezvous,
  type BinaryUploadProgress,
  type ClientRendezvousView,
  type ClientUiPingResponse,
  type JsonObject,
  type SnapshotSummary,
  type StoreEntry,
  type StoreListResponse,
  type VersionGraphResponse
} from "@ironmesh/api";
import { ironmeshUiRevision, ironmeshUiVersion } from "@ironmesh/config";
import { useEffect, useMemo, useRef, useState } from "react";
import { GalleryPage } from "../pages/GalleryPage";

type PageId = "overview" | "rendezvous" | "store" | "explorer" | "gallery" | "cluster";
type ExplorerSortField = "path" | "type" | "size" | "modified";
type ExplorerSortDirection = "asc" | "desc";
type BinaryUploadQueueStatus =
  | "queued"
  | "starting"
  | "uploading"
  | "finalizing"
  | "complete"
  | "failed";
type BinaryUploadQueueItem = {
  id: string;
  file: File;
  key: string;
  progress: BinaryUploadProgress;
  status: BinaryUploadQueueStatus;
  error: string | null;
};
type BinaryUploadSummary = {
  totalFiles: number;
  totalBytes: number;
  uploadedBytes: number;
  queuedFiles: number;
  activeFiles: number;
  completedFiles: number;
  failedFiles: number;
  percent: number;
};
type BinaryUploadController = {
  uploadKey: string;
  setUploadKey: (value: string) => void;
  selectedFiles: File[];
  setSelectedFiles: (files: File[]) => void;
  concurrency: number;
  setConcurrency: (value: number | string | null | undefined) => void;
  queue: BinaryUploadQueueItem[];
  running: boolean;
  summary: BinaryUploadSummary;
  lastResult: unknown | null;
  notice: string | null;
  clearNotice: () => void;
  queueFiles: () => void;
  uploadQueuedFiles: () => Promise<void>;
  clearQueue: () => void;
};
const EXPLORER_PREVIEW_BYTES = 1024;
const DEFAULT_BINARY_UPLOAD_CONCURRENCY = 2;
const MAX_BINARY_UPLOAD_CONCURRENCY = 8;

const pages = [
  {
    id: "overview" as const,
    label: "Overview",
    icon: IconPlugConnected,
    description: "Connection health, service metadata, and quick cluster summary."
  },
  {
    id: "rendezvous" as const,
    label: "Rendezvous",
    icon: IconPlugConnected,
    description: "Inspect relay endpoint status, active URL selection, and editable bootstrap rendezvous URLs."
  },
  {
    id: "store" as const,
    label: "Store",
    icon: IconFiles,
    description: "Text and binary object operations through the transport-aware client."
  },
  {
    id: "explorer" as const,
    label: "Explorer",
    icon: IconFolder,
    description: "Browse prefixes, snapshots, and version history."
  },
  {
    id: "gallery" as const,
    label: "Gallery",
    icon: IconPhoto,
    description: "Browse image objects through the shared media-aware store index."
  },
  {
    id: "cluster" as const,
    label: "Cluster",
    icon: IconServer,
    description: "Inspect cluster status, nodes, and replication planning."
  }
];

export function ClientShell() {
  const [opened, { toggle, close }] = useDisclosure();
  const [activePageId, setActivePageId] = useState<PageId>("overview");
  const [ping, setPing] = useState<ClientUiPingResponse | null>(null);
  const [health, setHealth] = useState<JsonObject | null>(null);
  const [clusterStatus, setClusterStatus] = useState<JsonObject | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ClientRendezvousView | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const binaryUpload = useBinaryUploadQueue();

  useEffect(() => {
    void refreshOverview();
  }, []);

  async function refreshOverview() {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const [nextPing, nextHealth, nextClusterStatus, nextConnectionStatus] = await Promise.all([
        getClientPing(),
        getClientHealth(),
        getClientClusterStatus(),
        getClientRendezvous()
      ]);
      setPing(nextPing);
      setHealth(nextHealth);
      setClusterStatus(nextClusterStatus);
      setConnectionStatus(nextConnectionStatus);
    } catch (error) {
      setOverviewError(error instanceof Error ? error.message : "Failed to refresh client overview");
    } finally {
      setOverviewLoading(false);
    }
  }

  return (
    <>
      <AppShell
        className="shell-root"
        header={{ height: 68 }}
        navbar={{ width: 280, breakpoint: "sm", collapsed: { mobile: !opened } }}
        padding={{ base: "xs", sm: "md", lg: "lg" }}
        styles={{
          header: {
            background: "linear-gradient(180deg, #f9fbfc 0%, #f2f6f8 100%)"
          },
          navbar: {
            background: "linear-gradient(180deg, #f9fbfc 0%, #f0f5f7 100%)"
          },
          main: {
            background: "transparent"
          }
        }}
      >
        <AppShell.Header className="shell-header">
          <Group className="shell-header-bar" h="100%" px="md" justify="space-between">
            <Group gap="sm">
              <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
              <IronmeshBrand surfaceLabel="Client UI" />
            </Group>
            <Group gap="sm">
              {binaryUpload.summary.totalFiles > 0 ? (
                <Button
                  variant="light"
                  color={binaryUploadHeaderColor(binaryUpload.summary, binaryUpload.running)}
                  size="xs"
                  leftSection={<IconFiles size={14} />}
                  onClick={() => setActivePageId("store")}
                >
                  {binaryUploadHeaderLabel(binaryUpload.summary, binaryUpload.running)}
                </Button>
              ) : null}
              {ping ? <Badge variant="light">{ping.service}</Badge> : null}
              <Badge color="teal" variant="filled">
                Transport-aware
              </Badge>
            </Group>
          </Group>
        </AppShell.Header>

        <AppShell.Navbar className="shell-navbar" p="sm">
          <Stack gap="xs">
            {pages.map((page) => {
              const Icon = page.icon;
              return (
                <NavLink
                  key={page.id}
                  active={page.id === activePageId}
                  label={page.label}
                  description={page.description}
                  leftSection={<Icon size={16} />}
                  onClick={() => {
                    setActivePageId(page.id);
                    close();
                  }}
                />
              );
            })}
          </Stack>
        </AppShell.Navbar>

        <AppShell.Main className="shell-main">
          <Stack className="shell-content" gap="lg">
            {activePageId === "overview" ? (
              <OverviewPage
                ping={ping}
                health={health}
                clusterStatus={clusterStatus}
                connectionStatus={connectionStatus}
                loading={overviewLoading}
                error={overviewError}
                onRefresh={refreshOverview}
              />
            ) : null}

            {activePageId === "rendezvous" ? <RendezvousPage /> : null}

            {activePageId === "store" ? <StorePage binaryUpload={binaryUpload} /> : null}

            {activePageId === "explorer" ? <ExplorerPage /> : null}

            {activePageId === "gallery" ? <GalleryPage /> : null}

            {activePageId === "cluster" ? (
              <ClusterPage
                health={health}
                clusterStatus={clusterStatus}
                overviewLoading={overviewLoading}
                onRefreshOverview={refreshOverview}
              />
            ) : null}
          </Stack>
        </AppShell.Main>
      </AppShell>
      {opened ? <div className="shell-backdrop" onClick={close} /> : null}
    </>
  );
}

function useBinaryUploadQueue(): BinaryUploadController {
  const [uploadKey, setUploadKey] = useState("images/");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [concurrency, setConcurrencyState] = useState(DEFAULT_BINARY_UPLOAD_CONCURRENCY);
  const [queue, setQueue] = useState<BinaryUploadQueueItem[]>([]);
  const [running, setRunning] = useState(false);
  const [lastResult, setLastResult] = useState<unknown | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const queueRef = useRef<BinaryUploadQueueItem[]>([]);
  const concurrencyRef = useRef(concurrency);
  const activeWorkersRef = useRef(0);

  const summary = useMemo<BinaryUploadSummary>(() => {
    return summarizeBinaryUploadQueue(queue);
  }, [queue]);

  function setQueueAndRef(
    updater: BinaryUploadQueueItem[] | ((current: BinaryUploadQueueItem[]) => BinaryUploadQueueItem[])
  ) {
    const next =
      typeof updater === "function"
        ? updater(queueRef.current)
        : updater;
    queueRef.current = next;
    setQueue(next);
  }

  function finalizeUploadRun() {
    const nextQueue = queueRef.current;
    const nextSummary = summarizeBinaryUploadQueue(nextQueue);
    setLastResult({
      operation: "binary-upload-queue",
      active_concurrency: Math.min(
        clampBinaryUploadConcurrency(concurrencyRef.current),
        nextSummary.totalFiles
      ),
      total_files: nextSummary.totalFiles,
      completed_files: nextSummary.completedFiles,
      failed_files: nextSummary.failedFiles,
      files: nextQueue.map((item) => ({
        key: item.key,
        filename: item.file.name,
        size_bytes: item.file.size,
        status: item.status === "failed" ? "failed" : "complete",
        error: item.error ?? undefined
      }))
    });

    if (nextSummary.failedFiles > 0) {
      setNotice(
        `${nextSummary.failedFiles} binary upload${nextSummary.failedFiles === 1 ? "" : "s"} failed. Inspect the queue for details.`
      );
    }
  }

  function claimNextQueuedItem(): BinaryUploadQueueItem | null {
    let claimed: BinaryUploadQueueItem | null = null;

    setQueueAndRef((current) => {
      const nextIndex = current.findIndex((item) => item.status === "queued");
      if (nextIndex < 0) {
        return current;
      }

      claimed = {
        ...current[nextIndex],
        progress: createBinaryUploadProgress(current[nextIndex].file.size),
        status: "starting",
        error: null
      };

      const next = [...current];
      next[nextIndex] = claimed;
      return next;
    });

    return claimed;
  }

  function ensureWorkersRunning() {
    const desiredConcurrency = clampBinaryUploadConcurrency(concurrencyRef.current);

    while (activeWorkersRef.current < desiredConcurrency) {
      const item = claimNextQueuedItem();
      if (!item) {
        break;
      }

      activeWorkersRef.current += 1;
      setRunning(true);

      void (async () => {
        try {
          const payload = await putBinaryObject(item.key, item.file, (progress) => {
            setQueueAndRef((current) =>
              current.map((entry) =>
                entry.id === item.id
                  ? {
                      ...entry,
                      progress,
                      status: binaryUploadQueueStatusFromProgress(progress),
                      error: null
                    }
                  : entry
              )
            );
          });

          setQueueAndRef((current) =>
            current.map((entry) =>
              entry.id === item.id
                ? {
                    ...entry,
                    progress: {
                      ...entry.progress,
                      uploadedBytes: payload.size_bytes,
                      totalBytes: payload.size_bytes,
                      uploadedChunks: entry.progress.totalChunks,
                      totalChunks: entry.progress.totalChunks,
                      percent: 100,
                      phase: "complete"
                    },
                    status: "complete",
                    error: null
                  }
                : entry
            )
          );
        } catch (nextError) {
          const message =
            nextError instanceof Error ? nextError.message : "Binary upload failed";

          setQueueAndRef((current) =>
            current.map((entry) =>
              entry.id === item.id
                ? {
                    ...entry,
                    status: "failed",
                    error: message
                  }
                : entry
            )
          );
        } finally {
          activeWorkersRef.current -= 1;
          ensureWorkersRunning();

          if (activeWorkersRef.current === 0) {
            setRunning(false);
            if (!queueRef.current.some((entry) => entry.status === "queued")) {
              finalizeUploadRun();
            }
          }
        }
      })();
    }
  }

  function queueFiles() {
    if (selectedFiles.length === 0) {
      setNotice("Select one or more binary files first.");
      return;
    }

    const occupiedKeys = new Set(
      queueRef.current
        .filter((item) => item.status !== "complete" && item.status !== "failed")
        .map((item) => item.key)
    );
    const duplicateKeys: string[] = [];
    const nextQueueItems: BinaryUploadQueueItem[] = [];

    for (const file of selectedFiles) {
      const key = deriveBinaryUploadKey(file, uploadKey, selectedFiles.length > 1);
      if (occupiedKeys.has(key)) {
        duplicateKeys.push(key);
        continue;
      }
      occupiedKeys.add(key);
      nextQueueItems.push(buildBinaryUploadQueueItem(file, key));
    }

    if (nextQueueItems.length === 0) {
      setNotice(
        duplicateKeys.length === 1
          ? `That upload key is already queued: ${duplicateKeys[0]}`
          : "All selected files resolve to upload keys that are already queued."
      );
      return;
    }

    setQueueAndRef((current) => [...current, ...nextQueueItems]);
    setSelectedFiles([]);
    setNotice(
      duplicateKeys.length > 0
        ? `Queued ${nextQueueItems.length} file(s) and skipped ${duplicateKeys.length} duplicate upload key${duplicateKeys.length === 1 ? "" : "s"}.`
        : null
    );
    setLastResult({
      operation: "binary-upload-queue-add",
      queued_files: nextQueueItems.map((item) => ({
        key: item.key,
        filename: item.file.name,
        size_bytes: item.file.size
      })),
      skipped_duplicate_keys: duplicateKeys
    });

    ensureWorkersRunning();
  }

  function clearQueue() {
    if (activeWorkersRef.current > 0) {
      setQueueAndRef((current) =>
        current.filter((item) => item.status !== "queued")
      );
      setSelectedFiles([]);
      setNotice("Removed queued files. Uploads already in progress will continue.");
      return;
    }

    setQueueAndRef([]);
    setSelectedFiles([]);
    setNotice(null);
  }

  async function uploadQueuedFiles() {
    ensureWorkersRunning();
  }

  useEffect(() => {
    queueRef.current = queue;
  }, [queue]);

  useEffect(() => {
    concurrencyRef.current = concurrency;
    ensureWorkersRunning();
  }, [concurrency]);

  return {
    uploadKey,
    setUploadKey,
    selectedFiles,
    setSelectedFiles,
    concurrency,
    setConcurrency: (value) => setConcurrencyState(clampBinaryUploadConcurrency(value)),
    queue,
    running,
    summary,
    lastResult,
    notice,
    clearNotice: () => setNotice(null),
    queueFiles,
    uploadQueuedFiles,
    clearQueue
  };
}

type OverviewPageProps = {
  ping: ClientUiPingResponse | null;
  health: JsonObject | null;
  clusterStatus: JsonObject | null;
  connectionStatus: ClientRendezvousView | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
};

function OverviewPage({
  ping,
  health,
  clusterStatus,
  connectionStatus,
  loading,
  error,
  onRefresh
}: OverviewPageProps) {
  const totalNodes = getNumber(clusterStatus, "total_nodes");
  const onlineNodes = getNumber(clusterStatus, "online_nodes");
  const offlineNodes = getNumber(clusterStatus, "offline_nodes");
  const replicationFactor = getNestedNumber(clusterStatus, "policy", "replication_factor");
  const runtimeMode = typeof health?.mode === "string" ? health.mode : "runtime";
  const connectionSummary = summarizeClientConnection(connectionStatus);
  const versionMismatch = Boolean(ping?.backend_version) && ping?.backend_version !== ironmeshUiVersion;

  return (
    <>
      <PageHeader
        title="Overview"
        description="Quick read of the current embedded client connection and upstream cluster state."
        actions={
          <Button leftSection={<IconRefresh size={16} />} loading={loading} onClick={() => void onRefresh()}>
            Refresh
          </Button>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <SimpleGrid cols={{ base: 1, md: 2, xl: 4 }}>
        <StatCard label="Service" value={ping?.service ?? "Loading..."} hint="Value returned by /api/ping." />
        <StatCard label="Runtime" value={runtimeMode} hint="Derived from /api/health." />
        <StatCard label="Cluster Nodes" value={totalNodes ?? "Unknown"} hint="Current total node count." />
        <StatCard
          label="Replication Factor"
          value={replicationFactor ?? "Unknown"}
          hint="Policy advertised by the upstream cluster."
        />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Connection summary</Text>
              <Group gap="sm">
                <Badge color="teal" variant="light">
                  {onlineNodes ?? 0} online
                </Badge>
                <Badge color={offlineNodes ? "yellow" : "gray"} variant="light">
                  {offlineNodes ?? 0} offline
                </Badge>
                <Badge color="blue" variant="light">
                  {totalNodes ?? 0} total
                </Badge>
              </Group>
              <Text c="dimmed" size="sm">
                This web UI runs on top of the same transport-aware Rust client used by desktop, Android, and CLI flows.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Version info</Text>
              <Text size="sm">
                UI build: <Code>{formatFullVersion(ironmeshUiVersion, ironmeshUiRevision)}</Code>
              </Text>
              <Text size="sm">
                Backend build: <Code>{formatFullVersion(ping?.backend_version, ping?.backend_revision)}</Code>
              </Text>
              {versionMismatch ? (
                <Alert color="yellow" variant="light">
                  The bundled UI version does not match the connected backend version.
                </Alert>
              ) : (
                <Text size="sm" c="dimmed">
                  UI and backend build details are shown here directly for easier diagnostics.
                </Text>
              )}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Active route</Text>
              <Group gap="sm">
                <Badge color={connectionStatus?.transport_mode === "relay" ? "teal" : "blue"} variant="light">
                  {connectionSummary.routeMode}
                </Badge>
                {connectionStatus?.transport_mode === "relay" && connectionStatus.active_url ? (
                  <Badge variant="light">{summarizeUrl(connectionStatus.active_url)}</Badge>
                ) : null}
              </Group>
              <Text size="sm">
                Target: <Code>{connectionSummary.target}</Code>
              </Text>
              <Text size="sm">
                Path: <Code>{connectionSummary.path}</Code>
              </Text>
              {connectionSummary.detail ? (
                <Text size="sm" c="dimmed">
                  {connectionSummary.detail}
                </Text>
              ) : null}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Health payload</Text>
              <JsonBlock value={health ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Cluster status payload</Text>
              <JsonBlock value={clusterStatus ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function RendezvousPage() {
  const [rendezvous, setRendezvous] = useState<ClientRendezvousView | null>(null);
  const [editableUrlsText, setEditableUrlsText] = useState("");
  const [urlsDirty, setUrlsDirty] = useState(false);
  const urlsDirtyRef = useRef(false);
  const [loading, setLoading] = useState(true);
  const [pendingAction, setPendingAction] = useState<"refresh" | "save" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    urlsDirtyRef.current = urlsDirty;
  }, [urlsDirty]);

  useEffect(() => {
    let cancelled = false;

    async function loadStatus(showLoading: boolean, preserveDraft: boolean) {
      if (showLoading) {
        setLoading(true);
      }
      try {
        const payload = await refreshClientRendezvous();
        if (cancelled) {
          return;
        }
        setRendezvous(payload);
        if (!preserveDraft || !urlsDirtyRef.current) {
          setEditableUrlsText(payload.configured_urls.join("\n"));
          setUrlsDirty(false);
        }
      } catch (nextError) {
        if (!cancelled) {
          setError(nextError instanceof Error ? nextError.message : "Failed loading rendezvous status");
        }
      } finally {
        if (!cancelled && showLoading) {
          setLoading(false);
        }
      }
    }

    void loadStatus(true, false);
    const refreshInterval = window.setInterval(() => {
      void loadStatus(false, true);
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(refreshInterval);
    };
  }, []);

  async function handleManualRefresh() {
    setPendingAction("refresh");
    setError(null);
    try {
      const payload = await refreshClientRendezvous();
      setRendezvous(payload);
      if (!urlsDirtyRef.current) {
        setEditableUrlsText(payload.configured_urls.join("\n"));
        setUrlsDirty(false);
      }
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed refreshing rendezvous status");
    } finally {
      setPendingAction(null);
    }
  }

  async function handleSave() {
    setPendingAction("save");
    setError(null);
    try {
      const rendezvous_urls = editableUrlsText
        .split(/\r?\n/)
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
      const payload = await updateClientRendezvous({ rendezvous_urls });
      setRendezvous(payload);
      setEditableUrlsText(payload.configured_urls.join("\n"));
      setUrlsDirty(false);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed updating rendezvous URLs");
    } finally {
      setPendingAction(null);
    }
  }

  const endpointStatuses = rendezvous?.endpoint_statuses ?? [];
  const connectedEndpoints = endpointStatuses.filter((endpoint) => endpoint.status === "connected").length;

  return (
    <>
      <PageHeader
        title="Rendezvous"
        description="Shared relay endpoint status and bootstrap rendezvous URL controls for Android and CLI-backed web sessions."
        actions={
          <Button
            leftSection={<IconRefresh size={16} />}
            loading={loading || pendingAction === "refresh"}
            onClick={() => void handleManualRefresh()}
          >
            Refresh
          </Button>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}
      {rendezvous?.last_probe_error ? (
        <Alert color="yellow" title="Probe warning">
          {rendezvous.last_probe_error}
        </Alert>
      ) : null}
      {!loading && rendezvous && !rendezvous.available ? (
        <Alert color="blue" title="Bootstrap-backed rendezvous config unavailable">
          This session was started without bootstrap metadata, so the shared web UI cannot edit or probe rendezvous URLs.
          Start the Android or CLI client from bootstrap configuration to manage them here.
        </Alert>
      ) : null}
      {rendezvous?.editable && rendezvous.persistence_source === "runtime_only" ? (
        <Alert color="yellow" title="Runtime-only change scope">
          Rendezvous URL edits apply to the current embedded client runtime now, but they are not persisted back into the
          original Android or CLI bootstrap source automatically.
        </Alert>
      ) : null}
      {rendezvous?.editable && rendezvous.persistence_source === "android_preferences" ? (
        <Alert color="teal" title="Persisted to Android preferences">
          Rendezvous URL edits are written back into the Android app's persisted bootstrap state and will be reused after restart.
        </Alert>
      ) : null}
      {rendezvous?.editable && rendezvous.persistence_source === "bootstrap_file" ? (
        <Alert color="teal" title="Persisted to bootstrap file">
          Rendezvous URL edits are written back into the bootstrap file that launched this web session.
        </Alert>
      ) : null}

      <SimpleGrid cols={{ base: 1, md: 2, xl: 4 }}>
        <StatCard label="Transport" value={rendezvous?.transport_mode ?? "Loading..."} hint="Current client transport mode." />
        <StatCard label="Relay policy" value={rendezvous?.relay_mode ?? "Unknown"} hint="Relay preference from the bootstrap, when available." />
        <StatCard label="Configured URLs" value={rendezvous?.configured_urls.length ?? 0} hint="Operator-managed rendezvous URLs currently loaded into this runtime." />
        <StatCard
          label="Active URL"
          value={rendezvous?.active_url ? summarizeUrl(rendezvous.active_url) : "None"}
          hint="Last successful rendezvous endpoint used by the active relay transport."
        />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Group justify="space-between">
                <Text fw={700}>Rendezvous URL list</Text>
                <Badge variant="light">{rendezvous?.editable ? "editable" : "read-only"}</Badge>
              </Group>
              <Text c="dimmed" size="sm">
                One URL per line. The shared web UI updates the bootstrap-backed rendezvous configuration used for future relay connection trials.
              </Text>
              <Textarea
                label="Configured rendezvous URLs"
                minRows={8}
                autosize
                value={editableUrlsText}
                disabled={!rendezvous?.editable}
                onChange={(event) => {
                  setEditableUrlsText(event.currentTarget.value);
                  setUrlsDirty(true);
                }}
                placeholder={"https://rendezvous-a.example:9443\nhttps://rendezvous-b.example:9443"}
              />
              <Group>
                <Button
                  loading={pendingAction === "save"}
                  disabled={!rendezvous?.editable}
                  onClick={() => void handleSave()}
                >
                  Save rendezvous URLs
                </Button>
              </Group>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Connection summary</Text>
              <Group gap="sm">
                <Badge color={connectedEndpoints > 0 ? "green" : "gray"} variant="light">
                  {endpointStatuses.length === 0 ? "no probes yet" : `${connectedEndpoints}/${endpointStatuses.length} connected`}
                </Badge>
                <Badge color={rendezvous?.mtls_required ? "blue" : "gray"} variant="light">
                  {rendezvous?.mtls_required ? "mTLS required" : "mTLS optional"}
                </Badge>
                <Badge color={rendezvous?.transport_mode === "relay" ? "teal" : "gray"} variant="light">
                  {rendezvous?.transport_mode === "relay" ? "relay active" : "direct active"}
                </Badge>
              </Group>
              <Text size="sm" c="dimmed">
                Active target node: {rendezvous?.active_target_node_id ?? "none"}
              </Text>
              <Text size="sm" c="dimmed">
                Persistence source: {rendezvous?.persistence_source ?? "unknown"}
              </Text>
              <JsonBlock
                value={
                  rendezvous ?? {
                    status: loading ? "loading" : "unavailable"
                  }
                }
              />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Group justify="space-between">
                <Text fw={700}>Endpoint status</Text>
                <Badge color={connectedEndpoints === endpointStatuses.length && endpointStatuses.length > 0 ? "green" : "yellow"} variant="light">
                  {endpointStatuses.length === 0 ? "no endpoints" : `${connectedEndpoints}/${endpointStatuses.length} connected`}
                </Badge>
              </Group>
              <Text c="dimmed" size="sm">
                The active URL comes from the live relay transport. Other rows show the latest shared-web probe result for each configured rendezvous service.
              </Text>
              <Table.ScrollContainer minWidth={820}>
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>URL</Table.Th>
                      <Table.Th>Status</Table.Th>
                      <Table.Th>Last attempt</Table.Th>
                      <Table.Th>Last success</Table.Th>
                      <Table.Th>Failures</Table.Th>
                      <Table.Th>Last error</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {endpointStatuses.map((endpoint) => (
                      <Table.Tr key={endpoint.url}>
                        <Table.Td>
                          <Group gap="xs">
                            <Code>{endpoint.url}</Code>
                            {endpoint.active ? (
                              <Badge color="teal" variant="filled">
                                active
                              </Badge>
                            ) : null}
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          <Badge color={rendezvousStatusColor(endpoint.status)} variant="light">
                            {endpoint.status}
                          </Badge>
                        </Table.Td>
                        <Table.Td>{formatUnixTimestamp(endpoint.last_attempt_unix)}</Table.Td>
                        <Table.Td>{formatUnixTimestamp(endpoint.last_success_unix)}</Table.Td>
                        <Table.Td>{endpoint.consecutive_failures}</Table.Td>
                        <Table.Td>{endpoint.last_error ?? "none"}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function StorePage({ binaryUpload }: { binaryUpload: BinaryUploadController }) {
  const [textUploadKey, setTextUploadKey] = useState("docs/readme.txt");
  const [textUploadValue, setTextUploadValue] = useState("hello from the React client UI");
  const [textDownloadKey, setTextDownloadKey] = useState("docs/readme.txt");
  const [textDownloadValue, setTextDownloadValue] = useState("");
  const [deleteKey, setDeleteKey] = useState("");
  const [binaryDownloadKey, setBinaryDownloadKey] = useState("images/demo.bin");
  const [result, setResult] = useState<unknown | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const {
    uploadKey: binaryUploadKey,
    setUploadKey: setBinaryUploadKey,
    selectedFiles: binaryFiles,
    setSelectedFiles: setBinaryFiles,
    concurrency: binaryUploadConcurrency,
    setConcurrency: setBinaryUploadConcurrency,
    queue: binaryUploadQueue,
    running: binaryUploadRunning,
    summary: binaryUploadSummary,
    lastResult: binaryUploadResult,
    notice: binaryUploadNotice,
    queueFiles: handleQueueBinaryFiles,
    clearQueue: handleClearBinaryUploadQueue
  } = binaryUpload;

  async function withAction<T>(action: string, run: () => Promise<T>): Promise<T | null> {
    setPendingAction(action);
    setError(null);
    try {
      return await run();
    } catch (nextError) {
      const message = nextError instanceof Error ? nextError.message : "Operation failed";
      setError(message);
      return null;
    } finally {
      setPendingAction(null);
    }
  }

  async function handleUploadText() {
    const payload = await withAction("upload-text", () => putStoreValue(textUploadKey.trim(), textUploadValue));
    if (payload) {
      setResult(payload);
    }
  }

  async function handleDownloadText() {
    const payload = await withAction("download-text", () => getStoreValue(textDownloadKey.trim()));
    if (payload) {
      setTextDownloadValue(payload.value ?? "");
      setResult(payload);
    }
  }

  async function handleDeleteObject() {
    const payload = await withAction("delete-object", () => deleteStoreValue(deleteKey.trim()));
    if (payload) {
      setResult(payload);
    }
  }

  async function handleDownloadBinary() {
    const key = binaryDownloadKey.trim();
    if (!key) {
      setError("Binary download key must not be empty.");
      return;
    }

    setPendingAction("download-binary");
    setError(null);
    try {
      triggerBrowserDownloadFromUrl(getBinaryObjectDownloadUrl(key));
      setResult({
        key,
        download_started: true
      });
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Store"
        description="Read, write, and delete objects without dropping out of the transport-aware client path."
      />

      {error ? <Alert color="red">{error}</Alert> : null}
      {binaryUploadNotice ? (
        <Alert color={binaryUploadSummary.failedFiles > 0 ? "red" : "blue"}>
          {binaryUploadNotice}
        </Alert>
      ) : null}

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Text upload</Text>
              <TextInput label="Object key" value={textUploadKey} onChange={(event) => setTextUploadKey(event.currentTarget.value)} />
              <Textarea
                label="Payload"
                autosize
                minRows={8}
                value={textUploadValue}
                onChange={(event) => setTextUploadValue(event.currentTarget.value)}
              />
              <Button loading={pendingAction === "upload-text"} onClick={() => void handleUploadText()}>
                Upload text object
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Text download</Text>
              <TextInput
                label="Object key"
                value={textDownloadKey}
                onChange={(event) => setTextDownloadKey(event.currentTarget.value)}
              />
              <Button loading={pendingAction === "download-text"} onClick={() => void handleDownloadText()}>
                Download text object
              </Button>
              <Textarea label="Downloaded payload" autosize minRows={8} value={textDownloadValue} readOnly />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Group justify="space-between" gap="sm" align="flex-start">
                <div>
                  <Text fw={700}>Binary file upload</Text>
                  <Text size="sm" c="dimmed">
                    Queue multiple files, then upload several sessions in parallel.
                  </Text>
                </div>
                <Badge color={binaryUploadRunning ? "blue" : "gray"} variant="light">
                  {binaryUploadRunning ? "queue running" : "queue idle"}
                </Badge>
              </Group>
              <TextInput
                label="Object key or prefix"
                description="With one file selected, a value without a trailing slash is treated as the exact key. Multiple files are uploaded underneath the prefix."
                value={binaryUploadKey}
                onChange={(event) => setBinaryUploadKey(event.currentTarget.value)}
              />
              <FileInput
                label="Files"
                description="Selecting files and adding them to the queue starts uploading immediately."
                value={binaryFiles.length > 0 ? binaryFiles : undefined}
                multiple
                clearable
                onChange={(value) => {
                  setBinaryFiles(value ?? []);
                }}
              />
              <NumberInput
                label="Parallel uploads"
                description={`How many files to upload at once (1-${MAX_BINARY_UPLOAD_CONCURRENCY}).`}
                value={binaryUploadConcurrency}
                min={1}
                max={MAX_BINARY_UPLOAD_CONCURRENCY}
                step={1}
                clampBehavior="strict"
                onChange={(value) => setBinaryUploadConcurrency(value)}
              />
              <Group gap="sm">
                <Button
                  variant="light"
                  onClick={() => {
                    setResult(null);
                    handleQueueBinaryFiles();
                  }}
                  disabled={binaryFiles.length === 0}
                >
                  Add files to queue
                </Button>
                <Button
                  variant="subtle"
                  color="gray"
                  onClick={() => {
                    setResult(null);
                    handleClearBinaryUploadQueue();
                  }}
                  disabled={binaryUploadQueue.length === 0}
                >
                  {binaryUploadRunning ? "Remove queued files" : "Clear queue"}
                </Button>
              </Group>
              {binaryUploadQueue.length > 0 ? (
                <Stack gap={6}>
                  <Group justify="space-between" gap="sm">
                    <Text size="sm" fw={600}>
                      Queue progress
                    </Text>
                    <Badge color={binaryUploadRunning ? "blue" : "gray"} variant="light">
                      {binaryUploadSummary.totalFiles} file{binaryUploadSummary.totalFiles === 1 ? "" : "s"}
                    </Badge>
                  </Group>
                  <Group gap="xs">
                    <Badge color="gray" variant="light">
                      {binaryUploadSummary.queuedFiles} queued
                    </Badge>
                    <Badge color="blue" variant="light">
                      {binaryUploadSummary.activeFiles} active
                    </Badge>
                    <Badge color="teal" variant="light">
                      {binaryUploadSummary.completedFiles} complete
                    </Badge>
                    <Badge color={binaryUploadSummary.failedFiles > 0 ? "red" : "gray"} variant="light">
                      {binaryUploadSummary.failedFiles} failed
                    </Badge>
                  </Group>
                  <Progress
                    value={binaryUploadSummary.percent}
                    animated={binaryUploadRunning && binaryUploadSummary.activeFiles > 0}
                  />
                  <Group justify="space-between" gap="sm">
                    <Text size="sm">
                      {formatExplorerSize(binaryUploadSummary.uploadedBytes)} / {formatExplorerSize(binaryUploadSummary.totalBytes)}
                    </Text>
                    <Text size="sm" c="dimmed">
                      {binaryUploadSummary.percent}%
                    </Text>
                  </Group>
                  <Table.ScrollContainer minWidth={840}>
                    <Table striped highlightOnHover withTableBorder>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>File</Table.Th>
                          <Table.Th>Object key</Table.Th>
                          <Table.Th>Status</Table.Th>
                          <Table.Th>Progress</Table.Th>
                          <Table.Th>Size</Table.Th>
                          <Table.Th>Error</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {binaryUploadQueue.map((item) => (
                          <Table.Tr key={item.id}>
                            <Table.Td>
                              <Stack gap={0}>
                                <Text size="sm" fw={600}>
                                  {item.file.name}
                                </Text>
                                <Text size="xs" c="dimmed">
                                  {item.file.type || "application/octet-stream"}
                                </Text>
                              </Stack>
                            </Table.Td>
                            <Table.Td>
                              <Code>{item.key}</Code>
                            </Table.Td>
                            <Table.Td>
                              <Badge
                                color={binaryUploadStatusColor(item.status)}
                                variant="light"
                              >
                                {binaryUploadPhaseLabel(item.status)}
                              </Badge>
                            </Table.Td>
                            <Table.Td>
                              <Stack gap={4}>
                                <Group gap="xs" wrap="nowrap">
                                  <Progress
                                    value={item.progress.percent}
                                    animated={
                                      item.status === "starting" ||
                                      item.status === "uploading" ||
                                      item.status === "finalizing"
                                    }
                                    style={{ flex: 1 }}
                                  />
                                  <Text size="xs" c="dimmed" miw={44}>
                                    {item.progress.percent}%
                                  </Text>
                                </Group>
                                <Text size="xs" c="dimmed">
                                  {formatExplorerSize(item.progress.uploadedBytes)} / {formatExplorerSize(item.progress.totalBytes)}
                                </Text>
                                <Text size="xs" c="dimmed">
                                  {item.progress.uploadedChunks} / {item.progress.totalChunks || 0} chunks acknowledged
                                </Text>
                              </Stack>
                            </Table.Td>
                            <Table.Td>{formatExplorerSize(item.file.size)}</Table.Td>
                            <Table.Td>
                              <Text size="xs" c={item.error ? "red" : "dimmed"}>
                                {item.error ?? "—"}
                              </Text>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                </Stack>
              ) : null}
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Binary file download</Text>
              <TextInput
                label="Object key"
                value={binaryDownloadKey}
                onChange={(event) => setBinaryDownloadKey(event.currentTarget.value)}
              />
              <Button loading={pendingAction === "download-binary"} onClick={() => void handleDownloadBinary()}>
                Download binary file
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Delete object</Text>
              <TextInput label="Object key" value={deleteKey} onChange={(event) => setDeleteKey(event.currentTarget.value)} />
              <Button color="red" loading={pendingAction === "delete-object"} onClick={() => void handleDeleteObject()}>
                Delete object
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Last operation</Text>
              <JsonBlock value={result ?? binaryUploadResult ?? { message: "No operation run yet." }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function ExplorerPage() {
  const [prefix, setPrefix] = useState("");
  const [depth, setDepth] = useState(1);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [entriesPayload, setEntriesPayload] = useState<StoreListResponse | null>(null);
  const [selectedPayload, setSelectedPayload] = useState<unknown>({ message: "Select an object or version to preview it." });
  const [versionKey, setVersionKey] = useState("");
  const [versionsPayload, setVersionsPayload] = useState<VersionGraphResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sortField, setSortField] = useState<ExplorerSortField>("path");
  const [sortDirection, setSortDirection] = useState<ExplorerSortDirection>("asc");

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
  }, []);

  async function refreshSnapshots() {
    setLoading("snapshots");
    setError(null);
    try {
      const payload = await listSnapshots();
      setSnapshots(payload);
      if (!snapshotId && payload.length > 0) {
        setSnapshotId(payload[0]?.id ?? null);
      }
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
      const payload = await listStoreEntries(targetPrefix.trim(), depth, snapshotId);
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

  async function readEntry(entry: StoreEntry) {
    if (entry.entry_type === "prefix" || entry.path.endsWith("/")) {
      await refreshEntries(entry.path);
      return;
    }

    setLoading(`read-entry:${entry.path}`);
    setError(null);
    try {
      const payload = await getStoreValue(
        entry.path,
        snapshotId,
        null,
        EXPLORER_PREVIEW_BYTES
      );
      setSelectedPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed reading object");
    } finally {
      setLoading(null);
    }
  }

  function downloadEntry(entry: StoreEntry) {
    if (entry.entry_type === "prefix" || entry.path.endsWith("/")) {
      return;
    }

    setError(null);
    triggerBrowserDownloadFromUrl(getBinaryObjectDownloadUrl(entry.path, snapshotId));
  }

  async function loadVersions() {
    if (!versionKey.trim()) {
      setError("Enter a key to load version history.");
      return;
    }

    setLoading("versions");
    setError(null);
    try {
      const payload = await getVersionGraph(versionKey.trim());
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
      const payload = await getStoreValue(
        versionKey.trim(),
        null,
        versionId,
        EXPLORER_PREVIEW_BYTES
      );
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

  return (
    <>
      <PageHeader
        title="Explorer"
        description="Inspect prefixes, snapshots, and version history through the same backend APIs exposed by serve-web and Android."
        actions={
          <Group gap="sm">
            <Button variant="default" loading={loading === "snapshots"} onClick={() => void refreshSnapshots()}>
              Refresh snapshots
            </Button>
            <Button leftSection={<IconRefresh size={16} />} loading={loading === "entries"} onClick={() => void refreshEntries()}>
              Refresh entries
            </Button>
          </Group>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <Grid>
        <Grid.Col span={{ base: 12, xl: 7 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Object browser</Text>
              <Grid>
                <Grid.Col span={{ base: 12, md: 6 }}>
                  <TextInput label="Prefix" value={prefix} onChange={(event) => setPrefix(event.currentTarget.value)} placeholder="docs/" />
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
                    data={[{ value: "", label: "Current data" }, ...snapshots.map((snapshot) => ({ value: snapshot.id, label: snapshot.id }))]}
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
              <Table.ScrollContainer minWidth={720}>
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{renderExplorerHeader("Path", "path", sortField, sortDirection, toggleSort)}</Table.Th>
                      <Table.Th>{renderExplorerHeader("Type", "type", sortField, sortDirection, toggleSort)}</Table.Th>
                      <Table.Th>{renderExplorerHeader("Size", "size", sortField, sortDirection, toggleSort)}</Table.Th>
                      <Table.Th>{renderExplorerHeader("Modified", "modified", sortField, sortDirection, toggleSort)}</Table.Th>
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
                              <Button size="xs" variant="light" onClick={() => void readEntry(entry)}>
                                Open
                              </Button>
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
                                <Button size="xs" variant="default" onClick={() => downloadEntry(entry)}>
                                  Download
                                </Button>
                              </Group>
                            )}
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
              {entriesPayload ? <JsonBlock value={entriesPayload} /> : null}
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

            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Text fw={700}>Version history</Text>
                <TextInput label="Key" value={versionKey} onChange={(event) => setVersionKey(event.currentTarget.value)} placeholder="docs/readme.txt" />
                <Button loading={loading === "versions"} onClick={() => void loadVersions()}>
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
                            <Button size="xs" variant="light" onClick={() => void readVersion(version.version_id)}>
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
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}

type ClusterPageProps = {
  health: JsonObject | null;
  clusterStatus: JsonObject | null;
  overviewLoading: boolean;
  onRefreshOverview: () => Promise<void>;
};

function ClusterPage({ health, clusterStatus, overviewLoading, onRefreshOverview }: ClusterPageProps) {
  const [nodes, setNodes] = useState<unknown[] | null>(null);
  const [replicationPlan, setReplicationPlan] = useState<JsonObject | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshNodes();
    void refreshReplicationPlan();
  }, []);

  async function refreshNodes() {
    setLoading("nodes");
    setError(null);
    try {
      setNodes(await getClientClusterNodes());
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading nodes");
    } finally {
      setLoading(null);
    }
  }

  async function refreshReplicationPlan() {
    setLoading("replication");
    setError(null);
    try {
      setReplicationPlan(await getClientReplicationPlan());
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading replication plan");
    } finally {
      setLoading(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Cluster"
        description="Operational cluster details exposed through the client web backend."
        actions={
          <Group gap="sm">
            <Button variant="default" loading={overviewLoading} onClick={() => void onRefreshOverview()}>
              Refresh status
            </Button>
            <Button variant="default" loading={loading === "nodes"} onClick={() => void refreshNodes()}>
              Refresh nodes
            </Button>
            <Button variant="default" loading={loading === "replication"} onClick={() => void refreshReplicationPlan()}>
              Refresh replication
            </Button>
          </Group>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <SimpleGrid cols={{ base: 1, md: 2, xl: 4 }}>
        <StatCard label="Total nodes" value={getNumber(clusterStatus, "total_nodes") ?? "Unknown"} />
        <StatCard label="Online nodes" value={getNumber(clusterStatus, "online_nodes") ?? "Unknown"} />
        <StatCard label="Under replicated" value={getNumber(replicationPlan, "under_replicated") ?? "Unknown"} />
        <StatCard label="Over replicated" value={getNumber(replicationPlan, "over_replicated") ?? "Unknown"} />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Health</Text>
              <JsonBlock value={health ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Cluster status</Text>
              <JsonBlock value={clusterStatus ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Nodes</Text>
              <JsonBlock value={nodes ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Replication plan</Text>
              <JsonBlock value={replicationPlan ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function formatUnixTimestamp(value: number | null): string {
  if (!value) {
    return "never";
  }

  return new Date(value * 1000).toLocaleString();
}

function summarizeClientConnection(connection: ClientRendezvousView | null): {
  routeMode: string;
  target: string;
  path: string;
  detail: string | null;
} {
  if (!connection) {
    return {
      routeMode: "loading",
      target: "loading",
      path: "loading",
      detail: null
    };
  }

  if (connection.transport_mode === "relay") {
    return {
      routeMode: "Relay",
      target: connection.active_target_node_id ?? "indirect node unknown",
      path: connection.active_url ?? "rendezvous endpoint unknown",
      detail: connection.active_url
        ? `Traffic is currently relayed through ${summarizeUrl(connection.active_url)}.`
        : "Relay transport is active, but no rendezvous endpoint is marked active yet."
    };
  }

  return {
    routeMode: "Direct",
    target: connection.direct_target_node_id ?? "server node unknown",
    path: connection.direct_url ?? "direct endpoint unknown",
    detail: connection.direct_url
      ? "Requests are currently going straight to the selected server node."
      : "This session is on a direct path, but the originating direct endpoint is not available."
  };
}

function formatFullVersion(version: string | null | undefined, revision: string | null | undefined): string {
  if (!version && !revision) {
    return "unknown";
  }
  if (version && revision) {
    return `${version} (${revision})`;
  }
  return version ?? revision ?? "unknown";
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

function createBinaryUploadProgress(totalBytes: number): BinaryUploadProgress {
  return {
    uploadedBytes: 0,
    totalBytes,
    uploadedChunks: 0,
    totalChunks: 0,
    percent: 0,
    phase: "starting"
  };
}

function buildBinaryUploadQueueItem(file: File, key: string): BinaryUploadQueueItem {
  return {
    id: `${key}:${file.name}:${file.size}:${file.lastModified}`,
    file,
    key,
    progress: createBinaryUploadProgress(file.size),
    status: "queued",
    error: null
  };
}

function deriveBinaryUploadKey(file: File, rawTarget: string, multipleFiles: boolean): string {
  const trimmedTarget = rawTarget.trim();
  if (!trimmedTarget) {
    return file.name;
  }
  if (!multipleFiles && !trimmedTarget.endsWith("/")) {
    return trimmedTarget;
  }

  const normalizedPrefix = trimmedTarget.replace(/\/+$/, "");
  return normalizedPrefix ? `${normalizedPrefix}/${file.name}` : file.name;
}

function clampBinaryUploadConcurrency(value: number | string | null | undefined): number {
  const numericValue =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim()
        ? Number(value)
        : DEFAULT_BINARY_UPLOAD_CONCURRENCY;

  if (!Number.isFinite(numericValue)) {
    return DEFAULT_BINARY_UPLOAD_CONCURRENCY;
  }

  return Math.min(
    MAX_BINARY_UPLOAD_CONCURRENCY,
    Math.max(1, Math.round(numericValue))
  );
}

function binaryUploadQueueStatusFromProgress(
  progress: BinaryUploadProgress
): BinaryUploadQueueStatus {
  return progress.phase;
}

function summarizeBinaryUploadQueue(
  queue: BinaryUploadQueueItem[]
): BinaryUploadSummary {
  let totalBytes = 0;
  let uploadedBytes = 0;
  let queuedFiles = 0;
  let activeFiles = 0;
  let completedFiles = 0;
  let failedFiles = 0;

  for (const item of queue) {
    totalBytes += item.progress.totalBytes;
    uploadedBytes += item.progress.uploadedBytes;

    if (item.status === "queued") {
      queuedFiles += 1;
    } else if (item.status === "complete") {
      completedFiles += 1;
    } else if (item.status === "failed") {
      failedFiles += 1;
    } else {
      activeFiles += 1;
    }
  }

  return {
    totalFiles: queue.length,
    totalBytes,
    uploadedBytes,
    queuedFiles,
    activeFiles,
    completedFiles,
    failedFiles,
    percent:
      totalBytes === 0 ? 0 : Math.round((uploadedBytes / Math.max(1, totalBytes)) * 100)
  };
}

function binaryUploadHeaderColor(
  summary: BinaryUploadSummary,
  running: boolean
): string {
  if (summary.failedFiles > 0) {
    return "red";
  }
  if (running || summary.activeFiles > 0) {
    return "blue";
  }
  if (summary.completedFiles > 0 && summary.completedFiles === summary.totalFiles) {
    return "teal";
  }
  return "gray";
}

function binaryUploadHeaderLabel(
  summary: BinaryUploadSummary,
  running: boolean
): string {
  const baseLabel = `Uploads ${summary.completedFiles}/${summary.totalFiles}`;
  if (running || summary.activeFiles > 0 || summary.queuedFiles > 0) {
    return `${baseLabel} · ${summary.percent}%`;
  }
  if (summary.failedFiles > 0) {
    return `${baseLabel} · ${summary.failedFiles} failed`;
  }
  return `${baseLabel} · done`;
}

function binaryUploadStatusColor(status: BinaryUploadQueueStatus): string {
  if (status === "queued") {
    return "gray";
  }
  if (status === "complete") {
    return "teal";
  }
  if (status === "failed") {
    return "red";
  }
  if (status === "finalizing") {
    return "violet";
  }
  return "blue";
}

function binaryUploadPhaseLabel(
  phase: BinaryUploadProgress["phase"] | BinaryUploadQueueStatus
): string {
  if (phase === "queued") {
    return "Queued";
  }
  if (phase === "starting") {
    return "Starting";
  }
  if (phase === "uploading") {
    return "Uploading";
  }
  if (phase === "finalizing") {
    return "Finalizing";
  }
  if (phase === "failed") {
    return "Failed";
  }
  return "Complete";
}

function renderExplorerHeader(
  label: string,
  field: ExplorerSortField,
  activeField: ExplorerSortField,
  direction: ExplorerSortDirection,
  onToggle: (field: ExplorerSortField) => void
) {
  const indicator =
    activeField === field ? (direction === "asc" ? "↑" : "↓") : "↕";

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
  left: StoreEntry,
  right: StoreEntry,
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

function shouldDisplayExplorerEntry(entry: StoreEntry, prefix: string): boolean {
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

function explorerDisplayPath(entry: StoreEntry, prefix: string): string {
  const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
  const normalizedPrefix = normalizeExplorerPrefix(prefix);
  const normalizedPath = normalizeExplorerPath(entry.path, isPrefix);

  if (!normalizedPrefix || !normalizedPath.startsWith(normalizedPrefix)) {
    return normalizedPath || entry.path;
  }

  const relativePath = normalizedPath.slice(normalizedPrefix.length);
  return relativePath || normalizedPath;
}

function normalizeExplorerPrefix(prefix: string): string {
  const trimmed = prefix.trim().replace(/^\/+/, "");
  if (!trimmed) {
    return "";
  }
  return `${trimmed.replace(/\/+$/, "")}/`;
}

function normalizeExplorerPath(path: string, isPrefix: boolean): string {
  const trimmed = path.trim().replace(/^\/+/, "");
  if (!trimmed) {
    return "";
  }
  if (isPrefix || trimmed.endsWith("/")) {
    return `${trimmed.replace(/\/+$/, "")}/`;
  }
  return trimmed;
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

function normalizeExplorerType(entry: StoreEntry): string {
  return entry.entry_type === "prefix" || entry.path.endsWith("/") ? "prefix" : entry.entry_type;
}

function rendezvousStatusColor(status: "unknown" | "connected" | "disconnected"): string {
  if (status === "connected") {
    return "green";
  }
  if (status === "disconnected") {
    return "red";
  }
  return "gray";
}

function summarizeUrl(value: string): string {
  try {
    const parsed = new URL(value);
    return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  } catch {
    return value;
  }
}

function getNumber(value: JsonObject | null, key: string): number | null {
  if (!value) {
    return null;
  }
  const candidate = value[key];
  return typeof candidate === "number" ? candidate : null;
}

function getNestedNumber(value: JsonObject | null, key: string, nestedKey: string): number | null {
  if (!value) {
    return null;
  }
  const nested = value[key];
  if (!nested || typeof nested !== "object" || Array.isArray(nested)) {
    return null;
  }
  const candidate = (nested as JsonObject)[nestedKey];
  return typeof candidate === "number" ? candidate : null;
}

function parentPrefix(path: string): string {
  const normalized = path.replace(/\/+$/, "");
  if (!normalized.includes("/")) {
    return "";
  }
  return normalized.split("/").slice(0, -1).join("/") + "/";
}

function triggerBrowserDownloadFromUrl(url: string) {
  const anchor = document.createElement("a");
  anchor.href = url;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}
