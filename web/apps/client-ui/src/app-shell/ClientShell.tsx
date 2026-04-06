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
  ColorSchemeControl,
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
  restoreStorePathFromSnapshot,
  getVersionGraph,
  listSnapshots,
  listStoreEntries,
  putBinaryObject,
  putStoreValue,
  refreshClientRendezvous,
  renameStorePath,
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
import { ExplorerPage as ClientExplorerPage } from "../pages/ExplorerPage";
import { GalleryPage } from "../pages/GalleryPage";

type PageId = "overview" | "rendezvous" | "store" | "explorer" | "gallery" | "cluster";
type BinaryUploadQueueStatus =
  | "queued"
  | "starting"
  | "uploading"
  | "finalizing"
  | "complete"
  | "canceled"
  | "failed";
type BinaryUploadQueueItem = {
  id: string;
  sourceFile: File | null;
  filename: string;
  contentType: string;
  sizeBytes: number;
  key: string;
  progress: BinaryUploadProgress;
  status: BinaryUploadQueueStatus;
  error: string | null;
  speedBytesPerSecond: number | null;
  speedSampleUploadedBytes: number;
  speedSampleAtMs: number | null;
};
type BinaryUploadSummary = {
  totalFiles: number;
  totalBytes: number;
  uploadedBytes: number;
  queuedFiles: number;
  activeFiles: number;
  completedFiles: number;
  canceledFiles: number;
  failedFiles: number;
  percent: number;
  speedBytesPerSecond: number | null;
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
  enqueueFiles: (files: File[], rawTarget: string) => boolean;
  cancelItem: (id: string) => void;
  uploadQueuedFiles: () => Promise<void>;
  clearQueue: () => void;
};
const DEFAULT_BINARY_UPLOAD_CONCURRENCY = 2;
const MAX_BINARY_UPLOAD_CONCURRENCY = 8;
const BINARY_UPLOAD_SPEED_STALE_AFTER_MS = 4000;
const BINARY_UPLOAD_SPEED_SMOOTHING_FACTOR = 0.35;

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
    description: "Browse photo and movie objects through the shared media-aware store index."
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
              <ColorSchemeControl />
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

            {activePageId === "explorer" ? (
              <ClientExplorerPage
                queueFilesToPrefix={(files, targetPrefix) =>
                  binaryUpload.enqueueFiles(files, targetPrefix)
                }
                onOpenStore={() => setActivePageId("store")}
              />
            ) : null}

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
  const [speedNowMs, setSpeedNowMs] = useState(() => Date.now());
  const queueRef = useRef<BinaryUploadQueueItem[]>([]);
  const concurrencyRef = useRef(concurrency);
  const activeWorkersRef = useRef(0);
  const uploadControllersRef = useRef<Map<string, AbortController>>(new Map());

  const summary = useMemo<BinaryUploadSummary>(() => {
    return summarizeBinaryUploadQueue(queue, speedNowMs);
  }, [queue, speedNowMs]);
  const hasLiveTransfer = useMemo(
    () => queue.some((item) => isBinaryUploadTransferSpeedStatus(item.status)),
    [queue]
  );

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
    const nextSummary = summarizeBinaryUploadQueue(nextQueue, Date.now());
    setLastResult({
      operation: "binary-upload-queue",
      active_concurrency: Math.min(
        clampBinaryUploadConcurrency(concurrencyRef.current),
        nextSummary.totalFiles
      ),
      total_files: nextSummary.totalFiles,
      completed_files: nextSummary.completedFiles,
      canceled_files: nextSummary.canceledFiles,
      failed_files: nextSummary.failedFiles,
      files: nextQueue.map((item) => ({
        key: item.key,
        filename: item.filename,
        size_bytes: item.sizeBytes,
        status:
          item.status === "failed"
            ? "failed"
            : item.status === "canceled"
              ? "canceled"
              : "complete",
        error: item.error ?? undefined
      }))
    });

    setNotice(buildBinaryUploadQueueCompletionNotice(nextSummary));
  }

  function claimNextQueuedItem(): BinaryUploadQueueItem | null {
    let claimed: BinaryUploadQueueItem | null = null;

    setQueueAndRef((current) => {
      const nextIndex = current.findIndex((item) => item.status === "queued");
      if (nextIndex < 0) {
        return current;
      }

      const nextItem = current[nextIndex];
      if (!nextItem.sourceFile) {
        return current.map((item, index) =>
          index === nextIndex
            ? {
                ...item,
                status: "failed",
                error: "Queued file source is no longer available."
              }
            : item
        );
      }

      claimed = {
        ...nextItem,
        progress: createBinaryUploadProgress(nextItem.sizeBytes),
        status: "starting",
        error: null
      };

      const next = [...current];
      next[nextIndex] = {
        ...claimed,
        sourceFile: null
      };
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
        const sourceFile = item.sourceFile;
        const controller = new AbortController();
        uploadControllersRef.current.set(item.id, controller);
        try {
          if (!sourceFile) {
            throw new Error("Queued file source is no longer available.");
          }

          const payload = await putBinaryObject(
            item.key,
            sourceFile,
            (progress) => {
              const measuredAtMs = Date.now();
              setQueueAndRef((current) =>
                current.map((entry) =>
                  entry.id === item.id
                    ? updateBinaryUploadQueueItemProgress(entry, progress, measuredAtMs)
                    : entry
                )
              );
            },
            {
              signal: controller.signal
            }
          );

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
                    error: null,
                    speedBytesPerSecond: null
                  }
                : entry
            )
          );
        } catch (nextError) {
          const canceled = isBinaryUploadAbortError(nextError);
          const message = canceled
            ? "Canceled by user."
            : nextError instanceof Error
              ? nextError.message
              : "Binary upload failed";

          setQueueAndRef((current) =>
            current.map((entry) =>
              entry.id === item.id
                ? {
                    ...entry,
                    status: canceled ? "canceled" : "failed",
                    error: message,
                    speedBytesPerSecond: null
                  }
                : entry
            )
          );
        } finally {
          uploadControllersRef.current.delete(item.id);
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
    enqueueFiles(selectedFiles, uploadKey);
    setSelectedFiles([]);
  }

  function enqueueFiles(files: File[], rawTarget: string): boolean {
    if (files.length === 0) {
      setNotice("Select one or more binary files first.");
      return false;
    }

    setUploadKey(rawTarget);

    const occupiedKeys = new Set(
      queueRef.current
        .filter(
          (item) =>
            item.status !== "complete" &&
            item.status !== "canceled" &&
            item.status !== "failed"
        )
        .map((item) => item.key)
    );
    const duplicateKeys: string[] = [];
    const nextQueueItems: BinaryUploadQueueItem[] = [];

    for (const file of files) {
      const key = deriveBinaryUploadKey(file, rawTarget, files.length > 1);
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
      return false;
    }

    setQueueAndRef((current) => [...current, ...nextQueueItems]);
    setNotice(
      duplicateKeys.length > 0
        ? `Queued ${nextQueueItems.length} file(s) and skipped ${duplicateKeys.length} duplicate upload key${duplicateKeys.length === 1 ? "" : "s"}.`
        : null
    );
    setLastResult({
      operation: "binary-upload-queue-add",
      queued_files: nextQueueItems.map((item) => ({
        key: item.key,
        filename: item.filename,
        size_bytes: item.sizeBytes
      })),
      skipped_duplicate_keys: duplicateKeys
    });

    ensureWorkersRunning();
    return true;
  }

  function cancelItem(id: string) {
    const existingItem = queueRef.current.find((item) => item.id === id);
    if (!existingItem) {
      return;
    }

    const controller = uploadControllersRef.current.get(id);

    setQueueAndRef((current) =>
      current.map((item) => {
        if (item.id !== id) {
          return item;
        }
        if (
          item.status === "complete" ||
          item.status === "failed" ||
          item.status === "canceled"
        ) {
          return item;
        }
        return {
          ...item,
          sourceFile: null,
          status: "canceled",
          error: "Canceled by user.",
          speedBytesPerSecond: null,
          speedSampleAtMs: null
        };
      })
    );

    if (
      existingItem.status === "complete" ||
      existingItem.status === "failed" ||
      existingItem.status === "canceled"
    ) {
      setQueueAndRef((current) => current.filter((item) => item.id !== id));
      return;
    }

    controller?.abort();
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

  useEffect(() => {
    if (!hasLiveTransfer) {
      return undefined;
    }

    const timer = window.setInterval(() => {
      setSpeedNowMs(Date.now());
    }, 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, [hasLiveTransfer]);

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
    enqueueFiles,
    cancelItem,
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
    cancelItem: handleCancelBinaryUploadItem,
    clearQueue: handleClearBinaryUploadQueue
  } = binaryUpload;
  const speedDisplayNowMs = Date.now();

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
        <Alert
          color={
            binaryUploadSummary.failedFiles > 0
              ? "red"
              : binaryUploadSummary.canceledFiles > 0
                ? "yellow"
                : "blue"
          }
        >
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
                    <Badge color={binaryUploadSummary.canceledFiles > 0 ? "yellow" : "gray"} variant="light">
                      {binaryUploadSummary.canceledFiles} canceled
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
                      {binaryUploadSummary.speedBytesPerSecond !== null
                        ? `${formatBinaryTransferSpeed(binaryUploadSummary.speedBytesPerSecond)} overall`
                        : binaryUploadQueue.some((item) => isBinaryUploadTransferSpeedStatus(item.status))
                          ? "Measuring speed..."
                          : binaryUploadRunning && binaryUploadSummary.activeFiles > 0
                            ? "Finalizing..."
                          : "No active transfer"}
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
                          <Table.Th>Action</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {binaryUploadQueue.map((item) => (
                          <Table.Tr key={item.id}>
                            <Table.Td>
                              <Stack gap={0}>
                                <Text size="sm" fw={600}>
                                  {item.filename}
                                </Text>
                                <Text size="xs" c="dimmed">
                                  {item.contentType}
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
                                  {renderBinaryUploadItemSpeed(item, speedDisplayNowMs)}
                                </Text>
                                <Text size="xs" c="dimmed">
                                  {item.progress.uploadedChunks} / {item.progress.totalChunks || 0} chunks acknowledged
                                </Text>
                              </Stack>
                            </Table.Td>
                            <Table.Td>{formatExplorerSize(item.sizeBytes)}</Table.Td>
                            <Table.Td>
                              <Text size="xs" c={item.status === "failed" ? "red" : "dimmed"}>
                                {item.error ?? "—"}
                              </Text>
                            </Table.Td>
                            <Table.Td>
                              <Button
                                variant="subtle"
                                color={binaryUploadActionColor(item.status)}
                                size="xs"
                                onClick={() => handleCancelBinaryUploadItem(item.id)}
                                aria-label={`${binaryUploadActionLabel(item.status)} ${item.filename}`}
                              >
                                {binaryUploadActionLabel(item.status)}
                              </Button>
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

function formatBinaryTransferSpeed(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value) || value <= 0) {
    return "—";
  }
  return `${formatExplorerSize(Math.round(value))}/s`;
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
    sourceFile: file,
    filename: file.name,
    contentType: file.type || "application/octet-stream",
    sizeBytes: file.size,
    key,
    progress: createBinaryUploadProgress(file.size),
    status: "queued",
    error: null,
    speedBytesPerSecond: null,
    speedSampleUploadedBytes: 0,
    speedSampleAtMs: null
  };
}

function updateBinaryUploadQueueItemProgress(
  entry: BinaryUploadQueueItem,
  progress: BinaryUploadProgress,
  measuredAtMs: number
): BinaryUploadQueueItem {
  if (entry.status === "canceled") {
    return entry;
  }

  let nextSpeed = entry.speedBytesPerSecond;

  if (progress.phase === "finalizing" || progress.phase === "complete") {
    nextSpeed = null;
  } else if (
    entry.speedSampleAtMs !== null &&
    progress.uploadedBytes > entry.speedSampleUploadedBytes
  ) {
    const elapsedMs = measuredAtMs - entry.speedSampleAtMs;
    if (elapsedMs > 0) {
      const instantSpeed =
        ((progress.uploadedBytes - entry.speedSampleUploadedBytes) * 1000) /
        elapsedMs;
      nextSpeed =
        nextSpeed === null
          ? instantSpeed
          : nextSpeed * (1 - BINARY_UPLOAD_SPEED_SMOOTHING_FACTOR) +
            instantSpeed * BINARY_UPLOAD_SPEED_SMOOTHING_FACTOR;
    }
  }

  return {
    ...entry,
    progress,
    status: binaryUploadQueueStatusFromProgress(progress),
    error: null,
    speedBytesPerSecond: nextSpeed,
    speedSampleUploadedBytes: progress.uploadedBytes,
    speedSampleAtMs: measuredAtMs
  };
}

function isBinaryUploadTransferSpeedStatus(
  status: BinaryUploadQueueStatus
): boolean {
  return status === "starting" || status === "uploading";
}

function currentBinaryUploadSpeed(
  item: BinaryUploadQueueItem,
  nowMs: number
): number | null {
  if (
    !isBinaryUploadTransferSpeedStatus(item.status) ||
    item.speedBytesPerSecond === null ||
    item.speedSampleAtMs === null
  ) {
    return null;
  }
  if (nowMs - item.speedSampleAtMs > BINARY_UPLOAD_SPEED_STALE_AFTER_MS) {
    return null;
  }
  return item.speedBytesPerSecond;
}

function renderBinaryUploadItemSpeed(
  item: BinaryUploadQueueItem,
  nowMs: number
): string {
  const speed = currentBinaryUploadSpeed(item, nowMs);
  if (speed !== null) {
    return `${formatBinaryTransferSpeed(speed)} current`;
  }
  if (isBinaryUploadTransferSpeedStatus(item.status)) {
    return "Measuring speed...";
  }
  if (item.status === "finalizing") {
    return "Finalizing...";
  }
  return "—";
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
  queue: BinaryUploadQueueItem[],
  nowMs: number
): BinaryUploadSummary {
  let totalBytes = 0;
  let uploadedBytes = 0;
  let queuedFiles = 0;
  let activeFiles = 0;
  let completedFiles = 0;
  let canceledFiles = 0;
  let failedFiles = 0;
  let speedBytesPerSecond = 0;
  let hasMeasuredSpeed = false;

  for (const item of queue) {
    totalBytes += item.status === "canceled"
      ? item.progress.uploadedBytes
      : item.progress.totalBytes;
    uploadedBytes += item.progress.uploadedBytes;
    const itemSpeed = currentBinaryUploadSpeed(item, nowMs);
    if (itemSpeed !== null) {
      speedBytesPerSecond += itemSpeed;
      hasMeasuredSpeed = true;
    }

    if (item.status === "queued") {
      queuedFiles += 1;
    } else if (item.status === "complete") {
      completedFiles += 1;
    } else if (item.status === "canceled") {
      canceledFiles += 1;
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
    canceledFiles,
    failedFiles,
    percent:
      totalBytes === 0 ? 0 : Math.round((uploadedBytes / Math.max(1, totalBytes)) * 100),
    speedBytesPerSecond: hasMeasuredSpeed ? speedBytesPerSecond : null
  };
}

function binaryUploadHeaderColor(
  summary: BinaryUploadSummary,
  running: boolean
): string {
  if (summary.failedFiles > 0) {
    return "red";
  }
  if (summary.canceledFiles > 0 && !running && summary.activeFiles === 0 && summary.queuedFiles === 0) {
    return "yellow";
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
    if (summary.speedBytesPerSecond !== null) {
      return `${baseLabel} · ${summary.percent}% · ${formatBinaryTransferSpeed(summary.speedBytesPerSecond)}`;
    }
    return `${baseLabel} · ${summary.percent}%`;
  }
  if (summary.failedFiles > 0 || summary.canceledFiles > 0) {
    const parts: string[] = [];
    if (summary.failedFiles > 0) {
      parts.push(`${summary.failedFiles} failed`);
    }
    if (summary.canceledFiles > 0) {
      parts.push(`${summary.canceledFiles} canceled`);
    }
    return `${baseLabel} · ${parts.join(", ")}`;
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
  if (status === "canceled") {
    return "yellow";
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
  if (phase === "canceled") {
    return "Canceled";
  }
  if (phase === "failed") {
    return "Failed";
  }
  return "Complete";
}

function binaryUploadActionLabel(status: BinaryUploadQueueStatus): string {
  if (
    status === "queued" ||
    status === "starting" ||
    status === "uploading" ||
    status === "finalizing"
  ) {
    return "Cancel";
  }
  return "Remove";
}

function binaryUploadActionColor(status: BinaryUploadQueueStatus): string {
  if (
    status === "queued" ||
    status === "starting" ||
    status === "uploading" ||
    status === "finalizing"
  ) {
    return "red";
  }
  return "gray";
}

function buildBinaryUploadQueueCompletionNotice(
  summary: BinaryUploadSummary
): string | null {
  const parts: string[] = [];
  if (summary.failedFiles > 0) {
    parts.push(
      `${summary.failedFiles} binary upload${summary.failedFiles === 1 ? "" : "s"} failed`
    );
  }
  if (summary.canceledFiles > 0) {
    parts.push(
      `${summary.canceledFiles} binary upload${summary.canceledFiles === 1 ? "" : "s"} canceled`
    );
  }
  if (parts.length === 0) {
    return null;
  }
  return `${parts.join(" and ")}. Inspect the queue for details.`;
}

function isBinaryUploadAbortError(error: unknown): boolean {
  return (
    error instanceof DOMException && error.name === "AbortError"
  ) || (
    error instanceof Error && error.name === "AbortError"
  );
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

function triggerBrowserDownloadFromUrl(url: string) {
  const anchor = document.createElement("a");
  anchor.href = url;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}
