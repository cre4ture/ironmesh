import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  clearAdminMediaCache,
  getClusterNodes,
  getRepairActivityStatus,
  getRendezvousConfig,
  getClusterSummary,
  getServerHealth,
  getStorageStatsCurrent,
  getStorageStatsHistory,
  getProcessStatsCurrent,
  getProcessStatsHistory,
  getProcessStatsMemory,
  getReplicationPlan,
  type StorageStatsSample,
  type ProcessStatsSample,
  type ChildProcessStat,
  type TemperatureComponentStat,
  type MemoryAttributionSample
} from "@ironmesh/api";
import { ironmeshUiRevision, ironmeshUiVersion } from "@ironmesh/config";
import {
  ActionIcon,
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Grid,
  Group,
  Loader,
  Modal,
  ScrollArea,
  Stack,
  Table,
  Text,
  Tooltip as MantineTooltip
} from "@mantine/core";
import {
  ironmeshPrimaryColor,
  StatCard,
  ZoomableTimeSeriesChart,
  formatTimeSeriesChartTimestamp
} from "@ironmesh/ui";
import { useDisclosure } from "@mantine/hooks";
import { useCallback, useMemo, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps
} from "recharts";
import { formatBytes, formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

type StorageHistoryRangeKey = "24h" | "7d" | "30d" | "90d" | "1y" | "all";

const STORAGE_HISTORY_MAX_POINTS = 360;
const STORAGE_HISTORY_RANGE_OPTIONS: Array<{
  key: StorageHistoryRangeKey;
  label: string;
  windowSecs: number | null;
}> = [
  { key: "24h", label: "24h", windowSecs: 24 * 60 * 60 },
  { key: "7d", label: "7d", windowSecs: 7 * 24 * 60 * 60 },
  { key: "30d", label: "30d", windowSecs: 30 * 24 * 60 * 60 },
  { key: "90d", label: "90d", windowSecs: 90 * 24 * 60 * 60 },
  { key: "1y", label: "1y", windowSecs: 365 * 24 * 60 * 60 },
  { key: "all", label: "All", windowSecs: null }
];

const EMPTY_STORAGE_HISTORY: StorageStatsSample[] = [];
const EMPTY_PROCESS_HISTORY: ProcessStatsSample[] = [];
const EMPTY_PROCESS_CHILDREN: ChildProcessStat[] = [];
const EMPTY_TEMPERATURE_COMPONENTS: TemperatureComponentStat[] = [];

const PROCESS_CHART_COLORS = { main: "#38bdf8", children: "#f59e0b" };
const PROCESS_TEMPERATURE_CHART_COLORS = { hottest: "#f97316", average: "#22c55e" };

type StorageStatsChartMetricKey =
  | "chunkStoreBytes"
  | "metadataFootprintBytes"
  | "latestSnapshotUniqueChunkBytes";

type StorageStatsChartPoint = {
  collectedAtMs: number;
  collectedAtUnix: number;
  chunkStoreBytes: number;
  metadataFootprintBytes: number;
  latestSnapshotUniqueChunkBytes: number;
};

const STORAGE_CHART_SERIES: Array<{
  key: StorageStatsChartMetricKey;
  label: string;
  color: string;
  badgeColor: string;
}> = [
  { key: "chunkStoreBytes", label: "Chunk store", color: "#38bdf8", badgeColor: "cyan" },
  { key: "metadataFootprintBytes", label: "Metadata footprint", color: "#f59e0b", badgeColor: "yellow" },
  {
    key: "latestSnapshotUniqueChunkBytes",
    label: "Latest snapshot unique",
    color: "#34d399",
    badgeColor: ironmeshPrimaryColor
  }
];

export function DashboardPage() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const [storageHistoryRange, setStorageHistoryRange] = useState<StorageHistoryRangeKey>("30d");
  const [clearMediaCacheOpened, clearMediaCacheDisclosure] = useDisclosure(false);
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canRunAdminMaintenance =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);
  const canInspectCluster = canRunAdminMaintenance;
  const canInspectRendezvous = canRunAdminMaintenance;

  const backendHealthQuery = useQuery({
    queryKey: ["dashboard", "health"],
    queryFn: () => getServerHealth()
  });
  const storageStatsQuery = useQuery({
    queryKey: ["dashboard", "storage-stats-current", normalizedAdminTokenOverride],
    queryFn: () => getStorageStatsCurrent(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster
  });
  const storageHistoryQuery = useQuery({
    queryKey: ["dashboard", "storage-stats-history", storageHistoryRange, normalizedAdminTokenOverride],
    queryFn: () => getStorageStatsHistory(storageHistoryRequestForRange(storageHistoryRange), normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster
  });
  const processStatsCurrentQuery = useQuery({
    queryKey: ["dashboard", "process-stats-current", normalizedAdminTokenOverride],
    queryFn: () => getProcessStatsCurrent(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster,
    refetchInterval: 3_000
  });
  const processStatsHistoryQuery = useQuery({
    queryKey: ["dashboard", "process-stats-history", normalizedAdminTokenOverride],
    queryFn: () => getProcessStatsHistory(undefined, normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster,
    refetchInterval: 3_000
  });
  const processStatsMemoryQuery = useQuery({
    queryKey: ["dashboard", "process-stats-memory", normalizedAdminTokenOverride],
    queryFn: () => getProcessStatsMemory(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster,
    refetchInterval: 5_000
  });
  const clusterSummaryQuery = useQuery({
    queryKey: ["dashboard", "cluster-summary", normalizedAdminTokenOverride],
    queryFn: () =>
      getClusterSummary(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster
  });
  const nodesQuery = useQuery({
    queryKey: ["dashboard", "cluster-nodes", normalizedAdminTokenOverride],
    queryFn: () => getClusterNodes(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster
  });
  const replicationPlanQuery = useQuery({
    queryKey: ["dashboard", "replication-plan", normalizedAdminTokenOverride],
    queryFn: () => getReplicationPlan(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster
  });
  const repairActivityQuery = useQuery({
    queryKey: ["dashboard", "repair-activity", normalizedAdminTokenOverride],
    queryFn: () => getRepairActivityStatus(normalizedAdminTokenOverride || undefined),
    enabled: canInspectCluster,
    refetchInterval: 3_000
  });
  const rendezvousConfigQuery = useQuery({
    queryKey: ["dashboard", "rendezvous-config", normalizedAdminTokenOverride],
    queryFn: () => getRendezvousConfig(normalizedAdminTokenOverride || undefined),
    enabled: canInspectRendezvous
  });

  const refresh = useCallback(async () => {
    const queryKeys: ReadonlyArray<readonly unknown[]> = [
      ["dashboard", "health"],
      ["dashboard", "storage-stats-current"],
      ["dashboard", "storage-stats-history", storageHistoryRange],
      ...(canInspectCluster
        ? [
            ["dashboard", "cluster-summary", normalizedAdminTokenOverride],
            ["dashboard", "cluster-nodes", normalizedAdminTokenOverride],
            ["dashboard", "replication-plan", normalizedAdminTokenOverride],
            ["dashboard", "repair-activity", normalizedAdminTokenOverride],
            ["dashboard", "process-stats-current", normalizedAdminTokenOverride],
            ["dashboard", "process-stats-history", normalizedAdminTokenOverride],
            ["dashboard", "process-stats-memory", normalizedAdminTokenOverride]
          ]
        : []),
      ...(canInspectRendezvous
        ? [["dashboard", "rendezvous-config", normalizedAdminTokenOverride]]
        : [])
    ];

    await Promise.all(
      queryKeys.map((queryKey) =>
        queryClient.refetchQueries({
          queryKey,
          exact: true
        })
      )
    );
  }, [
    canInspectCluster,
    canInspectRendezvous,
    normalizedAdminTokenOverride,
    queryClient,
    storageHistoryRange
  ]);

  const mediaCacheClearMutation = useMutation({
    mutationFn: () => clearAdminMediaCache(normalizedAdminTokenOverride || undefined),
    onSuccess: async () => {
      clearMediaCacheDisclosure.close();
      await refresh();
    }
  });

  const clusterSummary =
    canInspectCluster ? clusterSummaryQuery.data ?? null : null;
  const nodes = canInspectCluster ? nodesQuery.data ?? [] : [];
  const replicationPlan =
    canInspectCluster ? replicationPlanQuery.data ?? null : null;
  const repairActivity =
    canInspectCluster ? repairActivityQuery.data ?? null : null;
  const rendezvousConfig =
    canInspectRendezvous && !rendezvousConfigQuery.isError
      ? rendezvousConfigQuery.data ?? null
      : null;
  const backendHealth = backendHealthQuery.data ?? null;
  const storageStats = storageStatsQuery.data ?? null;
  const storageHistory = storageHistoryQuery.data ?? EMPTY_STORAGE_HISTORY;
  const processStatsCurrent =
    canInspectCluster ? processStatsCurrentQuery.data ?? null : null;
  const processStatsHistory =
    canInspectCluster ? processStatsHistoryQuery.data ?? EMPTY_PROCESS_HISTORY : EMPTY_PROCESS_HISTORY;
  const memoryAttribution: MemoryAttributionSample | null =
    canInspectCluster ? processStatsMemoryQuery.data ?? null : null;
  const mediaCacheClearResult = mediaCacheClearMutation.data ?? null;
  const mediaCacheClearPending = mediaCacheClearMutation.isPending;
  const loading =
    backendHealthQuery.isFetching ||
    storageStatsQuery.isFetching ||
    storageHistoryQuery.isFetching ||
    (canInspectCluster &&
      (clusterSummaryQuery.isFetching ||
        nodesQuery.isFetching ||
        replicationPlanQuery.isFetching ||
        repairActivityQuery.isFetching ||
        processStatsCurrentQuery.isFetching ||
        processStatsHistoryQuery.isFetching ||
        processStatsMemoryQuery.isFetching)) ||
    (canInspectRendezvous && rendezvousConfigQuery.isFetching);
  const error = firstErrorMessage([
    mediaCacheClearMutation.error,
    backendHealthQuery.error,
    storageStatsQuery.error,
    storageHistoryQuery.error,
    canInspectCluster ? clusterSummaryQuery.error : null,
    canInspectCluster ? nodesQuery.error : null,
    canInspectCluster ? replicationPlanQuery.error : null,
    canInspectCluster ? repairActivityQuery.error : null,
    canInspectCluster ? processStatsCurrentQuery.error : null,
    canInspectCluster ? processStatsHistoryQuery.error : null,
    canInspectCluster ? processStatsMemoryQuery.error : null
  ]);

  async function confirmMediaCacheClear() {
    await mediaCacheClearMutation.mutateAsync();
  }

  const localNode = clusterSummary
    ? nodes.find((node) => node.node_id === clusterSummary.local_node_id) ?? null
    : null;
  const connectedRendezvousEndpoints =
    rendezvousConfig?.endpoint_registrations.filter((endpoint) => endpoint.status === "connected") ?? [];
  const versionMismatch = Boolean(backendHealth?.version) && backendHealth?.version !== ironmeshUiVersion;
  const latestStorageSample = storageStats?.sample ?? null;
  const metadataFootprintBytes = latestStorageSample
    ? latestStorageSample.metadata_db_bytes +
      latestStorageSample.manifest_store_bytes +
      latestStorageSample.media_cache_bytes
    : null;
  const storageHistoryChronological = useMemo(
    () => [...storageHistory].reverse(),
    [storageHistory]
  );
  const selectedStorageHistoryRange =
    STORAGE_HISTORY_RANGE_OPTIONS.find((option) => option.key === storageHistoryRange) ??
    STORAGE_HISTORY_RANGE_OPTIONS[0];
  const latestProcessSample = processStatsCurrent?.sample ?? null;
  const processChildren = processStatsCurrent?.children ?? EMPTY_PROCESS_CHILDREN;
  const temperatureComponents =
    processStatsCurrent?.temperature_components ?? EMPTY_TEMPERATURE_COMPONENTS;
  const hottestTemperatureComponent =
    temperatureComponents.find((component) => component.temperature_celsius !== null && component.temperature_celsius !== undefined) ??
    null;
  const reportingTemperatureComponentCount = temperatureComponents.filter(
    (component) => component.temperature_celsius !== null && component.temperature_celsius !== undefined
  ).length;

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={680}>
          The dashboard focuses on the current cluster shape, replication pressure, and node health.
          Refreshing keeps the cards fast, while repair payloads and diagnostics still stay close to the backend during
          the migration.
        </Text>
        <Group>
          <Button variant="light" onClick={() => void refresh()} loading={loading}>
          Refresh
          </Button>
        </Group>
      </Group>
      {error ? <Alert color="red" title="Failed to load dashboard">{error}</Alert> : null}
      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Cluster Nodes"
            value={
              clusterSummary ? `${clusterSummary.online_nodes} / ${clusterSummary.total_nodes}` : loading ? <Loader size="sm" /> : "unknown"
            }
            hint="Online / total nodes"
            testId="dashboard-cluster-nodes-card"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Offline Nodes"
            value={clusterSummary ? clusterSummary.offline_nodes : loading ? <Loader size="sm" /> : "unknown"}
            hint="Detected from cluster heartbeats"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Replication Factor"
            value={
              clusterSummary ? clusterSummary.policy.replication_factor : loading ? <Loader size="sm" /> : "unknown"
            }
            hint="Current cluster replication policy"
          />
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Under-replicated Items"
            value={replicationPlan?.under_replicated ?? (loading ? <Loader size="sm" /> : "unknown")}
            hint="Items still missing desired copies"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Over-replicated Items"
            value={replicationPlan?.over_replicated ?? (loading ? <Loader size="sm" /> : "unknown")}
            hint="Items with extra copies pending cleanup"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Deferred Cleanup"
            value={replicationPlan?.cleanup_deferred_items ?? (loading ? <Loader size="sm" /> : "unknown")}
            hint="Items whose cleanup is intentionally deferred"
          />
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Chunk Store"
            value={
              latestStorageSample
                ? formatBytes(latestStorageSample.chunk_store_bytes)
                : storageStats?.collecting || loading
                  ? <Loader size="sm" />
                  : "pending"
            }
            hint="Chunk bytes currently stored on disk"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Metadata Footprint"
            value={
              metadataFootprintBytes !== null
                ? formatBytes(metadataFootprintBytes)
                : storageStats?.collecting || loading
                  ? <Loader size="sm" />
                  : "pending"
            }
            hint="Metadata DB, manifests, and media cache"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Latest Snapshot Unique"
            value={
              latestStorageSample
                ? formatBytes(latestStorageSample.latest_snapshot_unique_chunk_bytes)
                : storageStats?.collecting || loading
                  ? <Loader size="sm" />
                  : "pending"
            }
            hint="Deduplicated bytes referenced by the latest snapshot"
          />
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>This node</Text>
              <Group gap="sm">
                <Badge variant="light">
                  {clusterSummary?.local_node_id ?? (loading ? "loading" : "unknown")}
                </Badge>
                <Badge
                  color={localNode?.reachability.relay_required ? ironmeshPrimaryColor : "blue"}
                  variant="light"
                >
                  {localNode?.reachability.relay_required ? "relay-required" : "direct-capable"}
                </Badge>
              </Group>
              <Text size="sm">
                Public API: <Code>{localNode?.reachability.public_api_url ?? "not advertised"}</Code>
              </Text>
              <Text size="sm">
                Peer API: <Code>{localNode?.reachability.peer_api_url ?? "not advertised"}</Code>
              </Text>
              <Text size="sm" c="dimmed">
                The admin UI itself is served directly by this node.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Version info</Text>
              <Text size="sm">
                UI build: <Code>{formatFullVersion(ironmeshUiVersion, ironmeshUiRevision)}</Code>
              </Text>
              <Text size="sm">
                Backend build: <Code>{formatFullVersion(backendHealth?.version, backendHealth?.revision)}</Code>
              </Text>
              {versionMismatch ? (
                <Alert color="yellow" variant="light">
                  The bundled server-admin UI version does not match the running backend version.
                </Alert>
              ) : (
                <Text size="sm" c="dimmed">
                  UI and backend build details are shown here directly for easier operator diagnostics.
                </Text>
              )}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Group justify="space-between" align="flex-start">
                <Text fw={700}>Repair activity</Text>
                <Badge color={repairActivityBadgeColor(repairActivity?.state)} variant="light">
                  {repairActivity ? formatRepairActivityState(repairActivity.state) : loading ? "loading" : "unknown"}
                </Badge>
              </Group>
              <Group gap="xs">
                <Badge color={startupStatusColor(repairActivity?.startup_status)} variant="light">
                  startup {formatStartupRepairStatus(repairActivity?.startup_status ?? "disabled")}
                </Badge>
                <Badge variant="light">
                  {repairActivity
                    ? `${repairActivity.active_runs.length} active`
                    : loading
                      ? "loading"
                      : "unknown"}
                </Badge>
              </Group>
              <Text size="sm">
                {describeDashboardRepairSummary(repairActivity, replicationPlan)}
              </Text>
              <Text size="sm" c="dimmed">
                Detailed plan inspection, retained repair history, and the manual repair control now live on the Repair page.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Rendezvous participation</Text>
              <Group gap="sm">
                <Badge
                  color={rendezvousConfig?.registration_enabled ? ironmeshPrimaryColor : "gray"}
                  variant="light"
                >
                  {rendezvousConfig?.registration_enabled ? "registration enabled" : "registration disabled"}
                </Badge>
                <Badge
                  color={connectedRendezvousEndpoints.length > 0 ? "green" : "gray"}
                  variant="light"
                >
                  {rendezvousConfig
                    ? `${connectedRendezvousEndpoints.length}/${rendezvousConfig.endpoint_registrations.length} connected`
                    : loading
                      ? "loading"
                      : "unknown"}
                </Badge>
              </Group>
              <Text size="sm">
                Embedded listener: <Code>{rendezvousConfig?.managed_embedded_url ?? "not hosted here"}</Code>
              </Text>
              <Text size="sm">
                Connected rendezvous:{" "}
                <Code>
                  {connectedRendezvousEndpoints[0]?.url ??
                    rendezvousConfig?.effective_urls[0] ??
                    "none configured"}
                </Code>
              </Text>
              {!canInspectRendezvous ? (
                <Text size="sm" c="dimmed">
                  Sign in with the local admin password to inspect the live rendezvous registration details here.
                </Text>
              ) : null}
              <Text size="sm" c="dimmed">
                Full rendezvous URL editing and failover workflows remain on the Control Plane page.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Group justify="space-between" align="flex-start">
                <Stack gap={4}>
                  <Text fw={700}>Storage stats</Text>
                  <Text size="sm" c="dimmed" maw={760}>
                    Background collection keeps these numbers off the request path. The chart shows chunk-store growth,
                    metadata footprint, and the deduplicated size of the latest snapshot over time.
                  </Text>
                  <Text size="sm" c="dimmed">
                    {describeStorageHistoryWindow(
                      selectedStorageHistoryRange.label,
                      storageHistoryChronological
                    )}
                  </Text>
                </Stack>
                <Stack gap="xs" align="flex-end">
                  <Group gap="xs">
                    <Badge variant="light" color={storageStats?.collecting ? "blue" : "gray"}>
                      {storageStats?.collecting ? "collecting" : "idle"}
                    </Badge>
                    <Badge variant="light">
                      {storageStats?.last_success_unix
                        ? `updated ${formatUnixTs(storageStats.last_success_unix)}`
                        : "no sample yet"}
                    </Badge>
                  </Group>
                  <Group gap={6}>
                    {STORAGE_HISTORY_RANGE_OPTIONS.map((option) => (
                      <Button
                        key={option.key}
                        size="xs"
                        variant={option.key === storageHistoryRange ? "filled" : "default"}
                        onClick={() => setStorageHistoryRange(option.key)}
                      >
                        {option.label}
                      </Button>
                    ))}
                  </Group>
                </Stack>
              </Group>
              {storageStats?.last_error ? (
                <Alert color="yellow" variant="light" title="Latest storage stats refresh failed">
                  {storageStats.last_error}
                </Alert>
              ) : null}
              <StorageStatsSparkline samples={storageHistoryChronological} />
              <Grid>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <Text size="sm">
                    Latest snapshot ID:{" "}
                    <Code>{latestStorageSample?.latest_snapshot_id ?? "none yet"}</Code>
                  </Text>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <Text size="sm">
                    Snapshot objects:{" "}
                    <Code>{String(latestStorageSample?.latest_snapshot_object_count ?? 0)}</Code>
                  </Text>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <Text size="sm">
                    Snapshot logical size:{" "}
                    <Code>
                      {latestStorageSample
                        ? formatBytes(latestStorageSample.latest_snapshot_logical_bytes)
                        : "pending"}
                    </Code>
                  </Text>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <Text size="sm">
                    Sampled at:{" "}
                    <Code>
                      {latestStorageSample
                        ? formatUnixTs(latestStorageSample.collected_at_unix)
                        : "pending"}
                    </Code>
                  </Text>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Text size="sm">
                    Metadata DB:{" "}
                    <Code>
                      {latestStorageSample ? formatBytes(latestStorageSample.metadata_db_bytes) : "pending"}
                    </Code>
                  </Text>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Text size="sm">
                    Manifest store:{" "}
                    <Code>
                      {latestStorageSample ? formatBytes(latestStorageSample.manifest_store_bytes) : "pending"}
                    </Code>
                  </Text>
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <Text size="sm">
                    Media cache:{" "}
                    <Code>
                      {latestStorageSample ? formatBytes(latestStorageSample.media_cache_bytes) : "pending"}
                    </Code>
                  </Text>
                </Grid.Col>
              </Grid>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Group justify="space-between" align="flex-start">
                <Stack gap={4}>
                  <Text fw={700}>Process resource usage</Text>
                  <Text size="sm" c="dimmed" maw={760}>
                    CPU, memory, disk I/O, and temperature sensors for the ironmesh server host,
                    sampled every few seconds. Child processes (e.g. ffmpeg during video thumbnail
                    generation) are tracked separately.
                  </Text>
                </Stack>
                <Badge variant="light">
                  {latestProcessSample
                    ? `updated ${formatUnixTs(latestProcessSample.collected_at_unix)}`
                    : "no sample yet"}
                </Badge>
              </Group>
              <Grid>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Main Process CPU"
                    value={
                      latestProcessSample
                        ? `${latestProcessSample.main_cpu_percent.toFixed(1)}%`
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      processStatsCurrent
                        ? `of ${processStatsCurrent.logical_cpu_count} logical cores`
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Main Process RAM"
                    value={
                      latestProcessSample
                        ? formatBytes(latestProcessSample.main_memory_bytes)
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Main Process Disk I/O"
                    value={
                      latestProcessSample
                        ? `R ${formatBytes(latestProcessSample.main_disk_read_bytes_per_sec)}/s`
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      latestProcessSample
                        ? `W ${formatBytes(latestProcessSample.main_disk_write_bytes_per_sec)}/s`
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Child Processes CPU"
                    value={
                      latestProcessSample
                        ? `${latestProcessSample.children_cpu_percent.toFixed(1)}%`
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      latestProcessSample
                        ? `${latestProcessSample.children_count} process${latestProcessSample.children_count === 1 ? "" : "es"} running`
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Child Processes RAM"
                    value={
                      latestProcessSample
                        ? formatBytes(latestProcessSample.children_memory_bytes)
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Child Processes Disk I/O"
                    value={
                      latestProcessSample
                        ? `R ${formatBytes(latestProcessSample.children_disk_read_bytes_per_sec)}/s`
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      latestProcessSample
                        ? `W ${formatBytes(latestProcessSample.children_disk_write_bytes_per_sec)}/s`
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Peak Temperature"
                    value={
                      latestProcessSample
                        ? formatTemperature(latestProcessSample.hottest_temperature_celsius)
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      hottestTemperatureComponent
                        ? `${hottestTemperatureComponent.label}`
                        : latestProcessSample
                          ? "No reporting sensors"
                          : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Average Temperature"
                    value={
                      latestProcessSample
                        ? formatTemperature(latestProcessSample.average_temperature_celsius)
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      latestProcessSample
                        ? `${latestProcessSample.temperature_reporting_component_count ?? reportingTemperatureComponentCount} reporting sensor${(latestProcessSample.temperature_reporting_component_count ?? reportingTemperatureComponentCount) === 1 ? "" : "s"}`
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Temperature Sensors"
                    value={
                      latestProcessSample
                        ? (latestProcessSample.temperature_component_count ?? temperatureComponents.length) > 0
                          ? `${latestProcessSample.temperature_reporting_component_count ?? reportingTemperatureComponentCount} / ${latestProcessSample.temperature_component_count ?? temperatureComponents.length}`
                          : "not available"
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint="Reporting / discovered"
                  />
                </Grid.Col>
              </Grid>
              <ProcessStatsCharts samples={processStatsHistory} />
              <Stack gap={6}>
                <Text size="sm" fw={600}>Running child processes</Text>
                {processChildren.length === 0 ? (
                  <Text size="sm" c="dimmed">No child processes currently running.</Text>
                ) : (
                  <ScrollArea type="auto">
                    <Table striped highlightOnHover withTableBorder>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>PID</Table.Th>
                          <Table.Th>Name</Table.Th>
                          <Table.Th>CPU</Table.Th>
                          <Table.Th>RAM</Table.Th>
                          <Table.Th>Disk read</Table.Th>
                          <Table.Th>Disk write</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {processChildren.map((child) => (
                          <Table.Tr key={child.pid}>
                            <Table.Td>{child.pid}</Table.Td>
                            <Table.Td>{child.name}</Table.Td>
                            <Table.Td>{child.cpu_percent.toFixed(1)}%</Table.Td>
                            <Table.Td>{formatBytes(child.memory_bytes)}</Table.Td>
                            <Table.Td>{formatBytes(child.disk_read_bytes_per_sec)}/s</Table.Td>
                            <Table.Td>{formatBytes(child.disk_write_bytes_per_sec)}/s</Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </ScrollArea>
                )}
              </Stack>
              <Stack gap={6}>
                <Text size="sm" fw={600}>Temperature sensors</Text>
                {temperatureComponents.length === 0 ? (
                  <Text size="sm" c="dimmed">No temperature sensors currently reporting.</Text>
                ) : (
                  <ScrollArea type="auto">
                    <Table striped highlightOnHover withTableBorder>
                      <Table.Thead>
                        <Table.Tr>
                          <Table.Th>Sensor</Table.Th>
                          <Table.Th>Current</Table.Th>
                          <Table.Th>Max</Table.Th>
                          <Table.Th>Critical</Table.Th>
                        </Table.Tr>
                      </Table.Thead>
                      <Table.Tbody>
                        {temperatureComponents.map((component, index) => (
                          <Table.Tr key={`${component.label}-${index}`}>
                            <Table.Td>{component.label}</Table.Td>
                            <Table.Td>{formatOptionalTemperature(component.temperature_celsius)}</Table.Td>
                            <Table.Td>{formatOptionalTemperature(component.max_celsius)}</Table.Td>
                            <Table.Td>{formatOptionalTemperature(component.critical_celsius)}</Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </ScrollArea>
                )}
              </Stack>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Group justify="space-between" align="flex-start">
                <Stack gap={4}>
                  <Text fw={700}>Memory attribution</Text>
                  <Text size="sm" c="dimmed" maw={760}>
                    Why the process RSS above is what it is, not just what it is. See{" "}
                    <Code>docs/node-memory-footprint-reduction-plan.md</Code> for the full analysis.
                  </Text>
                </Stack>
                <Badge variant="light">
                  {memoryAttribution
                    ? `updated ${formatUnixTs(memoryAttribution.collected_at_unix)}`
                    : "no sample yet"}
                </Badge>
              </Group>
              <Grid>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Current-objects cache"
                    value={
                      memoryAttribution
                        ? `${memoryAttribution.current_objects_cache.resident_entries} / ${memoryAttribution.current_objects_cache.capacity}`
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      memoryAttribution
                        ? `~${formatBytes(memoryAttribution.current_objects_cache.estimated_resident_bytes)} resident, of ${memoryAttribution.current_objects_total_count} total objects`
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="In-flight uploads"
                    value={
                      memoryAttribution
                        ? `${memoryAttribution.in_flight_upload_session_count} session${memoryAttribution.in_flight_upload_session_count === 1 ? "" : "s"}`
                        : loading
                          ? <Loader size="sm" />
                          : "pending"
                    }
                    hint={
                      memoryAttribution
                        ? formatBytes(memoryAttribution.in_flight_upload_bytes)
                        : undefined
                    }
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 4 }}>
                  <StatCard
                    label="Last GC pass"
                    value={
                      memoryAttribution?.last_gc_pass
                        ? `${memoryAttribution.last_gc_pass.retained_manifests_processed} manifests`
                        : loading
                          ? <Loader size="sm" />
                          : "no pass yet"
                    }
                    hint={
                      memoryAttribution?.last_gc_pass
                        ? `batch ≤ ${memoryAttribution.last_gc_pass.peak_manifest_batch_size}, ${formatUnixTs(memoryAttribution.last_gc_pass.collected_at_unix)}${memoryAttribution.last_gc_pass.dry_run ? " (dry run)" : ""}`
                        : "triggered manually via maintenance/cleanup"
                    }
                  />
                </Grid.Col>
              </Grid>
              <Text size="xs" c="dimmed">
                FUSE hydrated-file memory isn't attributed here yet — it's tracked client-side, not
                by this server process, and the corresponding budget/eviction gauge lands with Slice 1.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 12 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Cluster nodes</Text>
                <Badge variant="light">{nodes.length} discovered</Badge>
              </Group>
              <ScrollArea type="auto">
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Node</Table.Th>
                      <Table.Th>Status</Table.Th>
                      <Table.Th>Reachability</Table.Th>
                      <Table.Th>Capacity</Table.Th>
                      <Table.Th>Free</Table.Th>
                      <Table.Th>Chunk Store</Table.Th>
                      <Table.Th>Metadata</Table.Th>
                      <Table.Th>Snapshot</Table.Th>
                      <Table.Th>Last heartbeat</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {nodes.length > 0 ? (
                      nodes.map((node) => {
                        const nodeStorageStats = node.storage_stats ?? null;
                        const metadataFootprintBytes = nodeStorageStats
                          ? nodeStorageStats.metadata_db_bytes +
                            nodeStorageStats.manifest_store_bytes +
                            nodeStorageStats.media_cache_bytes
                          : null;

                        return (
                        <Table.Tr key={node.node_id}>
                          <Table.Td>{node.node_id}</Table.Td>
                          <Table.Td>
                            <Badge color={node.status === "online" ? ironmeshPrimaryColor : "gray"} variant="light">
                              {node.status}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            {node.reachability.relay_required
                              ? "relay-required"
                              : node.reachability.public_api_url || node.reachability.peer_api_url || "direct endpoint not advertised"}
                          </Table.Td>
                          <Table.Td>{formatBytes(node.capacity_bytes)}</Table.Td>
                          <Table.Td>{formatBytes(node.free_bytes)}</Table.Td>
                          <Table.Td>
                            {nodeStorageStats ? (
                              <Stack gap={2}>
                                <Text size="sm">{formatBytes(nodeStorageStats.chunk_store_bytes)}</Text>
                                <Text size="xs" c="dimmed">
                                  {formatUnixTs(nodeStorageStats.collected_at_unix)}
                                </Text>
                              </Stack>
                            ) : (
                              <Text size="sm" c="dimmed">pending</Text>
                            )}
                          </Table.Td>
                          <Table.Td>
                            {metadataFootprintBytes !== null ? (
                              <Text size="sm">{formatBytes(metadataFootprintBytes)}</Text>
                            ) : (
                              <Text size="sm" c="dimmed">pending</Text>
                            )}
                          </Table.Td>
                          <Table.Td>
                            {nodeStorageStats ? (
                              <Stack gap={2}>
                                <Text size="sm">
                                  {formatBytes(nodeStorageStats.latest_snapshot_unique_chunk_bytes)}
                                </Text>
                                <Text size="xs" c="dimmed">
                                  logical {formatBytes(nodeStorageStats.latest_snapshot_logical_bytes)}
                                </Text>
                              </Stack>
                            ) : (
                              <Text size="sm" c="dimmed">pending</Text>
                            )}
                          </Table.Td>
                          <Table.Td>{formatUnixTs(node.last_heartbeat_unix)}</Table.Td>
                        </Table.Tr>
                      )})
                    ) : (
                      <Table.Tr>
                        <Table.Td colSpan={9}>
                          <Text c="dimmed">No nodes discovered yet.</Text>
                        </Table.Td>
                      </Table.Tr>
                    )}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 5 }}>
          <Stack gap="lg">
            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Group justify="space-between" align="flex-start">
                  <Stack gap={4}>
                    <Text fw={700}>Media cache maintenance</Text>
                    <Text size="sm" c="dimmed">
                      Clears generated thumbnails and cached media metadata so they rebuild from source objects on the
                      next access.
                    </Text>
                  </Stack>
                  <Button
                    size="sm"
                    color="red"
                    variant="light"
                    disabled={!canRunAdminMaintenance}
                    loading={mediaCacheClearPending}
                    onClick={clearMediaCacheDisclosure.open}
                  >
                    Clear media cache
                  </Button>
                </Group>
                {mediaCacheClearResult ? (
                  <Alert color={ironmeshPrimaryColor} variant="light" title="Media cache cleared">
                    Cleared {mediaCacheClearResult.deleted_metadata_records} metadata records and{" "}
                    {mediaCacheClearResult.deleted_thumbnail_files} generated thumbnails (
                    {formatBytes(mediaCacheClearResult.deleted_thumbnail_bytes)}) at{" "}
                    {formatUnixTs(mediaCacheClearResult.cleared_at_unix)}.
                  </Alert>
                ) : null}
                {!canRunAdminMaintenance ? (
                  <Text size="sm" c="dimmed">
                    Sign in with the local admin password to run destructive maintenance actions from this page.
                  </Text>
                ) : (
                  <Text size="sm" c="dimmed">
                    Existing object data is untouched. The next gallery or index read will repopulate media metadata as
                    needed.
                  </Text>
                )}
              </Stack>
            </Card>
          </Stack>
        </Grid.Col>
      </Grid>
      <Modal
        opened={clearMediaCacheOpened}
        onClose={clearMediaCacheDisclosure.close}
        title="Clear media cache"
        centered
      >
        <Stack gap="md">
          <Text c="dimmed">
            This removes generated thumbnails and cached multimedia metadata from this node only. The source files stay
            intact, and thumbnails regenerate lazily the next time they are requested.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={clearMediaCacheDisclosure.close}>
              Cancel
            </Button>
            <Button
              color="red"
              onClick={() => void confirmMediaCacheClear()}
              loading={mediaCacheClearPending}
            >
              Clear cache
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
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

function firstErrorMessage(errors: Array<unknown>): string | null {
  for (const error of errors) {
    if (!error) {
      continue;
    }
    return error instanceof Error ? error.message : String(error);
  }
  return null;
}

function formatTemperature(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "not available";
  }
  return `${value.toFixed(1)} C`;
}

function formatOptionalTemperature(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return "unknown";
  }
  return `${value.toFixed(1)} C`;
}

function formatRepairActivityState(state: string): string {
  switch (state) {
    case "running":
      return "running";
    case "scheduled":
      return "scheduled";
    case "idle":
    default:
      return "idle";
  }
}

function formatStartupRepairStatus(status: string): string {
  switch (status) {
    case "disabled":
      return "disabled";
    case "scheduled":
      return "scheduled";
    case "running":
      return "running";
    case "skipped_no_gaps":
      return "skipped";
    case "completed":
      return "completed";
    default:
      return status;
  }
}

function repairActivityBadgeColor(state: string | undefined): string {
  switch (state) {
    case "running":
      return "orange";
    case "scheduled":
      return "blue";
    case "idle":
    default:
      return "gray";
  }
}

function startupStatusColor(status: string | undefined): string {
  switch (status) {
    case "running":
      return "orange";
    case "completed":
      return ironmeshPrimaryColor;
    case "skipped_no_gaps":
      return "blue";
    case "scheduled":
      return "gray";
    case "disabled":
    default:
      return "gray";
  }
}

function describeDashboardRepairSummary(
  repairActivity: {
    latest_run?: {
      finished_at_unix: number;
      summary?: {
        attempted_transfers: number;
        successful_transfers: number;
        failed_transfers: number;
        skipped_items: number;
      } | null;
    } | null;
  } | null,
  replicationPlan: {
    items: Array<unknown>;
    under_replicated: number;
    over_replicated: number;
    cleanup_deferred_items: number;
  } | null
): string {
  if (!repairActivity && !replicationPlan) {
    return "Repair state has not loaded yet.";
  }

  const latestRunText = repairActivity?.latest_run
    ? `Latest run finished ${formatUnixTs(repairActivity.latest_run.finished_at_unix)}.`
    : "No retained repair run yet.";
  const latestSummary = repairActivity?.latest_run?.summary
    ? `${repairActivity.latest_run.summary.attempted_transfers} attempted, ${repairActivity.latest_run.summary.successful_transfers} successful, ${repairActivity.latest_run.summary.failed_transfers} failed, ${repairActivity.latest_run.summary.skipped_items} skipped.`
    : null;
  const plannerText = replicationPlan
    ? `${replicationPlan.items.length} planner item${replicationPlan.items.length === 1 ? "" : "s"} remain (${replicationPlan.under_replicated} under, ${replicationPlan.over_replicated} over, ${replicationPlan.cleanup_deferred_items} deferred).`
    : "Planner state is not available.";

  return [latestRunText, latestSummary, plannerText].filter(Boolean).join(" ");
}

type ProcessChartMetricKey =
  | "mainCpuPercent"
  | "childrenCpuPercent"
  | "mainMemoryBytes"
  | "childrenMemoryBytes"
  | "mainDiskReadBytesPerSec"
  | "childrenDiskReadBytesPerSec"
  | "mainDiskWriteBytesPerSec"
  | "childrenDiskWriteBytesPerSec";

type ProcessChartPoint = {
  collectedAtMs: number;
  collectedAtUnix: number;
} & Record<ProcessChartMetricKey, number>;

type TemperatureChartPoint = {
  collectedAtMs: number;
  collectedAtUnix: number;
  hottestTemperatureCelsius: number | null;
  averageTemperatureCelsius: number | null;
};

function ProcessStatsCharts({ samples }: { samples: ProcessStatsSample[] }) {
  const chartPoints: ProcessChartPoint[] = useMemo(
    () =>
      samples.map((sample) => ({
        collectedAtMs: sample.collected_at_unix * 1000,
        collectedAtUnix: sample.collected_at_unix,
        mainCpuPercent: sample.main_cpu_percent,
        childrenCpuPercent: sample.children_cpu_percent,
        mainMemoryBytes: sample.main_memory_bytes,
        childrenMemoryBytes: sample.children_memory_bytes,
        mainDiskReadBytesPerSec: sample.main_disk_read_bytes_per_sec,
        childrenDiskReadBytesPerSec: sample.children_disk_read_bytes_per_sec,
        mainDiskWriteBytesPerSec: sample.main_disk_write_bytes_per_sec,
        childrenDiskWriteBytesPerSec: sample.children_disk_write_bytes_per_sec
      })),
    [samples]
  );
  const temperatureChartPoints: TemperatureChartPoint[] = useMemo(
    () =>
      samples.map((sample) => ({
        collectedAtMs: sample.collected_at_unix * 1000,
        collectedAtUnix: sample.collected_at_unix,
        hottestTemperatureCelsius: sample.hottest_temperature_celsius ?? null,
        averageTemperatureCelsius: sample.average_temperature_celsius ?? null
      })),
    [samples]
  );

  if (chartPoints.length === 0) {
    return <Text c="dimmed">No process stats samples collected yet.</Text>;
  }

  return (
    <Grid>
      <Grid.Col span={{ base: 12, md: 6 }}>
        <ProcessMetricChart
          points={chartPoints}
          mainKey="mainCpuPercent"
          childrenKey="childrenCpuPercent"
          title="CPU usage"
          yLabel="CPU %"
          yTickFormatter={(value) => `${value.toFixed(0)}%`}
          tooltipFormatter={(value) => `${value.toFixed(1)}%`}
        />
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 6 }}>
        <ProcessMetricChart
          points={chartPoints}
          mainKey="mainMemoryBytes"
          childrenKey="childrenMemoryBytes"
          title="Memory usage"
          yLabel="RAM"
          yTickFormatter={(value) => formatBytes(value)}
          tooltipFormatter={(value) => formatBytes(value)}
        />
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 6 }}>
        <ProcessMetricChart
          points={chartPoints}
          mainKey="mainDiskReadBytesPerSec"
          childrenKey="childrenDiskReadBytesPerSec"
          title="Disk read"
          yLabel="Bytes/s"
          yTickFormatter={(value) => `${formatBytes(value)}/s`}
          tooltipFormatter={(value) => `${formatBytes(value)}/s`}
        />
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 6 }}>
        <ProcessMetricChart
          points={chartPoints}
          mainKey="mainDiskWriteBytesPerSec"
          childrenKey="childrenDiskWriteBytesPerSec"
          title="Disk write"
          yLabel="Bytes/s"
          yTickFormatter={(value) => `${formatBytes(value)}/s`}
          tooltipFormatter={(value) => `${formatBytes(value)}/s`}
        />
      </Grid.Col>
      <Grid.Col span={{ base: 12, md: 6 }}>
        <ProcessTemperatureChart points={temperatureChartPoints} />
      </Grid.Col>
    </Grid>
  );
}

function ProcessMetricChart({
  points,
  mainKey,
  childrenKey,
  title,
  yLabel,
  yTickFormatter,
  tooltipFormatter
}: {
  points: ProcessChartPoint[];
  mainKey: ProcessChartMetricKey;
  childrenKey: ProcessChartMetricKey;
  title: string;
  yLabel: string;
  yTickFormatter: (value: number) => string;
  tooltipFormatter: (value: number) => string;
}) {
  const yMax = Math.max(1, ...points.map((point) => Math.max(point[mainKey], point[childrenKey])));

  return (
    <Stack gap={6}>
      <Group justify="space-between" wrap="nowrap">
        <Text size="sm" fw={600}>
          {title}
        </Text>
        <Group gap="xs">
          <Badge variant="light" color="cyan">
            Main process
          </Badge>
          <Badge variant="light" color="yellow">
            Child processes
          </Badge>
        </Group>
      </Group>
      <ZoomableTimeSeriesChart
        points={points}
        height="12rem"
        emptyState={<Text c="dimmed">No samples collected yet.</Text>}
        zoomInAriaLabel={`Zoom in on ${title} chart`}
        zoomOutAriaLabel={`Zoom out of ${title} chart`}
        resetZoomAriaLabel={`Reset ${title} chart zoom`}
        renderChart={({ xDomain, visibleTimeSpanSeconds, brush }) => (
          <LineChart
            data={points}
            margin={{ top: 4, right: 12, bottom: 12, left: 4 }}
            accessibilityLayer
            role="img"
            title={title}
            desc={`Main process vs. child processes ${title.toLowerCase()} over time.`}
            {...({ "aria-label": `${title} chart` } as { "aria-label": string })}
          >
            <CartesianGrid stroke="#1e293b" strokeDasharray="4 4" vertical={false} />
            <XAxis
              dataKey="collectedAtMs"
              type="number"
              scale="time"
              domain={xDomain}
              allowDataOverflow
              tickFormatter={(value) =>
                formatTimeSeriesChartTimestamp(Math.floor(Number(value) / 1000), visibleTimeSpanSeconds)
              }
              tick={{ fill: "#cbd5e1", fontSize: "0.68rem" }}
              tickLine={{ stroke: "#475569" }}
              axisLine={{ stroke: "#334155" }}
              minTickGap={24}
            />
            <YAxis
              width={64}
              domain={[0, yMax]}
              tickFormatter={yTickFormatter}
              tick={{ fill: "#cbd5e1", fontSize: "0.68rem" }}
              tickLine={{ stroke: "#475569" }}
              axisLine={{ stroke: "#334155" }}
              label={{
                value: yLabel,
                angle: -90,
                position: "insideLeft",
                fill: "#e2e8f0",
                fontSize: "0.7rem",
                fontWeight: 600
              }}
            />
            <Tooltip
              formatter={(value, name) => [tooltipFormatter(Number(value)), name]}
              labelFormatter={(value) => formatUnixTs(Math.floor(Number(value) / 1000))}
              cursor={{ stroke: "#94a3b8", strokeDasharray: "4 4" }}
              isAnimationActive={false}
            />
            <Line
              type="linear"
              dataKey={mainKey}
              name="Main process"
              stroke={PROCESS_CHART_COLORS.main}
              strokeWidth={2}
              dot={points.length === 1 ? { r: 3, strokeWidth: 2 } : false}
              activeDot={{ r: 4, strokeWidth: 0 }}
              isAnimationActive={false}
            />
            <Line
              type="linear"
              dataKey={childrenKey}
              name="Child processes"
              stroke={PROCESS_CHART_COLORS.children}
              strokeWidth={2}
              dot={points.length === 1 ? { r: 3, strokeWidth: 2 } : false}
              activeDot={{ r: 4, strokeWidth: 0 }}
              isAnimationActive={false}
            />
            {brush}
          </LineChart>
        )}
      />
    </Stack>
  );
}

function ProcessTemperatureChart({
  points
}: {
  points: TemperatureChartPoint[];
}) {
  const yValues = points.flatMap((point) =>
    [point.hottestTemperatureCelsius, point.averageTemperatureCelsius].filter(
      (value): value is number => value !== null && Number.isFinite(value)
    )
  );

  if (yValues.length === 0) {
    return (
      <Stack gap={6}>
        <Group justify="space-between" wrap="nowrap">
          <Text size="sm" fw={600}>
            Temperature
          </Text>
          <Group gap="xs">
            <Badge variant="light" color="orange">
              Hottest sensor
            </Badge>
            <Badge variant="light" color="green">
              Average
            </Badge>
          </Group>
        </Group>
        <Text c="dimmed">No temperature samples collected yet.</Text>
      </Stack>
    );
  }

  const yMax = Math.max(1, ...yValues);

  return (
    <Stack gap={6}>
      <Group justify="space-between" wrap="nowrap">
        <Text size="sm" fw={600}>
          Temperature
        </Text>
        <Group gap="xs">
          <Badge variant="light" color="orange">
            Hottest sensor
          </Badge>
          <Badge variant="light" color="green">
            Average
          </Badge>
        </Group>
      </Group>
      <ZoomableTimeSeriesChart
        points={points}
        height="12rem"
        emptyState={<Text c="dimmed">No samples collected yet.</Text>}
        zoomInAriaLabel="Zoom in on temperature chart"
        zoomOutAriaLabel="Zoom out of temperature chart"
        resetZoomAriaLabel="Reset temperature chart zoom"
        renderChart={({ xDomain, visibleTimeSpanSeconds, brush }) => (
          <LineChart
            data={points}
            margin={{ top: 4, right: 12, bottom: 12, left: 4 }}
            accessibilityLayer
            role="img"
            title="Temperature"
            desc="Hottest and average host temperature sensor readings over time."
            {...({ "aria-label": "Temperature chart" } as { "aria-label": string })}
          >
            <CartesianGrid stroke="#1e293b" strokeDasharray="4 4" vertical={false} />
            <XAxis
              dataKey="collectedAtMs"
              type="number"
              scale="time"
              domain={xDomain}
              allowDataOverflow
              tickFormatter={(value) =>
                formatTimeSeriesChartTimestamp(Math.floor(Number(value) / 1000), visibleTimeSpanSeconds)
              }
              tick={{ fill: "#cbd5e1", fontSize: "0.68rem" }}
              tickLine={{ stroke: "#475569" }}
              axisLine={{ stroke: "#334155" }}
              minTickGap={24}
            />
            <YAxis
              width={64}
              domain={[0, yMax]}
              tickFormatter={(value) => `${value.toFixed(0)} C`}
              tick={{ fill: "#cbd5e1", fontSize: "0.68rem" }}
              tickLine={{ stroke: "#475569" }}
              axisLine={{ stroke: "#334155" }}
              label={{
                value: "Temp",
                angle: -90,
                position: "insideLeft",
                fill: "#e2e8f0",
                fontSize: "0.7rem",
                fontWeight: 600
              }}
            />
            <Tooltip
              formatter={(value, name) => [formatTemperature(Number(value)), name]}
              labelFormatter={(value) => formatUnixTs(Math.floor(Number(value) / 1000))}
              cursor={{ stroke: "#94a3b8", strokeDasharray: "4 4" }}
              isAnimationActive={false}
            />
            <Line
              type="linear"
              dataKey="hottestTemperatureCelsius"
              name="Hottest sensor"
              stroke={PROCESS_TEMPERATURE_CHART_COLORS.hottest}
              strokeWidth={2}
              dot={points.length === 1 ? { r: 3, strokeWidth: 2 } : false}
              activeDot={{ r: 4, strokeWidth: 0 }}
              connectNulls={false}
              isAnimationActive={false}
            />
            <Line
              type="linear"
              dataKey="averageTemperatureCelsius"
              name="Average"
              stroke={PROCESS_TEMPERATURE_CHART_COLORS.average}
              strokeWidth={2}
              dot={points.length === 1 ? { r: 3, strokeWidth: 2 } : false}
              activeDot={{ r: 4, strokeWidth: 0 }}
              connectNulls={false}
              isAnimationActive={false}
            />
            {brush}
          </LineChart>
        )}
      />
    </Stack>
  );
}

function StorageStatsSparkline({ samples }: { samples: StorageStatsSample[] }) {
  const chartPoints: StorageStatsChartPoint[] = useMemo(
    () =>
      samples.map((sample) => ({
        collectedAtMs: sample.collected_at_unix * 1000,
        collectedAtUnix: sample.collected_at_unix,
        chunkStoreBytes: sample.chunk_store_bytes,
        metadataFootprintBytes:
          sample.metadata_db_bytes + sample.manifest_store_bytes + sample.media_cache_bytes,
        latestSnapshotUniqueChunkBytes: sample.latest_snapshot_unique_chunk_bytes
      })),
    [samples]
  );

  if (chartPoints.length === 0) {
    return <Text c="dimmed">No storage stats samples collected yet.</Text>;
  }

  const yMax = Math.max(
    1,
    ...chartPoints.flatMap((point) =>
      STORAGE_CHART_SERIES.map((series) => point[series.key])
    )
  );

  return (
    <ZoomableTimeSeriesChart
      points={chartPoints}
      legend={
        <Group gap="md">
          {STORAGE_CHART_SERIES.map((series) => (
            <Badge key={series.key} color={series.badgeColor} variant="light">
              {series.label}
            </Badge>
          ))}
        </Group>
      }
      emptyState={<Text c="dimmed">No storage stats samples collected yet.</Text>}
      zoomInAriaLabel="Zoom in on storage history chart"
      zoomOutAriaLabel="Zoom out of storage history chart"
      resetZoomAriaLabel="Reset storage history chart zoom"
      renderChart={({ xDomain, visibleTimeSpanSeconds, brush }) => (
        <LineChart
          data={chartPoints}
          margin={{ top: 8, right: 20, bottom: 18, left: 8 }}
          accessibilityLayer
          role="img"
          title="Storage stats history"
          desc="Chunk store, metadata footprint, and latest snapshot unique bytes by sample time."
          {...({ "aria-label": "Storage stats history chart" } as { "aria-label": string })}
        >
          <CartesianGrid stroke="#1e293b" strokeDasharray="4 4" vertical={false} />
          <XAxis
            dataKey="collectedAtMs"
            type="number"
            scale="time"
            domain={xDomain}
            allowDataOverflow
            tickFormatter={(value) =>
              formatTimeSeriesChartTimestamp(
                Math.floor(Number(value) / 1000),
                visibleTimeSpanSeconds
              )
            }
            tick={{ fill: "#cbd5e1", fontSize: "0.72rem" }}
            tickLine={{ stroke: "#475569" }}
            axisLine={{ stroke: "#334155" }}
            minTickGap={24}
            label={{
              value: "Collected at (UTC)",
              position: "insideBottom",
              offset: -8,
              fill: "#e2e8f0",
              fontSize: "0.75rem",
              fontWeight: 600
            }}
          />
          <YAxis
            width={78}
            domain={[0, yMax]}
            allowDecimals={false}
            tickFormatter={(value) => formatBytes(Number(value))}
            tick={{ fill: "#cbd5e1", fontSize: "0.72rem" }}
            tickLine={{ stroke: "#475569" }}
            axisLine={{ stroke: "#334155" }}
            label={{
              value: "Storage used (bytes)",
              angle: -90,
              position: "insideLeft",
              fill: "#e2e8f0",
              fontSize: "0.75rem",
              fontWeight: 600
            }}
          />
          <Tooltip
            content={StorageStatsTooltip}
            cursor={{ stroke: "#94a3b8", strokeDasharray: "4 4" }}
            isAnimationActive={false}
          />
          {STORAGE_CHART_SERIES.map((series) => (
            <Line
              key={series.key}
              type="linear"
              dataKey={series.key}
              name={series.label}
              stroke={series.color}
              strokeWidth={2.5}
              dot={chartPoints.length === 1 ? { r: 3, strokeWidth: 2 } : false}
              activeDot={{ r: 5, strokeWidth: 0 }}
              isAnimationActive={false}
            />
          ))}
          {brush}
        </LineChart>
      )}
    />
  );
}

function StorageStatsTooltip({
  active,
  payload
}: TooltipContentProps) {
  if (!active || !payload || payload.length === 0) {
    return null;
  }

  const point = payload[0]?.payload as StorageStatsChartPoint | undefined;
  if (!point) {
    return null;
  }

  return (
    <Box
      style={{
        minWidth: "13rem",
        border: "1px solid #334155",
        borderRadius: "0.5rem",
        background: "rgba(15, 23, 42, 0.97)",
        boxShadow: "var(--mantine-shadow-md)",
        color: "#e2e8f0",
        padding: "0.625rem 0.75rem"
      }}
    >
      <Stack gap={4}>
        <Text size="xs" c="dimmed">
          {formatUnixTs(point.collectedAtUnix)}
        </Text>
        {STORAGE_CHART_SERIES.map((series) => (
          <Group key={series.key} justify="space-between" gap="md" wrap="nowrap">
            <Group gap={6} wrap="nowrap">
              <Box
                aria-hidden="true"
                style={{
                  width: "0.55rem",
                  height: "0.55rem",
                  borderRadius: "999px",
                  background: series.color
                }}
              />
              <Text size="xs">{series.label}</Text>
            </Group>
            <Text size="xs" fw={700}>
              {formatBytes(point[series.key])}
            </Text>
          </Group>
        ))}
      </Stack>
    </Box>
  );
}

function storageHistoryRequestForRange(rangeKey: StorageHistoryRangeKey): {
  sinceUnix?: number;
  maxPoints: number;
} {
  const selectedRange =
    STORAGE_HISTORY_RANGE_OPTIONS.find((option) => option.key === rangeKey) ??
    STORAGE_HISTORY_RANGE_OPTIONS[0];

  return {
    sinceUnix:
      selectedRange.windowSecs === null
        ? undefined
        : Math.max(0, Math.floor(Date.now() / 1000) - selectedRange.windowSecs),
    maxPoints: STORAGE_HISTORY_MAX_POINTS
  };
}

function describeStorageHistoryWindow(
  requestedLabel: string,
  samples: StorageStatsSample[]
): string {
  if (samples.length === 0) {
    return `Showing ${requestedLabel} view. No storage stats samples have been collected yet.`;
  }

  const oldestSample = samples[0];
  const newestSample = samples[samples.length - 1];
  return `Showing ${requestedLabel} view with ${samples.length} sampled points from ${formatUnixTs(
    oldestSample.collected_at_unix
  )} to ${formatUnixTs(newestSample.collected_at_unix)}.`;
}
