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
  getReplicationPlan,
  type StorageStatsSample
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
import { StatCard } from "@ironmesh/ui";
import { useDisclosure } from "@mantine/hooks";
import { IconZoomIn, IconZoomOut, IconZoomReset } from "@tabler/icons-react";
import { useCallback, useMemo, useState } from "react";
import {
  Brush,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
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

type StorageStatsBrushRange = {
  startIndex: number;
  endIndex: number;
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
    badgeColor: "teal"
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
    queryKey: ["dashboard", "storage-stats-current"],
    queryFn: () => getStorageStatsCurrent()
  });
  const storageHistoryQuery = useQuery({
    queryKey: ["dashboard", "storage-stats-history", storageHistoryRange],
    queryFn: () => getStorageStatsHistory(storageHistoryRequestForRange(storageHistoryRange))
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
            ["dashboard", "repair-activity", normalizedAdminTokenOverride]
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
        repairActivityQuery.isFetching)) ||
    (canInspectRendezvous && rendezvousConfigQuery.isFetching);
  const error = firstErrorMessage([
    mediaCacheClearMutation.error,
    backendHealthQuery.error,
    storageStatsQuery.error,
    storageHistoryQuery.error,
    canInspectCluster ? clusterSummaryQuery.error : null,
    canInspectCluster ? nodesQuery.error : null,
    canInspectCluster ? replicationPlanQuery.error : null,
    canInspectCluster ? repairActivityQuery.error : null
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
                  color={localNode?.reachability.relay_required ? "teal" : "blue"}
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
                  color={rendezvousConfig?.registration_enabled ? "teal" : "gray"}
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
                  Sign in or provide an admin token override to inspect the live rendezvous registration details here.
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
        <Grid.Col span={{ base: 12, xl: 7 }}>
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
                            <Badge color={node.status === "online" ? "teal" : "gray"} variant="light">
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
                  <Alert color="teal" variant="light" title="Media cache cleared">
                    Cleared {mediaCacheClearResult.deleted_metadata_records} metadata records and{" "}
                    {mediaCacheClearResult.deleted_thumbnail_files} generated thumbnails (
                    {formatBytes(mediaCacheClearResult.deleted_thumbnail_bytes)}) at{" "}
                    {formatUnixTs(mediaCacheClearResult.cleared_at_unix)}.
                  </Alert>
                ) : null}
                {!canRunAdminMaintenance ? (
                  <Text size="sm" c="dimmed">
                    Sign in or provide an admin token override to run destructive maintenance actions from this page.
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
      return "teal";
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

function StorageStatsSparkline({ samples }: { samples: StorageStatsSample[] }) {
  const [brushRange, setBrushRange] = useState<StorageStatsBrushRange | null>(null);
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

  const timeSpanSeconds = Math.max(
    0,
    (chartPoints[chartPoints.length - 1]?.collectedAtUnix ?? 0) -
      (chartPoints[0]?.collectedAtUnix ?? 0)
  );
  const yMax = Math.max(
    1,
    ...chartPoints.flatMap((point) =>
      STORAGE_CHART_SERIES.map((series) => point[series.key])
    )
  );
  const resolvedBrushRange = resolveStorageStatsBrushRange(brushRange, chartPoints.length);
  const xDomain = buildStorageStatsXDomain(chartPoints, resolvedBrushRange);
  const xAxisTimeSpanSeconds = Math.max(0, Math.floor((xDomain[1] - xDomain[0]) / 1000));
  const zoomed =
    resolvedBrushRange.startIndex > 0 ||
    resolvedBrushRange.endIndex < chartPoints.length - 1;
  const canZoom = chartPoints.length > 2;
  const visiblePointCount =
    resolvedBrushRange.endIndex - resolvedBrushRange.startIndex + 1;
  const handleBrushChange = (nextRange: Partial<StorageStatsBrushRange>) => {
    const nextBrushRange = resolveStorageStatsBrushRange(nextRange, chartPoints.length);
    const nextZoomed =
      nextBrushRange.startIndex > 0 ||
      nextBrushRange.endIndex < chartPoints.length - 1;
    if (zoomed && !nextZoomed) {
      return;
    }

    setBrushRange(nextBrushRange);
  };

  const setZoomWindow = (visibleRatio: number) => {
    if (!canZoom) {
      return;
    }

    const nextVisiblePointCount = Math.min(
      chartPoints.length,
      Math.max(2, Math.round(visiblePointCount * visibleRatio))
    );
    if (nextVisiblePointCount === visiblePointCount) {
      return;
    }

    const centerIndex = (resolvedBrushRange.startIndex + resolvedBrushRange.endIndex) / 2;
    const nextStartIndex = clampStorageStatsBrushStart(
      Math.round(centerIndex - (nextVisiblePointCount - 1) / 2),
      nextVisiblePointCount,
      chartPoints.length
    );

    setBrushRange({
      startIndex: nextStartIndex,
      endIndex: nextStartIndex + nextVisiblePointCount - 1
    });
  };

  return (
    <Stack gap="xs">
      <Box
        style={{
          width: "100%",
          height: "19rem",
          minHeight: "19rem",
          borderRadius: "var(--mantine-radius-md)",
          background: "#0f172a",
          padding: "0.75rem 0.5rem 0.25rem"
        }}
      >
        <ResponsiveContainer width="100%" height="100%">
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
                formatChartTimestamp(Math.floor(Number(value) / 1000), xAxisTimeSpanSeconds)
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
            {chartPoints.length > 1 ? (
              <Brush
                dataKey="collectedAtMs"
                height={28}
                travellerWidth={8}
                startIndex={resolvedBrushRange.startIndex}
                endIndex={resolvedBrushRange.endIndex}
                onChange={handleBrushChange}
                stroke="#64748b"
                fill="#111827"
                fontSize="0.65rem"
                tickFormatter={(value) =>
                  formatChartTimestamp(Math.floor(Number(value) / 1000), timeSpanSeconds)
                }
              />
            ) : null}
          </LineChart>
        </ResponsiveContainer>
      </Box>
      <Group justify="space-between" gap="xs">
        <Group gap="md">
          {STORAGE_CHART_SERIES.map((series) => (
            <Badge key={series.key} color={series.badgeColor} variant="light">
              {series.label}
            </Badge>
          ))}
        </Group>
        <Group gap={4}>
          <MantineTooltip label="Zoom in">
            <ActionIcon
              aria-label="Zoom in on storage history chart"
              disabled={!canZoom || visiblePointCount <= 2}
              size="sm"
              variant="default"
              onClick={() => setZoomWindow(0.5)}
            >
              <IconZoomIn size={16} />
            </ActionIcon>
          </MantineTooltip>
          <MantineTooltip label="Zoom out">
            <ActionIcon
              aria-label="Zoom out of storage history chart"
              disabled={!canZoom || !zoomed}
              size="sm"
              variant="default"
              onClick={() => setZoomWindow(2)}
            >
              <IconZoomOut size={16} />
            </ActionIcon>
          </MantineTooltip>
          <MantineTooltip label="Reset zoom">
            <ActionIcon
              aria-label="Reset storage history chart zoom"
              disabled={!zoomed}
              size="sm"
              variant="default"
              onClick={() => setBrushRange(null)}
            >
              <IconZoomReset size={16} />
            </ActionIcon>
          </MantineTooltip>
        </Group>
      </Group>
    </Stack>
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

function resolveStorageStatsBrushRange(
  range: Partial<StorageStatsBrushRange> | null | undefined,
  pointCount: number
): StorageStatsBrushRange {
  const lastIndex = Math.max(0, pointCount - 1);
  const rawStartIndex = Number.isFinite(range?.startIndex) ? Number(range?.startIndex) : 0;
  const rawEndIndex = Number.isFinite(range?.endIndex) ? Number(range?.endIndex) : lastIndex;
  const startIndex = Math.max(0, Math.min(Math.floor(rawStartIndex), lastIndex));
  const endIndex = Math.max(startIndex, Math.min(Math.floor(rawEndIndex), lastIndex));

  return { startIndex, endIndex };
}

function clampStorageStatsBrushStart(
  startIndex: number,
  visiblePointCount: number,
  pointCount: number
): number {
  const maxStartIndex = Math.max(0, pointCount - visiblePointCount);
  return Math.max(0, Math.min(startIndex, maxStartIndex));
}

function buildStorageStatsXDomain(
  chartPoints: StorageStatsChartPoint[],
  brushRange: StorageStatsBrushRange
): [number, number] {
  const firstPointMs = chartPoints[0]?.collectedAtMs ?? 0;
  if (chartPoints.length <= 1) {
    return [firstPointMs - 60_000, firstPointMs + 60_000];
  }

  const startMs = chartPoints[brushRange.startIndex]?.collectedAtMs ?? firstPointMs;
  const endMs =
    chartPoints[brushRange.endIndex]?.collectedAtMs ??
    chartPoints[chartPoints.length - 1].collectedAtMs;

  if (startMs === endMs) {
    return [startMs - 60_000, endMs + 60_000];
  }

  return [startMs, endMs];
}

function formatChartTimestamp(unixTs: number | null | undefined, timeSpanSeconds: number): string {
  if (!unixTs || !Number.isFinite(unixTs) || unixTs <= 0) {
    return "unknown";
  }
  const iso = new Date(unixTs * 1000).toISOString();
  if (timeSpanSeconds >= 365 * 24 * 60 * 60) {
    return iso.slice(0, 10);
  }
  if (timeSpanSeconds >= 30 * 24 * 60 * 60) {
    return iso.slice(5, 10);
  }
  if (timeSpanSeconds >= 86_400) {
    return iso.slice(5, 16).replace("T", " ");
  }
  return iso.slice(11, 16);
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
