import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  clearAdminMediaCache,
  getClusterNodes,
  getRendezvousConfig,
  getClusterSummary,
  getServerHealth,
  getStorageStatsCurrent,
  getStorageStatsHistory,
  getRecentLogs,
  getReplicationPlan,
  triggerReplicationRepair,
  type StorageStatsSample
} from "@ironmesh/api";
import { ironmeshUiRevision, ironmeshUiVersion } from "@ironmesh/config";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Divider,
  Grid,
  Group,
  Loader,
  Modal,
  ScrollArea,
  Stack,
  Table,
  Text
} from "@mantine/core";
import { JsonBlock, StatCard } from "@ironmesh/ui";
import { useDisclosure } from "@mantine/hooks";
import { useCallback, useState } from "react";
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

export function DashboardPage() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const [storageHistoryRange, setStorageHistoryRange] = useState<StorageHistoryRangeKey>("30d");
  const [clearMediaCacheOpened, clearMediaCacheDisclosure] = useDisclosure(false);
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const canRunAdminMaintenance =
    !sessionLoading && (!sessionStatus?.login_required || hasExplicitAdminAccess);
  const canInspectCluster = canRunAdminMaintenance;
  const canInspectRendezvous = canRunAdminMaintenance;

  const logsQuery = useQuery({
    queryKey: ["dashboard", "logs", 120],
    queryFn: () => getRecentLogs(120)
  });
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
  const rendezvousConfigQuery = useQuery({
    queryKey: ["dashboard", "rendezvous-config", normalizedAdminTokenOverride],
    queryFn: () => getRendezvousConfig(normalizedAdminTokenOverride || undefined),
    enabled: canInspectRendezvous
  });

  const refresh = useCallback(async () => {
    const queryKeys: ReadonlyArray<readonly unknown[]> = [
      ["dashboard", "logs", 120],
      ["dashboard", "health"],
      ["dashboard", "storage-stats-current"],
      ["dashboard", "storage-stats-history", storageHistoryRange],
      ...(canInspectCluster
        ? [
            ["dashboard", "cluster-summary", normalizedAdminTokenOverride],
            ["dashboard", "cluster-nodes", normalizedAdminTokenOverride],
            ["dashboard", "replication-plan", normalizedAdminTokenOverride]
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

  const repairMutation = useMutation({
    mutationFn: () => triggerReplicationRepair(),
    onSuccess: async () => {
      await refresh();
    }
  });

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
  const rendezvousConfig =
    canInspectRendezvous && !rendezvousConfigQuery.isError
      ? rendezvousConfigQuery.data ?? null
      : null;
  const logs = logsQuery.data ?? null;
  const backendHealth = backendHealthQuery.data ?? null;
  const storageStats = storageStatsQuery.data ?? null;
  const storageHistory = storageHistoryQuery.data ?? [];
  const repairResult = repairMutation.data ?? null;
  const mediaCacheClearResult = mediaCacheClearMutation.data ?? null;
  const repairPending = repairMutation.isPending;
  const mediaCacheClearPending = mediaCacheClearMutation.isPending;
  const loading =
    logsQuery.isFetching ||
    backendHealthQuery.isFetching ||
    storageStatsQuery.isFetching ||
    storageHistoryQuery.isFetching ||
    (canInspectCluster &&
      (clusterSummaryQuery.isFetching ||
        nodesQuery.isFetching ||
        replicationPlanQuery.isFetching)) ||
    (canInspectRendezvous && rendezvousConfigQuery.isFetching);
  const error = firstErrorMessage([
    repairMutation.error,
    mediaCacheClearMutation.error,
    logsQuery.error,
    backendHealthQuery.error,
    storageStatsQuery.error,
    storageHistoryQuery.error,
    canInspectCluster ? clusterSummaryQuery.error : null,
    canInspectCluster ? nodesQuery.error : null,
    canInspectCluster ? replicationPlanQuery.error : null
  ]);

  async function runRepair() {
    await repairMutation.mutateAsync();
  }

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
  const storageHistoryChronological = [...storageHistory].reverse();
  const selectedStorageHistoryRange =
    STORAGE_HISTORY_RANGE_OPTIONS.find((option) => option.key === storageHistoryRange) ??
    STORAGE_HISTORY_RANGE_OPTIONS[0];

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={680}>
          The dashboard focuses on the current cluster shape, replication pressure, and recent runtime output.
          Refreshing keeps the cards fast, while the raw JSON blocks still make backend parity easy to inspect during migration.
        </Text>
        <Group>
          <Button variant="default" onClick={() => void runRepair()} loading={repairPending}>
            Run repair pass
          </Button>
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
            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Group justify="space-between">
                  <Text fw={700}>Replication plan</Text>
                  <Badge variant="light">
                    {replicationPlan ? formatUnixTs(replicationPlan.generated_at_unix) : "not loaded"}
                  </Badge>
                </Group>
                <Text c="dimmed">Shows the current reconciliation view from the cluster leader perspective.</Text>
                <JsonBlock value={replicationPlan ?? { status: "loading" }} />
                <Divider />
                <Text fw={600}>Last repair result</Text>
                <JsonBlock value={repairResult ?? { status: "no repair pass triggered yet" }} />
              </Stack>
            </Card>
            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Text fw={700}>Recent logs</Text>
                <ScrollArea type="auto" mah={320}>
                  <Text ff="monospace" size="sm" style={{ whiteSpace: "pre-wrap" }}>
                    {logs?.entries?.join("\n") || (loading ? "loading..." : "no logs yet")}
                  </Text>
                </ScrollArea>
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

function StorageStatsSparkline({ samples }: { samples: StorageStatsSample[] }) {
  if (samples.length === 0) {
    return <Text c="dimmed">No storage stats samples collected yet.</Text>;
  }

  const width = 720;
  const height = 240;
  const padding = {
    top: 20,
    right: 16,
    bottom: 56,
    left: 72
  };
  const metadataValues = samples.map(
    (sample) => sample.metadata_db_bytes + sample.manifest_store_bytes + sample.media_cache_bytes
  );
  const maxima = Math.max(
    1,
    ...samples.map((sample) => sample.chunk_store_bytes),
    ...metadataValues,
    ...samples.map((sample) => sample.latest_snapshot_unique_chunk_bytes)
  );
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const baselineY = height - padding.bottom;
  const xAxisTicks = buildXAxisTicks(samples, width, padding);
  const yAxisTicks = Array.from(new Set([maxima, Math.round(maxima / 2), 0])).sort(
    (left, right) => right - left
  );

  const buildPath = (values: number[]): string => {
    if (values.length === 1) {
      const y = projectY(values[0], maxima, height, padding);
      return `M ${padding.left} ${y} L ${width - padding.right} ${y}`;
    }
    return values
      .map((value, index) => {
        const x = projectX(index, values.length, width, padding);
        const y = projectY(value, maxima, height, padding);
        return `${index === 0 ? "M" : "L"} ${x} ${y}`;
      })
      .join(" ");
  };

  return (
    <Stack gap="xs">
      <svg
        aria-label="Storage stats history chart"
        role="img"
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: "100%", height: "auto", display: "block" }}
      >
        <title>Storage stats history</title>
        <desc>Chunk store, metadata footprint, and latest snapshot unique bytes by sample time.</desc>
        <rect x="0" y="0" width={width} height={height} fill="#0f172a" rx="12" />
        {yAxisTicks.map((tickValue) => {
          const y = projectY(tickValue, maxima, height, padding);
          return (
            <g key={tickValue}>
              <line
                x1={padding.left}
                y1={y}
                x2={width - padding.right}
                y2={y}
                stroke="#1e293b"
                strokeWidth="1"
                strokeDasharray="4 4"
              />
              <text
                x={padding.left - 10}
                y={y}
                fill="#cbd5e1"
                fontSize="11"
                textAnchor="end"
                dominantBaseline="middle"
              >
                {formatBytes(tickValue)}
              </text>
            </g>
          );
        })}
        <line
          x1={padding.left}
          y1={padding.top}
          x2={padding.left}
          y2={baselineY}
          stroke="#334155"
          strokeWidth="1"
        />
        <line
          x1={padding.left}
          y1={baselineY}
          x2={width - padding.right}
          y2={baselineY}
          stroke="#334155"
          strokeWidth="1"
        />
        {xAxisTicks.map((tick) => (
          <g key={`${tick.label}-${tick.index}`}>
            <line
              x1={tick.x}
              y1={baselineY}
              x2={tick.x}
              y2={baselineY + 6}
              stroke="#475569"
              strokeWidth="1"
            />
            <text
              x={tick.x}
              y={baselineY + 22}
              fill="#cbd5e1"
              fontSize="11"
              textAnchor={tick.index === 0 ? "start" : tick.isLast ? "end" : "middle"}
            >
              {tick.label}
            </text>
          </g>
        ))}
        <path
          d={buildPath(samples.map((sample) => sample.chunk_store_bytes))}
          fill="none"
          stroke="#38bdf8"
          strokeWidth="3"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        <path
          d={buildPath(metadataValues)}
          fill="none"
          stroke="#f59e0b"
          strokeWidth="3"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        <path
          d={buildPath(samples.map((sample) => sample.latest_snapshot_unique_chunk_bytes))}
          fill="none"
          stroke="#34d399"
          strokeWidth="3"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        <text
          x={padding.left + chartWidth / 2}
          y={height - 14}
          fill="#e2e8f0"
          fontSize="12"
          fontWeight="600"
          textAnchor="middle"
        >
          Collected at (UTC)
        </text>
        <text
          x={18}
          y={padding.top + chartHeight / 2}
          fill="#e2e8f0"
          fontSize="12"
          fontWeight="600"
          textAnchor="middle"
          transform={`rotate(-90 18 ${padding.top + chartHeight / 2})`}
        >
          Storage used (bytes)
        </text>
      </svg>
      <Group gap="md">
        <Badge color="cyan" variant="light">
          Chunk store
        </Badge>
        <Badge color="yellow" variant="light">
          Metadata footprint
        </Badge>
        <Badge color="teal" variant="light">
          Latest snapshot unique
        </Badge>
      </Group>
    </Stack>
  );
}

function buildXAxisTicks(
  samples: StorageStatsSample[],
  width: number,
  padding: { left: number; right: number }
): Array<{ index: number; isLast: boolean; label: string; x: number }> {
  const timeSpanSeconds = Math.max(
    0,
    (samples[samples.length - 1]?.collected_at_unix ?? 0) - (samples[0]?.collected_at_unix ?? 0)
  );
  const indexes = Array.from(new Set([0, Math.floor((samples.length - 1) / 2), samples.length - 1])).sort(
    (left, right) => left - right
  );

  return indexes.map((index) => ({
    index,
    isLast: index === samples.length - 1,
    label: formatChartTimestamp(samples[index]?.collected_at_unix ?? null, timeSpanSeconds),
    x: projectX(index, samples.length, width, padding)
  }));
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

function projectX(
  index: number,
  sampleCount: number,
  width: number,
  padding: { left: number; right: number }
): number {
  if (sampleCount <= 1) {
    return padding.left + (width - padding.left - padding.right) / 2;
  }
  return padding.left + (index / (sampleCount - 1)) * (width - padding.left - padding.right);
}

function projectY(
  value: number,
  maxValue: number,
  height: number,
  padding: { top: number; bottom: number }
): number {
  const drawableHeight = height - padding.top - padding.bottom;
  const normalized = maxValue <= 0 ? 0 : value / maxValue;
  return height - padding.bottom - normalized * drawableHeight;
}
