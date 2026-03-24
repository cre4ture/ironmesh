import {
  getClusterNodes,
  getRendezvousConfig,
  getClusterSummary,
  getServerHealth,
  getStorageStatsCurrent,
  getStorageStatsHistory,
  getRecentLogs,
  getReplicationPlan,
  triggerReplicationRepair,
  type ClusterSummary,
  type LogsResponse,
  type NodeDescriptor,
  type RendezvousConfigView,
  type ReplicationPlan,
  type ServerHealthResponse,
  type StorageStatsCurrentResponse,
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
  ScrollArea,
  Stack,
  Table,
  Text
} from "@mantine/core";
import { JsonBlock, StatCard } from "@ironmesh/ui";
import { useCallback, useEffect, useState } from "react";
import { formatBytes, formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

export function DashboardPage() {
  const { adminTokenOverride, sessionStatus } = useAdminAccess();
  const [clusterSummary, setClusterSummary] = useState<ClusterSummary | null>(null);
  const [nodes, setNodes] = useState<NodeDescriptor[]>([]);
  const [replicationPlan, setReplicationPlan] = useState<ReplicationPlan | null>(null);
  const [rendezvousConfig, setRendezvousConfig] = useState<RendezvousConfigView | null>(null);
  const [logs, setLogs] = useState<LogsResponse | null>(null);
  const [backendHealth, setBackendHealth] = useState<ServerHealthResponse | null>(null);
  const [storageStats, setStorageStats] = useState<StorageStatsCurrentResponse | null>(null);
  const [storageHistory, setStorageHistory] = useState<StorageStatsSample[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [repairResult, setRepairResult] = useState<Record<string, unknown> | null>(null);
  const [repairPending, setRepairPending] = useState(false);
  const canInspectRendezvous =
    Boolean(adminTokenOverride.trim()) || Boolean(sessionStatus?.authenticated);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [summary, nodeList, plan, recentLogs, health, currentStorageStats, storageStatsHistory] = await Promise.all([
        getClusterSummary(),
        getClusterNodes(),
        getReplicationPlan(),
        getRecentLogs(120),
        getServerHealth(),
        getStorageStatsCurrent(),
        getStorageStatsHistory(120)
      ]);
      setClusterSummary(summary);
      setNodes(nodeList);
      setReplicationPlan(plan);
      setLogs(recentLogs);
      setBackendHealth(health);
      setStorageStats(currentStorageStats);
      setStorageHistory(storageStatsHistory);
      if (canInspectRendezvous) {
        try {
          setRendezvousConfig(await getRendezvousConfig(adminTokenOverride));
        } catch {
          setRendezvousConfig(null);
        }
      } else {
        setRendezvousConfig(null);
      }
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : String(refreshError));
    } finally {
      setLoading(false);
    }
  }, [adminTokenOverride, canInspectRendezvous]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function runRepair() {
    setRepairPending(true);
    setError(null);
    try {
      const payload = await triggerReplicationRepair();
      setRepairResult(payload);
      await refresh();
    } catch (repairError) {
      setError(repairError instanceof Error ? repairError.message : String(repairError));
    } finally {
      setRepairPending(false);
    }
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
                </Stack>
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

function StorageStatsSparkline({ samples }: { samples: StorageStatsSample[] }) {
  if (samples.length === 0) {
    return <Text c="dimmed">No storage stats samples collected yet.</Text>;
  }

  const width = 720;
  const height = 180;
  const padding = 16;
  const metadataValues = samples.map(
    (sample) => sample.metadata_db_bytes + sample.manifest_store_bytes + sample.media_cache_bytes
  );
  const maxima = Math.max(
    1,
    ...samples.map((sample) => sample.chunk_store_bytes),
    ...metadataValues,
    ...samples.map((sample) => sample.latest_snapshot_unique_chunk_bytes)
  );
  const baselineY = height - padding;

  const buildPath = (values: number[]): string => {
    if (values.length === 1) {
      const y = projectY(values[0], maxima, height, padding);
      return `M ${padding} ${y} L ${width - padding} ${y}`;
    }
    return values
      .map((value, index) => {
        const x = padding + (index / (values.length - 1)) * (width - padding * 2);
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
        <rect x="0" y="0" width={width} height={height} fill="#0f172a" rx="12" />
        <line
          x1={padding}
          y1={baselineY}
          x2={width - padding}
          y2={baselineY}
          stroke="#334155"
          strokeWidth="1"
        />
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

function projectY(value: number, maxValue: number, height: number, padding: number): number {
  const drawableHeight = height - padding * 2;
  const normalized = maxValue <= 0 ? 0 : value / maxValue;
  return height - padding - normalized * drawableHeight;
}
