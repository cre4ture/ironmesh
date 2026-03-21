import {
  getClusterNodes,
  getRendezvousConfig,
  getClusterSummary,
  getRecentLogs,
  getReplicationPlan,
  triggerReplicationRepair,
  type ClusterSummary,
  type LogsResponse,
  type NodeDescriptor,
  type RendezvousConfigView,
  type ReplicationPlan
} from "@ironmesh/api";
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
      const [summary, nodeList, plan, recentLogs] = await Promise.all([
        getClusterSummary(),
        getClusterNodes(),
        getReplicationPlan(),
        getRecentLogs(120)
      ]);
      setClusterSummary(summary);
      setNodes(nodeList);
      setReplicationPlan(plan);
      setLogs(recentLogs);
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
                      <Table.Th>Last heartbeat</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {nodes.length > 0 ? (
                      nodes.map((node) => (
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
                          <Table.Td>{formatUnixTs(node.last_heartbeat_unix)}</Table.Td>
                        </Table.Tr>
                      ))
                    ) : (
                      <Table.Tr>
                        <Table.Td colSpan={6}>
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
