import { useQuery } from "@tanstack/react-query";
import {
  getClientConnections,
  getClusterNodes,
  getClusterSummary,
  getRendezvousConfig,
  type ClientConnectionCursor,
  type ClientConnectionEntry,
  type ClientConnectionSummary,
  type ClientConnectionTransport,
  type NodeDescriptor
} from "@ironmesh/api";
import { ironmeshPrimaryColor, StatCard } from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text
} from "@mantine/core";
import { useEffect, useState } from "react";
import { RendezvousRegistrationStateSection } from "../components/RendezvousRegistrationStateSection";
import { useAdminAccess } from "../lib/admin-access";
import { formatRelativeUnixTs, formatUnixTs } from "../lib/format";

const CLIENT_CONNECTION_POLL_INTERVAL_MS = 3_000;
const RENDEZVOUS_REGISTRATION_POLL_INTERVAL_MS = 5_000;
const SERVER_NODE_CONNECTION_POLL_INTERVAL_MS = 3_000;
const RELATIVE_TIME_REFRESH_INTERVAL_MS = 1_000;
const LIMIT_OPTIONS = ["25", "50", "100", "200"].map((value) => ({
  value,
  label: `${value} active connections`
}));
const EMPTY_SUMMARY: ClientConnectionSummary = {
  total: 0,
  http_requests: 0,
  direct_transport: 0,
  relay_transport: 0
};

export function ClientConnectionsPage() {
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectConnections = !sessionLoading && (!loginRequired || hasExplicitAdminAccess);
  const [limit, setLimit] = useState("100");
  const [pageCursor, setPageCursor] = useState<ClientConnectionCursor | null>(null);
  const [cursorHistory, setCursorHistory] = useState<Array<ClientConnectionCursor | null>>([]);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const resolvedLimit = clampLimit(limit);
  const pageIndex = cursorHistory.length;

  useEffect(() => {
    setPageCursor(null);
    setCursorHistory([]);
  }, [normalizedAdminTokenOverride, resolvedLimit]);

  useEffect(() => {
    if (!canInspectConnections) {
      return;
    }

    const intervalId = window.setInterval(() => {
      setNowMs(Date.now());
    }, RELATIVE_TIME_REFRESH_INTERVAL_MS);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [canInspectConnections]);

  const connectionsQuery = useQuery({
    queryKey: [
      "client-connections",
      normalizedAdminTokenOverride,
      resolvedLimit,
      pageCursor?.connected_at_unix ?? null,
      pageCursor?.connection_id ?? null
    ],
    queryFn: () =>
      getClientConnections(
        {
          limit: resolvedLimit,
          before: pageCursor
        },
        normalizedAdminTokenOverride || undefined
      ),
    enabled: canInspectConnections,
    refetchInterval: pageIndex === 0 ? CLIENT_CONNECTION_POLL_INTERVAL_MS : false
  });
  const rendezvousConfigQuery = useQuery({
    queryKey: ["rendezvous-config", normalizedAdminTokenOverride],
    queryFn: () => getRendezvousConfig(normalizedAdminTokenOverride || undefined),
    enabled: canInspectConnections,
    refetchInterval: RENDEZVOUS_REGISTRATION_POLL_INTERVAL_MS
  });
  const clusterSummaryQuery = useQuery({
    queryKey: ["cluster-summary", normalizedAdminTokenOverride],
    queryFn: () => getClusterSummary(normalizedAdminTokenOverride || undefined),
    enabled: canInspectConnections,
    refetchInterval: SERVER_NODE_CONNECTION_POLL_INTERVAL_MS
  });
  const serverNodesQuery = useQuery({
    queryKey: ["cluster-nodes", normalizedAdminTokenOverride],
    queryFn: () => getClusterNodes(normalizedAdminTokenOverride || undefined),
    enabled: canInspectConnections,
    refetchInterval: SERVER_NODE_CONNECTION_POLL_INTERVAL_MS
  });

  const summary = canInspectConnections ? connectionsQuery.data?.summary ?? EMPTY_SUMMARY : EMPTY_SUMMARY;
  const entries = canInspectConnections ? connectionsQuery.data?.entries ?? [] : [];
  const nextCursor = connectionsQuery.data?.next_cursor ?? null;
  const peerNodes = (clusterSummaryQuery.data ? serverNodesQuery.data ?? [] : [])
    .filter((node) => node.node_id !== clusterSummaryQuery.data?.local_node_id)
    .sort((left, right) => left.node_id.localeCompare(right.node_id));

  function handleOlderPage() {
    if (!nextCursor || connectionsQuery.isFetching) {
      return;
    }
    setCursorHistory((current) => [...current, pageCursor]);
    setPageCursor(nextCursor);
  }

  function handleNewerPage() {
    setCursorHistory((current) => {
      if (current.length === 0) {
        setPageCursor(null);
        return current;
      }
      const previousCursor = current[current.length - 1] ?? null;
      setPageCursor(previousCursor);
      return current.slice(0, -1);
    });
  }

  if (!canInspectConnections) {
    return (
      <Stack gap="lg">
        <Alert color="yellow" title="Admin access required">
          Sign in with the local admin password to inspect the node’s currently active client
          requests and transport sessions.
        </Alert>
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      {connectionsQuery.error ? (
        <Alert color="red" title="Request failed">
          {connectionsQuery.error instanceof Error
            ? connectionsQuery.error.message
            : String(connectionsQuery.error)}
        </Alert>
      ) : null}
      {rendezvousConfigQuery.error ? (
        <Alert color="red" title="Rendezvous state unavailable">
          {rendezvousConfigQuery.error instanceof Error
            ? rendezvousConfigQuery.error.message
            : String(rendezvousConfigQuery.error)}
        </Alert>
      ) : null}
      {clusterSummaryQuery.error || serverNodesQuery.error ? (
        <Alert color="red" title="Server node connection state unavailable">
          {describeQueryError(clusterSummaryQuery.error ?? serverNodesQuery.error)}
        </Alert>
      ) : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={820}>
          Inspect live device traffic and the paths advertised by other server nodes. HTTP entries cover
          active authenticated client requests, while direct and relay entries represent accepted transport
          sessions that remain open across multiple operations.
        </Text>
        <Button
          variant="light"
          onClick={() => {
            void Promise.all([
              connectionsQuery.refetch(),
              rendezvousConfigQuery.refetch(),
              clusterSummaryQuery.refetch(),
              serverNodesQuery.refetch()
            ]);
          }}
          loading={
            connectionsQuery.isFetching ||
            rendezvousConfigQuery.isFetching ||
            clusterSummaryQuery.isFetching ||
            serverNodesQuery.isFetching
          }
        >
          Refresh
        </Button>
      </Group>

      <SimpleGrid cols={{ base: 1, md: 4 }}>
        <StatCard label="Active Connections" value={summary.total} hint="Current runtime snapshot" />
        <StatCard label="HTTP Requests" value={summary.http_requests} hint="Authenticated in-flight requests" />
        <StatCard label="Direct Transport" value={summary.direct_transport} hint="Accepted direct multiplex sessions" />
        <StatCard label="Relay Transport" value={summary.relay_transport} hint="Accepted rendezvous-backed sessions" />
      </SimpleGrid>

      <Card withBorder radius="md" padding="lg">
        <Group align="end" grow>
          <Select
            label="Limit"
            data={LIMIT_OPTIONS}
            value={limit}
            onChange={(value) => setLimit(value ?? "100")}
            allowDeselect={false}
          />
        </Group>
      </Card>

      {rendezvousConfigQuery.data?.registration_enabled ? (
        <Card withBorder radius="md" padding="lg">
          <RendezvousRegistrationStateSection
            rendezvousConfig={rendezvousConfigQuery.data}
            title="Rendezvous registration state"
          />
        </Card>
      ) : null}

      <Card withBorder radius="md" padding="lg">
        <Group justify="space-between" align="center" mb="md">
          <Stack gap={4}>
            <Text fw={700}>Server node connections</Text>
            <Text size="xs" c="dimmed">
              Live cluster membership, heartbeats, and advertised peer routes for the other server nodes.
            </Text>
          </Stack>
          <Badge variant="light">{peerNodes.length} peers</Badge>
        </Group>

        {serverNodesQuery.isLoading || clusterSummaryQuery.isLoading ? (
          <Text c="dimmed">Loading server node connection state...</Text>
        ) : peerNodes.length === 0 ? (
          <Text c="dimmed">No other server nodes are currently discovered.</Text>
        ) : (
          <Table striped highlightOnHover withTableBorder>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Server Node</Table.Th>
                <Table.Th>Status</Table.Th>
                <Table.Th>Last Heartbeat</Table.Th>
                <Table.Th>Connection Path</Table.Th>
                <Table.Th>Peer Endpoints</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {peerNodes.map((node) => (
                <Table.Tr key={node.node_id}>
                  <Table.Td>
                    <Text size="sm" fw={600} ff="monospace">
                      {node.node_id}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={node.status === "online" ? "green" : "gray"} variant="light">
                      {node.status}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <TimestampCell unixTs={node.last_heartbeat_unix} nowMs={nowMs} />
                  </Table.Td>
                  <Table.Td>
                    <ServerNodeConnectionPath node={node} />
                  </Table.Td>
                  <Table.Td>
                    <ServerNodeEndpoints node={node} />
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Group justify="space-between" align="center" mb="md">
          <Stack gap={4}>
            <Text size="sm" fw={600}>
              Page {pageIndex + 1}
            </Text>
            <Text size="xs" c="dimmed">
              Showing {entries.length} live entries from the current runtime registry. Older pages can
              shift while connections open and close.
            </Text>
          </Stack>
          <Group gap="xs">
            <Button
              size="xs"
              variant="default"
              onClick={handleNewerPage}
              disabled={pageIndex === 0 || connectionsQuery.isFetching}
            >
              Newer
            </Button>
            <Button
              size="xs"
              variant="default"
              onClick={handleOlderPage}
              disabled={!nextCursor || connectionsQuery.isFetching}
            >
              Older
            </Button>
          </Group>
        </Group>

        {connectionsQuery.isLoading ? (
          <Text c="dimmed">Loading active client connections...</Text>
        ) : entries.length === 0 ? (
          <Text c="dimmed">No active authenticated client connections are currently registered.</Text>
        ) : (
          <Table striped highlightOnHover withTableBorder>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Connected</Table.Th>
                <Table.Th>Last Activity</Table.Th>
                <Table.Th>Transport</Table.Th>
                <Table.Th>Device</Table.Th>
                <Table.Th>Connection Name</Table.Th>
                <Table.Th>Activity</Table.Th>
                <Table.Th>Credential</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {entries.map((entry) => (
                <Table.Tr key={entry.connection_id}>
                  <Table.Td>
                    <TimestampCell unixTs={entry.connected_at_unix} nowMs={nowMs} />
                  </Table.Td>
                  <Table.Td>
                    <TimestampCell unixTs={entry.last_activity_at_unix} nowMs={nowMs} />
                  </Table.Td>
                  <Table.Td>
                    <TransportCell entry={entry} />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" fw={600}>
                      {describeDevice(entry)}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{entry.connection_name ?? "-"}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Stack gap={2}>
                      <Text size="sm">{describePrimaryActivity(entry)}</Text>
                      {describeSecondaryActivity(entry) ? (
                        <Text size="xs" c="dimmed">
                          {describeSecondaryActivity(entry)}
                        </Text>
                      ) : null}
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{entry.credential_fingerprint ?? "-"}</Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}

function clampLimit(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return 100;
  }
  return Math.max(1, Math.min(1000, parsed));
}

function TimestampCell({
  unixTs,
  nowMs
}: {
  unixTs: number | null | undefined;
  nowMs: number;
}) {
  const absolute = formatUnixTs(unixTs);
  if (absolute === "unknown") {
    return <Text size="sm">{absolute}</Text>;
  }

  return (
    <Stack gap={2}>
      <Text size="sm">{absolute}</Text>
      <Text size="xs" c="dimmed">
        {formatRelativeUnixTs(unixTs, nowMs)}
      </Text>
    </Stack>
  );
}

function ServerNodeConnectionPath({ node }: { node: NodeDescriptor }) {
  const path = describeServerNodeConnectionPath(node);

  return (
    <Stack gap={2}>
      <Badge color={path.color} variant="light">
        {path.label}
      </Badge>
      <Text size="xs" c="dimmed">
        {path.detail}
      </Text>
    </Stack>
  );
}

function ServerNodeEndpoints({ node }: { node: NodeDescriptor }) {
  const endpoints = peerEndpoints(node);

  if (endpoints.length === 0) {
    return <Text size="sm" c="dimmed">No direct peer endpoint advertised</Text>;
  }

  return (
    <Stack gap={2}>
      {endpoints.map((endpoint) => (
        <Text key={endpoint} size="xs" ff="monospace">
          {endpoint}
        </Text>
      ))}
    </Stack>
  );
}

function TransportCell({ entry }: { entry: ClientConnectionEntry }) {
  const detail = describeTransportDetail(entry);

  return (
    <Stack gap={2}>
      <Badge color={transportBadgeColor(entry.transport)} variant="light">
        {transportLabel(entry.transport)}
      </Badge>
      {detail ? (
        <Text size="xs" c="dimmed" ff="monospace">
          {detail}
        </Text>
      ) : null}
    </Stack>
  );
}

function transportLabel(transport: ClientConnectionTransport): string {
  switch (transport) {
    case "http_request":
      return "http";
    case "direct_transport":
      return "direct";
    case "relay_transport":
      return "relay";
  }
}

function transportBadgeColor(transport: ClientConnectionTransport): string {
  switch (transport) {
    case "http_request":
      return "blue";
    case "direct_transport":
      return ironmeshPrimaryColor;
    case "relay_transport":
      return "grape";
  }
}

function describeTransportDetail(entry: ClientConnectionEntry): string | null {
  if (entry.transport !== "relay_transport") {
    return null;
  }
  if (!entry.rendezvous_url) {
    return "via unknown relay";
  }
  return `via ${summarizeUrl(entry.rendezvous_url)}`;
}

function describeServerNodeConnectionPath(node: NodeDescriptor): {
  label: string;
  color: string;
  detail: string;
} {
  if (node.reachability.relay_required) {
    return {
      label: "rendezvous relay",
      color: "grape",
      detail: "This node requires a relay path."
    };
  }

  if (peerEndpoints(node).length > 0) {
    return {
      label: "direct preferred",
      color: ironmeshPrimaryColor,
      detail: "A direct peer endpoint is advertised."
    };
  }

  if (node.capabilities.relay_tunnel) {
    return {
      label: "relay available",
      color: "blue",
      detail: "No direct peer endpoint is advertised."
    };
  }

  return {
    label: "not configured",
    color: "gray",
    detail: "No usable peer route is advertised."
  };
}

function peerEndpoints(node: NodeDescriptor): string[] {
  const endpoints = [
    node.reachability.peer_api_url,
    ...(node.reachability.peer_direct_urls ?? [])
  ]
    .filter((endpoint): endpoint is string => Boolean(endpoint?.trim()))
    .map((endpoint) => endpoint.trim());

  return [...new Set(endpoints)];
}

function describeQueryError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function describeDevice(entry: ClientConnectionEntry): string {
  if (entry.label && entry.label !== entry.device_id) {
    return `${entry.label} (${entry.device_id})`;
  }
  return entry.label ?? entry.device_id;
}

function describePrimaryActivity(entry: ClientConnectionEntry): string {
  if (entry.transport === "http_request") {
    if (entry.method && entry.path) {
      return `${entry.method} ${entry.path}`;
    }
    return entry.path ?? entry.method ?? "-";
  }

  if (entry.rendezvous_url) {
    return entry.rendezvous_url;
  }

  return entry.session_id ? `session ${entry.session_id}` : "-";
}

function describeSecondaryActivity(entry: ClientConnectionEntry): string | null {
  if (entry.transport === "relay_transport" && entry.session_id) {
    return `session ${entry.session_id}`;
  }
  if (entry.transport === "direct_transport" && entry.session_id) {
    return `session ${entry.session_id}`;
  }
  return null;
}

function summarizeUrl(value: string): string {
  try {
    const parsed = new URL(value);
    return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  } catch {
    return value;
  }
}
