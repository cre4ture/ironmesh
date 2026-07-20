import {
  Alert,
  Badge,
  Button,
  Card,
  Divider,
  Grid,
  Group,
  SimpleGrid,
  Stack,
  Table,
  Text
} from "@mantine/core";
import {
  getClientConnectionRoutes,
  getClientRendezvous,
  refreshClientConnectionRoutes,
  refreshClientRendezvous,
  type ClientConnectionRouteEndpointSnapshot,
  type ClientConnectionRouteSnapshot,
  type ClientRendezvousView
} from "@ironmesh/api";
import { PageHeader, StatCard } from "@ironmesh/ui";
import { useEffect, useMemo, useState } from "react";

type ConnectionSummary = {
  headline: string;
  detail: string;
  color: string;
};

type HolePunchingSummary = {
  label: string;
  detail: string;
  color: string;
};

const SNAPSHOT_POLL_MS = 5000;

export function ConnectionPathsPage() {
  const [routes, setRoutes] = useState<ClientConnectionRouteSnapshot | null>(null);
  const [rendezvous, setRendezvous] = useState<ClientRendezvousView | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function loadCurrentState(showLoading: boolean) {
      if (showLoading) {
        setLoading(true);
      }
      try {
        const [nextRoutes, nextRendezvous] = await Promise.all([
          getClientConnectionRoutes(),
          getClientRendezvous()
        ]);
        if (!active) {
          return;
        }
        setRoutes(nextRoutes);
        setRendezvous(nextRendezvous);
        setError(null);
      } catch (nextError) {
        if (!active || !showLoading) {
          return;
        }
        setError(
          nextError instanceof Error
            ? nextError.message
            : "Failed loading cached connection path diagnostics"
        );
      } finally {
        if (active && showLoading) {
          setLoading(false);
        }
      }
    }

    void loadCurrentState(true);
    const interval = window.setInterval(() => {
      void loadCurrentState(false);
    }, SNAPSHOT_POLL_MS);

    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, []);

  const summary = useMemo(() => buildConnectionSummary(routes), [routes]);
  const rankedEndpoints = useMemo(() => rankedRouteEndpoints(routes), [routes]);
  const snapshotUnixMs = routes?.generated_at_unix_ms ?? null;
  const activeEndpoint =
    routes?.endpoints.find((endpoint) => endpoint.active) ?? rankedEndpoints[0] ?? null;
  const preferredEndpoint = rankedEndpoints[0] ?? null;
  const holePunchingSummary = buildHolePunchingSummary(routes, activeEndpoint);
  const directCount = routes?.endpoints.filter(isDirectPath).length ?? 0;
  const relayCount = routes?.endpoints.filter((endpoint) => endpoint.path_kind === "relay_tunnel").length ?? 0;
  const healthyCount =
    routes?.endpoints.filter(
      (endpoint) =>
        endpoint.total_successes > 0 &&
        endpoint.consecutive_failures === 0 &&
        !isCoolingDown(endpoint, snapshotUnixMs)
    ).length ?? 0;

  async function refreshAll() {
    setRefreshing(true);
    setError(null);
    try {
      const [nextRoutes, nextRendezvous] = await Promise.all([
        refreshClientConnectionRoutes(),
        refreshClientRendezvous()
      ]);
      setRoutes(nextRoutes);
      setRendezvous(nextRendezvous);
    } catch (nextError) {
      setError(
        nextError instanceof Error
          ? nextError.message
          : "Failed refreshing connection path diagnostics"
      );
    } finally {
      setRefreshing(false);
    }
  }

  return (
    <>
      <PageHeader
        title="Connection Paths"
        description="Separate overview of every direct and relay path this embedded client can use to reach the cluster, plus the current route selection state."
        actions={
          <Button variant="default" loading={loading || refreshing} onClick={() => void refreshAll()}>
            Re-evaluate routes
          </Button>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <Alert color={summary.color} title="Overall search state">
        {summary.detail}
      </Alert>

      <SimpleGrid cols={{ base: 1, md: 2, xl: 5 }}>
        <StatCard label="State" value={summary.headline} />
        <StatCard
          label="Active path"
          value={activeEndpoint ? routeDisplayLabel(activeEndpoint) : loading ? "Loading..." : "None"}
        />
        <StatCard
          label="Preferred next"
          value={preferredEndpoint ? routeDisplayLabel(preferredEndpoint) : loading ? "Loading..." : "None"}
        />
        <StatCard label="Healthy methods" value={loading ? "Loading..." : healthyCount} />
        <StatCard
          label="Relay endpoints"
          value={loading ? "Loading..." : rendezvous?.configured_urls.length ?? 0}
          hint="Configured rendezvous URLs available to relay-capable routes."
        />
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2, xl: 5 }}>
        <StatCard label="Direct methods" value={loading ? "Loading..." : directCount} />
        <StatCard label="Relay methods" value={loading ? "Loading..." : relayCount} />
        <StatCard
          label="Current transport"
          value={rendezvous?.transport_mode ?? (loading ? "Loading..." : "Unknown")}
        />
        <StatCard
          label="Hole punching"
          value={
            loading ? (
              "Loading..."
            ) : (
              <Badge color={holePunchingSummary.color} variant="light">
                {holePunchingSummary.label}
              </Badge>
            )
          }
          hint={holePunchingSummary.detail}
        />
        <StatCard
          label="Snapshot time"
          value={formatUnixTimestampMs(routes?.generated_at_unix_ms ?? null)}
        />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 8 }}>
          <Stack gap="md">
            {rankedEndpoints.length === 0 && !loading ? (
              <Card withBorder radius="md" padding="lg">
                <Text fw={700}>No connection methods reported</Text>
                <Text c="dimmed" size="sm">
                  The embedded client did not expose any transport candidates.
                </Text>
              </Card>
            ) : null}

            {rankedEndpoints.map((endpoint, index) => (
              <Card key={endpoint.index} withBorder radius="md" padding="lg">
                <Stack gap="md">
                  <Group justify="space-between" align="flex-start">
                    <Stack gap={4}>
                      <Text fw={700}>{routeDisplayLabel(endpoint)}</Text>
                      <Text size="sm" c="dimmed">
                        {endpoint.locator}
                      </Text>
                    </Stack>
                    <Group gap="xs">
                      {endpoint.active ? (
                        <Badge color="blue" variant="light">
                          active
                        </Badge>
                      ) : null}
                      {index === 0 ? (
                        <Badge color="teal" variant="light">
                          top ranked
                        </Badge>
                      ) : null}
                      {endpoint.background_probe_in_flight ? (
                        <Badge color="violet" variant="light">
                          probing
                        </Badge>
                      ) : null}
                      {endpoint.path_kind === "direct_quic" ? (
                        <Badge color={holePunchingModeColor(endpoint)} variant="light">
                          {holePunchingModeLabel(endpoint)}
                        </Badge>
                      ) : null}
                      {isCoolingDown(endpoint, snapshotUnixMs) ? (
                        <Badge color="red" variant="light">
                          cooling down
                        </Badge>
                      ) : null}
                      {!endpoint.background_probe_in_flight &&
                      !isCoolingDown(endpoint, snapshotUnixMs) &&
                      endpoint.total_successes > 0 &&
                      endpoint.consecutive_failures === 0 ? (
                        <Badge color="green" variant="light">
                          healthy
                        </Badge>
                      ) : null}
                    </Group>
                  </Group>

                  <SimpleGrid cols={{ base: 2, md: 4 }}>
                    <StatCard label="Rank score" value={endpoint.score.toFixed(1)} />
                    <StatCard
                      label="Avg latency"
                      value={formatDurationValue(endpoint.ewma_latency_ms)}
                    />
                    <StatCard label="Successes" value={endpoint.total_successes} />
                    <StatCard label="Failures" value={endpoint.total_failures} />
                  </SimpleGrid>

                  <Table striped highlightOnHover withTableBorder withColumnBorders>
                    <Table.Tbody>
                      <Table.Tr>
                        <Table.Th>Target node</Table.Th>
                        <Table.Td>{endpoint.target_node_id ?? "n/a"}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th>Hole punching mode</Table.Th>
                        <Table.Td>
                          {endpoint.path_kind === "direct_quic"
                            ? holePunchingModeLabel(endpoint)
                            : "n/a"}
                        </Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th>Bootstrap order</Table.Th>
                        <Table.Td>{endpoint.bootstrap_rank + 1}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th>Last success</Table.Th>
                        <Table.Td>{formatUnixTimestampMs(endpoint.last_success_unix_ms ?? null)}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th>Last failure</Table.Th>
                        <Table.Td>{formatUnixTimestampMs(endpoint.last_failure_unix_ms ?? null)}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th>Last measurement</Table.Th>
                        <Table.Td>{formatUnixTimestampMs(endpoint.last_measurement_unix_ms ?? null)}</Table.Td>
                      </Table.Tr>
                      <Table.Tr>
                        <Table.Th>Consecutive failures</Table.Th>
                        <Table.Td>{endpoint.consecutive_failures}</Table.Td>
                      </Table.Tr>
                    </Table.Tbody>
                  </Table>

                  {endpoint.last_error ? (
                    <>
                      <Divider />
                      <Alert color="red" title="Last error">
                        {endpoint.last_error}
                      </Alert>
                    </>
                  ) : null}
                </Stack>
              </Card>
            ))}
          </Stack>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 4 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Text fw={700}>Relay status</Text>
              <Text size="sm" c="dimmed">
                Relay-capable routes rely on the shared rendezvous configuration exposed by the
                runtime.
              </Text>

              <SimpleGrid cols={2}>
                <StatCard
                  label="Relay policy"
                  value={rendezvous?.relay_mode ?? (loading ? "Loading..." : "Unknown")}
                />
                <StatCard
                  label="Active endpoint"
                  value={rendezvous?.active_url ? summarizeUrl(rendezvous.active_url) : "None"}
                />
              </SimpleGrid>

              {rendezvous?.last_probe_error ? (
                <Alert color="red" title="Latest rendezvous probe failed">
                  {rendezvous.last_probe_error}
                </Alert>
              ) : null}

              <Table striped withTableBorder withColumnBorders>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Endpoint</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Last success</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {(rendezvous?.endpoint_statuses ?? []).map((endpoint) => (
                    <Table.Tr key={endpoint.url}>
                      <Table.Td>{summarizeUrl(endpoint.url)}</Table.Td>
                      <Table.Td>
                        <Badge color={relayStatusColor(endpoint.status)} variant="light">
                          {endpoint.status}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{formatUnixTimestampSeconds(endpoint.last_success_unix)}</Table.Td>
                    </Table.Tr>
                  ))}
                  {(rendezvous?.endpoint_statuses.length ?? 0) === 0 ? (
                    <Table.Tr>
                      <Table.Td colSpan={3}>
                        <Text size="sm" c="dimmed">
                          No relay endpoint snapshot available.
                        </Text>
                      </Table.Td>
                    </Table.Tr>
                  ) : null}
                </Table.Tbody>
              </Table>
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function buildHolePunchingSummary(
  routes: ClientConnectionRouteSnapshot | null,
  activeEndpoint: ClientConnectionRouteEndpointSnapshot | null
): HolePunchingSummary {
  const directQuicEndpoints =
    routes?.endpoints.filter((endpoint) => endpoint.path_kind === "direct_quic") ?? [];

  if (directQuicEndpoints.length === 0) {
    return {
      label: "Unavailable",
      detail: "No direct QUIC candidate is available for hole punching.",
      color: "gray"
    };
  }

  if (
    activeEndpoint?.path_kind === "direct_quic" &&
    holePunchingMode(activeEndpoint) === "direct"
  ) {
    return {
      label: "Direct",
      detail: "A direct QUIC path is currently selected.",
      color: "green"
    };
  }

  if (directQuicEndpoints.some((endpoint) => holePunchingMode(endpoint) === "direct")) {
    return {
      label: "Direct",
      detail: "Hole punching has established a direct QUIC path; it is not the active route now.",
      color: "green"
    };
  }

  if (directQuicEndpoints.some((endpoint) => holePunchingMode(endpoint) === "unknown")) {
    return {
      label: "Checking",
      detail: "The direct QUIC session has not reported a selected network path yet.",
      color: "yellow"
    };
  }

  return {
    label: "Relay fallback",
    detail: "Direct QUIC is available, but the current session is using its relay path.",
    color: "teal"
  };
}

function holePunchingMode(endpoint: ClientConnectionRouteEndpointSnapshot): "direct" | "relay" | "unknown" {
  if (endpoint.hole_punching_mode === "direct") {
    return "direct";
  }
  if (endpoint.hole_punching_mode === "relay") {
    return "relay";
  }
  return "unknown";
}

function holePunchingModeLabel(endpoint: ClientConnectionRouteEndpointSnapshot): string {
  switch (holePunchingMode(endpoint)) {
    case "direct":
      return "direct path";
    case "relay":
      return "relay fallback";
    default:
      return "not established";
  }
}

function holePunchingModeColor(endpoint: ClientConnectionRouteEndpointSnapshot): string {
  switch (holePunchingMode(endpoint)) {
    case "direct":
      return "green";
    case "relay":
      return "teal";
    default:
      return "gray";
  }
}

function buildConnectionSummary(
  routes: ClientConnectionRouteSnapshot | null
): ConnectionSummary {
  if (!routes || routes.endpoints.length === 0) {
    return {
      headline: "Loading",
      detail: "Collecting direct and relay path diagnostics from the embedded client runtime.",
      color: "gray"
    };
  }

  const ranked = rankedRouteEndpoints(routes);
  const active = routes.endpoints.find((endpoint) => endpoint.active) ?? ranked[0] ?? null;
  const hasSuccess = routes.endpoints.some((endpoint) => endpoint.total_successes > 0);
  const hasProbeInFlight = routes.endpoints.some((endpoint) => endpoint.background_probe_in_flight);
  const hasCooling = routes.endpoints.some((endpoint) =>
    isCoolingDown(endpoint, routes.generated_at_unix_ms)
  );
  const bestHealthy = ranked.find(
    (endpoint) =>
      endpoint.total_successes > 0 &&
      endpoint.consecutive_failures === 0 &&
      !isCoolingDown(endpoint, routes.generated_at_unix_ms)
  );

  if (!hasSuccess && routes.endpoints.every((endpoint) => endpoint.total_failures === 0)) {
    return {
      headline: "Cold start",
      detail:
        "No path has completed a measured request yet. The client is still building its first route quality picture.",
      color: "gray"
    };
  }

  if (!hasSuccess && routes.endpoints.some((endpoint) => endpoint.total_failures > 0)) {
    return {
      headline: "No healthy path",
      detail:
        "Every known path has failed recently. Inspect the method cards below to see which route is cooling down or returning the latest error.",
      color: "red"
    };
  }

  if (active && active.path_kind === "relay_tunnel" && active.consecutive_failures === 0 && !hasProbeInFlight) {
    return {
      headline: "Relay active",
      detail:
        "The client is currently reaching the cluster through a relay-backed path. Direct paths may be cooling down, slower, or currently ranked behind relay.",
      color: "teal"
    };
  }

  if (active && isDirectPath(active) && active.consecutive_failures === 0 && !hasCooling && !hasProbeInFlight) {
    return {
      headline: "Direct settled",
      detail:
        "A direct cluster path is active and the router is not currently re-evaluating alternates.",
      color: "green"
    };
  }

  if (bestHealthy && hasProbeInFlight) {
    return {
      headline: "Re-evaluating",
      detail:
        "Background probes are running across alternate routes. The active path is usable, but the client is still checking whether a better route should win next.",
      color: "yellow"
    };
  }

  return {
    headline: "Recovering",
    detail:
      "The router has at least one usable path, but failures or cooldown windows are still influencing route selection.",
    color: "yellow"
  };
}

function rankedRouteEndpoints(
  routes: ClientConnectionRouteSnapshot | null
): ClientConnectionRouteEndpointSnapshot[] {
  if (!routes) {
    return [];
  }

  const byIndex = new Map(routes.endpoints.map((endpoint) => [endpoint.index, endpoint]));
  const ranked = routes.ranked_indices
    .map((index) => byIndex.get(index))
    .filter((endpoint): endpoint is ClientConnectionRouteEndpointSnapshot => endpoint != null);
  const missing = routes.endpoints.filter(
    (endpoint) => !routes.ranked_indices.includes(endpoint.index)
  );
  return [...ranked, ...missing];
}

function isDirectPath(endpoint: ClientConnectionRouteEndpointSnapshot): boolean {
  return (
    endpoint.path_kind === "direct_https" || endpoint.path_kind === "direct_quic"
  );
}

function routeDisplayLabel(endpoint: ClientConnectionRouteEndpointSnapshot): string {
  const relayHint =
    endpoint.path_kind === "relay_tunnel" ? summarizeRelayLocator(endpoint.locator) : null;
  const prefix =
    endpoint.path_kind === "relay_tunnel"
      ? relayHint
        ? `Relay via ${relayHint}`
        : "Relay"
      : endpoint.path_kind === "direct_quic"
        ? "Direct QUIC"
        : "Direct HTTPS";
  return endpoint.target_node_id ? `${prefix} to ${endpoint.target_node_id}` : prefix;
}

function isCoolingDown(
  endpoint: ClientConnectionRouteEndpointSnapshot,
  snapshotUnixMs: number | null | undefined
): boolean {
  if (!snapshotUnixMs || !endpoint.circuit_open_until_unix_ms) {
    return false;
  }
  return endpoint.circuit_open_until_unix_ms > snapshotUnixMs;
}

function formatDurationValue(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) {
    return "n/a";
  }
  return `${value.toFixed(1)} ms`;
}

function formatUnixTimestampMs(value: number | null | undefined): string {
  if (!value) {
    return "never";
  }
  return new Date(value).toLocaleString();
}

function formatUnixTimestampSeconds(value: number | null | undefined): string {
  if (!value) {
    return "never";
  }
  return new Date(value * 1000).toLocaleString();
}

function summarizeUrl(value: string): string {
  try {
    const parsed = new URL(value);
    return parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
  } catch {
    return value;
  }
}

function summarizeRelayLocator(locator: string): string | null {
  const rendezvousIndex = locator.lastIndexOf("@");
  if (rendezvousIndex < 0 || rendezvousIndex + 1 >= locator.length) {
    return null;
  }
  return summarizeUrl(locator.slice(rendezvousIndex + 1));
}

function relayStatusColor(status: "unknown" | "connected" | "disconnected"): string {
  if (status === "connected") {
    return "green";
  }
  if (status === "disconnected") {
    return "red";
  }
  return "gray";
}
