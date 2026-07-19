import {
  getHostDependencyReport,
  type HostDependencyReport,
  type HostDependencyStatus
} from "@ironmesh/api";
import { ironmeshPrimaryColor, StatCard } from "@ironmesh/ui";
import { Alert, Badge, Button, Code, Grid, Group, Stack, Table, Text } from "@mantine/core";
import { useCallback, useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatUnixTs } from "../lib/format";

export function DependenciesPage() {
  const { adminTokenOverride } = useAdminAccess();
  const [report, setReport] = useState<HostDependencyReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const payload = await getHostDependencyReport(adminTokenOverride);
      setReport(payload);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : String(refreshError));
    } finally {
      setLoading(false);
    }
  }, [adminTokenOverride]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const checks = report?.checks ?? [];
  const missingCount = checks.filter((check) => check.status === "missing").length;
  const readyCount = checks.filter((check) => check.status === "ready").length;
  const builtinCount = checks.filter((check) => check.status === "builtin").length;
  const optionalCount = checks.filter((check) => check.status === "optional").length;

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Failed to load host dependency status">{error}</Alert> : null}
      {missingCount > 0 ? (
        <Alert color="yellow" title="Host feature dependencies missing">
          {missingCount} host feature dependenc{missingCount === 1 ? "y is" : "ies are"} missing on this node.
          Resolve the missing checks below before relying on their affected server features.
        </Alert>
      ) : report ? (
        <Alert color={ironmeshPrimaryColor} title="Host dependency checks passed">
          This node has the currently known runtime dependencies for media processing, SMART/NVMe hardware health, and
          automatic Natural Earth map conversion.
        </Alert>
      ) : null}
      {optionalCount > 0 ? (
        <Alert color="blue" title="Optional host administration tooling unavailable">
          Cockpit is not installed on this host. IronMesh does not require it, but you can install and use Cockpit as a
          separate web interface for service restarts, updates, and host reboots.
        </Alert>
      ) : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This page checks host packages and commands required by server-node features, including <Code>smartctl</Code>
          for SMART/NVMe hardware health and the Natural Earth map-import tools. It also reports whether optional Cockpit
          host-administration tooling is installed. Cockpit remains a separate, separately authenticated interface for
          host-level operations; IronMesh does not restart services or the host itself.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={loading}>
          Refresh
        </Button>
      </Group>

      <Grid>
        <Grid.Col span={{ base: 12, md: 6, xl: 2 }}>
          <StatCard
            label="Host OS"
            value={report?.host_os || (loading ? "loading..." : "unknown")}
            hint={`Last checked: ${formatUnixTs(report?.generated_at_unix)}`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 2 }}>
          <StatCard
            label="Feature dependencies missing"
            value={loading && !report ? "loading..." : String(missingCount)}
            hint={missingCount > 0 ? "Resolve before using affected features" : "No blocking host gaps detected"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 2 }}>
          <StatCard
            label="Resolved"
            value={loading && !report ? "loading..." : String(readyCount)}
            hint="External dependencies found on this node"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 2 }}>
          <StatCard
            label="Built-in"
            value={loading && !report ? "loading..." : String(builtinCount)}
            hint="Checks that do not need host packages"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 2 }}>
          <StatCard
            label="Optional"
            value={loading && !report ? "loading..." : String(optionalCount)}
            hint={optionalCount > 0 ? "Advisory checks unavailable" : "Optional tooling detected"}
          />
        </Grid.Col>
      </Grid>

      <Table.ScrollContainer minWidth={920}>
        <Table striped highlightOnHover withTableBorder withColumnBorders>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Dependency</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Command</Table.Th>
              <Table.Th>Resolved path</Table.Th>
              <Table.Th>Install hint</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {checks.map((check) => (
              <Table.Tr key={check.id}>
                <Table.Td>
                  <Text fw={600} size="sm">
                    {check.feature}
                  </Text>
                  <Text c="dimmed" size="xs">
                    {check.summary}
                  </Text>
                </Table.Td>
                <Table.Td>
                  <Badge variant="light" color={dependencyBadgeColor(check.status)}>
                    {dependencyBadgeLabel(check.status)}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  {check.configured_path ? <Code>{check.configured_path}</Code> : "built-in"}
                </Table.Td>
                <Table.Td>
                  <Text size="xs" ff="monospace">
                    {check.resolved_path || "not resolved"}
                  </Text>
                </Table.Td>
                <Table.Td>
                  {check.install_hint ? (
                    <Text c={check.status === "missing" ? "red" : "dimmed"} size="xs">
                      {check.install_hint}
                    </Text>
                  ) : (
                    <Text c="dimmed" size="xs">
                      —
                    </Text>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Stack>
  );
}

function dependencyBadgeColor(status: HostDependencyStatus): string {
  switch (status) {
    case "ready":
      return ironmeshPrimaryColor;
    case "missing":
      return "red";
    case "builtin":
      return "blue";
    case "optional":
      return "gray";
  }
}

function dependencyBadgeLabel(status: HostDependencyStatus): string {
  switch (status) {
    case "ready":
      return "ready";
    case "missing":
      return "missing";
    case "builtin":
      return "built-in";
    case "optional":
      return "optional";
  }
}
