import {
  getHostDependencyReport,
  type HostDependencyCheck,
  type HostDependencyReport,
  type HostDependencyStatus
} from "@ironmesh/api";
import { ironmeshPrimaryColor, StatCard } from "@ironmesh/ui";
import { Alert, Badge, Button, Card, Grid, Group, Stack, Text } from "@mantine/core";
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

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Failed to load host dependency status">{error}</Alert> : null}
      {missingCount > 0 ? (
        <Alert color="yellow" title="Manual test blockers detected">
          {missingCount} required host dependenc{missingCount === 1 ? "y is" : "ies are"} missing on this node.
          Fix the missing checks below before expecting server-side video thumbnail generation to work.
        </Alert>
      ) : report ? (
        <Alert color={ironmeshPrimaryColor} title="Host dependency checks passed">
          This node has the currently known runtime dependencies needed for built-in image processing and server-side
          video metadata or thumbnail generation.
        </Alert>
      ) : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This page checks the host system for runtime dependencies that affect server-node features. The current focus
          is media processing, where image thumbnails use the built-in Rust pipeline while video metadata and poster
          generation rely on external tools such as ffprobe and ffmpeg.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={loading}>
          Refresh
        </Button>
      </Group>

      <Grid>
        <Grid.Col span={{ base: 12, md: 3 }}>
          <StatCard
            label="Host OS"
            value={report?.host_os || (loading ? "loading..." : "unknown")}
            hint={`Last checked: ${formatUnixTs(report?.generated_at_unix)}`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 3 }}>
          <StatCard
            label="Missing"
            value={loading && !report ? "loading..." : String(missingCount)}
            hint={missingCount > 0 ? "Resolve before media tests" : "No blocking host gaps detected"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 3 }}>
          <StatCard
            label="Resolved"
            value={loading && !report ? "loading..." : String(readyCount)}
            hint="External dependencies found on this node"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 3 }}>
          <StatCard
            label="Built-in"
            value={loading && !report ? "loading..." : String(builtinCount)}
            hint="Checks that do not need host packages"
          />
        </Grid.Col>
      </Grid>

      <Grid>
        {checks.map((check) => (
          <Grid.Col key={check.id} span={{ base: 12, xl: 4 }}>
            <DependencyCheckCard check={check} />
          </Grid.Col>
        ))}
      </Grid>
    </Stack>
  );
}

function DependencyCheckCard({ check }: { check: HostDependencyCheck }) {
  return (
    <Card withBorder radius="md" padding="lg" h="100%">
      <Stack gap="sm">
        <Group justify="space-between" align="flex-start">
          <Text fw={700}>{check.feature}</Text>
          <Badge variant="light" color={dependencyBadgeColor(check.status)}>
            {dependencyBadgeLabel(check.status)}
          </Badge>
        </Group>
        <Text c="dimmed">{check.summary}</Text>
        <Text size="sm">{check.detail}</Text>
        <Text size="sm" ff="monospace">
          Configured path: {check.configured_path || "n/a"}
        </Text>
        <Text size="sm" ff="monospace">
          Resolved path: {check.resolved_path || "not resolved"}
        </Text>
        {check.install_hint ? (
          <Alert color={check.status === "missing" ? "yellow" : "blue"} title="Install hint">
            {check.install_hint}
          </Alert>
        ) : null}
      </Stack>
    </Card>
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
  }
}
