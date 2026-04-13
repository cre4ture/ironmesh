import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getRepairActivityStatus,
  getRepairHistory,
  getReplicationPlan,
  triggerReplicationRepair,
  type RepairRunRecord,
  type ReplicationPlan
} from "@ironmesh/api";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Grid,
  Group,
  Loader,
  Modal,
  Progress,
  Stack,
  Table,
  Text
} from "@mantine/core";
import { JsonBlock, StatCard } from "@ironmesh/ui";
import { useCallback, useState } from "react";
import { formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

export function RepairPage() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const [selectedRun, setSelectedRun] = useState<RepairRunRecord | null>(null);
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectRepair =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);

  const repairActivityQuery = useQuery({
    queryKey: ["repair-page", "activity", normalizedAdminTokenOverride],
    queryFn: () => getRepairActivityStatus(normalizedAdminTokenOverride || undefined),
    enabled: canInspectRepair,
    refetchInterval: 3_000
  });
  const repairHistoryQuery = useQuery({
    queryKey: ["repair-page", "history", normalizedAdminTokenOverride],
    queryFn: () => getRepairHistory({ limit: 120 }, normalizedAdminTokenOverride || undefined),
    enabled: canInspectRepair
  });
  const replicationPlanQuery = useQuery({
    queryKey: ["repair-page", "replication-plan", normalizedAdminTokenOverride],
    queryFn: () => getReplicationPlan(normalizedAdminTokenOverride || undefined),
    enabled: canInspectRepair
  });

  const refresh = useCallback(async () => {
    const queryKeys: ReadonlyArray<readonly unknown[]> = [
      ["repair-page", "activity", normalizedAdminTokenOverride],
      ["repair-page", "history", normalizedAdminTokenOverride],
      ["repair-page", "replication-plan", normalizedAdminTokenOverride]
    ];

    await Promise.all(
      queryKeys.map((queryKey) =>
        queryClient.refetchQueries({
          queryKey,
          exact: true
        })
      )
    );
  }, [normalizedAdminTokenOverride, queryClient]);

  const repairMutation = useMutation({
    mutationFn: () => triggerReplicationRepair(normalizedAdminTokenOverride || undefined),
    onSuccess: async () => {
      await refresh();
    }
  });

  const repairActivity = canInspectRepair ? repairActivityQuery.data ?? null : null;
  const repairHistory = canInspectRepair ? repairHistoryQuery.data ?? null : null;
  const replicationPlan = canInspectRepair ? replicationPlanQuery.data ?? null : null;
  const latestRun = repairActivity?.latest_run ?? null;
  const activeRuns = repairActivity?.active_runs ?? [];
  const retentionLabel = repairHistory
    ? formatRetentionWindow(repairHistory.retention_secs)
    : "not loaded";
  const loading =
    repairActivityQuery.isFetching ||
    repairHistoryQuery.isFetching ||
    replicationPlanQuery.isFetching;
  const error = firstErrorMessage([
    repairMutation.error,
    repairActivityQuery.error,
    repairHistoryQuery.error,
    replicationPlanQuery.error
  ]);
  const replicationPlanEntries = replicationPlan
    ? replicationPlan.items
        .map((item) => ({
          item,
          status: getReplicationItemStatus(item),
          progress: getReplicationItemProgress(item)
        }))
        .sort(compareReplicationPlanEntries)
    : [];

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This page is the dedicated repair workspace for operators. It shows the live node-local
          repair state, retains recent repair runs for debugging, and keeps the full replication
          plan off the dashboard.
        </Text>
        <Group>
          <Button
            variant="default"
            onClick={() => void repairMutation.mutateAsync()}
            loading={repairMutation.isPending}
            disabled={!canInspectRepair}
          >
            Run cluster repair pass
          </Button>
          <Button variant="light" onClick={() => void refresh()} loading={loading}>
            Refresh
          </Button>
        </Group>
      </Group>

      {!canInspectRepair ? (
        <Alert color="blue" title="Admin access required">
          Sign in or provide an admin token override to inspect repair activity and retained run
          history.
        </Alert>
      ) : null}
      {error ? <Alert color="red" title="Failed to load repair state">{error}</Alert> : null}

      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Repair Activity"
            value={
              repairActivity
                ? formatRepairActivityState(repairActivity.state)
                : loading
                  ? <Loader size="sm" />
                  : "unknown"
            }
            hint={
              repairActivity
                ? `${activeRuns.length} active run${activeRuns.length === 1 ? "" : "s"}`
                : "Node-local repair executor state"
            }
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Latest Run"
            value={latestRun ? formatUnixTs(latestRun.finished_at_unix) : loading ? <Loader size="sm" /> : "none"}
            hint={latestRun ? `${formatRepairTrigger(latestRun.trigger)} · ${formatRepairStatus(latestRun.status)}` : "No retained repair run yet"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Planner Attention"
            value={replicationPlan ? replicationPlan.items.length : loading ? <Loader size="sm" /> : "unknown"}
            hint={replicationPlan ? `${replicationPlan.under_replicated} under · ${replicationPlan.over_replicated} over · ${replicationPlan.cleanup_deferred_items} deferred` : "Outstanding repair or cleanup items"}
          />
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Group justify="space-between" align="flex-start">
                <Stack gap={4}>
                  <Text fw={700}>Current repair state</Text>
                  <Text size="sm" c="dimmed">
                    Live activity is node-local. Cluster-wide manual repair runs appear here when
                    they originate from this node.
                  </Text>
                </Stack>
                <Badge color={repairActivityBadgeColor(repairActivity?.state)} variant="light">
                  {repairActivity ? formatRepairActivityState(repairActivity.state) : "unknown"}
                </Badge>
              </Group>
              <Group gap="xs">
                <Badge variant="light" color={startupStatusColor(repairActivity?.startup_status)}>
                  startup {formatStartupRepairStatus(repairActivity?.startup_status ?? "disabled")}
                </Badge>
                <Badge variant="light">retention {retentionLabel}</Badge>
              </Group>
              {activeRuns.length > 0 ? (
                <Stack gap="sm">
                  {activeRuns.map((activeRun) => (
                    <Card key={activeRun.run_id} withBorder radius="md" padding="sm">
                      <Stack gap={6}>
                        <Group gap="xs">
                          <Badge color="orange" variant="light">
                            {formatRepairTrigger(activeRun.trigger)}
                          </Badge>
                          <Badge color="blue" variant="light">
                            {activeRun.scope}
                          </Badge>
                        </Group>
                        <Text size="sm">
                          Started {formatUnixTs(activeRun.started_at_unix)}
                        </Text>
                        <Text size="xs" c="dimmed">
                          Run ID <Code>{activeRun.run_id}</Code>
                        </Text>
                      </Stack>
                    </Card>
                  ))}
                </Stack>
              ) : (
                <Text size="sm" c="dimmed">
                  No repair runs are active on this node.
                </Text>
              )}
              {latestRun ? (
                <Card withBorder radius="md" padding="sm">
                  <Stack gap={6}>
                    <Group justify="space-between" align="flex-start">
                      <Text fw={600}>Latest finished run</Text>
                      <Badge color={repairStatusColor(latestRun.status)} variant="light">
                        {formatRepairStatus(latestRun.status)}
                      </Badge>
                    </Group>
                    <Text size="sm">
                      {formatRepairTrigger(latestRun.trigger)} on {latestRun.scope} scope, finished{" "}
                      {formatUnixTs(latestRun.finished_at_unix)} after {formatDurationShort(latestRun.duration_ms)}.
                    </Text>
                    <Text size="sm" c="dimmed">
                      {describeRepairRunSummary(latestRun)}
                    </Text>
                  </Stack>
                </Card>
              ) : null}
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Text fw={700}>Retained repair runs</Text>
              <Text size="sm" c="dimmed">
                Each finished repair run is stored persistently for postmortem debugging until it ages out of the retention window.
              </Text>
            </Stack>
            <Badge variant="light">{repairHistory ? `${repairHistory.runs.length} retained` : "not loaded"}</Badge>
          </Group>
          {repairHistory && repairHistory.runs.length > 0 ? (
            <Table.ScrollContainer minWidth={960}>
              <Table striped highlightOnHover withTableBorder>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Finished</Table.Th>
                    <Table.Th>Trigger</Table.Th>
                    <Table.Th>Scope</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Duration</Table.Th>
                    <Table.Th>Plan</Table.Th>
                    <Table.Th>Outcome</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {repairHistory.runs.map((run) => (
                    <Table.Tr key={run.run_id}>
                      <Table.Td>
                        <Stack gap={2}>
                          <Text size="sm">{formatUnixTs(run.finished_at_unix)}</Text>
                          <Text size="xs" c="dimmed">
                            started {formatUnixTs(run.started_at_unix)}
                          </Text>
                        </Stack>
                      </Table.Td>
                      <Table.Td>
                        <Badge color="blue" variant="light">
                          {formatRepairTrigger(run.trigger)}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Badge color={run.scope === "cluster" ? "teal" : "gray"} variant="light">
                          {run.scope}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Badge color={repairStatusColor(run.status)} variant="light">
                          {formatRepairStatus(run.status)}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{formatDurationShort(run.duration_ms)}</Table.Td>
                      <Table.Td>
                        <Text size="sm">
                          {run.plan_summary.under_replicated} under / {run.plan_summary.over_replicated} over
                        </Text>
                        <Text size="xs" c="dimmed">
                          {run.plan_summary.item_count} item{run.plan_summary.item_count === 1 ? "" : "s"}
                        </Text>
                      </Table.Td>
                      <Table.Td maw={280}>
                        <Text size="sm">{describeRepairRunSummary(run)}</Text>
                      </Table.Td>
                      <Table.Td>
                        <Button size="xs" variant="default" onClick={() => setSelectedRun(run)}>
                          Inspect
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          ) : (
            <Text c="dimmed">
              {loading ? "Loading retained repair runs..." : "No retained repair runs yet."}
            </Text>
          )}
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Text fw={700}>Replication plan</Text>
              <Text size="sm" c="dimmed">
                Only subjects that still need repair or cleanup attention are listed here.
              </Text>
            </Stack>
            <Stack gap="xs" align="flex-end">
              <Badge variant="light">
                {replicationPlan ? formatUnixTs(replicationPlan.generated_at_unix) : "not loaded"}
              </Badge>
              <Badge
                variant="light"
                color={!replicationPlan ? "gray" : replicationPlanEntries.length === 0 ? "teal" : "orange"}
              >
                {replicationPlan
                  ? `${replicationPlanEntries.length} attention item${replicationPlanEntries.length === 1 ? "" : "s"}`
                  : "loading"}
              </Badge>
            </Stack>
          </Group>
          {replicationPlan ? (
            <Stack gap="md">
              <Group gap="xs">
                <Badge
                  variant="light"
                  color={replicationPlan.under_replicated > 0 ? "orange" : "teal"}
                >
                  {replicationPlan.under_replicated} under-replicated
                </Badge>
                <Badge
                  variant="light"
                  color={replicationPlan.over_replicated > 0 ? "yellow" : "gray"}
                >
                  {replicationPlan.over_replicated} cleanup recommended
                </Badge>
                <Badge
                  variant="light"
                  color={replicationPlan.cleanup_deferred_items > 0 ? "blue" : "gray"}
                >
                  {replicationPlan.cleanup_deferred_items} cleanup deferred
                </Badge>
              </Group>

              {replicationPlanEntries.length > 0 ? (
                <Table.ScrollContainer minWidth={980}>
                  <Table striped highlightOnHover withTableBorder>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Subject</Table.Th>
                        <Table.Th>Status</Table.Th>
                        <Table.Th>Replication progress</Table.Th>
                        <Table.Th>Desired nodes</Table.Th>
                        <Table.Th>Current nodes</Table.Th>
                        <Table.Th>Cleanup</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {replicationPlanEntries.map(({ item, status, progress }) => (
                        <Table.Tr key={item.key}>
                          <Table.Td maw={260}>
                            <Text size="sm" fw={600} ff="monospace" style={{ wordBreak: "break-word" }}>
                              {item.key}
                            </Text>
                          </Table.Td>
                          <Table.Td miw={180}>
                            <Stack gap={4}>
                              <Badge color={status.color} variant="light">
                                {status.label}
                              </Badge>
                              <Text size="xs" c="dimmed">
                                {status.detail}
                              </Text>
                            </Stack>
                          </Table.Td>
                          <Table.Td miw={220}>
                            <Stack gap={6}>
                              <Group gap="xs" wrap="nowrap">
                                <Progress
                                  value={progress.percent}
                                  color={status.color}
                                  animated={progress.percent < 100}
                                  style={{ flex: 1 }}
                                />
                                <Text size="xs" c="dimmed" miw={40}>
                                  {progress.percent}%
                                </Text>
                              </Group>
                              <Text size="xs" c="dimmed">
                                {progress.present} / {progress.total} desired nodes currently present
                              </Text>
                              {item.missing_nodes.length > 0 ? (
                                <Stack gap={4}>
                                  <Text size="xs" c="dimmed">
                                    Missing nodes
                                  </Text>
                                  {renderNodeBadges(item.missing_nodes, "orange", "none")}
                                </Stack>
                              ) : null}
                            </Stack>
                          </Table.Td>
                          <Table.Td miw={220}>
                            {renderNodeBadges(item.desired_nodes, "blue", "none planned")}
                          </Table.Td>
                          <Table.Td miw={220}>
                            {renderNodeBadges(item.current_nodes, "teal", "not stored anywhere")}
                          </Table.Td>
                          <Table.Td miw={220}>
                            <Stack gap={6}>
                              <Badge color={replicationCleanupColor(item.cleanup_option)} variant="light">
                                {formatReplicationCleanupOption(item.cleanup_option)}
                              </Badge>
                              {item.extra_nodes.length > 0 ? (
                                <Stack gap={4}>
                                  <Text size="xs" c="dimmed">
                                    Extra nodes
                                  </Text>
                                  {renderNodeBadges(item.extra_nodes, "yellow", "none")}
                                </Stack>
                              ) : null}
                              {item.deferred_extra_nodes > 0 ? (
                                <Text size="xs" c="dimmed">
                                  {item.deferred_extra_nodes} extra node
                                  {item.deferred_extra_nodes === 1 ? "" : "s"} retained within tolerance.
                                </Text>
                              ) : item.cleanup_option === "none" ? (
                                <Text size="xs" c="dimmed">
                                  No cleanup action pending.
                                </Text>
                              ) : null}
                            </Stack>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              ) : (
                <Alert color="teal" variant="light" title="Replication plan is healthy">
                  The planner does not currently report any subjects that need repair or cleanup.
                </Alert>
              )}
            </Stack>
          ) : (
            <Text c="dimmed">{loading ? "Loading replication plan..." : "Replication plan not loaded."}</Text>
          )}
        </Stack>
      </Card>

      <Modal
        opened={selectedRun !== null}
        onClose={() => setSelectedRun(null)}
        title="Repair run details"
        size="xl"
        centered
      >
        <Stack gap="md">
          {selectedRun ? (
            <>
              <Group gap="xs">
                <Badge color="blue" variant="light">
                  {formatRepairTrigger(selectedRun.trigger)}
                </Badge>
                <Badge color={selectedRun.scope === "cluster" ? "teal" : "gray"} variant="light">
                  {selectedRun.scope}
                </Badge>
                <Badge color={repairStatusColor(selectedRun.status)} variant="light">
                  {formatRepairStatus(selectedRun.status)}
                </Badge>
              </Group>
              <Text size="sm">
                Started {formatUnixTs(selectedRun.started_at_unix)} and finished{" "}
                {formatUnixTs(selectedRun.finished_at_unix)} after {formatDurationShort(selectedRun.duration_ms)}.
              </Text>
              <Text size="sm" c="dimmed">
                {describeRepairRunSummary(selectedRun)}
              </Text>
              <JsonBlock value={selectedRun} />
            </>
          ) : null}
        </Stack>
      </Modal>
    </Stack>
  );
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

function formatRepairTrigger(trigger: string): string {
  switch (trigger) {
    case "manual_request":
      return "manual request";
    case "startup_repair":
      return "startup repair";
    case "background_audit":
      return "background audit";
    case "autonomous_post_write":
      return "post-write";
    case "peer_cluster_request":
      return "peer cluster request";
    default:
      return trigger;
  }
}

function formatRepairStatus(status: string): string {
  switch (status) {
    case "completed":
      return "completed";
    case "skipped_no_gaps":
      return "skipped, no gaps";
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

function repairStatusColor(status: string): string {
  switch (status) {
    case "completed":
      return "teal";
    case "skipped_no_gaps":
      return "blue";
    default:
      return "gray";
  }
}

function formatRetentionWindow(seconds: number): string {
  const days = Math.round(seconds / (24 * 60 * 60));
  if (days >= 365 && days % 365 === 0) {
    return `${days / 365}y`;
  }
  return `${days}d`;
}

function formatDurationShort(durationMs: number): string {
  if (durationMs < 1_000) {
    return `${durationMs} ms`;
  }
  const seconds = durationMs / 1_000;
  if (seconds < 60) {
    return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  }
  const minutes = seconds / 60;
  return `${minutes.toFixed(minutes < 10 ? 1 : 0)} min`;
}

function describeRepairRunSummary(run: RepairRunRecord | null): string {
  if (!run) {
    return "No retained repair summary available.";
  }
  if (!run.summary) {
    return "No transfers were needed for this run.";
  }

  const summary = run.summary;
  const nodesText =
    summary.nodes_contacted !== null && summary.nodes_contacted !== undefined
      ? ` across ${summary.nodes_contacted} node${summary.nodes_contacted === 1 ? "" : "s"}`
      : "";
  const failureSuffix =
    summary.last_error && summary.last_error.length > 0
      ? ` Last error: ${summary.last_error}`
      : "";
  return `${summary.attempted_transfers} attempted, ${summary.successful_transfers} successful, ${summary.failed_transfers} failed, ${summary.skipped_items} skipped${nodesText}.${failureSuffix}`;
}

type ReplicationPlanItem = ReplicationPlan["items"][number];

type ReplicationPlanEntry = {
  item: ReplicationPlanItem;
  status: {
    label: string;
    color: string;
    detail: string;
    severity: number;
  };
  progress: {
    present: number;
    total: number;
    percent: number;
  };
};

function compareReplicationPlanEntries(left: ReplicationPlanEntry, right: ReplicationPlanEntry): number {
  if (left.status.severity !== right.status.severity) {
    return left.status.severity - right.status.severity;
  }
  if (left.progress.percent !== right.progress.percent) {
    return left.progress.percent - right.progress.percent;
  }
  return left.item.key.localeCompare(right.item.key);
}

function getReplicationItemStatus(item: ReplicationPlanItem): ReplicationPlanEntry["status"] {
  if (item.missing_nodes.length > 0 && item.extra_nodes.length > 0) {
    return {
      label: "repair + cleanup",
      color: "orange",
      detail: `${item.missing_nodes.length} missing and ${item.extra_nodes.length} extra node${item.extra_nodes.length === 1 ? "" : "s"}`,
      severity: 0
    };
  }

  if (item.missing_nodes.length > 0) {
    return {
      label: "under replicated",
      color: "orange",
      detail: `${item.missing_nodes.length} desired node${item.missing_nodes.length === 1 ? "" : "s"} still missing`,
      severity: 1
    };
  }

  if (item.extra_nodes.length > 0) {
    return {
      label: "cleanup recommended",
      color: "yellow",
      detail: `${item.extra_nodes.length} extra node${item.extra_nodes.length === 1 ? "" : "s"} can be removed`,
      severity: 2
    };
  }

  if (item.deferred_extra_nodes > 0 || item.cleanup_option === "deferred_within_tolerance") {
    return {
      label: "cleanup deferred",
      color: "blue",
      detail: `${item.deferred_extra_nodes} extra node${item.deferred_extra_nodes === 1 ? "" : "s"} retained within tolerance`,
      severity: 3
    };
  }

  return {
    label: "healthy",
    color: "teal",
    detail: "Desired placement is fully satisfied",
    severity: 4
  };
}

function getReplicationItemProgress(item: ReplicationPlanItem): ReplicationPlanEntry["progress"] {
  const total = item.desired_nodes.length;
  if (total === 0) {
    return {
      present: 0,
      total: 0,
      percent: 100
    };
  }

  const present = Math.max(0, total - item.missing_nodes.length);
  return {
    present,
    total,
    percent: Math.max(0, Math.min(100, Math.round((present / total) * 100)))
  };
}

function formatReplicationCleanupOption(option: ReplicationPlanItem["cleanup_option"]): string {
  switch (option) {
    case "recommended":
      return "cleanup recommended";
    case "deferred_within_tolerance":
      return "cleanup deferred";
    case "none":
    default:
      return "no cleanup";
  }
}

function replicationCleanupColor(option: ReplicationPlanItem["cleanup_option"]): string {
  switch (option) {
    case "recommended":
      return "yellow";
    case "deferred_within_tolerance":
      return "blue";
    case "none":
    default:
      return "gray";
  }
}

function renderNodeBadges(nodes: string[], color: string, emptyLabel: string) {
  if (nodes.length === 0) {
    return (
      <Text size="xs" c="dimmed">
        {emptyLabel}
      </Text>
    );
  }

  return (
    <Group gap={6} wrap="wrap">
      {nodes.map((node) => (
        <Badge key={node} color={color} variant="light">
          {node}
        </Badge>
      ))}
    </Group>
  );
}