import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getDataScrubClusterStatus,
  getManualRepairActions,
  getRepairActivityStatus,
  getRepairHistory,
  getReplicationPlan,
  runManualRepairAction,
  triggerDataScrub,
  triggerReplicationRepair,
  type DataScrubRunRecord,
  type RepairLogEntry,
  type ManualRepairActionRunResponse,
  type RepairRunRecord,
  type ReplicationPlan
} from "@ironmesh/api";
import { IconPlayerPlay, IconSearch } from "@tabler/icons-react";
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
  Select,
  Stack,
  Table,
  Text
} from "@mantine/core";
import { JsonBlock, StatCard } from "@ironmesh/ui";
import { useCallback, useEffect, useState } from "react";
import { formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

const DEFAULT_REPAIR_LIST_PAGE_SIZE = 20;
const REPAIR_LIST_PAGE_SIZE_OPTIONS = [10, 20, 50, 100].map((value) => ({
  value: String(value),
  label: `${value} per list`
}));

export function RepairPage() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const [selectedRun, setSelectedRun] = useState<RepairRunRecord | null>(null);
  const [selectedScrubRun, setSelectedScrubRun] = useState<DataScrubRunRecord | null>(null);
  const [manualActionResult, setManualActionResult] =
    useState<ManualRepairActionRunResponse | null>(null);
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
  const manualRepairActionsQuery = useQuery({
    queryKey: ["repair-page", "manual-actions", normalizedAdminTokenOverride],
    queryFn: () => getManualRepairActions(normalizedAdminTokenOverride || undefined),
    enabled: canInspectRepair
  });
  const replicationPlanQuery = useQuery({
    queryKey: ["repair-page", "replication-plan", normalizedAdminTokenOverride],
    queryFn: () => getReplicationPlan(normalizedAdminTokenOverride || undefined),
    enabled: canInspectRepair
  });
  const scrubClusterQuery = useQuery({
    queryKey: ["repair-page", "scrub-cluster", normalizedAdminTokenOverride],
    queryFn: () =>
      getDataScrubClusterStatus({ limit: 120 }, normalizedAdminTokenOverride || undefined),
    enabled: canInspectRepair,
    refetchInterval: 5_000
  });

  const refresh = useCallback(async () => {
    const queryKeys: ReadonlyArray<readonly unknown[]> = [
      ["repair-page", "activity", normalizedAdminTokenOverride],
      ["repair-page", "history", normalizedAdminTokenOverride],
      ["repair-page", "manual-actions", normalizedAdminTokenOverride],
      ["repair-page", "replication-plan", normalizedAdminTokenOverride],
      ["repair-page", "scrub-cluster", normalizedAdminTokenOverride]
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
  const scrubMutation = useMutation({
    mutationFn: () => triggerDataScrub("cluster", normalizedAdminTokenOverride || undefined),
    onSuccess: async () => {
      await refresh();
    }
  });
  const manualRepairActionMutation = useMutation({
    mutationFn: ({ actionId, dryRun }: { actionId: string; dryRun: boolean }) =>
      runManualRepairAction(actionId, { dryRun }, normalizedAdminTokenOverride || undefined),
    onSuccess: async (result) => {
      setManualActionResult(result);
      await refresh();
    }
  });

  const repairActivity = canInspectRepair ? repairActivityQuery.data ?? null : null;
  const repairHistory = canInspectRepair ? repairHistoryQuery.data ?? null : null;
  const manualRepairActions = canInspectRepair ? manualRepairActionsQuery.data?.actions ?? [] : [];
  const replicationPlan = canInspectRepair ? replicationPlanQuery.data ?? null : null;
  const scrubCluster = canInspectRepair ? scrubClusterQuery.data ?? null : null;
  const scrubAutoRepairRuns =
    repairHistory?.runs.filter((run) => run.trigger === "data_scrub_auto_repair") ?? [];
  const latestRun = repairActivity?.latest_run ?? null;
  const activeRuns = repairActivity?.active_runs ?? [];
  const scrubRuns = scrubCluster?.runs ?? [];
  const scrubNodes = scrubCluster?.nodes ?? [];
  const selectedScrubRelatedRepairRuns = selectedScrubRun
    ? findRelatedRepairRuns(selectedScrubRun, scrubAutoRepairRuns)
    : [];
  const latestScrubRun = mostRecentScrubRun(scrubRuns);
  const retentionLabel = repairHistory
    ? formatRetentionWindow(repairHistory.retention_secs)
    : "not loaded";
  const scrubRetentionLabel = scrubNodes[0]
    ? formatRetentionWindow(scrubNodes[0].retention_secs)
    : "not loaded";
  const replicationPlanEntries = replicationPlan
    ? replicationPlan.items
        .map((item) => ({
          item,
          status: getReplicationItemStatus(item),
          progress: getReplicationItemProgress(item)
        }))
        .sort(compareReplicationPlanEntries)
    : [];
  const [listPageSize, setListPageSize] = useState(DEFAULT_REPAIR_LIST_PAGE_SIZE);
  const [manualRepairActionsPageIndex, setManualRepairActionsPageIndex] = useClampedPageIndex(
    manualRepairActions.length,
    listPageSize
  );
  const [repairRunsPageIndex, setRepairRunsPageIndex] = useClampedPageIndex(
    repairHistory?.runs.length ?? 0,
    listPageSize
  );
  const [replicationPlanPageIndex, setReplicationPlanPageIndex] = useClampedPageIndex(
    replicationPlanEntries.length,
    listPageSize
  );
  const [scrubNodesPageIndex, setScrubNodesPageIndex] = useClampedPageIndex(
    scrubNodes.length,
    listPageSize
  );
  const [scrubRunsPageIndex, setScrubRunsPageIndex] = useClampedPageIndex(
    scrubRuns.length,
    listPageSize
  );
  const pagedManualRepairActions = paginateItems(
    manualRepairActions,
    manualRepairActionsPageIndex,
    listPageSize
  );
  const pagedRepairRuns = paginateItems(repairHistory?.runs ?? [], repairRunsPageIndex, listPageSize);
  const pagedReplicationPlanEntries = paginateItems(
    replicationPlanEntries,
    replicationPlanPageIndex,
    listPageSize
  );
  const pagedScrubNodes = paginateItems(scrubNodes, scrubNodesPageIndex, listPageSize);
  const pagedScrubRuns = paginateItems(scrubRuns, scrubRunsPageIndex, listPageSize);
  const loading =
    repairActivityQuery.isFetching ||
    repairHistoryQuery.isFetching ||
    manualRepairActionsQuery.isFetching ||
    replicationPlanQuery.isFetching ||
    scrubClusterQuery.isFetching;
  const error = firstErrorMessage([
    manualRepairActionMutation.error,
    scrubMutation.error,
    repairMutation.error,
    repairActivityQuery.error,
    repairHistoryQuery.error,
    manualRepairActionsQuery.error,
    replicationPlanQuery.error,
    scrubClusterQuery.error
  ]);

  function handleListPageSizeChange(value: string | null) {
    const nextPageSize = parseRepairListPageSize(value);
    setListPageSize(nextPageSize);
    setManualRepairActionsPageIndex(0);
    setRepairRunsPageIndex(0);
    setReplicationPlanPageIndex(0);
    setScrubNodesPageIndex(0);
    setScrubRunsPageIndex(0);
  }

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This page is the operator workspace for repair and data scrubbing. It keeps live repair
          state, retained repair runs, clustered scrub history, and the replication plan in one
          maintenance view instead of crowding the dashboard.
        </Text>
        <Stack gap="xs" align="flex-end">
          <Group>
            <Button
              variant="default"
              onClick={() => void repairMutation.mutateAsync()}
              loading={repairMutation.isPending}
              disabled={!canInspectRepair}
            >
              Run cluster repair pass
            </Button>
            <Button
              variant="default"
              color="teal"
              onClick={() => void scrubMutation.mutateAsync()}
              loading={scrubMutation.isPending}
              disabled={!canInspectRepair}
            >
              Run data scrub now
            </Button>
            <Button variant="light" onClick={() => void refresh()} loading={loading}>
              Refresh
            </Button>
          </Group>
          <Select
            label="Rows per list"
            value={String(listPageSize)}
            data={REPAIR_LIST_PAGE_SIZE_OPTIONS}
            allowDeselect={false}
            onChange={handleListPageSizeChange}
            w={160}
          />
        </Stack>
      </Group>

      {!canInspectRepair ? (
        <Alert color="blue" title="Admin access required">
          Sign in or provide an admin token override to inspect repair activity, clustered scrub
          history, and retained maintenance runs.
        </Alert>
      ) : null}
      {error ? <Alert color="red" title="Failed to load maintenance state">{error}</Alert> : null}

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <Text fw={700}>Manual repair actions</Text>
            <Stack gap="xs" align="flex-end">
              <Badge variant="light">
                {manualRepairActionsQuery.data
                  ? `${manualRepairActions.length} available`
                  : loading
                    ? "loading"
                    : "not loaded"}
              </Badge>
              <TablePageControls
                pagination={pagedManualRepairActions}
                onPrevious={() => setManualRepairActionsPageIndex((current) => current - 1)}
                onNext={() => setManualRepairActionsPageIndex((current) => current + 1)}
              />
            </Stack>
          </Group>
          {manualRepairActions.length > 0 ? (
            <Table.ScrollContainer minWidth={760}>
              <Table striped highlightOnHover withTableBorder>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Action</Table.Th>
                    <Table.Th>Description</Table.Th>
                    <Table.Th>Mode</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {pagedManualRepairActions.pageItems.map((action) => {
                    const actionPending =
                      manualRepairActionMutation.isPending &&
                      manualRepairActionMutation.variables?.actionId === action.id;
                    return (
                      <Table.Tr key={action.id}>
                        <Table.Td>
                          <Stack gap={4}>
                            <Text fw={600}>{action.label}</Text>
                            <Text size="xs" ff="monospace" c="dimmed">
                              {action.id}
                            </Text>
                          </Stack>
                        </Table.Td>
                        <Table.Td maw={420}>
                          <Text size="sm" c="dimmed">
                            {action.description}
                          </Text>
                        </Table.Td>
                        <Table.Td>
                          <Group gap="xs">
                            {action.dry_run_supported ? (
                              <Badge variant="light" color="blue">
                                dry run
                              </Badge>
                            ) : null}
                            <Badge variant="light" color={action.destructive ? "red" : "teal"}>
                              {action.destructive ? "destructive" : "metadata"}
                            </Badge>
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          <Group gap="xs" justify="flex-end" wrap="nowrap">
                            <Button
                              size="xs"
                              variant="default"
                              disabled={!canInspectRepair || !action.dry_run_supported}
                              loading={actionPending && manualRepairActionMutation.variables?.dryRun}
                              leftSection={<IconSearch size={14} />}
                              onClick={() =>
                                void manualRepairActionMutation.mutateAsync({
                                  actionId: action.id,
                                  dryRun: true
                                })
                              }
                            >
                              Dry run
                            </Button>
                            <Button
                              size="xs"
                              color={action.destructive ? "red" : "teal"}
                              variant="light"
                              disabled={!canInspectRepair}
                              loading={
                                actionPending && !manualRepairActionMutation.variables?.dryRun
                              }
                              leftSection={<IconPlayerPlay size={14} />}
                              onClick={() =>
                                void manualRepairActionMutation.mutateAsync({
                                  actionId: action.id,
                                  dryRun: false
                                })
                              }
                            >
                              Run action
                            </Button>
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          ) : (
            <Text c="dimmed">
              {loading ? "Loading manual repair actions..." : "No manual repair actions are available."}
            </Text>
          )}
          {manualActionResult ? (
            <Alert
              color={manualActionResult.changed ? "teal" : "blue"}
              variant="light"
              title={manualActionResult.dry_run ? "Manual repair dry run finished" : "Manual repair action finished"}
            >
              <Stack gap="sm">
                <Text size="sm">{manualActionResult.summary}</Text>
                <Text size="xs" c="dimmed">
                  Action <Code>{manualActionResult.action_id}</Code> finished after{" "}
                  {formatDurationShort(manualActionResult.duration_ms)}.
                </Text>
                <JsonBlock value={manualActionResult} />
              </Stack>
            </Alert>
          ) : null}
        </Stack>
      </Card>

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
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Scrub Coverage"
            value={scrubCluster ? scrubNodes.length : loading ? <Loader size="sm" /> : "unknown"}
            hint={scrubCluster ? `${scrubCluster.skipped_nodes.length} skipped node${scrubCluster.skipped_nodes.length === 1 ? "" : "s"}` : "Reachable nodes reporting scrub state"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Latest Scrub"
            value={latestScrubRun ? formatUnixTs(latestScrubRun.finished_at_unix) : loading ? <Loader size="sm" /> : "none"}
            hint={latestScrubRun ? `${formatDataScrubStatus(latestScrubRun.status)} · ${latestScrubRun.summary.issue_count} issue${latestScrubRun.summary.issue_count === 1 ? "" : "s"}` : "No retained scrub run yet"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Latest Scrub Findings"
            value={latestScrubRun ? latestScrubRun.summary.issue_count : loading ? <Loader size="sm" /> : "unknown"}
            hint={latestScrubRun ? `${latestScrubRun.summary.manifests_scanned} manifests · ${latestScrubRun.summary.chunks_scanned} chunks verified` : "Latest clustered scrub findings"}
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
                        {activeRun.live_log.length > 0 ? (
                          <Card withBorder radius="sm" padding="sm">
                            <Stack gap={6}>
                              <Group justify="space-between" align="flex-start">
                                <Text fw={600} size="sm">
                                  Live progress log
                                </Text>
                                <Group gap="xs">
                                  <Badge variant="light" color="teal">
                                    {activeRun.live_log.length} event
                                    {activeRun.live_log.length === 1 ? "" : "s"}
                                  </Badge>
                                  {activeRun.live_log_truncated ? (
                                    <Badge variant="light" color="yellow">
                                      latest slice
                                    </Badge>
                                  ) : null}
                                </Group>
                              </Group>
                              <Text size="xs" c="dimmed">
                                Latest event{" "}
                                {formatUnixTs(
                                  activeRun.last_log_at_unix ?? activeRun.started_at_unix
                                )}
                              </Text>
                              <div
                                role="log"
                                aria-live="polite"
                                style={{
                                  maxHeight: 240,
                                  overflowY: "auto",
                                  overflowX: "auto",
                                  paddingRight: 8
                                }}
                              >
                                <Text ff="monospace" size="xs" style={{ whiteSpace: "pre-wrap" }}>
                                  {activeRun.live_log
                                    .slice()
                                    .reverse()
                                    .map(formatRepairLogLine)
                                    .join("\n")}
                                </Text>
                              </div>
                            </Stack>
                          </Card>
                        ) : (
                          <Text size="xs" c="dimmed">
                            Waiting for live progress entries from this run.
                          </Text>
                        )}
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
            <Stack gap="xs" align="flex-end">
              <Badge variant="light">{repairHistory ? `${repairHistory.runs.length} retained` : "not loaded"}</Badge>
              <TablePageControls
                pagination={pagedRepairRuns}
                onPrevious={() => setRepairRunsPageIndex((current) => current - 1)}
                onNext={() => setRepairRunsPageIndex((current) => current + 1)}
              />
            </Stack>
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
                  {pagedRepairRuns.pageItems.map((run) => (
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
              <TablePageControls
                pagination={pagedReplicationPlanEntries}
                onPrevious={() => setReplicationPlanPageIndex((current) => current - 1)}
                onNext={() => setReplicationPlanPageIndex((current) => current + 1)}
              />
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
                      {pagedReplicationPlanEntries.pageItems.map(({ item, status, progress }) => (
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

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Text fw={700}>Data scrub status across reachable nodes</Text>
              <Text size="sm" c="dimmed">
                Each reachable node reports its own scrub scheduler state and latest retained scrub
                result here.
              </Text>
            </Stack>
            <Stack gap="xs" align="flex-end">
              <Badge variant="light">retention {scrubRetentionLabel}</Badge>
              <Badge variant="light" color={scrubNodes.length > 0 ? "teal" : "gray"}>
                {scrubNodes.length} reachable node{scrubNodes.length === 1 ? "" : "s"}
              </Badge>
              <TablePageControls
                pagination={pagedScrubNodes}
                onPrevious={() => setScrubNodesPageIndex((current) => current - 1)}
                onNext={() => setScrubNodesPageIndex((current) => current + 1)}
              />
            </Stack>
          </Group>

          {scrubCluster && scrubCluster.skipped_nodes.length > 0 ? (
            <Alert color="yellow" variant="light" title="Some nodes did not return scrub state">
              {scrubCluster.skipped_nodes
                .map((node) => `${node.node_id}: ${node.error}`)
                .join(" | ")}
            </Alert>
          ) : null}

          {scrubNodes.length > 0 ? (
            <Grid>
              {pagedScrubNodes.pageItems.map((node) => (
                <Grid.Col key={node.node_id} span={{ base: 12, md: 6, xl: 4 }}>
                  <Card withBorder radius="md" padding="md">
                    <Stack gap="sm">
                      <Group justify="space-between" align="flex-start">
                        <Stack gap={4}>
                          <Text fw={600} ff="monospace" style={{ wordBreak: "break-word" }}>
                            {node.node_id}
                          </Text>
                          <Text size="xs" c="dimmed">
                            {node.enabled
                              ? `scheduled every ${formatIntervalShort(node.interval_secs)}`
                              : "background schedule disabled"}
                          </Text>
                        </Stack>
                        <Badge color={dataScrubStateColor(node.state)} variant="light">
                          {formatDataScrubActivityState(node.state)}
                        </Badge>
                      </Group>
                      <Group gap="xs">
                        <Badge variant="light" color={node.enabled ? "teal" : "gray"}>
                          {node.enabled ? "scheduled" : "manual only"}
                        </Badge>
                        <Badge variant="light">retention {formatRetentionWindow(node.retention_secs)}</Badge>
                      </Group>
                      {node.active_runs.length > 0 ? (
                        <Stack gap={6}>
                          {node.active_runs.map((activeRun) => (
                            <Card key={activeRun.run_id} withBorder radius="md" padding="sm">
                              <Stack gap={4}>
                                <Group gap="xs">
                                  <Badge color="orange" variant="light">
                                    {formatDataScrubTrigger(activeRun.trigger)}
                                  </Badge>
                                  <Badge color="orange" variant="light">
                                    running
                                  </Badge>
                                </Group>
                                <Text size="sm">Started {formatUnixTs(activeRun.started_at_unix)}</Text>
                                <Text size="xs" c="dimmed">
                                  Run ID <Code>{activeRun.run_id}</Code>
                                </Text>
                              </Stack>
                            </Card>
                          ))}
                        </Stack>
                      ) : node.latest_run ? (
                        <Card withBorder radius="md" padding="sm">
                          <Stack gap={6}>
                            <Group justify="space-between" align="flex-start">
                              <Text fw={600}>Latest retained scrub</Text>
                              <Badge color={dataScrubStatusColor(node.latest_run.status)} variant="light">
                                {formatDataScrubStatus(node.latest_run.status)}
                              </Badge>
                            </Group>
                            <Text size="sm">
                              Finished {formatUnixTs(node.latest_run.finished_at_unix)} after {formatDurationShort(node.latest_run.duration_ms)}.
                            </Text>
                            <Text size="sm" c="dimmed">
                              {describeDataScrubRunSummary(node.latest_run)}
                            </Text>
                          </Stack>
                        </Card>
                      ) : (
                        <Text size="sm" c="dimmed">
                          No retained scrub run yet for this node.
                        </Text>
                      )}
                    </Stack>
                  </Card>
                </Grid.Col>
              ))}
            </Grid>
          ) : (
            <Text c="dimmed">
              {loading ? "Loading clustered scrub state..." : "No reachable nodes reported scrub state."}
            </Text>
          )}
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Text fw={700}>Retained data scrub runs</Text>
              <Text size="sm" c="dimmed">
                Retained scrub results are aggregated from reachable nodes so corruption checks can
                be reviewed without jumping between node admin pages.
              </Text>
            </Stack>
            <Stack gap="xs" align="flex-end">
              <Badge variant="light">{scrubCluster ? `${scrubRuns.length} retained` : "not loaded"}</Badge>
              <TablePageControls
                pagination={pagedScrubRuns}
                onPrevious={() => setScrubRunsPageIndex((current) => current - 1)}
                onNext={() => setScrubRunsPageIndex((current) => current + 1)}
              />
            </Stack>
          </Group>
          {scrubRuns.length > 0 ? (
            <Table.ScrollContainer minWidth={980}>
              <Table striped highlightOnHover withTableBorder>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Finished</Table.Th>
                    <Table.Th>Node</Table.Th>
                    <Table.Th>Trigger</Table.Th>
                    <Table.Th>Status</Table.Th>
                    <Table.Th>Duration</Table.Th>
                    <Table.Th>Verified</Table.Th>
                    <Table.Th>Findings</Table.Th>
                    <Table.Th>Auto-repair</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {pagedScrubRuns.pageItems.map((run) => {
                    const relatedRepairRuns = findRelatedRepairRuns(run, scrubAutoRepairRuns);

                    return <Table.Tr key={run.run_id}>
                      <Table.Td>
                        <Stack gap={2}>
                          <Text size="sm">{formatUnixTs(run.finished_at_unix)}</Text>
                          <Text size="xs" c="dimmed">
                            started {formatUnixTs(run.started_at_unix)}
                          </Text>
                        </Stack>
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" ff="monospace" style={{ wordBreak: "break-word" }}>
                          {run.reporting_node_id}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        <Badge color="blue" variant="light">
                          {formatDataScrubTrigger(run.trigger)}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Badge color={dataScrubStatusColor(run.status)} variant="light">
                          {formatDataScrubStatus(run.status)}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{formatDurationShort(run.duration_ms)}</Table.Td>
                      <Table.Td>
                        <Text size="sm">
                          {run.summary.manifests_scanned} manifests / {run.summary.chunks_scanned} chunks
                        </Text>
                        <Text size="xs" c="dimmed">
                          {formatBytesShort(run.summary.bytes_scanned)} read
                        </Text>
                      </Table.Td>
                      <Table.Td maw={280}>
                        <Text size="sm">{describeDataScrubRunSummary(run)}</Text>
                      </Table.Td>
                      <Table.Td miw={180}>
                        {relatedRepairRuns.length > 0 ? (
                          <Stack gap={6}>
                            <Badge color="teal" variant="light">
                              {relatedRepairRuns.length} follow-on auto-repair
                              {relatedRepairRuns.length === 1 ? "" : "s"}
                            </Badge>
                            <Button
                              size="xs"
                              variant="light"
                              onClick={() => setSelectedRun(relatedRepairRuns[0] ?? null)}
                            >
                              Inspect repair
                            </Button>
                          </Stack>
                        ) : (
                          <Text size="sm" c="dimmed">
                            none linked
                          </Text>
                        )}
                      </Table.Td>
                      <Table.Td>
                        <Button size="xs" variant="default" onClick={() => setSelectedScrubRun(run)}>
                          Inspect
                        </Button>
                      </Table.Td>
                    </Table.Tr>;
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          ) : (
            <Text c="dimmed">
              {loading ? "Loading retained scrub runs..." : "No retained scrub runs yet."}
            </Text>
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

      <Modal
        opened={selectedScrubRun !== null}
        onClose={() => setSelectedScrubRun(null)}
        title="Data scrub details"
        size="xl"
        centered
      >
        <Stack gap="md">
          {selectedScrubRun ? (
            <>
              <Group gap="xs">
                <Badge color="blue" variant="light">
                  {formatDataScrubTrigger(selectedScrubRun.trigger)}
                </Badge>
                <Badge color={dataScrubStatusColor(selectedScrubRun.status)} variant="light">
                  {formatDataScrubStatus(selectedScrubRun.status)}
                </Badge>
              </Group>
              <Text size="sm">
                Node <Code>{selectedScrubRun.reporting_node_id}</Code> started {formatUnixTs(selectedScrubRun.started_at_unix)} and finished {" "}
                {formatUnixTs(selectedScrubRun.finished_at_unix)} after {formatDurationShort(selectedScrubRun.duration_ms)}.
              </Text>
              <Text size="sm" c="dimmed">
                {describeDataScrubRunSummary(selectedScrubRun)}
              </Text>
              {selectedScrubRelatedRepairRuns.length > 0 ? (
                <Card withBorder radius="md" padding="sm">
                  <Stack gap={6}>
                    <Text fw={600}>Follow-on auto-repair</Text>
                    {selectedScrubRelatedRepairRuns.map((run) => (
                      <Group key={run.run_id} justify="space-between" align="flex-start">
                        <Stack gap={2}>
                          <Text size="sm">
                            {formatRepairTrigger(run.trigger)} finished {formatUnixTs(run.finished_at_unix)}
                          </Text>
                          <Text size="xs" c="dimmed">
                            {describeRepairRunSummary(run)}
                          </Text>
                        </Stack>
                        <Button size="xs" variant="light" onClick={() => setSelectedRun(run)}>
                          Inspect repair
                        </Button>
                      </Group>
                    ))}
                  </Stack>
                </Card>
              ) : null}
              <JsonBlock value={selectedScrubRun} />
            </>
          ) : null}
        </Stack>
      </Modal>
    </Stack>
  );
}

type PaginatedItems<T> = {
  pageItems: T[];
  pageIndex: number;
  pageCount: number;
  totalItems: number;
  startItem: number;
  endItem: number;
};

type TablePageControlsProps = {
  pagination: PaginatedItems<unknown>;
  onPrevious: () => void;
  onNext: () => void;
};

function useClampedPageIndex(totalItems: number, pageSize: number) {
  const [pageIndex, setPageIndex] = useState(0);

  useEffect(() => {
    setPageIndex((current) => clampPageIndex(current, totalItems, pageSize));
  }, [pageSize, totalItems]);

  return [pageIndex, setPageIndex] as const;
}

function paginateItems<T>(items: T[], pageIndex: number, pageSize: number): PaginatedItems<T> {
  const resolvedPageSize = Math.max(1, Math.trunc(pageSize) || DEFAULT_REPAIR_LIST_PAGE_SIZE);
  const totalItems = items.length;
  const pageCount = totalItems === 0 ? 1 : Math.ceil(totalItems / resolvedPageSize);
  const resolvedPageIndex = clampPageIndex(pageIndex, totalItems, resolvedPageSize);
  const startIndex = totalItems === 0 ? 0 : resolvedPageIndex * resolvedPageSize;
  const endIndex = Math.min(startIndex + resolvedPageSize, totalItems);

  return {
    pageItems: items.slice(startIndex, endIndex),
    pageIndex: resolvedPageIndex,
    pageCount,
    totalItems,
    startItem: totalItems === 0 ? 0 : startIndex + 1,
    endItem: endIndex
  };
}

function clampPageIndex(pageIndex: number, totalItems: number, pageSize: number): number {
  const maxPageIndex = Math.max(0, Math.ceil(totalItems / Math.max(1, pageSize)) - 1);
  return Math.min(Math.max(0, Math.trunc(pageIndex) || 0), maxPageIndex);
}

function parseRepairListPageSize(value: string | null): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return DEFAULT_REPAIR_LIST_PAGE_SIZE;
  }
  return parsed;
}

function TablePageControls({ pagination, onPrevious, onNext }: TablePageControlsProps) {
  if (pagination.totalItems === 0) {
    return null;
  }

  return (
    <Stack gap={4} align="flex-end">
      <Text size="xs" c="dimmed">
        Showing {pagination.startItem}-{pagination.endItem} of {pagination.totalItems}
      </Text>
      {pagination.pageCount > 1 ? (
        <Group gap="xs">
          <Button
            size="xs"
            variant="default"
            onClick={onPrevious}
            disabled={pagination.pageIndex === 0}
          >
            Prev
          </Button>
          <Text size="xs" c="dimmed">
            Page {pagination.pageIndex + 1} / {pagination.pageCount}
          </Text>
          <Button
            size="xs"
            variant="default"
            onClick={onNext}
            disabled={pagination.pageIndex >= pagination.pageCount - 1}
          >
            Next
          </Button>
        </Group>
      ) : null}
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
    case "data_scrub_auto_repair":
      return "scrub auto-repair";
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

function formatRepairLogEvent(event: string): string {
  return event.replaceAll("_", " ");
}

function formatRepairLogLine(entry: RepairLogEntry): string {
  const qualifiers: string[] = [];
  if (entry.key) {
    qualifiers.push(`key=${entry.key}`);
  }
  if (entry.version_id) {
    qualifiers.push(`version=${entry.version_id}`);
  }
  if (entry.subject && entry.subject !== entry.key) {
    qualifiers.push(`subject=${entry.subject}`);
  }
  if (entry.source_node_id || entry.target_node_id) {
    qualifiers.push(
      `path=${entry.source_node_id ?? "unknown"}->${entry.target_node_id ?? "unknown"}`
    );
  }

  return [
    `${formatUnixTs(entry.captured_at_unix)} [${formatRepairLogEvent(entry.event)}]`,
    entry.detail,
    qualifiers.length > 0 ? `(${qualifiers.join(", ")})` : null
  ]
    .filter((part): part is string => part !== null)
    .join(" ");
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

function mostRecentScrubRun(runs: DataScrubRunRecord[]): DataScrubRunRecord | null {
  return runs[0] ?? null;
}

function formatDataScrubActivityState(state: string): string {
  switch (state) {
    case "running":
      return "running";
    case "idle":
    default:
      return "idle";
  }
}

function formatDataScrubTrigger(trigger: string): string {
  switch (trigger) {
    case "manual_request":
      return "manual request";
    case "scheduled":
      return "scheduled";
    case "peer_cluster_request":
      return "peer cluster request";
    default:
      return trigger;
  }
}

function formatDataScrubStatus(status: string): string {
  switch (status) {
    case "clean":
      return "clean";
    case "issues_detected":
      return "issues detected";
    case "failed":
      return "failed";
    default:
      return status;
  }
}

function findRelatedRepairRuns(
  scrubRun: DataScrubRunRecord,
  repairRuns: RepairRunRecord[]
): RepairRunRecord[] {
  const lowerBound = scrubRun.finished_at_unix;
  const upperBound = scrubRun.finished_at_unix + 120;
  return repairRuns.filter(
    (run) =>
      run.trigger === "data_scrub_auto_repair" &&
      run.reporting_node_id === scrubRun.reporting_node_id &&
      run.started_at_unix >= lowerBound &&
      run.started_at_unix <= upperBound
  );
}

function dataScrubStateColor(state: string): string {
  switch (state) {
    case "running":
      return "orange";
    case "idle":
    default:
      return "gray";
  }
}

function dataScrubStatusColor(status: string): string {
  switch (status) {
    case "clean":
      return "teal";
    case "issues_detected":
      return "yellow";
    case "failed":
      return "red";
    default:
      return "gray";
  }
}

function formatIntervalShort(seconds: number): string {
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = seconds / 60;
  if (minutes < 60) {
    return `${minutes % 1 === 0 ? minutes.toFixed(0) : minutes.toFixed(1)}m`;
  }
  const hours = minutes / 60;
  if (hours < 24) {
    return `${hours % 1 === 0 ? hours.toFixed(0) : hours.toFixed(1)}h`;
  }
  const days = hours / 24;
  return `${days % 1 === 0 ? days.toFixed(0) : days.toFixed(1)}d`;
}

function formatBytesShort(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unitIndex]}`;
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

function describeDataScrubRunSummary(run: DataScrubRunRecord | null): string {
  if (!run) {
    return "No retained data scrub summary available.";
  }
  if (run.status === "failed") {
    return run.last_error && run.last_error.length > 0
      ? `Scrub failed before completion. Last error: ${run.last_error}`
      : "Scrub failed before completion.";
  }

  const findingsText =
    run.summary.issue_count === 0
      ? "No issues detected."
      : `${run.summary.issue_count} issue${run.summary.issue_count === 1 ? "" : "s"} detected.`;
  const verificationText = `${run.summary.manifests_scanned} manifests and ${run.summary.chunks_scanned} chunks verified.`;
  const sampleSuffix =
    run.summary.issue_sample_truncated && run.summary.sampled_issue_count > 0
      ? ` Showing ${run.summary.sampled_issue_count} sampled issue${run.summary.sampled_issue_count === 1 ? "" : "s"}.`
      : "";
  return `${findingsText} ${verificationText}${sampleSuffix}`;
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
