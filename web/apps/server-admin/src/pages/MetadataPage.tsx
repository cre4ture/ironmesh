import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getMetadataDbLogicalDistributionStatus,
  getStorageStatsCurrent,
  getStorageStatsHistory,
  startMetadataDbLogicalDistribution,
  type MetadataDbLogicalDistribution,
  type MetadataDbLogicalDistributionStatusResponse,
  type StorageStatsSample
} from "@ironmesh/api";
import {
  StatCard,
  ZoomableTimeSeriesChart,
  formatTimeSeriesChartTimestamp
} from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Code,
  Grid,
  Group,
  Progress,
  ScrollArea,
  Stack,
  Table,
  Text
} from "@mantine/core";
import { useCallback, useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps
} from "recharts";
import {
  resolveLivePollInterval,
  useLivePollingMode,
  useViewportVisibility
} from "../lib/live-polling";
import { formatBytes, formatRelativeUnixTs, formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

type MetadataHistoryRangeKey = "24h" | "7d" | "30d" | "90d" | "1y" | "all";

const METADATA_HISTORY_MAX_POINTS = 360;
const METADATA_HISTORY_RANGE_OPTIONS: Array<{
  key: MetadataHistoryRangeKey;
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

type MetadataChartPoint = {
  collectedAtMs: number;
  collectedAtUnix: number;
  metadataDbBytes: number;
  manifestStoreBytes: number;
  mediaCacheBytes: number;
  totalMetadataBytes: number;
};

const METADATA_CHART_SERIES: Array<{
  key: keyof Pick<
    MetadataChartPoint,
    "metadataDbBytes" | "manifestStoreBytes" | "mediaCacheBytes"
  >;
  label: string;
  color: string;
  badgeColor: string;
}> = [
  {
    key: "metadataDbBytes",
    label: "SQLite metadata DB",
    color: "#38bdf8",
    badgeColor: "cyan"
  },
  {
    key: "manifestStoreBytes",
    label: "Manifest store",
    color: "#f59e0b",
    badgeColor: "yellow"
  },
  {
    key: "mediaCacheBytes",
    label: "Media cache",
    color: "#2dd4bf",
    badgeColor: "teal"
  }
];

type MetadataBreakdownRow = {
  label: string;
  description: string;
  currentBytes: number | null;
  shareOfMetadata: number | null;
  shareOfManagedLocal: number | null;
  windowDeltaBytes: number | null;
};

type MetadataDbTableDisplayRow = {
  table: string;
  description: string;
  rowCount: number;
  trackedValueBytes: number;
  averageTrackedValueBytes: number | null;
  shareOfTrackedValueBytes: number | null;
  trackedColumns: string[];
};

export function MetadataPage() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const [historyRange, setHistoryRange] = useState<MetadataHistoryRangeKey>("30d");
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectDbDistribution =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);
  const metadataPollingMode = useLivePollingMode();
  const {
    ref: dbDistributionSectionRef,
    isVisible: dbDistributionSectionVisible
  } = useViewportVisibility<HTMLDivElement>({
    initialVisible: false,
    rootMargin: "200px 0px",
    threshold: 0.05
  });

  const currentQuery = useQuery({
    queryKey: ["metadata-page", "storage-stats-current", normalizedAdminTokenOverride],
    queryFn: () => getStorageStatsCurrent(normalizedAdminTokenOverride || undefined),
    enabled: canInspectDbDistribution
  });
  const historyQuery = useQuery({
    queryKey: ["metadata-page", "storage-stats-history", historyRange, normalizedAdminTokenOverride],
    queryFn: () => getStorageStatsHistory(storageHistoryRequestForRange(historyRange), normalizedAdminTokenOverride || undefined),
    enabled: canInspectDbDistribution
  });
  const dbDistributionStatusQuery = useQuery({
    queryKey: [
      "metadata-page",
      "metadata-db-logical-distribution-status",
      normalizedAdminTokenOverride
    ],
    queryFn: () =>
      getMetadataDbLogicalDistributionStatus(normalizedAdminTokenOverride || undefined),
    enabled: canInspectDbDistribution,
    refetchInterval: (query) => {
      if (query.state.data?.state !== "running") {
        return false;
      }

      if (dbDistributionSectionVisible) {
        return resolveLivePollInterval(metadataPollingMode, {
          live: 1_000,
          passive: 3_000,
          hidden: 10_000
        });
      }

      return resolveLivePollInterval(metadataPollingMode, {
        live: 5_000,
        passive: 10_000,
        hidden: 15_000
      });
    }
  });
  const startDbDistributionMutation = useMutation({
    mutationFn: () => startMetadataDbLogicalDistribution(normalizedAdminTokenOverride || undefined),
    onSuccess: async (result) => {
      queryClient.setQueryData(
        [
          "metadata-page",
          "metadata-db-logical-distribution-status",
          normalizedAdminTokenOverride
        ],
        result.status
      );
      await queryClient.refetchQueries({
        queryKey: [
          "metadata-page",
          "metadata-db-logical-distribution-status",
          normalizedAdminTokenOverride
        ],
        exact: true
      });
    }
  });

  const refresh = useCallback(async () => {
    const queryKeys: ReadonlyArray<readonly unknown[]> = [
      ["metadata-page", "storage-stats-current", normalizedAdminTokenOverride],
      [
        "metadata-page",
        "storage-stats-history",
        historyRange,
        normalizedAdminTokenOverride
      ],
      ...(canInspectDbDistribution
        ? [[
            "metadata-page",
            "metadata-db-logical-distribution-status",
            normalizedAdminTokenOverride
          ]]
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
  }, [canInspectDbDistribution, historyRange, normalizedAdminTokenOverride, queryClient]);

  const currentResponse = currentQuery.data ?? null;
  const currentSample = currentResponse?.sample ?? null;
  const history = historyQuery.data ?? EMPTY_STORAGE_HISTORY;
  const historyChronological = useMemo(() => [...history].reverse(), [history]);
  const chartSamples = useMemo(
    () =>
      historyChronological.length > 0
        ? historyChronological
        : currentSample
          ? [currentSample]
          : EMPTY_STORAGE_HISTORY,
    [currentSample, historyChronological]
  );
  const selectedHistoryRange =
    METADATA_HISTORY_RANGE_OPTIONS.find((option) => option.key === historyRange) ??
    METADATA_HISTORY_RANGE_OPTIONS[0];
  const metadataTotalBytes = currentSample ? metadataFootprintBytes(currentSample) : null;
  const managedLocalBytes =
    currentSample && metadataTotalBytes !== null
      ? currentSample.chunk_store_bytes + metadataTotalBytes
      : null;
  const metadataShareOfManagedLocal =
    metadataTotalBytes !== null && managedLocalBytes !== null && managedLocalBytes > 0
      ? metadataTotalBytes / managedLocalBytes
      : null;
  const metadataWindowDeltaBytes = deltaBetweenSamples(
    historyChronological,
    metadataFootprintBytes
  );
  const bytesPerSnapshotObject =
    currentSample &&
    metadataTotalBytes !== null &&
    currentSample.latest_snapshot_object_count > 0
      ? metadataTotalBytes / currentSample.latest_snapshot_object_count
      : null;
  const metadataVsLatestSnapshotUniqueRatio =
    currentSample &&
    metadataTotalBytes !== null &&
    currentSample.latest_snapshot_unique_chunk_bytes > 0
      ? metadataTotalBytes / currentSample.latest_snapshot_unique_chunk_bytes
      : null;
  const dominantMetadataComponent = currentSample
    ? largestMetadataComponent(currentSample)
    : null;
  const breakdownRows = buildMetadataBreakdownRows(
    currentSample,
    historyChronological,
    metadataTotalBytes,
    managedLocalBytes
  );
  const dbDistributionStatus = canInspectDbDistribution
    ? dbDistributionStatusQuery.data ?? null
    : null;
  const dbDistribution = dbDistributionStatus?.distribution ?? null;
  const dbDistributionProgress = dbDistributionStatus?.progress ?? null;
  const dbDistributionRunning = dbDistributionStatus?.state === "running";
  const dbDistributionRows = useMemo(
    () => buildMetadataDbTableDisplayRows(dbDistribution),
    [dbDistribution]
  );
  const dbDistributionRowsWithData = useMemo(
    () =>
      dbDistributionRows.filter(
        (row) => row.rowCount > 0 || row.trackedValueBytes > 0
      ),
    [dbDistributionRows]
  );
  const dominantDbTable = dbDistributionRowsWithData[0] ?? null;
  const dbTrackedCoverageRatio =
    currentSample &&
    dbDistribution &&
    currentSample.metadata_db_bytes > 0
      ? dbDistribution.total_tracked_value_bytes / currentSample.metadata_db_bytes
      : null;
  const loading =
    currentQuery.isFetching ||
    historyQuery.isFetching ||
    startDbDistributionMutation.isPending;
  const error = firstErrorMessage([currentQuery.error, historyQuery.error]);
  const dbDistributionError = canInspectDbDistribution
    ? firstErrorMessage([
        startDbDistributionMutation.error,
        dbDistributionStatusQuery.error
      ])
    : null;

  return (
    <Stack gap="lg">
      {error ? (
        <Alert color="red" title="Failed to load metadata storage overview">
          {error}
        </Alert>
      ) : null}

      {currentSample ? (
        <Alert color="teal" variant="light" title="Filesystem-level metadata footprint">
          This node currently uses {formatBytes(metadataTotalBytes)} for metadata across the
          SQLite state file, manifest directory, and media cache. The largest segment right now is{" "}
          <Code>{dominantMetadataComponent?.label ?? "unknown"}</Code>.
        </Alert>
      ) : currentResponse?.collecting ? (
        <Alert color="blue" variant="light" title="Metadata stats are being collected">
          The background collector is preparing the first metadata sample for this node.
        </Alert>
      ) : (
        <Alert color="gray" variant="light" title="No metadata sample yet">
          Storage stats have not produced a metadata sample yet for this node.
        </Alert>
      )}

      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={800}>
          This page focuses on metadata space consumption only. It separates growth in the SQLite
          metadata database, manifest files, and generated media cache so operators can spot where
          node-local bookkeeping or acceleration data is growing without mixing it into chunk
          payload storage.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={loading}>
          Refresh
        </Button>
      </Group>

      <Grid>
        <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
          <StatCard
            label="Metadata Footprint"
            value={currentSample ? formatBytes(metadataTotalBytes) : loading ? "loading..." : "unknown"}
            hint={
              currentResponse?.last_success_unix
                ? `Updated ${formatRelativeUnixTs(currentResponse.last_success_unix)}`
                : "Awaiting first successful sample"
            }
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
          <StatCard
            label="Window Change"
            value={
              historyChronological.length >= 2
                ? formatSignedBytes(metadataWindowDeltaBytes)
                : loading
                  ? "loading..."
                  : "n/a"
            }
            hint={`Delta across the selected ${selectedHistoryRange.label} history window`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
          <StatCard
            label="Share of Managed Local"
            value={
              metadataShareOfManagedLocal !== null
                ? formatPercent(metadataShareOfManagedLocal)
                : loading
                  ? "loading..."
                  : "unknown"
            }
            hint="Metadata bytes divided by metadata plus chunk-store bytes"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
          <StatCard
            label="Bytes per Snapshot Object"
            value={
              bytesPerSnapshotObject !== null
                ? formatBytes(bytesPerSnapshotObject)
                : loading
                  ? "loading..."
                  : "n/a"
            }
            hint="Metadata footprint normalized by latest snapshot object count"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="SQLite Metadata DB"
            value={
              currentSample ? formatBytes(currentSample.metadata_db_bytes) : loading ? "loading..." : "unknown"
            }
            hint="On-disk state database file"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Manifest Store"
            value={
              currentSample ? formatBytes(currentSample.manifest_store_bytes) : loading ? "loading..." : "unknown"
            }
            hint="Manifest files stored outside the database"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Media Cache"
            value={
              currentSample ? formatBytes(currentSample.media_cache_bytes) : loading ? "loading..." : "unknown"
            }
            hint="Generated thumbnails and cached media metadata"
          />
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <Stack gap={4}>
              <Text fw={700}>Metadata Space History</Text>
              <Text size="sm" c="dimmed" maw={760}>
                This is a filesystem-level time series of metadata bytes only. It tracks the
                SQLite state file, manifest directory, and generated media cache separately so you
                can see which part of the metadata surface is responsible for growth.
              </Text>
              <Text size="sm" c="dimmed">
                {describeMetadataHistoryWindow(selectedHistoryRange.label, chartSamples)}
              </Text>
            </Stack>
            <Stack gap="xs" align="flex-end">
              <Group gap="xs">
                <Badge variant="light" color={currentResponse?.collecting ? "blue" : "gray"}>
                  {currentResponse?.collecting ? "collecting" : "idle"}
                </Badge>
                <Badge variant="light">
                  {currentResponse?.last_success_unix
                    ? `updated ${formatUnixTs(currentResponse.last_success_unix)}`
                    : "no successful sample yet"}
                </Badge>
              </Group>
              <Group gap={6}>
                {METADATA_HISTORY_RANGE_OPTIONS.map((option) => (
                  <Button
                    key={option.key}
                    size="xs"
                    variant={option.key === historyRange ? "filled" : "default"}
                    onClick={() => setHistoryRange(option.key)}
                  >
                    {option.label}
                  </Button>
                ))}
              </Group>
            </Stack>
          </Group>

          {currentResponse?.last_error ? (
            <Alert color="yellow" variant="light" title="Latest storage stats refresh failed">
              {currentResponse.last_error}
            </Alert>
          ) : null}

          <MetadataHistoryChart samples={chartSamples} />
        </Stack>
      </Card>

      <div ref={dbDistributionSectionRef}>
        <Card withBorder radius="md" padding="lg">
          <Stack gap="md">
            <Group justify="space-between" align="flex-start">
              <Stack gap={4}>
                <Text fw={700}>Metadata DB Logical Distribution</Text>
                <Text size="sm" c="dimmed" maw={800}>
                  This first-pass database view estimates where logical content lives inside the
                  metadata database by summing the stored byte lengths of tracked TEXT and BLOB
                  columns per table. It is intentionally not a physical SQLite page breakdown yet, so
                  it excludes WAL growth, free pages, B-tree overhead, index pages, and most integer
                  storage.
                </Text>
                <Text size="sm" c="dimmed" maw={800}>
                  This scan now runs only when requested because it can be expensive on large
                  metadata databases. Once completed, the latest result stays cached in memory until
                  the next explicit refresh or a server restart.
                </Text>
              </Stack>
              <Stack gap="xs" align="flex-end">
                {canInspectDbDistribution ? (
                  <Button
                    variant="light"
                    onClick={() => void startDbDistributionMutation.mutateAsync()}
                    loading={startDbDistributionMutation.isPending}
                    disabled={dbDistributionRunning}
                  >
                    {dbDistributionRunning
                      ? "Analysis running"
                      : dbDistribution
                        ? "Refresh analysis"
                        : "Analyze metadata DB"}
                  </Button>
                ) : null}
                {dbDistributionStatus ? (
                  <Group gap="xs">
                    <Badge variant="light" color={dbDistributionRunning ? "blue" : "gray"}>
                      {dbDistributionRunning ? "running" : "idle"}
                    </Badge>
                    <Badge variant="light">
                      backend {dbDistributionStatus.backend}
                    </Badge>
                    {dbDistribution ? (
                      <Badge variant="light">
                        generated {formatUnixTs(dbDistribution.generated_at_unix)}
                      </Badge>
                    ) : null}
                  </Group>
                ) : null}
              </Stack>
            </Group>

            {!canInspectDbDistribution ? (
              <Text size="sm" c="dimmed">
                Sign in with the local admin password to inspect the per-table distribution inside
                the metadata database.
              </Text>
            ) : dbDistributionError ? (
              <Alert color="red" title="Failed to load metadata DB logical distribution">
                {dbDistributionError}
              </Alert>
            ) : null}

          {canInspectDbDistribution &&
          dbDistributionRunning &&
          dbDistributionProgress &&
          dbDistributionProgress.total_tables > 0 ? (
            <Alert color="blue" variant="light" title="Logical distribution analysis in progress">
              <Stack gap="xs">
                <Text size="sm">
                  Scanned {formatCount(dbDistributionProgress.completed_tables)} of{" "}
                  {formatCount(dbDistributionProgress.total_tables)} tracked tables
                  {dbDistributionProgress.current_table
                    ? `. Currently reading ${dbDistributionProgress.current_table}.`
                    : "."}
                </Text>
                <Progress
                  value={metadataDbDistributionProgressPercent(dbDistributionProgress)}
                  size="md"
                  radius="xl"
                  animated
                />
                {dbDistributionStatus?.started_at_unix ? (
                  <Text size="xs" c="dimmed">
                    Started {formatUnixTs(dbDistributionStatus.started_at_unix)}.
                  </Text>
                ) : null}
              </Stack>
            </Alert>
          ) : null}

          {canInspectDbDistribution &&
          !dbDistributionRunning &&
          dbDistributionStatus?.last_error ? (
            <Alert color="yellow" variant="light" title="Latest logical distribution run failed">
              {dbDistributionStatus.last_error}
            </Alert>
          ) : null}

          {canInspectDbDistribution && dbDistributionStatusQuery.isLoading && !dbDistributionStatus ? (
            <Text size="sm" c="dimmed">
              Loading metadata DB logical-distribution status…
            </Text>
          ) : null}

          {canInspectDbDistribution &&
          !dbDistribution &&
          !dbDistributionRunning &&
          !dbDistributionError &&
          !dbDistributionStatusQuery.isLoading ? (
            <Text size="sm" c="dimmed">
              No logical-distribution snapshot has been generated yet. Use{" "}
              <Code>Analyze metadata DB</Code> to run the scan on demand.
            </Text>
          ) : null}

            {canInspectDbDistribution && dbDistribution ? (
              <>
              <Grid>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <StatCard
                    label="Tracked Value Bytes"
                    value={formatBytes(dbDistribution.total_tracked_value_bytes)}
                    hint="Summed TEXT/BLOB content across tracked tables"
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <StatCard
                    label="Tracked Rows"
                    value={formatCount(dbDistribution.total_row_count)}
                    hint="Total rows across the tracked tables"
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <StatCard
                    label="Non-Empty Tables"
                    value={formatCount(dbDistributionRowsWithData.length)}
                    hint={`Out of ${formatCount(dbDistribution.tables.length)} tracked tables`}
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 6, xl: 3 }}>
                  <StatCard
                    label="Tracked vs DB File"
                    value={formatPercent(dbTrackedCoverageRatio)}
                    hint={
                      currentSample
                        ? `Compared with ${formatBytes(currentSample.metadata_db_bytes)} on disk`
                        : "Requires current metadata DB byte sample"
                    }
                  />
                </Grid.Col>
              </Grid>

              {dominantDbTable ? (
                <Alert color="blue" variant="light" title="Largest logical table footprint">
                  <Code>{dominantDbTable.table}</Code> currently carries{" "}
                  {formatBytes(dominantDbTable.trackedValueBytes)} of tracked value bytes across{" "}
                  {formatCount(dominantDbTable.rowCount)} row
                  {dominantDbTable.rowCount === 1 ? "" : "s"}.
                </Alert>
              ) : null}

              <ScrollArea type="auto">
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Table</Table.Th>
                      <Table.Th>Rows</Table.Th>
                      <Table.Th>Tracked value bytes</Table.Th>
                      <Table.Th>Share of tracked bytes</Table.Th>
                      <Table.Th>Avg tracked bytes</Table.Th>
                      <Table.Th>Tracked columns</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {dbDistributionRowsWithData.length > 0 ? (
                      dbDistributionRowsWithData.map((row) => (
                        <Table.Tr key={row.table}>
                          <Table.Td>
                            <Stack gap={2}>
                              <Text size="sm" fw={600}>
                                {row.table}
                              </Text>
                              <Text size="xs" c="dimmed">
                                {row.description}
                              </Text>
                            </Stack>
                          </Table.Td>
                          <Table.Td>{formatCount(row.rowCount)}</Table.Td>
                          <Table.Td>{formatBytes(row.trackedValueBytes)}</Table.Td>
                          <Table.Td>{formatPercent(row.shareOfTrackedValueBytes)}</Table.Td>
                          <Table.Td>{formatBytes(row.averageTrackedValueBytes)}</Table.Td>
                          <Table.Td>
                            <Text size="xs" ff="monospace">
                              {row.trackedColumns.join(", ")}
                            </Text>
                          </Table.Td>
                        </Table.Tr>
                      ))
                    ) : (
                      <Table.Tr>
                        <Table.Td colSpan={6}>
                          <Text c="dimmed">
                            No rows with tracked logical content are present in the metadata
                            database yet.
                          </Text>
                        </Table.Td>
                      </Table.Tr>
                    )}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
              </>
            ) : null}
          </Stack>
        </Card>
      </div>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 8 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Text fw={700}>Current Breakdown Details</Text>
              <ScrollArea type="auto">
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Segment</Table.Th>
                      <Table.Th>Current size</Table.Th>
                      <Table.Th>Share of metadata</Table.Th>
                      <Table.Th>Share of managed local</Table.Th>
                      <Table.Th>Window change</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {breakdownRows.map((row) => (
                      <Table.Tr key={row.label}>
                        <Table.Td>
                          <Stack gap={2}>
                            <Text size="sm" fw={600}>
                              {row.label}
                            </Text>
                            <Text size="xs" c="dimmed">
                              {row.description}
                            </Text>
                            {row.shareOfMetadata !== null ? (
                              <Progress
                                value={Math.max(0, Math.min(100, row.shareOfMetadata * 100))}
                                size="sm"
                                radius="xl"
                              />
                            ) : null}
                          </Stack>
                        </Table.Td>
                        <Table.Td>{formatBytes(row.currentBytes)}</Table.Td>
                        <Table.Td>{formatPercent(row.shareOfMetadata)}</Table.Td>
                        <Table.Td>{formatPercent(row.shareOfManagedLocal)}</Table.Td>
                        <Table.Td>{formatSignedBytes(row.windowDeltaBytes)}</Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 4 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="sm">
              <Text fw={700}>Latest Snapshot Context</Text>
              <Text size="sm" c="dimmed">
                These numbers help relate metadata overhead to the most recent namespace snapshot
                rather than looking at raw bytes alone.
              </Text>
              <Text size="sm">
                Latest snapshot ID: <Code>{currentSample?.latest_snapshot_id ?? "none yet"}</Code>
              </Text>
              <Text size="sm">
                Snapshot created: <Code>{formatUnixTs(currentSample?.latest_snapshot_created_at_unix)}</Code>
              </Text>
              <Text size="sm">
                Sample collected: <Code>{formatUnixTs(currentSample?.collected_at_unix)}</Code>
              </Text>
              <Text size="sm">
                Snapshot objects: <Code>{String(currentSample?.latest_snapshot_object_count ?? 0)}</Code>
              </Text>
              <Text size="sm">
                Snapshot logical bytes:{" "}
                <Code>
                  {currentSample
                    ? formatBytes(currentSample.latest_snapshot_logical_bytes)
                    : "unknown"}
                </Code>
              </Text>
              <Text size="sm">
                Snapshot unique chunk bytes:{" "}
                <Code>
                  {currentSample
                    ? formatBytes(currentSample.latest_snapshot_unique_chunk_bytes)
                    : "unknown"}
                </Code>
              </Text>
              <Text size="sm">
                Metadata per snapshot object: <Code>{formatBytes(bytesPerSnapshotObject)}</Code>
              </Text>
              <Text size="sm">
                Metadata vs unique snapshot bytes:{" "}
                <Code>{formatPercent(metadataVsLatestSnapshotUniqueRatio)}</Code>
              </Text>
              <Text size="sm">
                Chunk store bytes:{" "}
                <Code>{currentSample ? formatBytes(currentSample.chunk_store_bytes) : "unknown"}</Code>
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}

function MetadataHistoryChart({ samples }: { samples: StorageStatsSample[] }) {
  const chartPoints = useMemo<MetadataChartPoint[]>(
    () =>
      samples.map((sample) => ({
        collectedAtMs: sample.collected_at_unix * 1000,
        collectedAtUnix: sample.collected_at_unix,
        metadataDbBytes: sample.metadata_db_bytes,
        manifestStoreBytes: sample.manifest_store_bytes,
        mediaCacheBytes: sample.media_cache_bytes,
        totalMetadataBytes: metadataFootprintBytes(sample)
      })),
    [samples]
  );

  if (chartPoints.length === 0) {
    return <Text c="dimmed">No storage stats samples collected yet.</Text>;
  }

  const yMax = Math.max(1, ...chartPoints.map((point) => point.totalMetadataBytes));

  return (
    <ZoomableTimeSeriesChart
      points={chartPoints}
      height="20rem"
      minHeight="20rem"
      legend={
        <Group gap="md">
          {METADATA_CHART_SERIES.map((series) => (
            <Badge key={series.key} color={series.badgeColor} variant="light">
              {series.label}
            </Badge>
          ))}
          <Badge color="pink" variant="light">
            Total metadata
          </Badge>
        </Group>
      }
      emptyState={<Text c="dimmed">No storage stats samples collected yet.</Text>}
      zoomInAriaLabel="Zoom in on metadata history chart"
      zoomOutAriaLabel="Zoom out of metadata history chart"
      resetZoomAriaLabel="Reset metadata history chart zoom"
      renderChart={({ xDomain, visibleTimeSpanSeconds, brush }) => (
        <AreaChart
          data={chartPoints}
          margin={{ top: 8, right: 20, bottom: 18, left: 8 }}
          accessibilityLayer
          role="img"
          title="Metadata space history"
          desc="SQLite metadata DB, manifest store, media cache, and total metadata bytes by sample time."
          {...({ "aria-label": "Metadata space history chart" } as { "aria-label": string })}
        >
          <defs>
            <linearGradient id="metadata-db-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.12} />
            </linearGradient>
            <linearGradient id="manifest-store-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.42} />
              <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.1} />
            </linearGradient>
            <linearGradient id="media-cache-fill" x1="0" x2="0" y1="0" y2="1">
              <stop offset="5%" stopColor="#2dd4bf" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#2dd4bf" stopOpacity={0.1} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="#1e293b" strokeDasharray="4 4" vertical={false} />
          <XAxis
            dataKey="collectedAtMs"
            type="number"
            scale="time"
            domain={xDomain}
            allowDataOverflow
            tickFormatter={(value) =>
              formatTimeSeriesChartTimestamp(
                Math.floor(Number(value) / 1000),
                visibleTimeSpanSeconds
              )
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
              value: "Metadata used (bytes)",
              angle: -90,
              position: "insideLeft",
              fill: "#e2e8f0",
              fontSize: "0.75rem",
              fontWeight: 600
            }}
          />
          <Tooltip
            content={MetadataHistoryTooltip}
            cursor={{ stroke: "#94a3b8", strokeDasharray: "4 4" }}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="metadataDbBytes"
            stackId="metadata"
            name="SQLite metadata DB"
            stroke="#38bdf8"
            fill="url(#metadata-db-fill)"
            strokeWidth={1.8}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="manifestStoreBytes"
            stackId="metadata"
            name="Manifest store"
            stroke="#f59e0b"
            fill="url(#manifest-store-fill)"
            strokeWidth={1.8}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="mediaCacheBytes"
            stackId="metadata"
            name="Media cache"
            stroke="#2dd4bf"
            fill="url(#media-cache-fill)"
            strokeWidth={1.8}
            isAnimationActive={false}
          />
          <Area
            type="monotone"
            dataKey="totalMetadataBytes"
            name="Total metadata"
            stroke="#f43f5e"
            fillOpacity={0}
            strokeWidth={2.2}
            isAnimationActive={false}
          />
          {brush}
        </AreaChart>
      )}
    />
  );
}

function MetadataHistoryTooltip({ active, payload }: TooltipContentProps) {
  if (!active || !payload || payload.length === 0) {
    return null;
  }

  const point = payload[0]?.payload as MetadataChartPoint | undefined;
  if (!point) {
    return null;
  }

  return (
    <Box
      style={{
        minWidth: "14rem",
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
        {METADATA_CHART_SERIES.map((series) => (
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
        <Group justify="space-between" gap="md" wrap="nowrap">
          <Text size="xs" fw={700}>
            Total metadata
          </Text>
          <Text size="xs" fw={700}>
            {formatBytes(point.totalMetadataBytes)}
          </Text>
        </Group>
      </Stack>
    </Box>
  );
}

function buildMetadataBreakdownRows(
  sample: StorageStatsSample | null,
  history: StorageStatsSample[],
  metadataTotalBytes: number | null,
  managedLocalBytes: number | null
): MetadataBreakdownRow[] {
  const buildRow = (
    label: string,
    description: string,
    currentBytes: number | null,
    windowDeltaBytes: number | null
  ): MetadataBreakdownRow => ({
    label,
    description,
    currentBytes,
    shareOfMetadata:
      currentBytes !== null && metadataTotalBytes !== null && metadataTotalBytes > 0
        ? currentBytes / metadataTotalBytes
        : null,
    shareOfManagedLocal:
      currentBytes !== null && managedLocalBytes !== null && managedLocalBytes > 0
        ? currentBytes / managedLocalBytes
        : null,
    windowDeltaBytes
  });

  return [
    buildRow(
      "SQLite metadata DB",
      "Authoritative node state, indexes, history samples, and audit metadata.",
      sample?.metadata_db_bytes ?? null,
      deltaBetweenSamples(history, (entry) => entry.metadata_db_bytes)
    ),
    buildRow(
      "Manifest store",
      "Manifest files persisted outside the database for object reconstruction.",
      sample?.manifest_store_bytes ?? null,
      deltaBetweenSamples(history, (entry) => entry.manifest_store_bytes)
    ),
    buildRow(
      "Media cache",
      "Generated thumbnails plus cached media metadata used by gallery-style views.",
      sample?.media_cache_bytes ?? null,
      deltaBetweenSamples(history, (entry) => entry.media_cache_bytes)
    )
  ];
}

function buildMetadataDbTableDisplayRows(
  distribution: MetadataDbLogicalDistribution | null
): MetadataDbTableDisplayRow[] {
  if (!distribution) {
    return [];
  }

  return distribution.tables.map((table) => ({
    table: table.table,
    description: describeMetadataDbTable(table.table),
    rowCount: table.row_count,
    trackedValueBytes: table.tracked_value_bytes,
    averageTrackedValueBytes: table.average_tracked_value_bytes ?? null,
    shareOfTrackedValueBytes:
      distribution.total_tracked_value_bytes > 0
        ? table.tracked_value_bytes / distribution.total_tracked_value_bytes
        : null,
    trackedColumns: table.tracked_columns
  }));
}

function metadataDbDistributionProgressPercent(
  progress: MetadataDbLogicalDistributionStatusResponse["progress"]
): number {
  if (!progress || progress.total_tables <= 0) {
    return 0;
  }

  return Math.max(
    0,
    Math.min(100, Math.round((progress.completed_tables / progress.total_tables) * 100))
  );
}

function describeMetadataDbTable(table: string): string {
  switch (table) {
    case "metadata_meta":
      return "Small metadata key-value records such as schema version state.";
    case "current_objects":
      return "Current object path to manifest and stable object ID mapping.";
    case "version_indexes":
      return "Serialized version history indexes for each object.";
    case "snapshots":
      return "Retained namespace snapshots with full snapshot payloads.";
    case "storage_stats_current":
      return "Most recent persisted storage-stats sample.";
    case "storage_stats_state":
      return "Small persisted counters and reconciliation state.";
    case "storage_stats_history":
      return "Historical storage-stats samples retained for charts.";
    case "repair_attempts":
      return "Repair backoff counters for failed replication work.";
    case "repair_run_history":
      return "Retained repair run reports and summaries.";
    case "data_scrub_run_history":
      return "Retained data-scrub reports and issue samples.";
    case "cluster_replicas":
      return "Replica placement mapping of subjects to node IDs.";
    case "client_credential_state":
      return "Serialized client credential, pairing, and bootstrap claim state.";
    case "admin_audit_events":
      return "Admin audit event log entries stored as JSON payloads.";
    case "data_change_events":
      return "Retained node-local feed of uploads, deletes, renames, and copies.";
    case "media_cache":
      return "Cached media metadata records tracked in the database.";
    case "cached_chunks":
      return "Chunk-cache metadata such as access counts and source hints.";
    case "locally_owned_manifests":
      return "Manifest hashes marked as locally owned by this node.";
    case "reconcile_markers":
      return "Markers that prevent duplicate reconcile imports.";
    default:
      return "Tracked metadata DB table.";
  }
}

function largestMetadataComponent(sample: StorageStatsSample): {
  label: string;
  bytes: number;
} {
  const candidates = [
    { label: "SQLite metadata DB", bytes: sample.metadata_db_bytes },
    { label: "Manifest store", bytes: sample.manifest_store_bytes },
    { label: "Media cache", bytes: sample.media_cache_bytes }
  ];

  return candidates.reduce((largest, current) =>
    current.bytes > largest.bytes ? current : largest
  );
}

function metadataFootprintBytes(sample: StorageStatsSample): number {
  return sample.metadata_db_bytes + sample.manifest_store_bytes + sample.media_cache_bytes;
}

function deltaBetweenSamples(
  samples: StorageStatsSample[],
  selector: (sample: StorageStatsSample) => number
): number | null {
  if (samples.length < 2) {
    return null;
  }

  return selector(samples[samples.length - 1]) - selector(samples[0]);
}

function storageHistoryRequestForRange(rangeKey: MetadataHistoryRangeKey): {
  sinceUnix?: number;
  maxPoints: number;
} {
  const selectedRange =
    METADATA_HISTORY_RANGE_OPTIONS.find((option) => option.key === rangeKey) ??
    METADATA_HISTORY_RANGE_OPTIONS[0];

  return {
    sinceUnix:
      selectedRange.windowSecs === null
        ? undefined
        : Math.max(0, Math.floor(Date.now() / 1000) - selectedRange.windowSecs),
    maxPoints: METADATA_HISTORY_MAX_POINTS
  };
}

function describeMetadataHistoryWindow(
  requestedLabel: string,
  samples: StorageStatsSample[]
): string {
  if (samples.length === 0) {
    return `Showing ${requestedLabel} view. No storage stats samples have been collected yet.`;
  }

  const oldestSample = samples[0];
  const newestSample = samples[samples.length - 1];
  if (samples.length === 1) {
    return `Showing ${requestedLabel} view with a single sample collected at ${formatUnixTs(
      newestSample.collected_at_unix
    )}.`;
  }

  return `Showing ${requestedLabel} view with ${samples.length} sampled points from ${formatUnixTs(
    oldestSample.collected_at_unix
  )} to ${formatUnixTs(newestSample.collected_at_unix)}.`;
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

function formatPercent(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) {
    return "n/a";
  }

  return new Intl.NumberFormat("en", {
    style: "percent",
    maximumFractionDigits: value < 0.1 ? 1 : 0
  }).format(value);
}

function formatSignedBytes(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) {
    return "n/a";
  }
  if (value === 0) {
    return "0 B";
  }

  const prefix = value > 0 ? "+" : "-";
  return `${prefix}${formatBytes(Math.abs(value))}`;
}

function formatCount(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) {
    return "n/a";
  }

  return new Intl.NumberFormat("en").format(value);
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
