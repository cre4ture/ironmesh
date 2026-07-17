import {
  getAdminMapDatasetImportStatus,
  startAdminMapDatasetImport,
  type AdminMapDatasetImportJobView
} from "@ironmesh/api";
import { ironmeshPrimaryColor } from "@ironmesh/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  NumberInput,
  Progress,
  Stack,
  Text,
  Textarea
} from "@mantine/core";
import { type ReactNode, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatBytes, formatRelativeUnixTs, formatUnixTs } from "../lib/format";

const DEFAULT_MAP_IMPORT_PART_SIZE_GIB = 10;
const GIB_BYTES = 1024 ** 3;

export function MapDatasetImportCard() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectMapImport =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);
  const [mapImportSource, setMapImportSource] = useState("");
  const [partSizeGiB, setPartSizeGiB] = useState<number>(DEFAULT_MAP_IMPORT_PART_SIZE_GIB);

  const mapImportStatusQuery = useQuery({
    queryKey: ["gallery-page", "map-import", normalizedAdminTokenOverride],
    queryFn: () => getAdminMapDatasetImportStatus(normalizedAdminTokenOverride || undefined),
    enabled: canInspectMapImport,
    refetchInterval: (query) =>
      query.state.data?.active_job?.state === "running" ? 2_000 : false
  });
  const startMapImportMutation = useMutation({
    mutationFn: () =>
      startAdminMapDatasetImport(
        {
          source: mapImportSource.trim(),
          part_size_bytes: Math.round(partSizeGiB * GIB_BYTES)
        },
        normalizedAdminTokenOverride || undefined
      ),
    onSuccess: async (response) => {
      queryClient.setQueryData(
        ["gallery-page", "map-import", normalizedAdminTokenOverride],
        response.status
      );
      await queryClient.refetchQueries({
        queryKey: ["gallery-page", "map-import", normalizedAdminTokenOverride],
        exact: true
      });
    }
  });

  const mapImportStatus = canInspectMapImport ? mapImportStatusQuery.data ?? null : null;
  const activeMapImport = mapImportStatus?.active_job ?? null;
  const mapImportError = firstErrorMessage([
    mapImportStatusQuery.error,
    startMapImportMutation.error
  ]);
  const canStartMapImport =
    canInspectMapImport &&
    mapImportStatus?.can_start_new !== false &&
    mapImportSource.trim().length > 0 &&
    Number.isFinite(partSizeGiB) &&
    partSizeGiB > 0;

  return (
    <>
      {mapImportError ? (
        <Alert color="red" title="Failed to manage the map dataset import">
          {mapImportError}
        </Alert>
      ) : null}

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between" align="flex-start">
            <div>
              <Text fw={600}>Map dataset import</Text>
              <Text c="dimmed" size="sm" maw={860}>
                Paste the MapTiler URL or the full copied <Code>wget -c ...</Code> command. The
                server node downloads the MBTiles file with resumable range requests, ingests it
                directly into IronMesh chunks, finalizes configurable part objects under{" "}
                <Code>sys/maps/</Code>, and resumes automatically after server restarts.
              </Text>
            </div>
            <MapDatasetImportStateBadge job={activeMapImport} />
          </Group>

          <Alert color="yellow" variant="light" title="Filename expectation">
            The shared gallery basemap currently looks for the standard MapTiler manifest keys
            already wired into this page. Use the default MapTiler filenames so the imported
            dataset is picked up automatically by the existing gallery map modes.
          </Alert>

          <Textarea
            label="MapTiler URL or pasted CLI command"
            description="The tokenized source URL is persisted server-side for resumable retries and restart-safe continuation, but the admin UI only shows a redacted display form afterward."
            placeholder="wget -c https://data.maptiler.com/download/.../maptiler-satellite-2017-11-02-planet.mbtiles"
            minRows={3}
            autosize
            value={mapImportSource}
            onChange={(event) => setMapImportSource(event.currentTarget.value)}
            disabled={mapImportStatus?.can_start_new === false}
          />

          <Group align="flex-end">
            <NumberInput
              label="Part size"
              description="Each finalized part object keeps its own IronMesh object key under sys/maps/."
              value={partSizeGiB}
              min={1}
              max={64}
              step={1}
              suffix=" GiB"
              allowDecimal={false}
              onChange={(value) =>
                setPartSizeGiB(typeof value === "number" && Number.isFinite(value) ? value : 10)
              }
              w={220}
              disabled={mapImportStatus?.can_start_new === false}
            />
            <Button
              loading={startMapImportMutation.isPending}
              disabled={!canStartMapImport}
              onClick={() => void startMapImportMutation.mutateAsync()}
            >
              Start import
            </Button>
          </Group>

          {activeMapImport ? (
            <MapDatasetImportProgress job={activeMapImport} />
          ) : (
            <Alert color="gray" variant="light" title="No imported map dataset job yet">
              This node has not started a persisted MapTiler dataset import yet.
            </Alert>
          )}
        </Stack>
      </Card>
    </>
  );
}

function MapDatasetImportStateBadge({ job }: { job: AdminMapDatasetImportJobView | null }) {
  if (!job) {
    return (
      <Badge color="gray" variant="light">
        idle
      </Badge>
    );
  }

  return (
    <Badge
      color={
        job.state === "completed"
          ? ironmeshPrimaryColor
          : job.state === "failed"
            ? "red"
            : "blue"
      }
      variant="light"
    >
      {job.state}
    </Badge>
  );
}

function MapDatasetImportProgress({ job }: { job: AdminMapDatasetImportJobView }) {
  const currentPartProgressPercent =
    job.current_part_size_bytes && job.current_part_size_bytes > 0
      ? Math.min(100, (job.current_part_completed_bytes / job.current_part_size_bytes) * 100)
      : 0;

  return (
    <Card withBorder radius="md" padding="md">
      <Stack gap="sm">
        <Group justify="space-between" align="center">
          <Text fw={600}>{job.dataset_filename}</Text>
          <Text c="dimmed" size="sm">
            {job.source_display}
          </Text>
        </Group>

        <div>
          <Group justify="space-between" align="center" mb={6}>
            <Text size="sm" fw={500}>
              Overall progress
            </Text>
            <Text size="sm" c="dimmed">
              {formatProgressPercent(job.progress_percent)}
            </Text>
          </Group>
          <Progress value={job.progress_percent} color={ironmeshPrimaryColor} />
        </div>

        {job.current_part_key ? (
          <div>
            <Group justify="space-between" align="center" mb={6}>
              <Text size="sm" fw={500}>
                Current part {job.current_part_id ?? "unknown"} ({(job.current_part_index ?? 0) + 1}/
                {job.total_parts})
              </Text>
              <Text size="sm" c="dimmed">
                {job.current_part_key}
              </Text>
            </Group>
            <Progress value={currentPartProgressPercent} color="blue" />
          </div>
        ) : null}

        <Group gap="xl" align="flex-start">
          <ImportDetail label="Logical file">
            <Code>{job.logical_key}</Code>
          </ImportDetail>
          <ImportDetail label="Manifest">
            <Code>{job.manifest_key}</Code>
          </ImportDetail>
        </Group>

        <Group gap="xl" align="flex-start">
          <ImportDetail label="Downloaded">
            <Text size="sm">
              {formatBytes(job.completed_bytes + job.current_part_completed_bytes)} of{" "}
              {formatBytes(job.total_size_bytes)}
            </Text>
          </ImportDetail>
          <ImportDetail label="Finalized parts">
            <Text size="sm">
              {job.completed_parts} of {job.total_parts}
            </Text>
          </ImportDetail>
          <ImportDetail label="Configured part size">
            <Text size="sm">{formatBytes(job.part_size_bytes)}</Text>
          </ImportDetail>
        </Group>

        <Group gap="xl" align="flex-start">
          <ImportDetail label="Started">
            <Text size="sm">
              {formatUnixTs(job.started_at_unix)} ({formatRelativeUnixTs(job.started_at_unix)})
            </Text>
          </ImportDetail>
          <ImportDetail label="Updated">
            <Text size="sm">
              {formatUnixTs(job.updated_at_unix)} ({formatRelativeUnixTs(job.updated_at_unix)})
            </Text>
          </ImportDetail>
          {job.next_retry_at_unix ? (
            <ImportDetail label="Next retry">
              <Text size="sm">
                {formatUnixTs(job.next_retry_at_unix)} ({formatRelativeUnixTs(job.next_retry_at_unix)})
              </Text>
            </ImportDetail>
          ) : null}
        </Group>

        {job.last_error ? (
          <Alert
            color={job.state === "failed" ? "red" : "yellow"}
            variant="light"
            title={
              job.state === "failed"
                ? "Import stopped with an error"
                : `Most recent retryable error${job.retry_count > 0 ? ` (${job.retry_count} retries)` : ""}`
            }
          >
            {job.last_error}
          </Alert>
        ) : null}
      </Stack>
    </Card>
  );
}

function ImportDetail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <Text size="sm" c="dimmed">
        {label}
      </Text>
      {children}
    </div>
  );
}

function firstErrorMessage(errors: Array<unknown>): string | null {
  for (const error of errors) {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }
  }
  return null;
}

function formatProgressPercent(value: number): string {
  if (!Number.isFinite(value)) {
    return "unknown";
  }
  return `${Math.max(0, Math.min(100, value)).toFixed(1)}%`;
}
