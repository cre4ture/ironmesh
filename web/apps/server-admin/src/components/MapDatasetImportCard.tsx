import {
  getAdminGalleryMapConfiguration,
  getAdminMapDatasetImportStatus,
  getNaturalEarthMapImportStatus,
  startAdminMapDatasetImport,
  startNaturalEarthMapImport,
  type AdminMapDatasetImportJobView,
  type NaturalEarthImportJobView,
  type NaturalEarthImportProfile
} from "@ironmesh/api";
import { ironmeshPrimaryColor } from "@ironmesh/ui";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Accordion,
  Badge,
  Card,
  Code,
  Group,
  Progress,
  ScrollArea,
  Stack,
  Text
} from "@mantine/core";
import { type ReactNode, useEffect, useMemo, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatBytes, formatRelativeUnixTs, formatUnixTs } from "../lib/format";
import {
  MapDatasetImportWizard,
  type MapDatasetImportWizardTarget,
  type MapImportProfile
} from "./MapDatasetImportWizard";

const DEFAULT_MAP_IMPORT_PART_SIZE_GIB = 10;
const GIB_BYTES = 1024 ** 3;

type MapImportTarget = MapDatasetImportWizardTarget;
type MapDatasetProvider = MapImportTarget["provider"];

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
  const [selectedTargetKey, setSelectedTargetKey] = useState<string | null>(null);
  const [selectedImportProfile, setSelectedImportProfile] = useState<MapImportProfile | null>(
    null
  );
  const [wizardStep, setWizardStep] = useState(0);

  const mapConfigurationQuery = useQuery({
    queryKey: ["gallery-page", "map-configuration", normalizedAdminTokenOverride],
    queryFn: () => getAdminGalleryMapConfiguration(normalizedAdminTokenOverride || undefined),
    enabled: canInspectMapImport,
    staleTime: 5_000
  });
  const importTargets = useMemo(
    () => mapImportTargets(mapConfigurationQuery.data?.configuration.variants ?? []),
    [mapConfigurationQuery.data]
  );
  const importTargetSignature = importTargets.map((target) => target.key).join("\u0000");
  const selectedTarget = importTargets.find((target) => target.key === selectedTargetKey) ?? null;
  const naturalEarthTarget =
    importTargets.find(
      (target) => target.variantId === "natural-earth-globe" && target.asset === "raster"
    ) ?? null;
  const naturalEarthLabelsRasterTarget =
    importTargets.find(
      (target) => target.variantId === "natural-earth-labels" && target.asset === "raster"
    ) ?? null;
  const naturalEarthLabelsVectorTarget =
    importTargets.find(
      (target) => target.variantId === "natural-earth-labels" && target.asset === "vector"
    ) ?? null;
  const naturalEarthVectorTarget =
    importTargets.find(
      (target) => target.variantId === "natural-earth-vector" && target.asset === "vector"
    ) ?? null;
  const naturalEarthHypsoTarget =
    importTargets.find(
      (target) => target.variantId === "natural-earth-hypso" && target.asset === "raster"
    ) ?? null;
  useEffect(() => {
    if (!selectedTargetKey || !importTargets.some((target) => target.key === selectedTargetKey)) {
      setSelectedTargetKey(importTargets[0]?.key ?? null);
    }
  }, [selectedTargetKey, importTargetSignature]);

  const mapImportStatusQuery = useQuery({
    queryKey: ["gallery-page", "map-import", normalizedAdminTokenOverride],
    queryFn: () => getAdminMapDatasetImportStatus(normalizedAdminTokenOverride || undefined),
    enabled: canInspectMapImport,
    refetchInterval: (query) =>
      query.state.data?.active_job?.state === "running" ? 2_000 : false
  });
  const naturalEarthImportStatusQuery = useQuery({
    queryKey: ["gallery-page", "natural-earth-map-import", normalizedAdminTokenOverride],
    queryFn: () => getNaturalEarthMapImportStatus(normalizedAdminTokenOverride || undefined),
    enabled: canInspectMapImport,
    refetchInterval: (query) =>
      query.state.data?.active_job?.state === "running" ? 2_000 : false
  });
  const startMapImportMutation = useMutation({
    mutationFn: () =>
      startAdminMapDatasetImport(
        {
          source: mapImportSource.trim(),
          part_size_bytes: Math.round(partSizeGiB * GIB_BYTES),
          variant_id: selectedTarget?.variantId,
          asset: selectedTarget?.asset
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
  const startNaturalEarthImportMutation = useMutation({
    mutationFn: (profile: NaturalEarthImportProfile) =>
      startNaturalEarthMapImport({ profile }, normalizedAdminTokenOverride || undefined),
    onSuccess: async (job) => {
      queryClient.setQueryData(
        ["gallery-page", "natural-earth-map-import", normalizedAdminTokenOverride],
        { active_job: job, can_start_new: false }
      );
      await queryClient.refetchQueries({
        queryKey: ["gallery-page", "natural-earth-map-import", normalizedAdminTokenOverride],
        exact: true
      });
    }
  });

  const mapImportStatus = canInspectMapImport ? mapImportStatusQuery.data ?? null : null;
  const activeMapImport = mapImportStatus?.active_job ?? null;
  const naturalEarthImportStatus = canInspectMapImport
    ? naturalEarthImportStatusQuery.data ?? null
    : null;
  const naturalEarthJob = naturalEarthImportStatus?.active_job ?? null;
  const mapImportError = firstErrorMessage([
    mapImportStatusQuery.error,
    naturalEarthImportStatusQuery.error,
    mapConfigurationQuery.error,
    startMapImportMutation.error,
    startNaturalEarthImportMutation.error
  ]);
  const canStartMapImport =
    canInspectMapImport &&
    mapImportStatus?.can_start_new !== false &&
    Boolean(selectedTarget) &&
    mapImportSource.trim().length > 0 &&
    Number.isFinite(partSizeGiB) &&
    partSizeGiB > 0;
  const canStartNaturalEarthImport =
    canInspectMapImport &&
    naturalEarthImportStatus?.can_start_new !== false &&
    mapImportStatus?.can_start_new !== false;
  const canStartSelectedImport =
    selectedImportProfile === "natural-earth-physical"
      ? canStartNaturalEarthImport && naturalEarthTarget !== null
      : selectedImportProfile === "natural-earth-physical-with-labels"
        ?
          canStartNaturalEarthImport &&
          naturalEarthLabelsRasterTarget !== null &&
          naturalEarthLabelsVectorTarget !== null
        : selectedImportProfile === "natural-earth-cross-blended-hypso"
          ? canStartNaturalEarthImport && naturalEarthHypsoTarget !== null
          : selectedImportProfile === "natural-earth-vector"
            ? canStartNaturalEarthImport && naturalEarthVectorTarget !== null
          : canStartMapImport;
  const importControlsLocked =
    mapImportStatus?.can_start_new === false ||
    naturalEarthImportStatus?.can_start_new === false ||
    startMapImportMutation.isPending ||
    startNaturalEarthImportMutation.isPending;

  function selectImportProfile(value: string) {
    setSelectedImportProfile(value as MapImportProfile);
    setWizardStep(0);
  }

  function startSelectedImport() {
    if (selectedImportProfile === "natural-earth-physical") {
      void startNaturalEarthImportMutation.mutateAsync("physical");
      return;
    }
    if (selectedImportProfile === "natural-earth-physical-with-labels") {
      void startNaturalEarthImportMutation.mutateAsync("physical_with_labels");
      return;
    }
    if (selectedImportProfile === "natural-earth-vector") {
      void startNaturalEarthImportMutation.mutateAsync("physical_vector");
      return;
    }
    if (selectedImportProfile === "natural-earth-cross-blended-hypso") {
      void startNaturalEarthImportMutation.mutateAsync("cross_blended_hypso");
      return;
    }
    if (selectedImportProfile === "remote-mbtiles") {
      void startMapImportMutation.mutateAsync();
    }
  }

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
              <Text fw={600}>Map dataset import wizard</Text>
              <Text c="dimmed" size="sm" maw={860}>
                Select the desired map outcome first. The wizard then asks only for the source and
                destination information that profile requires before starting a background job.
              </Text>
            </div>
            {naturalEarthJob ? (
              <NaturalEarthImportStateBadge job={naturalEarthJob} />
            ) : (
              <MapDatasetImportStateBadge job={activeMapImport} />
            )}
          </Group>

          <Alert color="blue" variant="light" title="Background jobs validate before publication">
            Each import writes only to its configured map artifact or artifacts. A labels job
            validates both outputs before it begins publication, and the map view keeps using the
            previously published data until a replacement manifest is available.
          </Alert>

          <MapDatasetImportWizard
            profile={selectedImportProfile}
            step={wizardStep}
            source={mapImportSource}
            partSizeGiB={partSizeGiB}
            selectedTargetKey={selectedTargetKey}
            targets={importTargets}
            selectedTarget={selectedTarget}
            naturalEarthTarget={naturalEarthTarget}
            naturalEarthLabelsRasterTarget={naturalEarthLabelsRasterTarget}
            naturalEarthLabelsVectorTarget={naturalEarthLabelsVectorTarget}
            naturalEarthVectorTarget={naturalEarthVectorTarget}
            naturalEarthHypsoTarget={naturalEarthHypsoTarget}
            mapConfigurationLoading={mapConfigurationQuery.isLoading}
            controlsLocked={importControlsLocked}
            canStartImport={canStartSelectedImport}
            startingImport={
              startMapImportMutation.isPending || startNaturalEarthImportMutation.isPending
            }
            onProfileChange={selectImportProfile}
            onSourceChange={setMapImportSource}
            onPartSizeChange={setPartSizeGiB}
            onTargetChange={setSelectedTargetKey}
            onBack={() => setWizardStep((current) => Math.max(0, current - 1))}
            onContinue={() => setWizardStep((current) => Math.min(3, current + 1))}
            onStart={startSelectedImport}
          />

          <Stack gap="sm">
            <Text fw={600}>Import jobs</Text>
            {naturalEarthJob ? <NaturalEarthImportProgress job={naturalEarthJob} /> : null}
            {activeMapImport ? <MapDatasetImportProgress job={activeMapImport} /> : null}
            {!naturalEarthJob && !activeMapImport ? (
              <Alert color="gray" variant="light" title="No map import job yet">
                Select a map profile above to configure and start the first background job.
              </Alert>
            ) : null}
          </Stack>
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

function NaturalEarthImportStateBadge({ job }: { job: NaturalEarthImportJobView }) {
  return (
    <Badge
      color={job.state === "ready" ? ironmeshPrimaryColor : job.state === "failed" ? "red" : "blue"}
      variant="light"
    >
      Natural Earth: {job.state}
    </Badge>
  );
}

function NaturalEarthImportProgress({ job }: { job: NaturalEarthImportJobView }) {
  const includesLabels = job.profile === "physical_with_labels";
  const isVectorMap = job.profile === "physical_vector";
  const profileDetails = naturalEarthImportProfileDetails(job.profile);
  const artifacts = job.artifacts ?? [];
  return (
    <Card withBorder radius="md" padding="md">
      <Stack gap="sm">
        <Group justify="space-between" align="center">
          <Text fw={600}>
            {profileDetails.title}
          </Text>
          <NaturalEarthImportStateBadge job={job} />
        </Group>
        <Text size="sm">{job.phase}</Text>
        <Group gap="xl" align="flex-start">
          <ImportDetail label="Source">
            <Text size="sm">{profileDetails.source}</Text>
          </ImportDetail>
          <ImportDetail label={artifacts.length > 1 ? "Published artifacts" : "Published artifact"}>
            <Stack gap={4}>
              {(artifacts.length > 0
                ? artifacts
                : [
                    {
                      manifest_key: job.manifest_key,
                      asset: "raster",
                      logical_size_bytes: job.logical_size_bytes
                    }
                  ]
              ).map((artifact) => (
                <Text key={artifact.manifest_key} size="sm">
                  {artifact.asset}: <Code>{artifact.manifest_key}</Code>
                  {artifact.logical_size_bytes > 0 ? ` (${formatBytes(artifact.logical_size_bytes)})` : ""}
                </Text>
              ))}
            </Stack>
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
          {job.logical_size_bytes > 0 ? (
            <ImportDetail label="Published size">
              <Text size="sm">{formatBytes(job.logical_size_bytes)}</Text>
            </ImportDetail>
          ) : null}
        </Group>
        {job.error ? (
          <Alert color="red" variant="light" title="Import stopped with an error">
            {job.error}
          </Alert>
        ) : null}
        {includesLabels && job.state === "ready" ? (
          <Alert color="blue" variant="light" title="Enable the labels map variant">
            The label overlay is published. In Gallery map variants, make{" "}
            <Code>Natural Earth Globe + labels</Code> visible and select it as the initial map when
            you want the gallery to use it.
          </Alert>
        ) : null}
        {isVectorMap && job.state === "ready" ? (
          <Alert color="blue" variant="light" title="Enable the vector map variant">
            The vector map is published. In Gallery map variants, make <Code>Natural Earth Vector</Code>{" "}
            visible and select it as the initial map when you want the gallery to use it.
          </Alert>
        ) : null}
        {job.log_entries.length > 0 ? (
          <Accordion variant="contained">
            <Accordion.Item value="natural-earth-import-log">
              <Accordion.Control>
                Conversion log ({job.log_entries.length} entries)
              </Accordion.Control>
              <Accordion.Panel>
                <ScrollArea h={320} type="auto">
                  <Stack gap="sm" pr="sm">
                    {job.log_entries.map((entry, index) => (
                      <div key={`${entry.timestamp_unix}-${index}`}>
                        <Text size="xs" c="dimmed" mb={4}>
                          {formatUnixTs(entry.timestamp_unix)}
                        </Text>
                        <Code block>{entry.message}</Code>
                      </div>
                    ))}
                  </Stack>
                </ScrollArea>
              </Accordion.Panel>
            </Accordion.Item>
          </Accordion>
        ) : null}
      </Stack>
    </Card>
  );
}

function naturalEarthImportProfileDetails(profile: NaturalEarthImportProfile): {
  title: string;
  source: string;
} {
  switch (profile) {
    case "physical":
      return {
        title: "Natural Earth physical world map",
        source: "Official Natural Earth 10m physical archive"
      };
    case "physical_with_labels":
      return {
        title: "Natural Earth physical world map + labels",
        source: "Official Natural Earth 10m physical and cultural archives"
      };
    case "physical_vector":
      return {
        title: "Natural Earth vector world map",
        source: "Official Natural Earth 10m physical and cultural archives"
      };
    case "cross_blended_hypso":
      return {
        title: "Natural Earth hypsometric relief map",
        source: "Official Natural Earth 10m Cross Blended Hypso raster archive"
      };
  }
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

        {job.variant_id && job.asset ? (
          <Text size="sm" c="dimmed">
            Target: {job.variant_id} — {job.asset}
          </Text>
        ) : null}

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

function mapImportTargets(
  variants: Array<{
    id: string;
    label: string;
    raster_manifest_key?: string | null;
    vector_manifest_key?: string | null;
  }>
): MapImportTarget[] {
  return variants.flatMap((variant) => {
    const targets: MapImportTarget[] = [];
    const provider = mapDatasetProvider(variant);
    if (variant.raster_manifest_key) {
      targets.push({
        key: `${variant.id}:raster`,
        variantId: variant.id,
        asset: "raster",
        label: variant.label,
        manifestKey: variant.raster_manifest_key,
        provider
      });
    }
    if (variant.vector_manifest_key) {
      targets.push({
        key: `${variant.id}:vector`,
        variantId: variant.id,
        asset: "vector",
        label: variant.label,
        manifestKey: variant.vector_manifest_key,
        provider
      });
    }
    return targets;
  });
}

function mapDatasetProvider(variant: {
  id: string;
  raster_manifest_key?: string | null;
  vector_manifest_key?: string | null;
}): MapDatasetProvider {
  const manifestKeys = [variant.raster_manifest_key, variant.vector_manifest_key];
  if (variant.id.startsWith("maptiler-") || manifestKeys.some((key) => key?.includes("maptiler-"))) {
    return {
      label: "MapTiler Data",
      homepageUrl: "https://data.maptiler.com/",
      acquisitionHint:
        "Get the matching legacy MBTiles package from MapTiler Data and check its current license before importing."
    };
  }
  if (variant.id.startsWith("natural-earth-")) {
    return {
      label: "Natural Earth",
      homepageUrl: "https://www.naturalearthdata.com/",
      acquisitionHint:
        "Natural Earth publishes public-domain source data; package the needed layers as a compatible MBTiles file before importing."
    };
  }
  if (variant.id === "openmaptiles-street") {
    return {
      label: "OpenMapTiles",
      homepageUrl: "https://openmaptiles.org/",
      acquisitionHint:
        "Use an OpenMapTiles-compatible MBTiles package and confirm the data provider's license and attribution requirements."
    };
  }
  return {
    acquisitionHint:
      "Obtain a properly licensed MBTiles package compatible with this variant's style and keep the required attribution in the map configuration."
  };
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
