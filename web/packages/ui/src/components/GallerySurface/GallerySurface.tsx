import {
  Alert,
  AspectRatio,
  Badge,
  Button,
  Card,
  Center,
  Code,
  Grid,
  Group,
  Loader,
  Modal,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
  ThemeIcon
} from "@mantine/core";
import {
  IconArrowUp,
  IconChevronLeft,
  IconChevronRight,
  IconFolder,
  IconLayoutGrid,
  IconMap2,
  IconMapPin,
  IconRefresh
} from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { JsonBlock } from "../JsonBlock/JsonBlock";

type GallerySortOrder = "captured_desc" | "path_asc";
type GalleryViewMode = "grid" | "map";

const imageExtensions = [".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"];
const GALLERY_THUMBNAILS_PER_ROW_STORAGE_KEY = "ironmesh.gallery.thumbnails_per_row";
const GALLERY_VIEW_MODE_STORAGE_KEY = "ironmesh.gallery.view_mode";

export type GallerySnapshot = {
  id: string;
  [key: string]: unknown;
};

export type GalleryEntry = {
  path: string;
  entry_type: string;
  media?: {
    status?: string | null;
    media_type?: string | null;
    mime_type?: string | null;
    width?: number | null;
    height?: number | null;
    taken_at_unix?: number | null;
    gps?: {
      latitude: number;
      longitude: number;
    } | null;
    thumbnail?: {
      url: string;
    } | null;
    error?: string | null;
  } | null;
};

export type GalleryPayload = {
  prefix: string;
  depth: number;
  entry_count: number;
  entries: GalleryEntry[];
  [key: string]: unknown;
};

export type GalleryPreviewRequest = {
  url: string;
  headers?: Record<string, string>;
};

export type GalleryImageRequests = {
  thumbnail: GalleryPreviewRequest;
  original?: GalleryPreviewRequest | null;
};

type GalleryNavigationItem = {
  key: string;
  kind: "up" | "prefix";
  label: string;
  description: string;
  targetPrefix: string;
};

type GallerySurfaceProps = {
  intro?: string;
  previewHint: string;
  loadSnapshots: () => Promise<GallerySnapshot[]>;
  loadEntries: (prefix: string, depth: number, snapshotId: string | null) => Promise<GalleryPayload>;
  getImageRequests: (entry: GalleryEntry, snapshotId: string | null) => GalleryImageRequests;
};

export function GallerySurface({
  intro,
  previewHint,
  loadSnapshots,
  loadEntries,
  getImageRequests
}: GallerySurfaceProps) {
  const [prefix, setPrefix] = useState("");
  const [depth, setDepth] = useState(4);
  const [thumbnailsPerRow, setThumbnailsPerRow] = useState(loadStoredThumbnailsPerRow);
  const [viewMode, setViewMode] = useState(loadStoredViewMode);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<GallerySnapshot[]>([]);
  const [entriesPayload, setEntriesPayload] = useState<GalleryPayload | null>(null);
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const [sortOrder, setSortOrder] = useState<GallerySortOrder>("captured_desc");
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshSnapshots();
  }, [loadSnapshots]);

  useEffect(() => {
    void refreshEntries();
  }, [loadEntries]);

  useEffect(() => {
    persistThumbnailsPerRow(thumbnailsPerRow);
  }, [thumbnailsPerRow]);

  useEffect(() => {
    persistViewMode(viewMode);
  }, [viewMode]);

  const imageEntries = sortGalleryEntries(
    (entriesPayload?.entries ?? []).filter(isGalleryImageEntry),
    sortOrder
  );
  const geotaggedEntries = imageEntries.filter(hasGalleryGpsCoordinates);
  const currentGalleryPrefix = normalizeGalleryPrefix(entriesPayload?.prefix ?? prefix);
  const navigationItems = buildGalleryNavigationItems(
    entriesPayload?.entries ?? [],
    currentGalleryPrefix
  );
  const readyCount = imageEntries.filter((entry) => entry.media?.status === "ready").length;
  const pendingCount = imageEntries.filter((entry) => entry.media?.status === "pending").length;
  const hiddenOnMapCount = imageEntries.length - geotaggedEntries.length;
  const selectedIndex = selectedPath
    ? imageEntries.findIndex((entry) => entry.path === selectedPath)
    : -1;
  const selectedEntry = selectedIndex >= 0 ? imageEntries[selectedIndex] ?? null : null;
  const selectedImageRequests = selectedEntry
    ? getImageRequests(selectedEntry, snapshotId)
    : null;
  const canNavigatePrevious = selectedIndex > 0;
  const canNavigateNext = selectedIndex >= 0 && selectedIndex < imageEntries.length - 1;

  useEffect(() => {
    if (selectedPath && selectedIndex === -1) {
      setSelectedPath(null);
    }
  }, [selectedIndex, selectedPath]);

  useEffect(() => {
    if (selectedIndex < 0) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "ArrowLeft" && canNavigatePrevious) {
        event.preventDefault();
        setSelectedPath(imageEntries[selectedIndex - 1]?.path ?? null);
      }

      if (event.key === "ArrowRight" && canNavigateNext) {
        event.preventDefault();
        setSelectedPath(imageEntries[selectedIndex + 1]?.path ?? null);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [canNavigateNext, canNavigatePrevious, imageEntries, selectedIndex]);

  async function refreshSnapshots() {
    setLoading("snapshots");
    setError(null);
    try {
      const payload = await loadSnapshots();
      setSnapshots(payload);
      if (!snapshotId && payload.length > 0) {
        setSnapshotId(payload[0]?.id ?? null);
      }
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed to load snapshots");
    } finally {
      setLoading(null);
    }
  }

  async function refreshEntries(nextPrefix?: string, nextSnapshotId?: string | null) {
    setLoading("entries");
    setError(null);
    const targetPrefix = nextPrefix ?? prefix;
    const targetSnapshot = nextSnapshotId === undefined ? snapshotId : nextSnapshotId;
    try {
      const payload = await loadEntries(targetPrefix.trim(), depth, targetSnapshot);
      setEntriesPayload(payload);
      if (typeof nextPrefix === "string") {
        setPrefix(nextPrefix);
      }
    } catch (nextError) {
      setError(
        nextError instanceof Error ? nextError.message : "Failed to load gallery entries"
      );
    } finally {
      setLoading(null);
    }
  }

  function showRelativeEntry(delta: -1 | 1) {
    if (selectedIndex < 0) {
      return;
    }

    const nextIndex = selectedIndex + delta;
    if (nextIndex < 0 || nextIndex >= imageEntries.length) {
      return;
    }

    setSelectedPath(imageEntries[nextIndex]?.path ?? null);
  }

  return (
    <Stack gap="lg">
      {intro ? (
        <Text c="dimmed" maw={720}>
          {intro}
        </Text>
      ) : null}

      {error ? <Alert color="red">{error}</Alert> : null}

      <Grid>
        <Grid.Col span={{ base: 12, xl: 4 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Group justify="space-between" align="flex-start">
                <Text fw={700}>Scope</Text>
                <Group gap="sm">
                  <Button
                    variant="default"
                    loading={loading === "snapshots"}
                    onClick={() => void refreshSnapshots()}
                  >
                    Refresh snapshots
                  </Button>
                  <Button
                    leftSection={<IconRefresh size={16} />}
                    loading={loading === "entries"}
                    onClick={() => void refreshEntries()}
                  >
                    Refresh gallery
                  </Button>
                </Group>
              </Group>
              <TextInput
                label="Prefix"
                value={prefix}
                onChange={(event) => setPrefix(event.currentTarget.value)}
                placeholder="gallery/"
              />
              <NumberInput
                label="Depth"
                min={1}
                max={64}
                value={depth}
                onChange={(value) => setDepth(typeof value === "number" && value > 0 ? value : 1)}
              />
              <Select
                label="Snapshot"
                data={[
                  { value: "", label: "Current data" },
                  ...snapshots.map((snapshot) => ({ value: snapshot.id, label: snapshot.id }))
                ]}
                value={snapshotId ?? ""}
                onChange={(value) => {
                  const nextSnapshot = value || null;
                  setSnapshotId(nextSnapshot);
                  void refreshEntries(undefined, nextSnapshot);
                }}
              />
              <Select
                label="Sort"
                data={[
                  { value: "captured_desc", label: "Newest first" },
                  { value: "path_asc", label: "Path" }
                ]}
                value={sortOrder}
                onChange={(value) =>
                  setSortOrder(value === "path_asc" ? "path_asc" : "captured_desc")
                }
              />
              <Group grow>
                <Button
                  variant={viewMode === "grid" ? "filled" : "default"}
                  leftSection={<IconLayoutGrid size={14} />}
                  onClick={() => setViewMode("grid")}
                >
                  Grid
                </Button>
                <Button
                  variant={viewMode === "map" ? "filled" : "default"}
                  leftSection={<IconMap2 size={14} />}
                  onClick={() => setViewMode("map")}
                >
                  Map
                </Button>
              </Group>
              <Select
                label="Thumbnails per row"
                data={[
                  { value: "1", label: "1 per row" },
                  { value: "2", label: "2 per row" },
                  { value: "3", label: "3 per row" },
                  { value: "4", label: "4 per row" },
                  { value: "5", label: "5 per row" },
                  { value: "6", label: "6 per row" }
                ]}
                value={String(thumbnailsPerRow)}
                onChange={(value) => {
                  setThumbnailsPerRow(parseThumbnailsPerRow(value));
                }}
              />
              <Group gap="sm">
                <Button onClick={() => void refreshEntries()}>Load</Button>
                <Button variant="default" onClick={() => void refreshEntries(parentPrefix(prefix))}>
                  Up one prefix
                </Button>
                <Button variant="subtle" onClick={() => void refreshEntries("")}>
                  Root
                </Button>
              </Group>
              <Group gap="xs">
                <Badge variant="light">{imageEntries.length} images</Badge>
                <Badge color="grape" variant="light">
                  {geotaggedEntries.length} geo-tagged
                </Badge>
                <Badge color="blue" variant="light">
                  {navigationItems.filter((item) => item.kind === "prefix").length} folders
                </Badge>
                <Badge color="green" variant="light">
                  {readyCount} ready
                </Badge>
                {pendingCount > 0 ? (
                  <Badge color="yellow" variant="light">
                    {pendingCount} pending
                  </Badge>
                ) : null}
              </Group>
              <Text size="sm" c="dimmed">
                {previewHint}
              </Text>
              <JsonBlock
                value={
                  entriesPayload ?? {
                    message: "No gallery payload loaded yet."
                  }
                }
              />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 8 }}>
          {viewMode === "map" ? (
            <Stack gap="md">
              {navigationItems.length > 0 ? (
                <Group gap="sm">
                  {navigationItems.map((item) => (
                    <Button
                      key={item.key}
                      variant={item.kind === "up" ? "default" : "light"}
                      leftSection={
                        item.kind === "up" ? <IconArrowUp size={16} /> : <IconFolder size={16} />
                      }
                      onClick={() => void refreshEntries(item.targetPrefix)}
                    >
                      {item.label}
                    </Button>
                  ))}
                </Group>
              ) : null}

              {geotaggedEntries.length === 0 ? (
                <Card withBorder radius="md" padding="xl">
                  <Stack gap="xs" align="center">
                    <Text fw={700}>No geo-tagged images in view</Text>
                    <Text c="dimmed" ta="center">
                      The current gallery scope has {imageEntries.length} image
                      {imageEntries.length === 1 ? "" : "s"}, but none with GPS coordinates yet.
                    </Text>
                  </Stack>
                </Card>
              ) : (
                <GalleryWorldMap
                  entries={geotaggedEntries}
                  hiddenOnMapCount={hiddenOnMapCount}
                  selectedPath={selectedPath}
                  getMarkerRequest={(entry) => getImageRequests(entry, snapshotId).thumbnail}
                  onSelectPath={setSelectedPath}
                />
              )}
            </Stack>
          ) : imageEntries.length === 0 && navigationItems.length === 0 ? (
            <Card withBorder radius="md" padding="xl">
              <Stack gap="xs" align="center">
                <Text fw={700}>No image objects in view</Text>
                <Text c="dimmed" ta="center">
                  Load a different prefix or increase the depth to include nested image keys.
                </Text>
              </Stack>
            </Card>
          ) : (
            <SimpleGrid
              cols={{
                base: 1,
                sm: Math.min(thumbnailsPerRow, 2),
                md: Math.min(thumbnailsPerRow, 3),
                lg: thumbnailsPerRow
              }}
            >
              {navigationItems.map((item) => (
                <Card
                  key={item.key}
                  withBorder
                  radius="md"
                  padding="sm"
                  style={{ cursor: "pointer" }}
                  onClick={() => void refreshEntries(item.targetPrefix)}
                >
                  <Card.Section>
                    <AspectRatio ratio={1}>
                      <Center style={{ height: "100%", background: "var(--mantine-color-blue-0)" }}>
                        <Stack gap="xs" align="center">
                          <ThemeIcon size={54} radius="xl" variant="light" color="blue">
                            {item.kind === "up" ? <IconArrowUp size={28} /> : <IconFolder size={28} />}
                          </ThemeIcon>
                          <Text fw={700}>{item.label}</Text>
                        </Stack>
                      </Center>
                    </AspectRatio>
                  </Card.Section>

                  <Stack gap={6} mt="sm">
                    <Badge color="blue" variant="light">
                      {item.kind === "up" ? "navigation" : "folder"}
                    </Badge>
                    <Text size="sm" c="dimmed">
                      {item.description}
                    </Text>
                  </Stack>
                </Card>
              ))}

              {imageEntries.map((entry) => {
                const imageRequests = getImageRequests(entry, snapshotId);
                return (
                  <Card
                    key={entry.path}
                    withBorder
                    radius="md"
                    padding="sm"
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelectedPath(entry.path)}
                  >
                    <Card.Section>
                      <AspectRatio ratio={1}>
                        <GalleryImagePreview
                          request={imageRequests.thumbnail}
                          alt={entry.path}
                          fit="cover"
                        />
                      </AspectRatio>
                    </Card.Section>

                    <Stack gap={6} mt="sm">
                      <Group justify="space-between" align="flex-start" wrap="nowrap">
                        <Text fw={700} lineClamp={1}>
                          {fileName(entry.path)}
                        </Text>
                        <Badge color={mediaStatusColor(entry.media?.status)} variant="light">
                          {entry.media?.status ?? "uncached"}
                        </Badge>
                      </Group>
                      <Code>{entry.path}</Code>
                      <Group gap={6}>
                        {entry.media?.width && entry.media?.height ? (
                          <Badge variant="dot">
                            {entry.media.width} x {entry.media.height}
                          </Badge>
                        ) : null}
                        {entry.media?.mime_type ? (
                          <Badge variant="dot">{entry.media.mime_type}</Badge>
                        ) : null}
                        {entry.media?.gps ? <Badge color="grape" variant="dot">GPS</Badge> : null}
                      </Group>
                      {entry.media?.taken_at_unix ? (
                        <Text size="sm" c="dimmed">
                          Captured {formatTakenAt(entry.media.taken_at_unix)}
                        </Text>
                      ) : null}
                    </Stack>
                  </Card>
                );
              })}
            </SimpleGrid>
          )}
        </Grid.Col>
      </Grid>

      <Modal
        opened={selectedEntry !== null}
        onClose={() => setSelectedPath(null)}
        title={
          selectedEntry
            ? `${fileName(selectedEntry.path)} (${selectedIndex + 1} of ${imageEntries.length})`
            : "Image preview"
        }
        fullScreen
        styles={{
          body: {
            paddingTop: 0
          }
        }}
      >
        {selectedEntry && selectedImageRequests ? (
          <Stack gap="md">
            <div style={{ height: "calc(100vh - 17rem)", minHeight: "24rem" }}>
              <GalleryLightboxImage
                requests={selectedImageRequests}
                alt={selectedEntry.path}
                canNavigatePrevious={canNavigatePrevious}
                canNavigateNext={canNavigateNext}
                onNavigatePrevious={() => showRelativeEntry(-1)}
                onNavigateNext={() => showRelativeEntry(1)}
              />
            </div>
            <Group gap="xs">
              <Badge variant="light">
                {selectedIndex + 1} / {imageEntries.length}
              </Badge>
              <Badge color={mediaStatusColor(selectedEntry.media?.status)} variant="light">
                {selectedEntry.media?.status ?? "uncached"}
              </Badge>
              {selectedEntry.media?.mime_type ? (
                <Badge variant="light">{selectedEntry.media.mime_type}</Badge>
              ) : null}
              {selectedEntry.media?.width && selectedEntry.media?.height ? (
                <Badge variant="light">
                  {selectedEntry.media.width} x {selectedEntry.media.height}
                </Badge>
              ) : null}
            </Group>
            <Text size="sm" c="dimmed">
              {selectedEntry.path}
            </Text>
            {selectedEntry.media?.taken_at_unix ? (
              <Text size="sm">Captured {formatTakenAt(selectedEntry.media.taken_at_unix)}</Text>
            ) : null}
            {selectedEntry.media?.error ? <Alert color="yellow">{selectedEntry.media.error}</Alert> : null}
            <JsonBlock value={selectedEntry} />
          </Stack>
        ) : null}
      </Modal>
    </Stack>
  );
}

type GalleryWorldMapProps = {
  entries: GalleryEntry[];
  hiddenOnMapCount: number;
  selectedPath: string | null;
  getMarkerRequest: (entry: GalleryEntry) => GalleryPreviewRequest;
  onSelectPath: (path: string) => void;
};

function GalleryWorldMap({
  entries,
  hiddenOnMapCount,
  selectedPath,
  getMarkerRequest,
  onSelectPath
}: GalleryWorldMapProps) {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="md">
        <Group justify="space-between" align="flex-start">
          <div>
            <Text fw={700}>Geo-tagged world map</Text>
            <Text size="sm" c="dimmed">
              Click a thumbnail marker to open the fullscreen image viewer.
            </Text>
          </div>
          <Group gap="xs">
            <Badge color="grape" variant="light">
              {entries.length} markers
            </Badge>
            {hiddenOnMapCount > 0 ? (
              <Badge color="gray" variant="light">
                {hiddenOnMapCount} without GPS
              </Badge>
            ) : null}
          </Group>
        </Group>

        <div
          aria-label="Geotagged gallery map"
          style={{
            position: "relative",
            aspectRatio: "16 / 9",
            overflow: "hidden",
            borderRadius: "calc(var(--mantine-radius-md) - 2px)",
            background:
              "radial-gradient(circle at 18% 16%, rgba(255, 255, 255, 0.32), transparent 28%), linear-gradient(180deg, #0c3348 0%, #144e6c 48%, #0d2f44 100%)",
            boxShadow: "inset 0 0 0 1px rgba(255, 255, 255, 0.08)"
          }}
        >
          <svg
            viewBox="0 0 1000 560"
            preserveAspectRatio="none"
            aria-hidden="true"
            style={{
              position: "absolute",
              inset: 0,
              width: "100%",
              height: "100%"
            }}
          >
            <defs>
              <linearGradient id="ironmesh-gallery-map-land" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#335c49" />
                <stop offset="100%" stopColor="#244739" />
              </linearGradient>
            </defs>
            {[1, 2, 3, 4, 5].map((index) => (
              <line
                key={`parallel:${index}`}
                x1="0"
                x2="1000"
                y1={index * (560 / 6)}
                y2={index * (560 / 6)}
                stroke="rgba(255, 255, 255, 0.14)"
                strokeWidth="1"
              />
            ))}
            {[1, 2, 3, 4, 5, 6, 7].map((index) => (
              <line
                key={`meridian:${index}`}
                y1="0"
                y2="560"
                x1={index * (1000 / 8)}
                x2={index * (1000 / 8)}
                stroke="rgba(255, 255, 255, 0.12)"
                strokeWidth="1"
              />
            ))}
            <line
              x1="0"
              x2="1000"
              y1="280"
              y2="280"
              stroke="rgba(255, 255, 255, 0.22)"
              strokeWidth="1.5"
            />
            <line
              y1="0"
              y2="560"
              x1="500"
              x2="500"
              stroke="rgba(255, 255, 255, 0.18)"
              strokeWidth="1.5"
            />
            <path
              d="M101 125c28-31 79-50 120-42 43 8 66 33 96 46 25 11 60 8 74 35 14 27-13 63-27 92-16 33-15 68-37 92-26 28-72 20-111 7-42-14-80-37-104-71-22-32-28-78-19-114 8-35-10-82 8-105z"
              fill="url(#ironmesh-gallery-map-land)"
              opacity="0.78"
            />
            <path
              d="M247 330c32-8 51 19 63 43 13 28 15 64-3 88-17 23-48 38-77 31-27-7-47-34-50-62-3-23 12-43 23-63 11-20 18-32 44-37z"
              fill="url(#ironmesh-gallery-map-land)"
              opacity="0.72"
            />
            <path
              d="M474 108c33-22 84-25 118-12 28 11 39 33 61 49 26 20 67 16 87 43 25 33 26 87 8 126-21 46-70 77-120 82-43 5-91-9-126-35-34-26-60-67-57-111 2-34 26-64 27-98 0-20-14-30 2-44z"
              fill="url(#ironmesh-gallery-map-land)"
              opacity="0.82"
            />
            <path
              d="M542 352c23-20 63-24 92-16 27 8 41 31 52 54 12 24 21 53 8 77-15 29-52 46-85 43-31-3-59-24-71-53-13-32-20-78 4-105z"
              fill="url(#ironmesh-gallery-map-land)"
              opacity="0.74"
            />
            <path
              d="M770 352c23-13 51-12 76-4 24 8 49 25 56 50 7 22-7 48-26 60-23 15-53 15-79 11-21-3-44-10-56-28-11-17-10-42 2-58 7-10 15-22 27-31z"
              fill="url(#ironmesh-gallery-map-land)"
              opacity="0.8"
            />
          </svg>

          {entries.map((entry) => {
            const gps = entry.media?.gps;
            if (!gps) {
              return null;
            }

            const projection = projectGpsToWorldMap(gps.latitude, gps.longitude);
            return (
              <GalleryMapMarker
                key={entry.path}
                entry={entry}
                request={getMarkerRequest(entry)}
                projectedX={projection.x}
                projectedY={projection.y}
                selected={selectedPath === entry.path}
                onClick={() => onSelectPath(entry.path)}
              />
            );
          })}

          <div
            style={{
              position: "absolute",
              left: 16,
              bottom: 12,
              display: "flex",
              gap: 12,
              color: "rgba(255, 255, 255, 0.72)",
              fontSize: "0.78rem",
              letterSpacing: "0.04em",
              textTransform: "uppercase"
            }}
          >
            <span>180W</span>
            <span>Prime meridian</span>
            <span>180E</span>
          </div>
        </div>
      </Stack>
    </Card>
  );
}

type GalleryMapMarkerProps = {
  entry: GalleryEntry;
  request: GalleryPreviewRequest;
  projectedX: number;
  projectedY: number;
  selected: boolean;
  onClick: () => void;
};

function GalleryMapMarker({
  entry,
  request,
  projectedX,
  projectedY,
  selected,
  onClick
}: GalleryMapMarkerProps) {
  const [imageFailed, setImageFailed] = useState(false);
  const { resolvedSrc, failed } = useResolvedImageRequest(request);
  const signature = requestSignature(request);
  const gps = entry.media?.gps;

  useEffect(() => {
    setImageFailed(false);
  }, [signature]);

  return (
    <button
      type="button"
      aria-label={`Open map marker for ${entry.path}`}
      title={
        gps
          ? `${entry.path} (${gps.latitude.toFixed(4)}, ${gps.longitude.toFixed(4)})`
          : entry.path
      }
      onClick={onClick}
      style={{
        position: "absolute",
        left: `${projectedX * 100}%`,
        top: `${projectedY * 100}%`,
        width: selected ? 58 : 50,
        height: selected ? 58 : 50,
        padding: 0,
        borderRadius: "50%",
        border: selected
          ? "3px solid rgba(255, 255, 255, 0.98)"
          : "2px solid rgba(255, 255, 255, 0.72)",
        outline: 0,
        overflow: "hidden",
        transform: "translate(-50%, -50%)",
        background: failed || imageFailed ? "rgba(18, 48, 64, 0.92)" : "rgba(255, 255, 255, 0.16)",
        boxShadow: selected
          ? "0 0 0 6px rgba(164, 80, 255, 0.24), 0 18px 34px rgba(0, 0, 0, 0.42)"
          : "0 12px 28px rgba(0, 0, 0, 0.34)",
        cursor: "pointer"
      }}
    >
      {failed || imageFailed || !resolvedSrc ? (
        <Center style={{ width: "100%", height: "100%" }}>
          <IconMapPin size={18} color="white" />
        </Center>
      ) : (
        <img
          src={resolvedSrc}
          alt={entry.path}
          loading="lazy"
          decoding="async"
          onError={() => setImageFailed(true)}
          style={{
            width: "100%",
            height: "100%",
            objectFit: "cover"
          }}
        />
      )}
    </button>
  );
}

type GalleryImagePreviewProps = {
  request: GalleryPreviewRequest;
  alt: string;
  fit: "contain" | "cover";
};

function GalleryImagePreview({ request, alt, fit }: GalleryImagePreviewProps) {
  const [imageFailed, setImageFailed] = useState(false);
  const { resolvedSrc, failed: requestFailed } = useResolvedImageRequest(request);
  const signature = requestSignature(request);

  useEffect(() => {
    setImageFailed(false);
  }, [signature]);

  if (requestFailed || imageFailed) {
    return (
      <Center style={{ height: "100%", background: "var(--mantine-color-gray-0)" }}>
        <Text size="sm" c="dimmed">
          Preview unavailable
        </Text>
      </Center>
    );
  }

  if (!resolvedSrc) {
    return (
      <Center style={{ height: "100%", background: "var(--mantine-color-gray-0)" }}>
        <Loader size="sm" color="gray" />
      </Center>
    );
  }

  return (
    <img
      src={resolvedSrc}
      alt={alt}
      loading="lazy"
      decoding="async"
      onError={() => setImageFailed(true)}
      style={{
        width: "100%",
        height: "100%",
        objectFit: fit,
        background: "var(--mantine-color-gray-0)"
      }}
    />
  );
}

type GalleryLightboxImageProps = {
  requests: GalleryImageRequests;
  alt: string;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
};

function GalleryLightboxImage({
  requests,
  alt,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext
}: GalleryLightboxImageProps) {
  const thumbnail = useResolvedImageRequest(requests.thumbnail);
  const originalRequest =
    requests.original && !sameImageRequest(requests.thumbnail, requests.original)
      ? requests.original
      : null;
  const original = useResolvedImageRequest(originalRequest);
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const [originalFailed, setOriginalFailed] = useState(false);
  const [originalLoaded, setOriginalLoaded] = useState(false);
  const [touchStart, setTouchStart] = useState<{ x: number; y: number } | null>(null);
  const thumbnailSignature = requestSignature(requests.thumbnail);
  const originalSignature = requestSignature(originalRequest);
  const showingOriginal = Boolean(originalRequest);

  useEffect(() => {
    setThumbnailFailed(false);
  }, [thumbnailSignature]);

  useEffect(() => {
    setOriginalFailed(false);
    setOriginalLoaded(false);
  }, [originalSignature]);

  const thumbnailVisible = Boolean(thumbnail.resolvedSrc) && !thumbnail.failed && !thumbnailFailed;
  const originalVisible = Boolean(original.resolvedSrc) && !original.failed && !originalFailed;
  const fullImageUnavailable = showingOriginal && (original.failed || originalFailed);
  const originalPending = showingOriginal && !fullImageUnavailable && !originalLoaded;

  return (
    <div
      style={{
        position: "relative",
        width: "100%",
        height: "100%",
        overflow: "hidden",
        borderRadius: "var(--mantine-radius-md)",
        background: "var(--mantine-color-dark-9)",
        touchAction: "pan-y"
      }}
      onTouchStart={(event) => {
        const touch = event.touches[0];
        if (!touch) {
          return;
        }
        setTouchStart({ x: touch.clientX, y: touch.clientY });
      }}
      onTouchEnd={(event) => {
        if (!touchStart) {
          return;
        }

        const touch = event.changedTouches[0];
        setTouchStart(null);
        if (!touch) {
          return;
        }

        const deltaX = touch.clientX - touchStart.x;
        const deltaY = touch.clientY - touchStart.y;
        if (Math.abs(deltaX) < 48 || Math.abs(deltaX) <= Math.abs(deltaY)) {
          return;
        }

        if (deltaX < 0 && canNavigateNext) {
          onNavigateNext();
        }

        if (deltaX > 0 && canNavigatePrevious) {
          onNavigatePrevious();
        }
      }}
    >
      {thumbnailVisible ? (
        <img
          src={thumbnail.resolvedSrc ?? undefined}
          alt={alt}
          loading="eager"
          decoding="async"
          onError={() => setThumbnailFailed(true)}
          style={{
            position: "absolute",
            inset: 0,
            width: "100%",
            height: "100%",
            objectFit: "contain",
            filter: originalPending ? "none" : "blur(0px)",
            background: "var(--mantine-color-dark-9)"
          }}
        />
      ) : (
        <Center
          style={{
            position: "absolute",
            inset: 0,
            background: "var(--mantine-color-gray-0)"
          }}
        >
          <Loader size="sm" color="gray" />
        </Center>
      )}

      {originalVisible ? (
        <img
          src={original.resolvedSrc ?? undefined}
          alt={alt}
          loading="eager"
          decoding="async"
          onLoad={() => setOriginalLoaded(true)}
          onError={() => setOriginalFailed(true)}
          style={{
            position: "absolute",
            inset: 0,
            width: "100%",
            height: "100%",
            objectFit: "contain",
            opacity: originalLoaded ? 1 : 0,
            transition: "opacity 180ms ease",
            background: "transparent"
          }}
        />
      ) : null}

      {originalPending ? (
        <div
          style={{
            position: "absolute",
            top: 16,
            right: 16
          }}
        >
          <Badge
            color="dark"
            variant="filled"
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            Loading original image
          </Badge>
        </div>
      ) : null}

      {fullImageUnavailable ? (
        <div
          style={{
            position: "absolute",
            left: 16,
            bottom: 16
          }}
        >
          <Badge color="yellow" variant="filled">
            Full image unavailable, showing thumbnail
          </Badge>
        </div>
      ) : null}

      <GalleryLightboxEdgeButton
        direction="previous"
        enabled={canNavigatePrevious}
        onClick={onNavigatePrevious}
      />
      <GalleryLightboxEdgeButton
        direction="next"
        enabled={canNavigateNext}
        onClick={onNavigateNext}
      />
    </div>
  );
}

type GalleryLightboxEdgeButtonProps = {
  direction: "previous" | "next";
  enabled: boolean;
  onClick: () => void;
};

function GalleryLightboxEdgeButton({
  direction,
  enabled,
  onClick
}: GalleryLightboxEdgeButtonProps) {
  const isPrevious = direction === "previous";

  return (
    <button
      type="button"
      aria-label={isPrevious ? "Previous image" : "Next image"}
      onClick={onClick}
      disabled={!enabled}
      style={{
        position: "absolute",
        top: 0,
        bottom: 0,
        [isPrevious ? "left" : "right"]: 0,
        width: "18%",
        minWidth: 72,
        border: 0,
        padding: isPrevious ? "0 0 0 16px" : "0 16px 0 0",
        display: "flex",
        alignItems: "center",
        justifyContent: isPrevious ? "flex-start" : "flex-end",
        cursor: enabled ? "pointer" : "default",
        color: enabled ? "white" : "rgba(255, 255, 255, 0.28)",
        background: isPrevious
          ? "linear-gradient(90deg, rgba(0, 0, 0, 0.28) 0%, rgba(0, 0, 0, 0) 100%)"
          : "linear-gradient(270deg, rgba(0, 0, 0, 0.28) 0%, rgba(0, 0, 0, 0) 100%)"
      }}
    >
      {isPrevious ? <IconChevronLeft size={28} /> : <IconChevronRight size={28} />}
    </button>
  );
}

function useResolvedImageRequest(
  request: GalleryPreviewRequest | null | undefined
): { resolvedSrc: string | null; failed: boolean } {
  const [failed, setFailed] = useState(false);
  const [resolvedSrc, setResolvedSrc] = useState<string | null>(request?.url ?? null);
  const hasHeaders = Boolean(request?.headers && Object.keys(request.headers).length > 0);
  const signature = requestSignature(request);

  useEffect(() => {
    setFailed(false);

    if (!request) {
      setResolvedSrc(null);
      return;
    }

    if (!hasHeaders) {
      setResolvedSrc(request.url);
      return;
    }

    const controller = new AbortController();
    let objectUrl: string | null = null;
    let active = true;

    setResolvedSrc(null);

    void fetch(request.url, {
      credentials: "same-origin",
      headers: request.headers,
      signal: controller.signal
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }

        const blob = await response.blob();
        if (!active) {
          return;
        }

        objectUrl = URL.createObjectURL(blob);
        setResolvedSrc(objectUrl);
      })
      .catch(() => {
        if (!active || controller.signal.aborted) {
          return;
        }
        setFailed(true);
      });

    return () => {
      active = false;
      controller.abort();
      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
    };
  }, [hasHeaders, request?.url, signature]);

  return { resolvedSrc, failed };
}

function isGalleryImageEntry(entry: GalleryEntry): boolean {
  if (entry.entry_type !== "key") {
    return false;
  }

  if (entry.media?.mime_type?.startsWith("image/")) {
    return true;
  }

  if (entry.media?.media_type === "image") {
    return true;
  }

  const lowerPath = entry.path.toLowerCase();
  return imageExtensions.some((extension) => lowerPath.endsWith(extension));
}

function isGalleryPrefixEntry(entry: GalleryEntry): boolean {
  return entry.entry_type === "prefix" || entry.path.endsWith("/");
}

function hasGalleryGpsCoordinates(entry: GalleryEntry): boolean {
  const latitude = entry.media?.gps?.latitude;
  const longitude = entry.media?.gps?.longitude;
  return (
    typeof latitude === "number" &&
    Number.isFinite(latitude) &&
    typeof longitude === "number" &&
    Number.isFinite(longitude)
  );
}

function sortGalleryEntries(entries: GalleryEntry[], sortOrder: GallerySortOrder): GalleryEntry[] {
  return [...entries].sort((left, right) => {
    if (sortOrder === "path_asc") {
      return left.path.localeCompare(right.path);
    }

    const leftTakenAt = left.media?.taken_at_unix ?? 0;
    const rightTakenAt = right.media?.taken_at_unix ?? 0;
    if (leftTakenAt !== rightTakenAt) {
      return rightTakenAt - leftTakenAt;
    }
    return left.path.localeCompare(right.path);
  });
}

function mediaStatusColor(status?: string | null): string {
  if (status === "ready") {
    return "green";
  }
  if (status === "pending") {
    return "yellow";
  }
  if (status === "failed") {
    return "red";
  }
  return "gray";
}

function sameImageRequest(
  left: GalleryPreviewRequest | null | undefined,
  right: GalleryPreviewRequest | null | undefined
): boolean {
  return requestSignature(left) === requestSignature(right);
}

function requestSignature(request: GalleryPreviewRequest | null | undefined): string {
  if (!request) {
    return "";
  }

  const headers = JSON.stringify(
    Object.entries(request.headers ?? {}).sort(([left], [right]) => left.localeCompare(right))
  );
  return `${request.url}::${headers}`;
}

function buildGalleryNavigationItems(
  entries: GalleryEntry[],
  currentPrefix: string
): GalleryNavigationItem[] {
  const items: GalleryNavigationItem[] = [];
  const seenPrefixes = new Set<string>();

  if (currentPrefix) {
    const parent = parentPrefix(currentPrefix);
    items.push({
      key: `up:${currentPrefix}`,
      kind: "up",
      label: "Up one level",
      description: parent || "Return to the root folder",
      targetPrefix: parent
    });
  }

  for (const entry of entries) {
    if (!isGalleryPrefixEntry(entry)) {
      continue;
    }

    const normalizedPath = normalizeGalleryPrefix(entry.path);
    if (!normalizedPath || normalizedPath === currentPrefix) {
      continue;
    }
    if (!normalizedPath.startsWith(currentPrefix)) {
      continue;
    }

    const relativePath = normalizedPath.slice(currentPrefix.length);
    const trimmedRelative = relativePath.replace(/\/$/, "");
    if (!trimmedRelative || trimmedRelative.includes("/")) {
      continue;
    }
    if (seenPrefixes.has(normalizedPath)) {
      continue;
    }

    seenPrefixes.add(normalizedPath);
    items.push({
      key: `prefix:${normalizedPath}`,
      kind: "prefix",
      label: `${trimmedRelative}/`,
      description: `Open ${normalizedPath}`,
      targetPrefix: normalizedPath
    });
  }

  return items.sort((left, right) => {
    if (left.kind !== right.kind) {
      return left.kind === "up" ? -1 : 1;
    }
    return left.label.localeCompare(right.label);
  });
}

function normalizeGalleryPrefix(path: string): string {
  const trimmed = path.trim().replace(/^\/+/, "");
  if (!trimmed) {
    return "";
  }
  return `${trimmed.replace(/\/+$/, "")}/`;
}

function loadStoredThumbnailsPerRow(): number {
  if (typeof window === "undefined") {
    return 3;
  }

  return parseThumbnailsPerRow(window.localStorage.getItem(GALLERY_THUMBNAILS_PER_ROW_STORAGE_KEY));
}

function loadStoredViewMode(): GalleryViewMode {
  if (typeof window === "undefined") {
    return "grid";
  }

  return parseViewMode(window.localStorage.getItem(GALLERY_VIEW_MODE_STORAGE_KEY));
}

function persistThumbnailsPerRow(value: number) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(
    GALLERY_THUMBNAILS_PER_ROW_STORAGE_KEY,
    String(parseThumbnailsPerRow(value))
  );
}

function persistViewMode(value: GalleryViewMode) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(GALLERY_VIEW_MODE_STORAGE_KEY, parseViewMode(value));
}

function parseThumbnailsPerRow(value: string | number | null | undefined): number {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) && parsed >= 1 && parsed <= 6 ? parsed : 3;
}

function parseViewMode(value: string | null | undefined): GalleryViewMode {
  return value === "map" ? "map" : "grid";
}

function formatTakenAt(value: number): string {
  return new Date(value * 1000).toLocaleString();
}

function fileName(path: string): string {
  return path.split("/").pop() || path;
}

function parentPrefix(path: string): string {
  const normalized = path.replace(/\/+$/, "");
  if (!normalized.includes("/")) {
    return "";
  }
  return `${normalized.split("/").slice(0, -1).join("/")}/`;
}

function projectGpsToWorldMap(latitude: number, longitude: number): { x: number; y: number } {
  const clampedLatitude = Math.max(-85, Math.min(85, latitude));
  const wrappedLongitude = ((((longitude + 180) % 360) + 360) % 360) - 180;

  return {
    x: Math.max(0.028, Math.min(0.972, (wrappedLongitude + 180) / 360)),
    y: Math.max(0.04, Math.min(0.96, (90 - clampedLatitude) / 180))
  };
}
