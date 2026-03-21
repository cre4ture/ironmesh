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
  TextInput
} from "@mantine/core";
import { IconRefresh } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import { JsonBlock } from "../JsonBlock/JsonBlock";

type GallerySortOrder = "captured_desc" | "path_asc";

const imageExtensions = [".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"];

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

type GallerySurfaceProps = {
  intro?: string;
  previewHint: string;
  loadSnapshots: () => Promise<GallerySnapshot[]>;
  loadEntries: (prefix: string, depth: number, snapshotId: string | null) => Promise<GalleryPayload>;
  getPreviewRequest: (entry: GalleryEntry, snapshotId: string | null) => GalleryPreviewRequest;
};

export function GallerySurface({
  intro,
  previewHint,
  loadSnapshots,
  loadEntries,
  getPreviewRequest
}: GallerySurfaceProps) {
  const [prefix, setPrefix] = useState("");
  const [depth, setDepth] = useState(4);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<GallerySnapshot[]>([]);
  const [entriesPayload, setEntriesPayload] = useState<GalleryPayload | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<GalleryEntry | null>(null);
  const [sortOrder, setSortOrder] = useState<GallerySortOrder>("captured_desc");
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshSnapshots();
  }, [loadSnapshots]);

  useEffect(() => {
    void refreshEntries();
  }, [loadEntries]);

  const imageEntries = sortGalleryEntries(
    (entriesPayload?.entries ?? []).filter(isGalleryImageEntry),
    sortOrder
  );
  const readyCount = imageEntries.filter((entry) => entry.media?.status === "ready").length;
  const pendingCount = imageEntries.filter((entry) => entry.media?.status === "pending").length;

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
          {imageEntries.length === 0 ? (
            <Card withBorder radius="md" padding="xl">
              <Stack gap="xs" align="center">
                <Text fw={700}>No image objects in view</Text>
                <Text c="dimmed" ta="center">
                  Load a different prefix or increase the depth to include nested image keys.
                </Text>
              </Stack>
            </Card>
          ) : (
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }}>
              {imageEntries.map((entry) => (
                <Card
                  key={entry.path}
                  withBorder
                  radius="md"
                  padding="sm"
                  style={{ cursor: "pointer" }}
                  onClick={() => setSelectedEntry(entry)}
                >
                  <Card.Section>
                    <AspectRatio ratio={1}>
                      <GalleryImagePreview
                        request={getPreviewRequest(entry, snapshotId)}
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
                    </Group>
                    {entry.media?.taken_at_unix ? (
                      <Text size="sm" c="dimmed">
                        Captured {formatTakenAt(entry.media.taken_at_unix)}
                      </Text>
                    ) : null}
                  </Stack>
                </Card>
              ))}
            </SimpleGrid>
          )}
        </Grid.Col>
      </Grid>

      <Modal
        opened={selectedEntry !== null}
        onClose={() => setSelectedEntry(null)}
        title={selectedEntry ? fileName(selectedEntry.path) : "Image preview"}
        size="xl"
        centered
      >
        {selectedEntry ? (
          <Stack gap="md">
            <AspectRatio ratio={4 / 3}>
              <GalleryImagePreview
                request={getPreviewRequest(selectedEntry, snapshotId)}
                alt={selectedEntry.path}
                fit="contain"
              />
            </AspectRatio>
            <Group gap="xs">
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

type GalleryImagePreviewProps = {
  request: GalleryPreviewRequest;
  alt: string;
  fit: "contain" | "cover";
};

function GalleryImagePreview({ request, alt, fit }: GalleryImagePreviewProps) {
  const [failed, setFailed] = useState(false);
  const [resolvedSrc, setResolvedSrc] = useState<string | null>(request.url);
  const hasHeaders = Boolean(request.headers && Object.keys(request.headers).length > 0);
  const headerSignature = JSON.stringify(
    Object.entries(request.headers ?? {}).sort(([left], [right]) => left.localeCompare(right))
  );

  useEffect(() => {
    setFailed(false);

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
  }, [hasHeaders, headerSignature, request.url]);

  if (failed) {
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
      onError={() => setFailed(true)}
      style={{
        width: "100%",
        height: "100%",
        objectFit: fit,
        background: "var(--mantine-color-gray-0)"
      }}
    />
  );
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
