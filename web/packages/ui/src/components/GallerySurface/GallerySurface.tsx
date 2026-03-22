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
import { IconChevronLeft, IconChevronRight, IconRefresh } from "@tabler/icons-react";
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

export type GalleryImageRequests = {
  thumbnail: GalleryPreviewRequest;
  original?: GalleryPreviewRequest | null;
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
  const [thumbnailsPerRow, setThumbnailsPerRow] = useState(3);
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

  const imageEntries = sortGalleryEntries(
    (entriesPayload?.entries ?? []).filter(isGalleryImageEntry),
    sortOrder
  );
  const readyCount = imageEntries.filter((entry) => entry.media?.status === "ready").length;
  const pendingCount = imageEntries.filter((entry) => entry.media?.status === "pending").length;
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
                  const parsed = Number(value);
                  setThumbnailsPerRow(
                    Number.isFinite(parsed) && parsed >= 1 && parsed <= 6 ? parsed : 3
                  );
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
            <SimpleGrid
              cols={{
                base: 1,
                sm: Math.min(thumbnailsPerRow, 2),
                md: Math.min(thumbnailsPerRow, 3),
                lg: thumbnailsPerRow
              }}
            >
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
