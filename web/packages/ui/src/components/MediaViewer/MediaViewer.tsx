import {
  Badge,
  Button,
  Center,
  Group,
  Loader,
  Modal,
  Stack,
  Text,
  ThemeIcon
} from "@mantine/core";
import {
  IconChevronLeft,
  IconChevronRight,
  IconMapPin,
  IconPhoto,
  IconPlayerPlay,
  IconVideo
} from "@tabler/icons-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type PointerEvent as ReactPointerEvent,
  type ReactNode
} from "react";

export type MediaPreviewRequest = {
  url: string;
  headers?: Record<string, string>;
};

export type MediaPreviewRequests = {
  thumbnail?: MediaPreviewRequest | null;
  original: MediaPreviewRequest;
};

export type MediaKind = "image" | "video";

export type MediaMissingThumbnailInfo = {
  title: string;
  detail: string;
  color: string;
};

export type MediaLightboxItem = {
  key: string;
  title: string;
  description: string;
  alt: string;
  kind: MediaKind;
  requests: MediaPreviewRequests;
  missingThumbnailInfo?: MediaMissingThumbnailInfo | null;
  status?: string | null;
  mimeType?: string | null;
  width?: number | null;
  height?: number | null;
  takenAtUnix?: number | null;
  gps?: { latitude: number; longitude: number } | null;
};

type MediaLightboxModalProps = {
  opened: boolean;
  onClose: () => void;
  itemCount: number;
  selectedIndex: number;
  selectedItem: MediaLightboxItem | null;
  getItemAtIndex: (index: number) => MediaLightboxItem | null;
  onSelectIndex: (index: number) => void | Promise<void>;
  extraActions?: ReactNode;
  renderDetails?: (item: MediaLightboxItem) => ReactNode;
};

type MediaThumbnailPreviewProps = {
  kind: MediaKind;
  request: MediaPreviewRequest | null;
  alt: string;
  missingThumbnailInfo?: MediaMissingThumbnailInfo | null;
};

const imageExtensions = [".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"];
const videoExtensions = [".m4v", ".mkv", ".mov", ".mp4", ".ogv", ".webm"];
const browserInlineImageMimeTypes = new Set([
  "image/avif",
  "image/bmp",
  "image/gif",
  "image/jpeg",
  "image/png",
  "image/svg+xml",
  "image/webp"
]);
const browserInlineImageExtensions = [".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"];
const browserUnsupportedInlineImageMimeTypes = new Set([
  "image/heic",
  "image/heic-sequence",
  "image/heif",
  "image/heif-sequence",
  "image/tiff",
  "image/x-tiff"
]);
const browserUnsupportedInlineImageExtensions = [".heic", ".heif", ".tif", ".tiff"];
const LIGHTBOX_STRIP_RADIUS = 3;
const MEDIA_IMAGE_ZOOM_MIN_SCALE = 1;
const MEDIA_IMAGE_ZOOM_MAX_SCALE = 6;
const MEDIA_IMAGE_WHEEL_ZOOM_SENSITIVITY = 0.0018;

type MediaSourceDimensions = {
  width: number;
  height: number;
};

type MediaLightboxZoomState = {
  scale: number;
  offsetX: number;
  offsetY: number;
};

type MediaLightboxPointerDragState = {
  pointerId: number;
  startClientX: number;
  startClientY: number;
  startOffsetX: number;
  startOffsetY: number;
};

type MediaLightboxWheelLikeEvent = {
  ctrlKey: boolean;
  deltaY: number;
  clientX: number;
  clientY: number;
  preventDefault: () => void;
  stopPropagation: () => void;
};

export function MediaLightboxModal({
  opened,
  onClose,
  itemCount,
  selectedIndex,
  selectedItem,
  getItemAtIndex,
  onSelectIndex,
  extraActions,
  renderDetails
}: MediaLightboxModalProps) {
  const [isSlideshowMode, setIsSlideshowMode] = useState(false);
  const canNavigatePrevious = selectedIndex > 0;
  const canNavigateNext = selectedIndex >= 0 && selectedIndex < itemCount - 1;
  const selectedItemPreviewSignature = selectedItem
    ? mediaPreviewRequestSignature(selectedItem.requests.original)
    : "";
  const stripIndexes = useMemo(
    () => buildLightboxStripIndexes(selectedIndex, itemCount, LIGHTBOX_STRIP_RADIUS),
    [itemCount, selectedIndex]
  );

  useEffect(() => {
    if (!opened) {
      setIsSlideshowMode(false);
    }
  }, [opened]);

  useEffect(() => {
    if (!opened || selectedIndex < 0) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (isTextInputTarget(event.target)) {
        return;
      }

      if (event.key === "Escape" && isSlideshowMode) {
        event.preventDefault();
        setIsSlideshowMode(false);
        return;
      }

      if (event.key === "ArrowLeft" && canNavigatePrevious) {
        event.preventDefault();
        void onSelectIndex(selectedIndex - 1);
      }

      if (event.key === "ArrowRight" && canNavigateNext) {
        event.preventDefault();
        void onSelectIndex(selectedIndex + 1);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [
    canNavigateNext,
    canNavigatePrevious,
    isSlideshowMode,
    onSelectIndex,
    opened,
    selectedIndex
  ]);

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={
        isSlideshowMode
          ? null
          : selectedItem
            ? `${selectedItem.title} (${selectedIndex + 1} of ${itemCount})`
            : "Media preview"
      }
      withCloseButton={!isSlideshowMode}
      closeOnEscape={!isSlideshowMode}
      fullScreen
      styles={{
        content: {
          background: isSlideshowMode ? "var(--mantine-color-dark-9)" : undefined
        },
        header: {
          display: isSlideshowMode ? "none" : undefined
        },
        body: {
          padding: isSlideshowMode ? 0 : undefined,
          paddingTop: 0
        }
      }}
    >
      {selectedItem ? (
        <Stack gap={isSlideshowMode ? 0 : "md"}>
          <div
            style={{
              height: isSlideshowMode ? "100dvh" : "calc(100vh - 21rem)",
              minHeight: isSlideshowMode ? undefined : "20rem"
            }}
          >
            {selectedItem.kind === "video" ? (
              <MediaLightboxVideo
                key={`video:${selectedItem.key}:${selectedItemPreviewSignature}`}
                item={selectedItem}
                mediaOnly={isSlideshowMode}
                canNavigatePrevious={canNavigatePrevious}
                canNavigateNext={canNavigateNext}
                onNavigatePrevious={() => void onSelectIndex(selectedIndex - 1)}
                onNavigateNext={() => void onSelectIndex(selectedIndex + 1)}
              />
            ) : (
              <MediaLightboxImage
                key={`image:${selectedItem.key}:${selectedItemPreviewSignature}`}
                item={selectedItem}
                mediaOnly={isSlideshowMode}
                canNavigatePrevious={canNavigatePrevious}
                canNavigateNext={canNavigateNext}
                onNavigatePrevious={() => void onSelectIndex(selectedIndex - 1)}
                onNavigateNext={() => void onSelectIndex(selectedIndex + 1)}
              />
            )}
          </div>
          {!isSlideshowMode ? (
            <>
              {itemCount > 1 ? (
                <MediaLightboxThumbnailStrip
                  selectedIndex={selectedIndex}
                  selectedItem={selectedItem}
                  indexes={stripIndexes}
                  getItemAtIndex={getItemAtIndex}
                  onSelectIndex={onSelectIndex}
                />
              ) : null}
              <Group justify="space-between" align="center" gap="sm">
                <Group gap="xs">
                  <Badge variant="light">
                    {selectedIndex + 1} / {itemCount}
                  </Badge>
                  <Badge color={selectedItem.kind === "video" ? "violet" : "blue"} variant="light">
                    {selectedItem.kind === "video" ? "movie" : "photo"}
                  </Badge>
                  {selectedItem.status?.trim() ? (
                    <Badge color={mediaStatusColor(selectedItem.status)} variant="light">
                      {selectedItem.status.trim()}
                    </Badge>
                  ) : null}
                  {selectedItem.mimeType?.trim() ? (
                    <Badge variant="light">{selectedItem.mimeType.trim()}</Badge>
                  ) : null}
                  {selectedItem.width && selectedItem.height ? (
                    <Badge variant="light">
                      {selectedItem.width} x {selectedItem.height}
                    </Badge>
                  ) : null}
                  {selectedItem.gps ? (
                    <Badge
                      variant="light"
                      color="green"
                      leftSection={<IconMapPin size={12} />}
                    >
                      {selectedItem.gps.latitude.toFixed(5)}, {selectedItem.gps.longitude.toFixed(5)}
                    </Badge>
                  ) : null}
                </Group>
                <Group gap="xs" wrap="nowrap">
                  {extraActions}
                  <Button
                    variant="default"
                    size="xs"
                    leftSection={<IconPlayerPlay size={14} />}
                    onClick={() => setIsSlideshowMode(true)}
                  >
                    Start slideshow
                  </Button>
                </Group>
              </Group>
              <Text size="sm" c="dimmed">
                {selectedItem.description}
              </Text>
              {selectedItem.takenAtUnix ? (
                <Text size="sm">Captured {formatTakenAt(selectedItem.takenAtUnix)}</Text>
              ) : null}
              {renderDetails ? renderDetails(selectedItem) : null}
            </>
          ) : null}
        </Stack>
      ) : null}
    </Modal>
  );
}

export function MediaThumbnailPreview({
  kind,
  request,
  alt,
  missingThumbnailInfo
}: MediaThumbnailPreviewProps) {
  if (!request) {
    return <MediaThumbnailPlaceholder kind={kind} info={missingThumbnailInfo} compact />;
  }

  if (kind === "video") {
    return (
      <div style={{ position: "relative", width: "100%", height: "100%" }}>
        <MediaImagePreview request={request} alt={alt} fit="cover" />
        <div
          style={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "linear-gradient(180deg, rgba(0, 0, 0, 0.02), rgba(0, 0, 0, 0.34))",
            pointerEvents: "none"
          }}
        >
          <ThemeIcon size={44} radius="xl" color="dark" variant="filled">
            <IconPlayerPlay size={22} />
          </ThemeIcon>
        </div>
      </div>
    );
  }

  return <MediaImagePreview request={request} alt={alt} fit="cover" />;
}

export function useResolvedMediaPreviewRequest(
  request: MediaPreviewRequest | null | undefined
): { resolvedSrc: string | null; failed: boolean } {
  const [failed, setFailed] = useState(false);
  const [resolvedSrc, setResolvedSrc] = useState<string | null>(request?.url ?? null);
  const hasHeaders = Boolean(request?.headers && Object.keys(request.headers).length > 0);
  const signature = mediaPreviewRequestSignature(request);

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

export function mediaPreviewRequestSignature(
  request: MediaPreviewRequest | null | undefined
): string {
  if (!request) {
    return "";
  }

  const headers = JSON.stringify(
    Object.entries(request.headers ?? {}).sort(([left], [right]) => left.localeCompare(right))
  );
  return `${request.url}::${headers}`;
}

export function resolveMediaKind(
  path: string,
  mediaType?: string | null,
  mimeType?: string | null
): MediaKind | null {
  if (mimeType?.startsWith("image/")) {
    return "image";
  }

  if (mimeType?.startsWith("video/")) {
    return "video";
  }

  if (mediaType === "image") {
    return "image";
  }

  if (mediaType === "video") {
    return "video";
  }

  const lowerPath = path.toLowerCase();
  if (imageExtensions.some((extension) => lowerPath.endsWith(extension))) {
    return "image";
  }
  if (videoExtensions.some((extension) => lowerPath.endsWith(extension))) {
    return "video";
  }

  return null;
}

function isBrowserInlineImagePreviewUnsupported(
  path: string,
  mimeType?: string | null
): boolean {
  const normalizedMimeType = mimeType?.trim().toLowerCase() ?? "";
  if (normalizedMimeType) {
    if (browserInlineImageMimeTypes.has(normalizedMimeType)) {
      return false;
    }
    if (browserUnsupportedInlineImageMimeTypes.has(normalizedMimeType)) {
      return true;
    }
  }

  const lowerPath = path.toLowerCase();
  if (browserInlineImageExtensions.some((extension) => lowerPath.endsWith(extension))) {
    return false;
  }
  if (browserUnsupportedInlineImageExtensions.some((extension) => lowerPath.endsWith(extension))) {
    return true;
  }

  return false;
}

export function defaultMediaMissingThumbnailInfo(kind: MediaKind): MediaMissingThumbnailInfo {
  return kind === "video"
    ? {
        title: "Poster thumbnail unavailable",
        detail: "This movie does not have an indexed poster thumbnail to display.",
        color: "gray"
      }
    : {
        title: "Thumbnail unavailable",
        detail: "This item does not have an indexed thumbnail to display.",
        color: "gray"
      };
}

export function mediaStatusColor(status?: string | null): string {
  if (status === "ready") {
    return "green";
  }
  if (status === "pending") {
    return "yellow";
  }
  if (status === "incomplete") {
    return "orange";
  }
  if (status === "failed") {
    return "red";
  }
  return "gray";
}

type MediaLightboxImageProps = {
  item: MediaLightboxItem;
  mediaOnly: boolean;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
};

function MediaLightboxImage({
  item,
  mediaOnly,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext
}: MediaLightboxImageProps) {
  const thumbnailRequest = item.requests.thumbnail ?? null;
  const thumbnail = useResolvedMediaPreviewRequest(thumbnailRequest);
  const originalRequest = item.requests.original;
  const originalPreviewUnsupported = isBrowserInlineImagePreviewUnsupported(
    item.description || item.alt,
    item.mimeType
  );
  const original = useResolvedMediaPreviewRequest(originalRequest);
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const [originalFailed, setOriginalFailed] = useState(false);
  const [originalLoaded, setOriginalLoaded] = useState(false);
  const [sourceDimensions, setSourceDimensions] = useState<MediaSourceDimensions | null>(() =>
    resolveMediaSourceDimensions(item.width, item.height)
  );
  const [zoomState, setZoomState] = useState<MediaLightboxZoomState>({
    scale: MEDIA_IMAGE_ZOOM_MIN_SCALE,
    offsetX: 0,
    offsetY: 0
  });
  const [isDragging, setIsDragging] = useState(false);
  const thumbnailSignature = mediaPreviewRequestSignature(thumbnailRequest);
  const originalSignature = mediaPreviewRequestSignature(originalRequest);
  const interactiveRef = useRef<HTMLDivElement | null>(null);
  const pointerDragRef = useRef<MediaLightboxPointerDragState | null>(null);

  useEffect(() => {
    setThumbnailFailed(false);
  }, [thumbnailSignature]);

  useEffect(() => {
    setOriginalFailed(false);
    setOriginalLoaded(false);
    setSourceDimensions(resolveMediaSourceDimensions(item.width, item.height));
    setZoomState({
      scale: MEDIA_IMAGE_ZOOM_MIN_SCALE,
      offsetX: 0,
      offsetY: 0
    });
    setIsDragging(false);
    pointerDragRef.current = null;
  }, [originalSignature]);

  const thumbnailVisible = Boolean(thumbnail.resolvedSrc) && !thumbnail.failed && !thumbnailFailed;
  const originalVisible =
    !originalPreviewUnsupported &&
    Boolean(original.resolvedSrc) &&
    !original.failed &&
    !originalFailed;
  const fullImageUnavailable = !originalPreviewUnsupported && (original.failed || originalFailed);
  const originalPending = !originalPreviewUnsupported && !fullImageUnavailable && !originalLoaded;
  const thumbnailLoadFailed = Boolean(thumbnailRequest) && (thumbnail.failed || thumbnailFailed);
  const thumbnailNotice = thumbnailLoadFailed
    ? {
        title: "Indexed thumbnail failed to load",
        detail: "The UI has a thumbnail URL for this item, but fetching it failed.",
        color: "yellow"
      }
    : item.missingThumbnailInfo;
  const inlineFallbackNotice = originalPreviewUnsupported
    ? thumbnailVisible
      ? "Browser cannot preview the original format, showing thumbnail"
      : "Browser cannot preview the original image format"
    : null;
  const imageTransform = `translate(${zoomState.offsetX}px, ${zoomState.offsetY}px) scale(${zoomState.scale})`;

  function measureZoomMetrics() {
    const container = interactiveRef.current;
    if (!container) {
      return null;
    }

    const rect = container.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) {
      return null;
    }

    const resolvedSourceWidth = sourceDimensions?.width ?? item.width ?? rect.width;
    const resolvedSourceHeight = sourceDimensions?.height ?? item.height ?? rect.height;
    const containedSize = resolveContainedMediaSize(
      rect.width,
      rect.height,
      resolvedSourceWidth,
      resolvedSourceHeight
    );

    return { rect, containedSize };
  }

  function clampZoomTransform(scale: number, offsetX: number, offsetY: number) {
    if (scale <= MEDIA_IMAGE_ZOOM_MIN_SCALE) {
      return {
        scale: MEDIA_IMAGE_ZOOM_MIN_SCALE,
        offsetX: 0,
        offsetY: 0
      };
    }

    const metrics = measureZoomMetrics();
    if (!metrics) {
      return { scale, offsetX, offsetY };
    }

    const maxOffsetX = Math.max(
      0,
      (metrics.containedSize.width * scale - metrics.rect.width) / 2
    );
    const maxOffsetY = Math.max(
      0,
      (metrics.containedSize.height * scale - metrics.rect.height) / 2
    );

    return {
      scale,
      offsetX: clamp(offsetX, -maxOffsetX, maxOffsetX),
      offsetY: clamp(offsetY, -maxOffsetY, maxOffsetY)
    };
  }

  function updateSourceDimensions(width: number, height: number) {
    if (width <= 0 || height <= 0) {
      return;
    }

    setSourceDimensions((current) => {
      if (current?.width === width && current.height === height) {
        return current;
      }
      return { width, height };
    });
  }

  function handleZoomWheel(event: MediaLightboxWheelLikeEvent) {
    if (!event.ctrlKey) {
      return;
    }

    const metrics = measureZoomMetrics();
    if (!metrics) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();

    const currentScale = zoomState.scale;
    const nextScale = clamp(
      currentScale * Math.exp(-event.deltaY * MEDIA_IMAGE_WHEEL_ZOOM_SENSITIVITY),
      MEDIA_IMAGE_ZOOM_MIN_SCALE,
      MEDIA_IMAGE_ZOOM_MAX_SCALE
    );

    if (Math.abs(nextScale - currentScale) < 0.001) {
      return;
    }

    const pointX = event.clientX - metrics.rect.left - metrics.rect.width / 2;
    const pointY = event.clientY - metrics.rect.top - metrics.rect.height / 2;
    const scaleRatio = nextScale / currentScale;
    const nextOffsetX = pointX - (pointX - zoomState.offsetX) * scaleRatio;
    const nextOffsetY = pointY - (pointY - zoomState.offsetY) * scaleRatio;

    setZoomState(clampZoomTransform(nextScale, nextOffsetX, nextOffsetY));
  }

  useEffect(() => {
    const interactive = interactiveRef.current;
    if (!interactive) {
      return;
    }

    function handleNativeWheel(event: WheelEvent) {
      handleZoomWheel(event);
    }

    interactive.addEventListener("wheel", handleNativeWheel, { passive: false });
    return () => interactive.removeEventListener("wheel", handleNativeWheel);
  }, [handleZoomWheel]);

  function handlePointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.pointerType !== "mouse" || event.button !== 0 || zoomState.scale <= 1) {
      return;
    }

    pointerDragRef.current = {
      pointerId: event.pointerId,
      startClientX: event.clientX,
      startClientY: event.clientY,
      startOffsetX: zoomState.offsetX,
      startOffsetY: zoomState.offsetY
    };
    setIsDragging(true);
    event.currentTarget.setPointerCapture(event.pointerId);
    event.preventDefault();
  }

  function handlePointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const pointerDrag = pointerDragRef.current;
    if (!pointerDrag || pointerDrag.pointerId !== event.pointerId) {
      return;
    }

    event.preventDefault();
    setZoomState(
      clampZoomTransform(
        zoomState.scale,
        pointerDrag.startOffsetX + (event.clientX - pointerDrag.startClientX),
        pointerDrag.startOffsetY + (event.clientY - pointerDrag.startClientY)
      )
    );
  }

  function endPointerDrag(target: HTMLDivElement, pointerId: number) {
    const pointerDrag = pointerDragRef.current;
    if (!pointerDrag || pointerDrag.pointerId !== pointerId) {
      return;
    }

    pointerDragRef.current = null;
    setIsDragging(false);
    if (target.hasPointerCapture(pointerId)) {
      target.releasePointerCapture(pointerId);
    }
  }

  return (
    <MediaLightboxFrame
      showNavigationControls={!mediaOnly}
      canNavigatePrevious={canNavigatePrevious}
      canNavigateNext={canNavigateNext}
      onNavigatePrevious={onNavigatePrevious}
      onNavigateNext={onNavigateNext}
    >
      <div
        ref={interactiveRef}
        data-media-zoom-surface="true"
        data-media-zoom-scale={zoomState.scale.toFixed(2)}
        title="Hold Ctrl and scroll to zoom this image"
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={(event) => endPointerDrag(event.currentTarget, event.pointerId)}
        onPointerCancel={(event) => endPointerDrag(event.currentTarget, event.pointerId)}
        style={{
          position: "absolute",
          inset: 0,
          overflow: "hidden",
          userSelect: "none",
          cursor:
            zoomState.scale > MEDIA_IMAGE_ZOOM_MIN_SCALE
              ? isDragging
                ? "grabbing"
                : "grab"
              : "zoom-in"
        }}
      >
        {thumbnailVisible ? (
          <img
            key={thumbnailSignature}
            src={thumbnail.resolvedSrc ?? undefined}
            alt={item.alt}
            loading="eager"
            decoding="async"
            draggable={false}
            onLoad={(event) =>
              updateSourceDimensions(
                event.currentTarget.naturalWidth,
                event.currentTarget.naturalHeight
              )
            }
            onError={() => setThumbnailFailed(true)}
            style={{
              position: "absolute",
              inset: 0,
              width: "100%",
              height: "100%",
              objectFit: "contain",
              filter: originalPending ? "none" : "blur(0px)",
              background: "var(--mantine-color-dark-9)",
              transform: imageTransform,
              transformOrigin: "center center"
            }}
          />
        ) : (
          <div
            style={{
              position: "absolute",
              inset: 0,
              transform: imageTransform,
              transformOrigin: "center center"
            }}
          >
            <MediaThumbnailPlaceholder
              kind="image"
              info={thumbnailNotice}
              showLoader={originalPending && !originalVisible}
              fullHeight
            />
          </div>
        )}

        {originalVisible ? (
          <img
            key={originalSignature}
            src={original.resolvedSrc ?? undefined}
            alt={item.alt}
            loading="eager"
            decoding="async"
            draggable={false}
            onLoad={(event) => {
              setOriginalLoaded(true);
              updateSourceDimensions(
                event.currentTarget.naturalWidth,
                event.currentTarget.naturalHeight
              );
            }}
            onError={() => setOriginalFailed(true)}
            style={{
              position: "absolute",
              inset: 0,
              width: "100%",
              height: "100%",
              objectFit: "contain",
              opacity: originalLoaded ? 1 : 0,
              transition: "opacity 180ms ease",
              background: "transparent",
              transform: imageTransform,
              transformOrigin: "center center"
            }}
          />
        ) : null}
      </div>

      {originalPending ? (
        <div
          style={{
            position: "absolute",
            top: 16,
            right: 16
          }}
        >
          <Badge color="dark" variant="filled">
            Loading original image
          </Badge>
        </div>
      ) : null}

      {fullImageUnavailable || inlineFallbackNotice ? (
        <div
          style={{
            position: "absolute",
            left: 16,
            bottom: 16
          }}
        >
          <Badge color={fullImageUnavailable ? "yellow" : "gray"} variant="filled">
            {fullImageUnavailable
              ? "Full image unavailable, showing thumbnail"
              : inlineFallbackNotice}
          </Badge>
        </div>
      ) : null}
    </MediaLightboxFrame>
  );
}

type MediaLightboxVideoProps = {
  item: MediaLightboxItem;
  mediaOnly: boolean;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
};

function MediaLightboxVideo({
  item,
  mediaOnly,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext
}: MediaLightboxVideoProps) {
  const video = useResolvedMediaPreviewRequest(item.requests.original);
  const poster = useResolvedMediaPreviewRequest(item.requests.thumbnail ?? null);

  return (
    <MediaLightboxFrame
      showNavigationControls={!mediaOnly}
      canNavigatePrevious={canNavigatePrevious}
      canNavigateNext={canNavigateNext}
      onNavigatePrevious={onNavigatePrevious}
      onNavigateNext={onNavigateNext}
      navigationPlacement="below"
    >
      {video.resolvedSrc ? (
        <video
          key={mediaPreviewRequestSignature(item.requests.original)}
          src={video.resolvedSrc}
          poster={poster.resolvedSrc ?? undefined}
          controls
          playsInline
          preload="metadata"
          aria-label={item.alt}
          style={{
            width: "100%",
            height: "100%",
            objectFit: "contain",
            background: "var(--mantine-color-dark-9)"
          }}
        />
      ) : (
        <Center
          style={{
            position: "absolute",
            inset: 0,
            background: "var(--mantine-color-dark-9)"
          }}
        >
          {video.failed ? (
            <Badge color="yellow" variant="filled">
              Movie unavailable
            </Badge>
          ) : (
            <Loader size="sm" color="gray" />
          )}
        </Center>
      )}
    </MediaLightboxFrame>
  );
}

type MediaLightboxFrameProps = {
  children: ReactNode;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
  navigationPlacement?: "overlay" | "below";
  showNavigationControls?: boolean;
};

function MediaLightboxFrame({
  children,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext,
  navigationPlacement = "overlay",
  showNavigationControls = true
}: MediaLightboxFrameProps) {
  const [touchStart, setTouchStart] = useState<{ x: number; y: number } | null>(null);
  const useFooterNavigation = navigationPlacement === "below" && showNavigationControls;

  return (
    <div
      style={{
        width: "100%",
        height: "100%",
        display: "flex",
        flexDirection: "column",
        gap: useFooterNavigation ? "0.75rem" : 0
      }}
    >
      <div
        style={{
          position: "relative",
          flex: 1,
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
        {children}
        {showNavigationControls && !useFooterNavigation ? (
          <>
            <MediaLightboxEdgeButton
              direction="previous"
              enabled={canNavigatePrevious}
              onClick={onNavigatePrevious}
            />
            <MediaLightboxEdgeButton
              direction="next"
              enabled={canNavigateNext}
              onClick={onNavigateNext}
            />
          </>
        ) : null}
      </div>
      {useFooterNavigation ? (
        <Group grow wrap="nowrap">
          <Button
            variant="default"
            leftSection={<IconChevronLeft size={16} />}
            disabled={!canNavigatePrevious}
            onClick={onNavigatePrevious}
          >
            Previous item
          </Button>
          <Button
            variant="default"
            rightSection={<IconChevronRight size={16} />}
            disabled={!canNavigateNext}
            onClick={onNavigateNext}
          >
            Next item
          </Button>
        </Group>
      ) : null}
    </div>
  );
}

type MediaLightboxThumbnailStripProps = {
  indexes: number[];
  selectedIndex: number;
  selectedItem: MediaLightboxItem;
  getItemAtIndex: (index: number) => MediaLightboxItem | null;
  onSelectIndex: (index: number) => void | Promise<void>;
};

function MediaLightboxThumbnailStrip({
  indexes,
  selectedIndex,
  selectedItem,
  getItemAtIndex,
  onSelectIndex
}: MediaLightboxThumbnailStripProps) {
  return (
    <div
      aria-label="Media viewer thumbnails"
      style={{
        display: "flex",
        gap: 12,
        overflowX: "auto",
        paddingBottom: 4
      }}
    >
      {indexes.map((index) => {
        const item = index === selectedIndex ? selectedItem : getItemAtIndex(index);
        const selected = index === selectedIndex;

        return (
          <button
            key={`media-strip:${index}`}
            type="button"
            aria-label={item ? item.alt : `Show item ${index + 1}`}
            aria-current={selected ? "true" : undefined}
            onClick={() => void onSelectIndex(index)}
            style={{
              flex: "0 0 auto",
              width: 108,
              borderRadius: 10,
              border: selected
                ? "2px solid var(--mantine-color-blue-6)"
                : "1px solid var(--mantine-color-gray-3)",
              background: selected
                ? "var(--mantine-color-blue-0)"
                : "var(--mantine-color-body)",
              padding: 6,
              cursor: selected ? "default" : "pointer"
            }}
          >
            <div
              style={{
                width: "100%",
                height: 64,
                borderRadius: 8,
                overflow: "hidden",
                background: "var(--mantine-color-gray-0)",
                marginBottom: 6
              }}
            >
              {item ? (
                <MediaThumbnailPreview
                  kind={item.kind}
                  request={item.requests.thumbnail ?? null}
                  alt={item.alt}
                  missingThumbnailInfo={item.missingThumbnailInfo}
                />
              ) : (
                <Center style={{ width: "100%", height: "100%" }}>
                  <Loader size="sm" color="gray" />
                </Center>
              )}
            </div>
            <Text size="xs" fw={selected ? 700 : 500} lineClamp={1} ta="left">
              {item?.title ?? `Item ${index + 1}`}
            </Text>
            <Text size="xs" c="dimmed" lineClamp={1} ta="left">
              {item?.description ?? "Loading"}
            </Text>
          </button>
        );
      })}
    </div>
  );
}

type MediaLightboxEdgeButtonProps = {
  direction: "previous" | "next";
  enabled: boolean;
  onClick: () => void;
};

function MediaLightboxEdgeButton({
  direction,
  enabled,
  onClick
}: MediaLightboxEdgeButtonProps) {
  const isPrevious = direction === "previous";

  return (
    <button
      type="button"
      aria-label={isPrevious ? "Previous item" : "Next item"}
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

type MediaImagePreviewProps = {
  request: MediaPreviewRequest;
  alt: string;
  fit: "contain" | "cover";
};

function MediaImagePreview({ request, alt, fit }: MediaImagePreviewProps) {
  const [imageFailed, setImageFailed] = useState(false);
  const { resolvedSrc, failed: requestFailed } = useResolvedMediaPreviewRequest(request);
  const signature = mediaPreviewRequestSignature(request);

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
        display: "block",
        width: "100%",
        height: "100%",
        objectFit: fit,
        background: "var(--mantine-color-gray-0)"
      }}
    />
  );
}

type MediaThumbnailPlaceholderProps = {
  kind: MediaKind;
  info?: MediaMissingThumbnailInfo | null;
  showLoader?: boolean;
  fullHeight?: boolean;
  compact?: boolean;
};

function MediaThumbnailPlaceholder({
  kind,
  info,
  showLoader = false,
  fullHeight = true,
  compact = false
}: MediaThumbnailPlaceholderProps) {
  const resolvedInfo = info ?? defaultMediaMissingThumbnailInfo(kind);
  const icon = kind === "video" ? <IconVideo size={compact ? 18 : 24} /> : <IconPhoto size={compact ? 18 : 24} />;

  return (
    <Center
      style={{
        width: "100%",
        height: fullHeight ? "100%" : undefined,
        minHeight: fullHeight ? undefined : 0,
        background:
          kind === "video"
            ? "linear-gradient(180deg, rgba(30, 41, 59, 1) 0%, rgba(15, 23, 42, 1) 100%)"
            : "var(--mantine-color-gray-0)",
        padding: compact ? "0.5rem" : "1rem"
      }}
    >
      <Stack align="center" gap={compact ? 4 : 6} maw="90%">
        {showLoader ? <Loader size="sm" color="gray" /> : icon}
        <Text
          size={compact ? "xs" : "sm"}
          fw={600}
          ta="center"
          c={kind === "video" ? "gray.2" : "dark"}
          lineClamp={compact ? 1 : 2}
        >
          {resolvedInfo.title}
        </Text>
        {!compact ? (
          <Text
            size="xs"
            ta="center"
            c={kind === "video" ? "gray.4" : "dimmed"}
            lineClamp={4}
          >
            {resolvedInfo.detail}
          </Text>
        ) : null}
      </Stack>
    </Center>
  );
}

function buildLightboxStripIndexes(centerIndex: number, totalCount: number, radius: number): number[] {
  if (centerIndex < 0 || totalCount <= 0) {
    return [];
  }

  const start = Math.max(0, centerIndex - radius);
  const end = Math.min(totalCount - 1, centerIndex + radius);
  const indexes: number[] = [];
  for (let index = start; index <= end; index += 1) {
    indexes.push(index);
  }
  return indexes;
}

function formatTakenAt(value: number): string {
  return new Date(value * 1000).toLocaleString();
}

function resolveMediaSourceDimensions(
  width?: number | null,
  height?: number | null
): MediaSourceDimensions | null {
  if (!width || !height || width <= 0 || height <= 0) {
    return null;
  }

  return { width, height };
}

function resolveContainedMediaSize(
  containerWidth: number,
  containerHeight: number,
  sourceWidth: number,
  sourceHeight: number
) {
  if (
    containerWidth <= 0 ||
    containerHeight <= 0 ||
    sourceWidth <= 0 ||
    sourceHeight <= 0
  ) {
    return { width: containerWidth, height: containerHeight };
  }

  const widthRatio = containerWidth / sourceWidth;
  const heightRatio = containerHeight / sourceHeight;
  const scale = Math.min(widthRatio, heightRatio);

  return {
    width: sourceWidth * scale,
    height: sourceHeight * scale
  };
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(value, minimum), maximum);
}

function isTextInputTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  const tagName = target.tagName;
  if (tagName === "INPUT" || tagName === "TEXTAREA" || tagName === "SELECT") {
    return true;
  }

  return target.isContentEditable;
}
