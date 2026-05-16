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
  Switch,
  Text,
  TextInput,
  ThemeIcon
} from "@mantine/core";
import { useElementSize } from "@mantine/hooks";
import {
  IconArrowUp,
  IconChevronLeft,
  IconChevronRight,
  IconFolder,
  IconLayoutGrid,
  IconMap2,
  IconMapPin,
  IconPlayerPlay,
  IconRefresh
} from "@tabler/icons-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  GalleryBasemapMap,
  type GalleryBasemapConfig,
  type GalleryMapProjection
} from "./GalleryBasemapMap";
import { JsonBlock } from "../JsonBlock/JsonBlock";
import {
  directChildStorePrefix,
  normalizeStorePrefix,
  parentStorePrefix,
  storeEntryName
} from "../store-paths";

export type { GalleryBasemapConfig } from "./GalleryBasemapMap";

type GallerySortOrder = "captured_desc" | "path_asc";
type GalleryMediaKind = "image" | "video";
type GalleryMediaFilter = "all" | GalleryMediaKind;
type GalleryViewMode = "grid" | "map";

const imageExtensions = [".avif", ".bmp", ".gif", ".jpeg", ".jpg", ".png", ".webp"];
const videoExtensions = [".m4v", ".mkv", ".mov", ".mp4", ".ogv", ".webm"];
const GALLERY_THUMBNAILS_PER_ROW_STORAGE_KEY = "ironmesh.gallery.thumbnails_per_row";
const GALLERY_SHOW_METADATA_STORAGE_KEY = "ironmesh.gallery.show_metadata";
const GALLERY_VIEW_MODE_STORAGE_KEY = "ironmesh.gallery.view_mode";
const GALLERY_BASEMAP_ID_STORAGE_KEY = "ironmesh.gallery.basemap_id";
const GALLERY_MAP_PROJECTION_STORAGE_KEY = "ironmesh.gallery.map_projection";
const GALLERY_MAP_FULLSCREEN_HISTORY_KEY = "ironmesh.gallery.map_fullscreen";
const MAX_WORLD_MAP_THUMBNAIL_MARKERS = 120;
const GALLERY_VIRTUAL_PAGE_ROW_COUNT = 8;
const GALLERY_VIRTUAL_PAGE_PRELOAD_RADIUS = 1;
const GALLERY_VIRTUAL_PAGE_KEEP_RADIUS = 2;
const GALLERY_VIRTUAL_PAGE_ROOT_MARGIN = "900px 0px";

const EMPTY_GALLERY_MEDIA_SUMMARY: GalleryMediaSummary = {
  ready_count: 0,
  pending_count: 0,
  incomplete_count: 0,
  image_count: 0,
  video_count: 0,
  geotagged_count: 0
};

export type GallerySnapshot = {
  id: string;
  [key: string]: unknown;
};

export type GalleryEntry = {
  path: string;
  entry_type: string;
  version?: string | null;
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
  total_entry_count?: number;
  offset?: number;
  limit?: number | null;
  has_more?: boolean;
  media_summary?: GalleryMediaSummary | null;
  entries: GalleryEntry[];
  [key: string]: unknown;
};

export type GalleryMediaSummary = {
  ready_count: number;
  pending_count: number;
  incomplete_count: number;
  image_count: number;
  video_count: number;
  geotagged_count: number;
};

export type GalleryPreviewRequest = {
  url: string;
  headers?: Record<string, string>;
};

export type GalleryMediaRequests = {
  thumbnail?: GalleryPreviewRequest | null;
  original: GalleryPreviewRequest;
};

type GalleryMissingThumbnailInfo = {
  title: string;
  detail: string;
  color: string;
};

type GalleryNavigationItem = {
  key: string;
  kind: "up" | "prefix";
  label: string;
  description: string;
  targetPrefix: string;
};

export type GalleryLoadEntriesOptions = {
  view?: "raw" | "tree";
  offset?: number;
  limit?: number;
  sort?: GallerySortOrder;
  mediaFilter?: GalleryMediaFilter;
};

type GalleryLoadedScope = {
  prefix: string;
  depth: number;
  snapshotId: string | null;
};

type GallerySelection = {
  source: "grid" | "map";
  index: number;
  path: string;
};

type GalleryGridPageState = {
  status: "loading" | "ready" | "error";
  entries: GalleryEntry[];
  error?: string | null;
};

type GalleryGridCollection = {
  prefix: string;
  depth: number;
  snapshotId: string | null;
  totalEntryCount: number;
  mediaSummary: GalleryMediaSummary;
  pageSize: number;
  pageCount: number;
};

type GallerySurfaceProps = {
  intro?: string;
  previewHint: string;
  basemaps?: GalleryBasemapConfig[] | null;
  allowedMediaKinds?: GalleryMediaKind[];
  loadSnapshots: () => Promise<GallerySnapshot[]>;
  loadEntries: (
    prefix: string,
    depth: number,
    snapshotId: string | null,
    options?: GalleryLoadEntriesOptions
  ) => Promise<GalleryPayload>;
  getMediaRequests: (entry: GalleryEntry, snapshotId: string | null) => GalleryMediaRequests;
  retryMediaEntry?: (
    entry: GalleryEntry,
    snapshotId: string | null
  ) => Promise<GalleryEntry["media"] | null>;
};

export function GallerySurface({
  intro,
  previewHint,
  basemaps,
  allowedMediaKinds,
  loadSnapshots,
  loadEntries,
  getMediaRequests,
  retryMediaEntry
}: GallerySurfaceProps) {
  const [prefix, setPrefix] = useState("");
  const [depth, setDepth] = useState(4);
  const [thumbnailsPerRow, setThumbnailsPerRow] = useState(loadStoredThumbnailsPerRow);
  const [showMetadata, setShowMetadata] = useState(loadStoredShowMetadata);
  const { ref: galleryGridRef, width: galleryGridWidth } = useElementSize();
  const [viewMode, setViewMode] = useState(loadStoredViewMode);
  const [activeBasemapId, setActiveBasemapId] = useState(loadStoredBasemapId);
  const [activeMapProjection, setActiveMapProjection] = useState(loadStoredMapProjection);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<GallerySnapshot[]>([]);
  const [loadedScope, setLoadedScope] = useState<GalleryLoadedScope | null>(null);
  const [navigationPayload, setNavigationPayload] = useState<GalleryPayload | null>(null);
  const [mapPayload, setMapPayload] = useState<GalleryPayload | null>(null);
  const [gridCollection, setGridCollection] = useState<GalleryGridCollection | null>(null);
  const [gridPages, setGridPages] = useState<Record<number, GalleryGridPageState>>({});
  const [gridPageHeights, setGridPageHeights] = useState<Record<number, number>>({});
  const [gridActivePageIndex, setGridActivePageIndex] = useState(0);
  const [selection, setSelection] = useState<GallerySelection | null>(null);
  const [sortOrder, setSortOrder] = useState<GallerySortOrder>("captured_desc");
  const [mediaFilter, setMediaFilter] = useState<GalleryMediaFilter>(
    allowedMediaKinds && allowedMediaKinds.length > 1 ? "all" : allowedMediaKinds?.[0] ?? "image"
  );
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [debugPayloadOpened, setDebugPayloadOpened] = useState(false);
  const [retryingSelectedMedia, setRetryingSelectedMedia] = useState(false);
  const [selectedMediaRetryError, setSelectedMediaRetryError] = useState<string | null>(null);
  const loadedScopeRef = useRef<GalleryLoadedScope | null>(null);
  const gridCollectionRef = useRef<GalleryGridCollection | null>(null);
  const gridPagesRef = useRef<Record<number, GalleryGridPageState>>({});
  const galleryRequestVersionRef = useRef(0);

  useEffect(() => {
    void refreshSnapshots();
  }, [loadSnapshots]);

  useEffect(() => {
    void refreshEntries();
  }, [loadEntries]);

  useEffect(() => {
    loadedScopeRef.current = loadedScope;
  }, [loadedScope]);

  useEffect(() => {
    gridCollectionRef.current = gridCollection;
  }, [gridCollection]);

  useEffect(() => {
    gridPagesRef.current = gridPages;
  }, [gridPages]);

  useEffect(() => {
    persistThumbnailsPerRow(thumbnailsPerRow);
  }, [thumbnailsPerRow]);

  useEffect(() => {
    persistShowMetadata(showMetadata);
  }, [showMetadata]);

  useEffect(() => {
    persistViewMode(viewMode);
  }, [viewMode]);

  useEffect(() => {
    persistMapProjection(activeMapProjection);
  }, [activeMapProjection]);

  const compactGalleryGrid = galleryGridWidth > 0 && galleryGridWidth < 540;
  const galleryGridGap = showMetadata ? (compactGalleryGrid ? 8 : 10) : 0;
  const galleryGridColumns = resolveGalleryGridColumns(
    thumbnailsPerRow,
    galleryGridWidth,
    galleryGridGap,
    showMetadata
  );
  const galleryCardPadding = showMetadata ? (compactGalleryGrid ? 8 : 10) : 0;
  const galleryCardRadius = showMetadata ? (compactGalleryGrid ? "sm" : "md") : 0;
  const galleryCardBorderWidth = showMetadata ? (compactGalleryGrid ? 0.75 : 1) : 0;
  const galleryCardContentGap = compactGalleryGrid ? 4 : 6;
  const galleryNavigationIconSize = compactGalleryGrid ? 46 : 54;
  const galleryNavigationGlyphSize = compactGalleryGrid ? 24 : 28;
  const galleryVirtualPageSize = resolveGalleryVirtualPageSize(galleryGridColumns);
  const enabledMediaKinds: GalleryMediaKind[] = allowedMediaKinds?.length
    ? [...allowedMediaKinds]
    : ["image"];
  const requestedServerMediaFilter = resolveServerGalleryMediaFilter(
    enabledMediaKinds,
    mediaFilter
  );
  const availableBasemaps = basemaps ?? [];
  const activeBasemap =
    availableBasemaps.find((candidate) => candidate.id === activeBasemapId) ??
    availableBasemaps[0] ??
    null;
  const currentGalleryPrefix = normalizeGalleryPrefix(
    navigationPayload?.prefix ?? loadedScope?.prefix ?? prefix
  );
  const navigationItems = buildGalleryNavigationItems(
    navigationPayload?.entries ?? [],
    currentGalleryPrefix
  );
  const mapMediaEntries = mapPayload?.entries ?? [];
  const geotaggedEntries = mapMediaEntries.filter(hasGalleryGpsCoordinates);
  const activeMediaSummary =
    viewMode === "map"
      ? galleryPayloadMediaSummary(mapPayload)
      : gridCollection?.mediaSummary ?? EMPTY_GALLERY_MEDIA_SUMMARY;
  const totalMediaCount =
    viewMode === "map"
      ? galleryPayloadTotalEntryCount(mapPayload)
      : gridCollection?.totalEntryCount ?? 0;
  const readyCount = activeMediaSummary.ready_count;
  const pendingCount = activeMediaSummary.pending_count;
  const incompleteCount = activeMediaSummary.incomplete_count;
  const imageCount = activeMediaSummary.image_count;
  const videoCount = activeMediaSummary.video_count;
  const hiddenOnMapCount = Math.max(0, totalMediaCount - activeMediaSummary.geotagged_count);
  const selectedIndex = selection?.index ?? -1;
  const selectedEntry =
    selection?.source === "map"
      ? mapMediaEntries[selectedIndex] ?? null
      : getGalleryGridEntryAtIndex(gridPages, gridCollection, selectedIndex);
  const selectedTotalCount = selection?.source === "map" ? mapMediaEntries.length : totalMediaCount;
  const selectedMediaKind = selectedEntry ? galleryMediaKind(selectedEntry) : null;
  const activeSnapshotId = loadedScope?.snapshotId ?? snapshotId;
  const selectedMediaRequests = selectedEntry
    ? getMediaRequests(selectedEntry, activeSnapshotId)
    : null;
  const selectedMissingThumbnailInfo = selectedEntry
    ? galleryMissingThumbnailInfo(selectedEntry)
    : null;
  const selectedMediaError = selectedEntry?.media?.error ?? null;
  const selectedMediaViewerKey =
    selectedEntry && selectedMediaRequests
      ? `${selectedEntry.path}::${requestSignature(selectedMediaRequests.thumbnail)}::${requestSignature(selectedMediaRequests.original)}`
      : null;
  const canNavigatePrevious = selectedIndex > 0;
  const canNavigateNext = selectedIndex >= 0 && selectedIndex < selectedTotalCount - 1;
  const canRetrySelectedPoster =
    Boolean(retryMediaEntry) &&
    selectedMediaKind === "video" &&
    selectedMissingThumbnailInfo?.title === "Poster thumbnail unavailable";

  useEffect(() => {
    persistBasemapId(activeBasemap?.id ?? "");
  }, [activeBasemap?.id]);

  useEffect(() => {
    setRetryingSelectedMedia(false);
    setSelectedMediaRetryError(null);
  }, [selectedEntry?.path, selectedMediaViewerKey]);

  useEffect(() => {
    if (!selection) {
      return;
    }

    if (selection.source === "map") {
      if (selection.index < 0 || selection.index >= mapMediaEntries.length) {
        setSelection(null);
      }
      return;
    }

    if (!gridCollection || selection.index < 0 || selection.index >= gridCollection.totalEntryCount) {
      setSelection(null);
      return;
    }

    void ensureGridPageLoaded(pageIndexForGalleryEntry(selection.index, gridCollection.pageSize));
  }, [gridCollection, mapMediaEntries.length, selection]);

  useEffect(() => {
    if (viewMode !== "grid" || !gridCollection || gridCollection.pageCount === 0) {
      return;
    }

    const anchorPageIndex =
      selection?.source === "grid"
        ? pageIndexForGalleryEntry(selection.index, gridCollection.pageSize)
        : gridActivePageIndex;
    const preloadStart = Math.max(0, anchorPageIndex - GALLERY_VIRTUAL_PAGE_PRELOAD_RADIUS);
    const preloadEnd = Math.min(
      gridCollection.pageCount - 1,
      anchorPageIndex + GALLERY_VIRTUAL_PAGE_PRELOAD_RADIUS
    );
    const keepStart = Math.max(0, anchorPageIndex - GALLERY_VIRTUAL_PAGE_KEEP_RADIUS);
    const keepEnd = Math.min(
      gridCollection.pageCount - 1,
      anchorPageIndex + GALLERY_VIRTUAL_PAGE_KEEP_RADIUS
    );

    for (let pageIndex = preloadStart; pageIndex <= preloadEnd; pageIndex += 1) {
      void ensureGridPageLoaded(pageIndex);
    }

    setGridPages((current) => {
      const nextEntries = Object.entries(current);
      let changed = false;
      const next: Record<number, GalleryGridPageState> = {};
      for (const [key, value] of nextEntries) {
        const pageIndex = Number(key);
        if (
          pageIndex >= keepStart &&
          pageIndex <= keepEnd
        ) {
          next[pageIndex] = value;
          continue;
        }
        if (value.status === "loading") {
          next[pageIndex] = value;
          continue;
        }
        changed = true;
      }
      return changed ? next : current;
    });
  }, [gridActivePageIndex, gridCollection, selection, viewMode]);

  useEffect(() => {
    if (!loadedScopeRef.current) {
      return;
    }

    void reloadAppliedEntries();
  }, [galleryVirtualPageSize, mediaFilter, sortOrder, viewMode]);

  useEffect(() => {
    if (selectedIndex < 0) {
      return;
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "ArrowLeft" && canNavigatePrevious) {
        event.preventDefault();
        void showRelativeEntry(-1);
      }

      if (event.key === "ArrowRight" && canNavigateNext) {
        event.preventDefault();
        void showRelativeEntry(1);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [canNavigateNext, canNavigatePrevious, selectedIndex, selection, totalMediaCount]);

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
    const targetScope: GalleryLoadedScope = {
      prefix: (nextPrefix ?? prefix).trim(),
      depth,
      snapshotId: nextSnapshotId === undefined ? snapshotId : nextSnapshotId
    };
    await loadGalleryScope(targetScope, typeof nextPrefix === "string");
  }

  async function reloadAppliedEntries() {
    const scope = loadedScopeRef.current;
    if (!scope) {
      return;
    }

    await loadGalleryScope(scope, false);
  }

  async function loadGalleryScope(targetScope: GalleryLoadedScope, syncPrefixInput: boolean) {
    const requestVersion = galleryRequestVersionRef.current + 1;
    galleryRequestVersionRef.current = requestVersion;
    setLoading("entries");
    setError(null);
    setSelection(null);
    setNavigationPayload(null);
    setMapPayload(null);
    setGridCollection(null);
    setGridPages({});
    setGridPageHeights({});
    setGridActivePageIndex(0);

    try {
      const navigationPromise = loadEntries(targetScope.prefix, 1, targetScope.snapshotId, {
        view: "tree"
      });

      if (viewMode === "map") {
        const [navigation, mediaPayload] = await Promise.all([
          navigationPromise,
          loadEntries(targetScope.prefix, targetScope.depth, targetScope.snapshotId, {
            view: "tree",
            sort: sortOrder,
            mediaFilter: requestedServerMediaFilter
          })
        ]);

        if (requestVersion !== galleryRequestVersionRef.current) {
          return;
        }

        setNavigationPayload(navigation);
        setMapPayload(mediaPayload);
        loadedScopeRef.current = targetScope;
        setLoadedScope(targetScope);
        if (syncPrefixInput) {
          setPrefix(targetScope.prefix);
        }
        return;
      }

      const [navigation, firstPagePayload] = await Promise.all([
        navigationPromise,
        loadEntries(targetScope.prefix, targetScope.depth, targetScope.snapshotId, {
          view: "tree",
          sort: sortOrder,
          mediaFilter: requestedServerMediaFilter,
          offset: 0,
          limit: galleryVirtualPageSize
        })
      ]);

      if (requestVersion !== galleryRequestVersionRef.current) {
        return;
      }

      const totalEntryCount = galleryPayloadTotalEntryCount(firstPagePayload);
      const nextCollection: GalleryGridCollection = {
        prefix: firstPagePayload.prefix,
        depth: firstPagePayload.depth,
        snapshotId: targetScope.snapshotId,
        totalEntryCount,
        mediaSummary: galleryPayloadMediaSummary(firstPagePayload),
        pageSize: galleryVirtualPageSize,
        pageCount: totalEntryCount > 0 ? Math.ceil(totalEntryCount / galleryVirtualPageSize) : 0
      };

      setNavigationPayload(navigation);
      setGridCollection(nextCollection);
      setGridPages({
        0: {
          status: "ready",
          entries: firstPagePayload.entries,
          error: null
        }
      });
      loadedScopeRef.current = targetScope;
      setLoadedScope(targetScope);
      if (syncPrefixInput) {
        setPrefix(targetScope.prefix);
      }
    } catch (nextError) {
      if (requestVersion === galleryRequestVersionRef.current) {
        setError(
          nextError instanceof Error ? nextError.message : "Failed to load gallery entries"
        );
      }
    } finally {
      if (requestVersion === galleryRequestVersionRef.current) {
        setLoading(null);
      }
    }
  }

  async function ensureGridPageLoaded(pageIndex: number): Promise<GalleryGridPageState | null> {
    const scope = loadedScopeRef.current;
    const collection = gridCollectionRef.current;
    if (!scope || !collection || pageIndex < 0 || pageIndex >= collection.pageCount) {
      return null;
    }

    const existing = gridPagesRef.current[pageIndex];
    if (existing?.status === "ready") {
      return existing;
    }
    if (existing?.status === "loading") {
      return existing;
    }

    setGridPages((current) => ({
      ...current,
      [pageIndex]: {
        status: "loading",
        entries: current[pageIndex]?.entries ?? [],
        error: null
      }
    }));

    const requestVersion = galleryRequestVersionRef.current;

    try {
      const payload = await loadEntries(scope.prefix, scope.depth, scope.snapshotId, {
        view: "tree",
        sort: sortOrder,
        mediaFilter: requestedServerMediaFilter,
        offset: pageIndex * collection.pageSize,
        limit: collection.pageSize
      });

      if (requestVersion !== galleryRequestVersionRef.current) {
        return null;
      }

      const totalEntryCount = galleryPayloadTotalEntryCount(payload);
      const nextCollection: GalleryGridCollection = {
        prefix: payload.prefix,
        depth: payload.depth,
        snapshotId: scope.snapshotId,
        totalEntryCount,
        mediaSummary: galleryPayloadMediaSummary(payload),
        pageSize: collection.pageSize,
        pageCount: totalEntryCount > 0 ? Math.ceil(totalEntryCount / collection.pageSize) : 0
      };
      setGridCollection(nextCollection);
      const nextPage: GalleryGridPageState = {
        status: "ready",
        entries: payload.entries,
        error: null
      };
      setGridPages((current) => ({
        ...current,
        [pageIndex]: nextPage
      }));
      return nextPage;
    } catch (nextError) {
      if (requestVersion !== galleryRequestVersionRef.current) {
        return null;
      }

      const nextPage: GalleryGridPageState = {
        status: "error",
        entries: [],
        error: nextError instanceof Error ? nextError.message : "Failed to load gallery page"
      };
      setGridPages((current) => ({
        ...current,
        [pageIndex]: nextPage
      }));
      return nextPage;
    }
  }

  function handleGridPageMeasured(pageIndex: number, height: number) {
    setGridPageHeights((current) => {
      if (current[pageIndex] === height) {
        return current;
      }

      return {
        ...current,
        [pageIndex]: height
      };
    });
  }

  function replaceGalleryEntryMedia(path: string, media: GalleryEntry["media"] | null) {
    setMapPayload((current) => {
      if (!current) {
        return current;
      }

      let changed = false;
      const entries = current.entries.map((entry) => {
        if (entry.path !== path) {
          return entry;
        }
        changed = true;
        return {
          ...entry,
          media
        };
      });

      return changed
        ? {
            ...current,
            entries
          }
        : current;
    });

    setGridPages((current) => {
      let changed = false;
      const next: Record<number, GalleryGridPageState> = {};

      for (const [pageKey, page] of Object.entries(current)) {
        let pageChanged = false;
        const entries = page.entries.map((entry) => {
          if (entry.path !== path) {
            return entry;
          }
          pageChanged = true;
          return {
            ...entry,
            media
          };
        });

        next[Number(pageKey)] = pageChanged
          ? {
              ...page,
              entries
            }
          : page;
        changed ||= pageChanged;
      }

      return changed ? next : current;
    });
  }

  async function handleRetrySelectedMedia() {
    if (!retryMediaEntry || !selectedEntry) {
      return;
    }

    const selectedPath = selectedEntry.path;
    setRetryingSelectedMedia(true);
    setSelectedMediaRetryError(null);

    try {
      const media = await retryMediaEntry(selectedEntry, activeSnapshotId);
      replaceGalleryEntryMedia(selectedPath, media ?? null);
    } catch (nextError) {
      setSelectedMediaRetryError(
        nextError instanceof Error
          ? nextError.message
          : "Failed to retry poster extraction for this item"
      );
    } finally {
      setRetryingSelectedMedia(false);
    }
  }

  async function showRelativeEntry(delta: -1 | 1) {
    if (!selection) {
      return;
    }

    const nextIndex = selection.index + delta;
    if (nextIndex < 0 || nextIndex >= selectedTotalCount) {
      return;
    }

    if (selection.source === "map") {
      const nextEntry = mapMediaEntries[nextIndex] ?? null;
      if (nextEntry) {
        setSelection({
          source: "map",
          index: nextIndex,
          path: nextEntry.path
        });
      }
      return;
    }

    if (!gridCollection) {
      return;
    }

    const pageIndex = pageIndexForGalleryEntry(nextIndex, gridCollection.pageSize);
    const page = await ensureGridPageLoaded(pageIndex);
    const nextEntry =
      page?.entries[galleryEntryWithinPage(nextIndex, gridCollection.pageSize)] ??
      getGalleryGridEntryAtIndex(gridPagesRef.current, gridCollectionRef.current, nextIndex);
    if (nextEntry) {
      setSelection({
        source: "grid",
        index: nextIndex,
        path: nextEntry.path
      });
    }
  }

  const galleryGridStyle = {
    display: "grid",
    gridTemplateColumns: `repeat(${galleryGridColumns}, minmax(0, 1fr))`,
    gap: galleryGridGap,
    alignItems: "start"
  } as const;

  const galleryDebugValue =
    viewMode === "map"
      ? mapPayload ?? {
          message: "No gallery payload loaded yet."
        }
      : gridCollection
        ? {
            navigation: navigationPayload,
            collection: gridCollection,
            pages: Object.entries(gridPages)
              .sort(([left], [right]) => Number(left) - Number(right))
              .map(([pageIndex, page]) => ({
                pageIndex: Number(pageIndex),
                status: page.status,
                entry_count: page.entries.length,
                error: page.error ?? null,
                entries: page.entries
              }))
          }
        : {
            message: "No gallery payload loaded yet."
          };

  function renderNavigationCard(item: GalleryNavigationItem) {
    if (showMetadata) {
      return (
        <Card
          key={item.key}
          data-gallery-card="true"
          withBorder
          radius={galleryCardRadius}
          padding={galleryCardPadding}
          style={{
            cursor: "pointer",
            minWidth: 0,
            overflow: "hidden",
            borderWidth: galleryCardBorderWidth
          }}
          onClick={() => void refreshEntries(item.targetPrefix)}
        >
          <Card.Section>
            <AspectRatio ratio={1}>
              <Center style={{ height: "100%", background: "var(--mantine-color-blue-0)" }}>
                <Stack gap="xs" align="center">
                  <ThemeIcon
                    size={galleryNavigationIconSize}
                    radius="xl"
                    variant="light"
                    color="blue"
                  >
                    {item.kind === "up" ? (
                      <IconArrowUp size={galleryNavigationGlyphSize} />
                    ) : (
                      <IconFolder size={galleryNavigationGlyphSize} />
                    )}
                  </ThemeIcon>
                  <Text fw={700} ta="center" lineClamp={2}>
                    {item.label}
                  </Text>
                </Stack>
              </Center>
            </AspectRatio>
          </Card.Section>

          <Stack data-gallery-card-metadata="true" gap={galleryCardContentGap} mt={galleryCardPadding}>
            <Badge color="blue" variant="light">
              {item.kind === "up" ? "navigation" : "folder"}
            </Badge>
            <Text size="sm" c="dimmed" lineClamp={3}>
              {item.description}
            </Text>
          </Stack>
        </Card>
      );
    }

    return (
      <div
        key={item.key}
        data-gallery-card="true"
        style={{ cursor: "pointer", minWidth: 0, overflow: "hidden", lineHeight: 0 }}
        onClick={() => void refreshEntries(item.targetPrefix)}
      >
        <AspectRatio ratio={1} style={{ display: "block", lineHeight: 0 }}>
          <Center style={{ height: "100%", background: "var(--mantine-color-blue-0)" }}>
            <Stack gap="xs" align="center">
              <ThemeIcon size={galleryNavigationIconSize} radius="xl" variant="light" color="blue">
                {item.kind === "up" ? (
                  <IconArrowUp size={galleryNavigationGlyphSize} />
                ) : (
                  <IconFolder size={galleryNavigationGlyphSize} />
                )}
              </ThemeIcon>
              <Text fw={700} ta="center" lineClamp={2}>
                {item.label}
              </Text>
            </Stack>
          </Center>
        </AspectRatio>
      </div>
    );
  }

  function renderMediaCard(entry: GalleryEntry, entryIndex: number) {
    const mediaRequests = getMediaRequests(entry, activeSnapshotId);
    const mediaKind = galleryMediaKind(entry) ?? "image";
    const missingThumbnailInfo = galleryMissingThumbnailInfo(entry);

    if (showMetadata) {
      return (
        <Card
          key={entry.path}
          data-gallery-card="true"
          withBorder
          radius={galleryCardRadius}
          padding={galleryCardPadding}
          style={{
            cursor: "pointer",
            minWidth: 0,
            overflow: "hidden",
            borderWidth: galleryCardBorderWidth
          }}
          onClick={() =>
            setSelection({
              source: "grid",
              index: entryIndex,
              path: entry.path
            })
          }
        >
          <Card.Section>
            <AspectRatio ratio={1}>
              <GalleryGridPreview
                kind={mediaKind}
                request={mediaRequests.thumbnail ?? null}
                alt={entry.path}
                missingThumbnailInfo={missingThumbnailInfo}
              />
            </AspectRatio>
          </Card.Section>

          <Stack data-gallery-card-metadata="true" gap={galleryCardContentGap} mt={galleryCardPadding}>
            <Group justify="space-between" align="flex-start" wrap="nowrap">
              <Text fw={700} lineClamp={1}>
                {fileName(entry.path)}
              </Text>
              <Badge color={mediaStatusColor(entry.media?.status)} variant="light">
                {entry.media?.status ?? "uncached"}
              </Badge>
            </Group>
            <Code
              style={{
                display: "block",
                whiteSpace: "normal",
                overflowWrap: "anywhere",
                wordBreak: "break-word"
              }}
            >
              {entry.path}
            </Code>
            <Group gap={galleryCardContentGap}>
              <Badge color={mediaKind === "video" ? "violet" : "blue"} variant="dot">
                {mediaKind === "video" ? "movie" : "photo"}
              </Badge>
              {entry.media?.width && entry.media?.height ? (
                <Badge variant="dot">
                  {entry.media.width} x {entry.media.height}
                </Badge>
              ) : null}
              {entry.media?.mime_type ? <Badge variant="dot">{entry.media.mime_type}</Badge> : null}
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
    }

    return (
      <div
        key={entry.path}
        data-gallery-card="true"
        style={{ cursor: "pointer", minWidth: 0, overflow: "hidden", lineHeight: 0 }}
        onClick={() =>
          setSelection({
            source: "grid",
            index: entryIndex,
            path: entry.path
          })
        }
      >
        <AspectRatio ratio={1} style={{ display: "block", lineHeight: 0 }}>
          <GalleryGridPreview
            kind={mediaKind}
            request={mediaRequests.thumbnail ?? null}
            alt={entry.path}
            missingThumbnailInfo={missingThumbnailInfo}
          />
        </AspectRatio>
      </div>
    );
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
        <Grid.Col span={12}>
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
              <SimpleGrid cols={{ base: 1, md: 3 }} spacing="md" verticalSpacing="md">
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
              </SimpleGrid>
              <SimpleGrid
                cols={{ base: 1, sm: 2, xl: enabledMediaKinds.length > 1 ? 5 : 4 }}
                spacing="md"
                verticalSpacing="md"
              >
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
                {enabledMediaKinds.length > 1 ? (
                  <Select
                    label="Media"
                    data={[
                      { value: "all", label: "Photos and movies" },
                      ...(enabledMediaKinds.includes("image")
                        ? [{ value: "image", label: "Photos only" }]
                        : []),
                      ...(enabledMediaKinds.includes("video")
                        ? [{ value: "video", label: "Movies only" }]
                        : [])
                    ]}
                    value={mediaFilter}
                    onChange={(value) => {
                      setMediaFilter(
                        value === "image" || value === "video" || value === "all" ? value : "all"
                      );
                    }}
                  />
                ) : null}
                <Stack gap={6}>
                  <Text size="sm" fw={500}>
                    Grid / Map
                  </Text>
                  <Group grow wrap="nowrap">
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
                </Stack>
                <NumberInput
                  label="Thumbnails per row"
                  min={1}
                  max={64}
                  step={1}
                  allowDecimal={false}
                  allowNegative={false}
                  value={thumbnailsPerRow}
                  onChange={(value) => {
                    setThumbnailsPerRow((current) => parseThumbnailsPerRow(value, current));
                  }}
                />
                <Switch
                  label="Show metadata"
                  checked={showMetadata}
                  onChange={(event) => setShowMetadata(event.currentTarget.checked)}
                  mt={34}
                />
              </SimpleGrid>
              <Group justify="space-between" gap="sm">
                <Group gap="sm">
                  <Button onClick={() => void refreshEntries()}>Load</Button>
                  <Button variant="default" onClick={() => void refreshEntries(parentPrefix(prefix))}>
                    Up one prefix
                  </Button>
                  <Button variant="subtle" onClick={() => void refreshEntries("")}>
                    Root
                  </Button>
                </Group>
                <Button variant="subtle" onClick={() => setDebugPayloadOpened(true)}>
                  Debug JSON
                </Button>
              </Group>
              <Group gap="xs">
                <Badge variant="light">
                  {totalMediaCount} {totalMediaCount === 1 ? "item" : "items"}
                </Badge>
                {imageCount > 0 ? (
                  <Badge color="blue" variant="light">
                    {imageCount} {imageCount === 1 ? "photo" : "photos"}
                  </Badge>
                ) : null}
                {videoCount > 0 ? (
                  <Badge color="violet" variant="light">
                    {videoCount} {videoCount === 1 ? "movie" : "movies"}
                  </Badge>
                ) : null}
                <Badge color="grape" variant="light">
                  {activeMediaSummary.geotagged_count} geo-tagged
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
                {incompleteCount > 0 ? (
                  <Badge color="orange" variant="light">
                    {incompleteCount} incomplete
                  </Badge>
                ) : null}
              </Group>
              <Text size="sm" c="dimmed">
                {previewHint}
              </Text>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={12}>
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
                    <Text fw={700}>No geo-tagged media in view</Text>
                    <Text c="dimmed" ta="center">
                      The current gallery scope has {totalMediaCount} media
                      {totalMediaCount === 1 ? " item" : " items"}, but none with GPS
                      coordinates yet.
                    </Text>
                  </Stack>
                </Card>
              ) : (
                <GalleryMapPanel
                  basemaps={availableBasemaps}
                  activeBasemap={activeBasemap}
                  onSelectBasemap={setActiveBasemapId}
                  activeProjection={activeMapProjection}
                  onSelectProjection={setActiveMapProjection}
                  entries={geotaggedEntries}
                  hiddenOnMapCount={hiddenOnMapCount}
                  selectedPath={selection?.path ?? null}
                  getMarkerRequest={(entry) => getMediaRequests(entry, activeSnapshotId).thumbnail ?? null}
                  onSelectPath={(path) => {
                    const nextIndex = mapMediaEntries.findIndex((entry) => entry.path === path);
                    if (nextIndex >= 0) {
                      setSelection({
                        source: "map",
                        index: nextIndex,
                        path
                      });
                    }
                  }}
                />
              )}
            </Stack>
          ) : totalMediaCount === 0 && navigationItems.length === 0 ? (
            <Card withBorder radius="md" padding="xl">
              <Stack gap="xs" align="center">
                <Text fw={700}>No media objects in view</Text>
                <Text c="dimmed" ta="center">
                  Load a different prefix or increase the depth to include nested photo or movie
                  keys.
                </Text>
              </Stack>
            </Card>
          ) : (
            <Stack gap={galleryGridGap > 0 ? galleryGridGap : 8}>
              <div ref={galleryGridRef} data-gallery-grid="true" style={galleryGridStyle}>
                {navigationItems.map((item) => renderNavigationCard(item))}
              </div>
              {gridCollection
                ? Array.from({ length: gridCollection.pageCount }, (_, pageIndex) => {
                    const page = gridPages[pageIndex];
                    const expectedEntryCount = resolveGalleryVirtualPageEntryCount(
                      pageIndex,
                      gridCollection.totalEntryCount,
                      gridCollection.pageSize
                    );
                    const pageMinHeight =
                      gridPageHeights[pageIndex] ??
                      resolveGalleryVirtualPageEstimatedHeight(
                        galleryGridWidth,
                        galleryGridColumns,
                        galleryGridGap,
                        showMetadata,
                        expectedEntryCount
                      );
                    const pageOffset = pageIndex * gridCollection.pageSize;

                    return (
                      <GalleryVirtualPageSlot
                        key={`gallery-page:${pageIndex}`}
                        index={pageIndex}
                        minHeight={pageMinHeight}
                        measure={page?.status === "ready"}
                        onVisible={setGridActivePageIndex}
                        onMeasured={handleGridPageMeasured}
                      >
                        {page?.status === "ready" ? (
                          <div data-gallery-grid="true" style={galleryGridStyle}>
                            {page.entries.map((entry, entryOffset) =>
                              renderMediaCard(entry, pageOffset + entryOffset)
                            )}
                          </div>
                        ) : page?.status === "error" ? (
                          <Card withBorder radius="md" padding="lg">
                            <Stack gap="sm" align="center">
                              <Text fw={700}>Failed to load gallery page</Text>
                              <Text size="sm" c="dimmed" ta="center">
                                {page.error ?? "The requested page did not load."}
                              </Text>
                              <Button variant="default" onClick={() => void ensureGridPageLoaded(pageIndex)}>
                                Retry page
                              </Button>
                            </Stack>
                          </Card>
                        ) : (
                          <Center style={{ minHeight: pageMinHeight }}>
                            <Loader size="sm" color="gray" />
                          </Center>
                        )}
                      </GalleryVirtualPageSlot>
                    );
                  })
                : null}
            </Stack>
          )}
        </Grid.Col>
      </Grid>

      <Modal
        opened={debugPayloadOpened}
        onClose={() => setDebugPayloadOpened(false)}
        title="Gallery debug JSON"
        size="xl"
      >
        <JsonBlock value={galleryDebugValue} />
      </Modal>

      <Modal
        opened={selectedEntry !== null}
        onClose={() => setSelection(null)}
        title={
          selectedEntry
            ? `${fileName(selectedEntry.path)} (${selectedIndex + 1} of ${selectedTotalCount})`
            : "Media preview"
        }
        fullScreen
        styles={{
          body: {
            paddingTop: 0
          }
        }}
      >
        {selectedEntry && selectedMediaRequests && selectedMediaKind ? (
          <Stack gap="md">
            <div style={{ height: "calc(100vh - 17rem)", minHeight: "24rem" }}>
              {selectedMediaKind === "video" ? (
                <GalleryLightboxVideo
                  key={selectedMediaViewerKey ?? selectedEntry.path}
                  request={selectedMediaRequests.original}
                  posterRequest={selectedMediaRequests.thumbnail ?? null}
                  alt={selectedEntry.path}
                  canNavigatePrevious={canNavigatePrevious}
                  canNavigateNext={canNavigateNext}
                  onNavigatePrevious={() => showRelativeEntry(-1)}
                  onNavigateNext={() => showRelativeEntry(1)}
                />
              ) : (
                <GalleryLightboxImage
                  key={selectedMediaViewerKey ?? selectedEntry.path}
                  requests={selectedMediaRequests}
                  alt={selectedEntry.path}
                  missingThumbnailInfo={selectedMissingThumbnailInfo}
                  canNavigatePrevious={canNavigatePrevious}
                  canNavigateNext={canNavigateNext}
                  onNavigatePrevious={() => showRelativeEntry(-1)}
                  onNavigateNext={() => showRelativeEntry(1)}
                />
              )}
            </div>
            <Group gap="xs">
              <Badge variant="light">
                {selectedIndex + 1} / {selectedTotalCount}
              </Badge>
              <Badge color={selectedMediaKind === "video" ? "violet" : "blue"} variant="light">
                {selectedMediaKind === "video" ? "movie" : "photo"}
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
            {selectedMissingThumbnailInfo ? (
              <Stack gap="xs">
                <Alert
                  color={selectedMissingThumbnailInfo.color}
                  title={selectedMissingThumbnailInfo.title}
                >
                  {selectedMissingThumbnailInfo.detail}
                </Alert>
                {canRetrySelectedPoster ? (
                  <Button
                    leftSection={<IconRefresh size={16} />}
                    loading={retryingSelectedMedia}
                    onClick={() => void handleRetrySelectedMedia()}
                  >
                    Retry metadata and poster extraction
                  </Button>
                ) : null}
              </Stack>
            ) : null}
            {selectedEntry.media?.taken_at_unix ? (
              <Text size="sm">Captured {formatTakenAt(selectedEntry.media.taken_at_unix)}</Text>
            ) : null}
            {selectedMediaRetryError ? <Alert color="red">{selectedMediaRetryError}</Alert> : null}
            {selectedMediaError && selectedMediaError !== selectedMissingThumbnailInfo?.detail ? (
              <Alert color="yellow">{selectedMediaError}</Alert>
            ) : null}
            <JsonBlock value={selectedEntry} />
          </Stack>
        ) : null}
      </Modal>
    </Stack>
  );
}

type GalleryVirtualPageSlotProps = {
  index: number;
  minHeight: number;
  measure: boolean;
  onVisible: (index: number) => void;
  onMeasured: (index: number, height: number) => void;
  children: ReactNode;
};

function GalleryVirtualPageSlot({
  index,
  minHeight,
  measure,
  onVisible,
  onMeasured,
  children
}: GalleryVirtualPageSlotProps) {
  const slotRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const element = slotRef.current;
    if (!element) {
      return;
    }

    if (typeof IntersectionObserver === "undefined") {
      onVisible(index);
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          onVisible(index);
        }
      },
      { rootMargin: GALLERY_VIRTUAL_PAGE_ROOT_MARGIN }
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [index, onVisible]);

  useEffect(() => {
    if (!measure) {
      return;
    }

    const element = slotRef.current;
    if (!element) {
      return;
    }

    if (typeof ResizeObserver === "undefined") {
      const nextHeight = element.getBoundingClientRect().height;
      if (nextHeight > 0) {
        onMeasured(index, nextHeight);
      }
      return;
    }

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry || entry.contentRect.height <= 0) {
        return;
      }
      onMeasured(index, entry.contentRect.height);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, [index, measure, onMeasured, children]);

  return (
    <div ref={slotRef} style={{ minHeight }}>
      {children}
    </div>
  );
}

function resolveServerGalleryMediaFilter(
  allowedKinds: GalleryMediaKind[],
  filter: GalleryMediaFilter
): GalleryMediaFilter {
  if (allowedKinds.length === 1) {
    return allowedKinds[0] ?? "image";
  }

  return filter;
}

function normalizeGalleryMediaSummary(
  summary?: Partial<GalleryMediaSummary> | null
): GalleryMediaSummary {
  return {
    ready_count:
      typeof summary?.ready_count === "number" ? summary.ready_count : EMPTY_GALLERY_MEDIA_SUMMARY.ready_count,
    pending_count:
      typeof summary?.pending_count === "number" ? summary.pending_count : EMPTY_GALLERY_MEDIA_SUMMARY.pending_count,
    incomplete_count:
      typeof summary?.incomplete_count === "number"
        ? summary.incomplete_count
        : EMPTY_GALLERY_MEDIA_SUMMARY.incomplete_count,
    image_count:
      typeof summary?.image_count === "number" ? summary.image_count : EMPTY_GALLERY_MEDIA_SUMMARY.image_count,
    video_count:
      typeof summary?.video_count === "number" ? summary.video_count : EMPTY_GALLERY_MEDIA_SUMMARY.video_count,
    geotagged_count:
      typeof summary?.geotagged_count === "number"
        ? summary.geotagged_count
        : EMPTY_GALLERY_MEDIA_SUMMARY.geotagged_count
  };
}

function galleryPayloadMediaSummary(payload: GalleryPayload | null): GalleryMediaSummary {
  return normalizeGalleryMediaSummary(payload?.media_summary);
}

function galleryPayloadTotalEntryCount(payload: GalleryPayload | null): number {
  if (!payload) {
    return 0;
  }

  if (typeof payload.total_entry_count === "number") {
    return payload.total_entry_count;
  }

  return payload.entry_count ?? payload.entries.length;
}

function resolveGalleryVirtualPageSize(columns: number): number {
  const safeColumns = Math.max(1, columns);
  return safeColumns * GALLERY_VIRTUAL_PAGE_ROW_COUNT;
}

function pageIndexForGalleryEntry(index: number, pageSize: number): number {
  const safePageSize = Math.max(1, pageSize);
  return Math.floor(index / safePageSize);
}

function galleryEntryWithinPage(index: number, pageSize: number): number {
  const safePageSize = Math.max(1, pageSize);
  return index % safePageSize;
}

function getGalleryGridEntryAtIndex(
  gridPages: Record<number, GalleryGridPageState>,
  collection: GalleryGridCollection | null,
  index: number
): GalleryEntry | null {
  if (!collection || index < 0 || index >= collection.totalEntryCount) {
    return null;
  }

  const page = gridPages[pageIndexForGalleryEntry(index, collection.pageSize)];
  if (!page || page.status !== "ready") {
    return null;
  }

  return page.entries[galleryEntryWithinPage(index, collection.pageSize)] ?? null;
}

function resolveGalleryVirtualPageEntryCount(
  pageIndex: number,
  totalEntryCount: number,
  pageSize: number
): number {
  const safePageSize = Math.max(1, pageSize);
  const offset = pageIndex * safePageSize;
  return Math.max(0, Math.min(safePageSize, totalEntryCount - offset));
}

function resolveGalleryVirtualPageEstimatedHeight(
  gridWidth: number,
  columns: number,
  gap: number,
  showMetadata: boolean,
  entryCount: number
): number {
  const safeColumns = Math.max(1, columns);
  const safeEntryCount = Math.max(1, entryCount);
  const rowCount = Math.max(1, Math.ceil(safeEntryCount / safeColumns));
  const usableWidth =
    gridWidth > 0 ? Math.max(0, gridWidth - gap * Math.max(0, safeColumns - 1)) : 0;
  const cardWidth = usableWidth > 0 ? usableWidth / safeColumns : showMetadata ? 180 : 140;
  const cardHeight = Math.max(showMetadata ? 220 : 140, cardWidth + (showMetadata ? 124 : 0));
  return rowCount * cardHeight + Math.max(0, rowCount - 1) * gap;
}

type GalleryMapPanelProps = {
  basemaps: GalleryBasemapConfig[];
  activeBasemap: GalleryBasemapConfig | null;
  onSelectBasemap: (id: string) => void;
  activeProjection: GalleryMapProjection;
  onSelectProjection: (projection: GalleryMapProjection) => void;
  entries: GalleryEntry[];
  hiddenOnMapCount: number;
  selectedPath: string | null;
  getMarkerRequest: (entry: GalleryEntry) => GalleryPreviewRequest | null;
  onSelectPath: (path: string) => void;
};

function GalleryMapPanel({
  basemaps,
  activeBasemap,
  onSelectBasemap,
  activeProjection,
  onSelectProjection,
  entries,
  hiddenOnMapCount,
  selectedPath,
  getMarkerRequest,
  onSelectPath
}: GalleryMapPanelProps) {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const pushedFullscreenHistoryRef = useRef(false);
  const toggleFullscreen = () => setIsFullscreen((current) => !current);

  useEffect(() => {
    if (!isFullscreen || typeof document === "undefined" || typeof window === "undefined") {
      return;
    }

    const previousOverflow = document.body.style.overflow;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !document.querySelector('[role="dialog"]')) {
        if (pushedFullscreenHistoryRef.current) {
          window.history.back();
          return;
        }
        setIsFullscreen(false);
      }
    };
    const handlePopState = () => {
      pushedFullscreenHistoryRef.current = false;
      setIsFullscreen(false);
    };

    const historyState =
      window.history.state && typeof window.history.state === "object"
        ? {
            ...window.history.state,
            [GALLERY_MAP_FULLSCREEN_HISTORY_KEY]: true
          }
        : {
            [GALLERY_MAP_FULLSCREEN_HISTORY_KEY]: true
          };

    window.history.pushState(historyState, "", window.location.href);
    pushedFullscreenHistoryRef.current = true;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("popstate", handlePopState);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("popstate", handlePopState);
    };
  }, [isFullscreen]);

  const fallbackMap = (
    <GalleryWorldMap
      entries={entries}
      hiddenOnMapCount={hiddenOnMapCount}
      isFullscreen={isFullscreen}
      selectedPath={selectedPath}
      getMarkerRequest={getMarkerRequest}
      onSelectPath={onSelectPath}
      onToggleFullscreen={toggleFullscreen}
    />
  );

  if (!activeBasemap) {
    return fallbackMap;
  }

  const basemapMap = (
    <GalleryBasemapMap
      basemap={activeBasemap}
      projection={activeProjection}
      entries={entries}
      hiddenOnMapCount={hiddenOnMapCount}
      isFullscreen={isFullscreen}
      selectedPath={selectedPath}
      getMarkerRequest={getMarkerRequest}
      onSelectPath={onSelectPath}
      onToggleFullscreen={toggleFullscreen}
      fallback={fallbackMap}
    />
  );

  return (
    <Stack gap="sm">
      <div style={{ display: isFullscreen ? "none" : undefined }}>
        {basemaps.length > 1 || activeBasemap ? (
          <Group gap="sm">
            {basemaps.length > 1
              ? basemaps.map((basemap) => (
                  <Button
                    key={basemap.id}
                    variant={basemap.id === activeBasemap.id ? "filled" : "default"}
                    onClick={() => onSelectBasemap(basemap.id)}
                  >
                    {basemap.modeLabel ?? basemap.label ?? basemap.id}
                  </Button>
                ))
              : null}
            {activeBasemap ? (
              <Group gap="xs">
                <Button
                  variant={activeProjection === "mercator" ? "filled" : "default"}
                  aria-pressed={activeProjection === "mercator"}
                  onClick={() => onSelectProjection("mercator")}
                >
                  Flat
                </Button>
                <Button
                  variant={activeProjection === "globe" ? "filled" : "default"}
                  aria-pressed={activeProjection === "globe"}
                  onClick={() => onSelectProjection("globe")}
                >
                  Globe
                </Button>
              </Group>
            ) : null}
          </Group>
        ) : null}
      </div>

      <div>{basemapMap}</div>
    </Stack>
  );
}

type GalleryWorldMapProps = {
  entries: GalleryEntry[];
  hiddenOnMapCount: number;
  isFullscreen: boolean;
  selectedPath: string | null;
  getMarkerRequest: (entry: GalleryEntry) => GalleryPreviewRequest | null;
  onSelectPath: (path: string) => void;
  onToggleFullscreen: () => void;
};

function GalleryWorldMap({
  entries,
  hiddenOnMapCount,
  isFullscreen,
  selectedPath,
  getMarkerRequest,
  onSelectPath,
  onToggleFullscreen
}: GalleryWorldMapProps) {
  const suppressMarkerThumbnails = entries.length > MAX_WORLD_MAP_THUMBNAIL_MARKERS;
  const mapViewport = (
    <div
      aria-label="Geotagged gallery map"
      style={{
        position: isFullscreen ? "fixed" : "relative",
        inset: isFullscreen ? 0 : undefined,
        zIndex: isFullscreen ? 150 : undefined,
        width: isFullscreen ? "100vw" : undefined,
        height: isFullscreen ? "100dvh" : undefined,
        aspectRatio: isFullscreen ? undefined : "16 / 9",
        overflow: "hidden",
        borderRadius: isFullscreen ? 0 : "calc(var(--mantine-radius-md) - 2px)",
        background:
          "radial-gradient(circle at 18% 16%, rgba(255, 255, 255, 0.32), transparent 28%), linear-gradient(180deg, #0c3348 0%, #144e6c 48%, #0d2f44 100%)",
        boxShadow: isFullscreen ? "none" : "inset 0 0 0 1px rgba(255, 255, 255, 0.08)"
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
            request={
              !suppressMarkerThumbnails || selectedPath === entry.path
                ? getMarkerRequest(entry)
                : null
            }
            projectedX={projection.x}
            projectedY={projection.y}
            selected={selectedPath === entry.path}
            onClick={() => onSelectPath(entry.path)}
          />
        );
      })}

      {!isFullscreen ? (
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
      ) : null}
      {suppressMarkerThumbnails ? (
        <div
          style={{
            position: "absolute",
            right: 16,
            top: 16
          }}
        >
          <Badge color="dark" variant="filled">
            Showing pins for {entries.length} markers
          </Badge>
        </div>
      ) : null}
    </div>
  );

  return (
    <Card
      withBorder={!isFullscreen}
      radius={isFullscreen ? 0 : "md"}
      padding={isFullscreen ? 0 : "lg"}
      style={
        isFullscreen
          ? {
              background: "transparent",
              border: 0,
              boxShadow: "none"
            }
          : undefined
      }
    >
      <Stack gap="md">
        <div style={{ display: isFullscreen ? "none" : undefined }}>
          <Group justify="space-between" align="flex-start">
            <div>
              <Text fw={700}>Geo-tagged world map</Text>
              <Text size="sm" c="dimmed">
                Click a marker to open the fullscreen media viewer.
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
              <Button variant="default" onClick={onToggleFullscreen}>
                Fullscreen map
              </Button>
            </Group>
          </Group>
        </div>

        {mapViewport}
      </Stack>
    </Card>
  );
}

type GalleryMapMarkerProps = {
  entry: GalleryEntry;
  request: GalleryPreviewRequest | null;
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
  const { resolvedSrc, failed } = useResolvedPreviewRequest(request);
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
        boxShadow: selected ? "0 0 0 6px rgba(164, 80, 255, 0.24)" : "none",
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
  const { resolvedSrc, failed: requestFailed } = useResolvedPreviewRequest(request);
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
        display: "block",
        width: "100%",
        height: "100%",
        objectFit: fit,
        background: "var(--mantine-color-gray-0)"
      }}
    />
  );
}

type GalleryGridPreviewProps = {
  kind: GalleryMediaKind;
  request: GalleryPreviewRequest | null;
  alt: string;
  missingThumbnailInfo?: GalleryMissingThumbnailInfo | null;
};

function GalleryGridPreview({
  kind,
  request,
  alt,
  missingThumbnailInfo
}: GalleryGridPreviewProps) {
  if (!request) {
    return (
      <GalleryThumbnailPlaceholder kind={kind} info={missingThumbnailInfo} />
    );
  }

  if (kind === "video") {
    return (
      <div style={{ position: "relative", width: "100%", height: "100%" }}>
        <GalleryImagePreview request={request} alt={alt} fit="cover" />
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
          <ThemeIcon size={56} radius="xl" color="dark" variant="filled">
            <IconPlayerPlay size={28} />
          </ThemeIcon>
        </div>
      </div>
    );
  }

  return <GalleryImagePreview request={request} alt={alt} fit="cover" />;
}

type GalleryLightboxImageProps = {
  requests: GalleryMediaRequests;
  alt: string;
  missingThumbnailInfo?: GalleryMissingThumbnailInfo | null;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
};

function GalleryLightboxImage({
  requests,
  alt,
  missingThumbnailInfo,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext
}: GalleryLightboxImageProps) {
  const thumbnailRequest = requests.thumbnail ?? null;
  const thumbnail = useResolvedPreviewRequest(thumbnailRequest);
  const originalRequest = requests.original;
  const original = useResolvedPreviewRequest(originalRequest);
  const [thumbnailFailed, setThumbnailFailed] = useState(false);
  const [originalFailed, setOriginalFailed] = useState(false);
  const [originalLoaded, setOriginalLoaded] = useState(false);
  const thumbnailSignature = requestSignature(thumbnailRequest);
  const originalSignature = requestSignature(originalRequest);

  useEffect(() => {
    setThumbnailFailed(false);
  }, [thumbnailSignature]);

  useEffect(() => {
    setOriginalFailed(false);
    setOriginalLoaded(false);
  }, [originalSignature]);

  const thumbnailVisible = Boolean(thumbnail.resolvedSrc) && !thumbnail.failed && !thumbnailFailed;
  const originalVisible = Boolean(original.resolvedSrc) && !original.failed && !originalFailed;
  const fullImageUnavailable = original.failed || originalFailed;
  const originalPending = !fullImageUnavailable && !originalLoaded;
  const thumbnailLoadFailed = Boolean(thumbnailRequest) && (thumbnail.failed || thumbnailFailed);
  const thumbnailNotice = thumbnailLoadFailed
    ? {
        title: "Indexed thumbnail failed to load",
        detail: "The gallery has a thumbnail URL for this item, but fetching it failed.",
        color: "yellow"
      }
    : missingThumbnailInfo;

  return (
    <GalleryLightboxFrame
      canNavigatePrevious={canNavigatePrevious}
      canNavigateNext={canNavigateNext}
      onNavigatePrevious={onNavigatePrevious}
      onNavigateNext={onNavigateNext}
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
        <div
          style={{
            position: "absolute",
            inset: 0
          }}
        >
          <GalleryThumbnailPlaceholder
            kind="image"
            info={thumbnailNotice}
            showLoader={originalPending && !originalVisible}
            fullHeight
          />
        </div>
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
    </GalleryLightboxFrame>
  );
}

type GalleryLightboxVideoProps = {
  request: GalleryPreviewRequest;
  posterRequest: GalleryPreviewRequest | null;
  alt: string;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
};

function GalleryLightboxVideo({
  request,
  posterRequest,
  alt,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext
}: GalleryLightboxVideoProps) {
  const video = useResolvedPreviewRequest(request);
  const poster = useResolvedPreviewRequest(posterRequest);

  return (
    <GalleryLightboxFrame
      canNavigatePrevious={canNavigatePrevious}
      canNavigateNext={canNavigateNext}
      onNavigatePrevious={onNavigatePrevious}
      onNavigateNext={onNavigateNext}
      navigationPlacement="below"
    >
      {video.resolvedSrc ? (
        <video
          key={requestSignature(request)}
          src={video.resolvedSrc}
          poster={poster.resolvedSrc ?? undefined}
          controls
          playsInline
          preload="metadata"
          aria-label={alt}
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
    </GalleryLightboxFrame>
  );
}

type GalleryThumbnailPlaceholderProps = {
  kind: GalleryMediaKind;
  info?: GalleryMissingThumbnailInfo | null;
  showLoader?: boolean;
  fullHeight?: boolean;
};

function GalleryThumbnailPlaceholder({
  kind,
  info,
  showLoader = false,
  fullHeight = true
}: GalleryThumbnailPlaceholderProps) {
  const resolvedInfo = info ?? defaultMissingThumbnailInfo(kind);

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
        padding: "1rem"
      }}
    >
      <Stack align="center" gap={6} maw="90%">
        {showLoader ? <Loader size="sm" color="gray" /> : null}
        <Text
          size="sm"
          fw={600}
          ta="center"
          c={kind === "video" ? "gray.2" : "dark"}
          lineClamp={2}
        >
          {resolvedInfo.title}
        </Text>
        <Text
          size="xs"
          ta="center"
          c={kind === "video" ? "gray.4" : "dimmed"}
          lineClamp={4}
        >
          {resolvedInfo.detail}
        </Text>
      </Stack>
    </Center>
  );
}

type GalleryLightboxFrameProps = {
  children: ReactNode;
  canNavigatePrevious: boolean;
  canNavigateNext: boolean;
  onNavigatePrevious: () => void;
  onNavigateNext: () => void;
  navigationPlacement?: "overlay" | "below";
};

function GalleryLightboxFrame({
  children,
  canNavigatePrevious,
  canNavigateNext,
  onNavigatePrevious,
  onNavigateNext,
  navigationPlacement = "overlay"
}: GalleryLightboxFrameProps) {
  const [touchStart, setTouchStart] = useState<{ x: number; y: number } | null>(null);
  const useFooterNavigation = navigationPlacement === "below";

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
        {!useFooterNavigation ? (
          <>
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

function useResolvedPreviewRequest(
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

function galleryMediaKind(entry: GalleryEntry): GalleryMediaKind | null {
  if (entry.entry_type !== "key") {
    return null;
  }

  if (entry.media?.mime_type?.startsWith("image/")) {
    return "image";
  }

  if (entry.media?.mime_type?.startsWith("video/")) {
    return "video";
  }

  if (entry.media?.media_type === "image") {
    return "image";
  }

  if (entry.media?.media_type === "video") {
    return "video";
  }

  const lowerPath = entry.path.toLowerCase();
  if (imageExtensions.some((extension) => lowerPath.endsWith(extension))) {
    return "image";
  }
  if (videoExtensions.some((extension) => lowerPath.endsWith(extension))) {
    return "video";
  }
  return null;
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

function mediaStatusColor(status?: string | null): string {
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

function galleryMissingThumbnailInfo(entry: GalleryEntry): GalleryMissingThumbnailInfo | null {
  if (entry.media?.thumbnail?.url) {
    return null;
  }

  const kind = galleryMediaKind(entry);
  const thumbnailLabel = kind === "video" ? "Poster thumbnail" : "Thumbnail";
  const status = entry.media?.status;

  if (entry.media?.error) {
    return {
      title: `${thumbnailLabel} unavailable`,
      detail: entry.media.error,
      color: mediaStatusColor(status)
    };
  }

  if (status === "pending") {
    return {
      title: `${thumbnailLabel} pending`,
      detail:
        kind === "video"
          ? "Video metadata or poster generation has not finished yet on this node."
          : "Image indexing has not produced a thumbnail yet on this node.",
      color: "yellow"
    };
  }

  if (status === "incomplete") {
    return {
      title: `${thumbnailLabel} incomplete`,
      detail: "Media indexing finished without producing a usable thumbnail.",
      color: "orange"
    };
  }

  if (status === "failed") {
    return {
      title: `${thumbnailLabel} failed`,
      detail: "Thumbnail generation failed. Check the media error, host dependency status, or server logs.",
      color: "red"
    };
  }

  if (status === "ready") {
    return {
      title: `${thumbnailLabel} missing`,
      detail: "Media is marked ready, but the index does not include a thumbnail URL.",
      color: "yellow"
    };
  }

  return {
    title: `${thumbnailLabel} unavailable`,
    detail: "This entry does not have an indexed thumbnail to display.",
    color: "gray"
  };
}

function defaultMissingThumbnailInfo(kind: GalleryMediaKind): GalleryMissingThumbnailInfo {
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
    const targetPrefix = galleryDirectChildPrefix(entry, currentPrefix);
    if (!targetPrefix || targetPrefix === currentPrefix) {
      continue;
    }

    if (seenPrefixes.has(targetPrefix)) {
      continue;
    }

    seenPrefixes.add(targetPrefix);
    const relativePath = targetPrefix.slice(currentPrefix.length) || targetPrefix;
    items.push({
      key: `prefix:${targetPrefix}`,
      kind: "prefix",
      label: relativePath,
      description: `Open ${targetPrefix}`,
      targetPrefix
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
  return normalizeStorePrefix(path);
}

function galleryDirectChildPrefix(entry: GalleryEntry, currentPrefix: string): string | null {
  return directChildStorePrefix(entry.path, currentPrefix, isGalleryPrefixEntry(entry));
}

function loadStoredThumbnailsPerRow(): number {
  if (typeof window === "undefined") {
    return 3;
  }

  return parseThumbnailsPerRow(window.localStorage.getItem(GALLERY_THUMBNAILS_PER_ROW_STORAGE_KEY));
}

function loadStoredShowMetadata(): boolean {
  if (typeof window === "undefined") {
    return true;
  }

  return parseShowMetadata(window.localStorage.getItem(GALLERY_SHOW_METADATA_STORAGE_KEY));
}

function loadStoredViewMode(): GalleryViewMode {
  if (typeof window === "undefined") {
    return "grid";
  }

  return parseViewMode(window.localStorage.getItem(GALLERY_VIEW_MODE_STORAGE_KEY));
}

function loadStoredBasemapId(): string {
  if (typeof window === "undefined") {
    return "";
  }

  return window.localStorage.getItem(GALLERY_BASEMAP_ID_STORAGE_KEY) ?? "";
}

function loadStoredMapProjection(): GalleryMapProjection {
  if (typeof window === "undefined") {
    return "mercator";
  }

  return parseMapProjection(window.localStorage.getItem(GALLERY_MAP_PROJECTION_STORAGE_KEY));
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

function persistShowMetadata(value: boolean) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(
    GALLERY_SHOW_METADATA_STORAGE_KEY,
    String(parseShowMetadata(value))
  );
}

function persistViewMode(value: GalleryViewMode) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(GALLERY_VIEW_MODE_STORAGE_KEY, parseViewMode(value));
}

function persistBasemapId(value: string) {
  if (typeof window === "undefined") {
    return;
  }

  if (value.trim()) {
    window.localStorage.setItem(GALLERY_BASEMAP_ID_STORAGE_KEY, value.trim());
    return;
  }

  window.localStorage.removeItem(GALLERY_BASEMAP_ID_STORAGE_KEY);
}

function persistMapProjection(value: GalleryMapProjection) {
  if (typeof window === "undefined") {
    return;
  }

  window.localStorage.setItem(
    GALLERY_MAP_PROJECTION_STORAGE_KEY,
    parseMapProjection(value)
  );
}

function parseThumbnailsPerRow(
  value: string | number | null | undefined,
  fallback = 3
): number {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) && parsed >= 1
    ? Math.max(1, Math.floor(parsed))
    : Math.max(1, Math.floor(fallback));
}

function parseShowMetadata(value: boolean | string | null | undefined): boolean {
  if (typeof value === "boolean") {
    return value;
  }

  if (value === "false") {
    return false;
  }

  if (value === "true") {
    return true;
  }

  return true;
}

function resolveGalleryGridColumns(
  requestedColumns: number,
  containerWidth: number,
  gap: number,
  showMetadata: boolean
): number {
  const safeRequestedColumns = parseThumbnailsPerRow(requestedColumns);
  const availableWidth =
    Number.isFinite(containerWidth) && containerWidth > 0
      ? containerWidth
      : typeof window !== "undefined"
        ? Math.max(window.innerWidth - 32, 0)
        : 0;

  if (!Number.isFinite(availableWidth) || availableWidth <= 0) {
    return safeRequestedColumns;
  }

  const minimumCardWidth = minimumGalleryCardWidth(safeRequestedColumns, showMetadata);
  const maxColumns = Math.max(1, Math.floor((availableWidth + gap) / (minimumCardWidth + gap)));
  return Math.max(1, Math.min(safeRequestedColumns, maxColumns));
}

function minimumGalleryCardWidth(requestedColumns: number, showMetadata: boolean): number {
  const safeRequestedColumns = parseThumbnailsPerRow(requestedColumns);
  if (safeRequestedColumns === 1) {
    return showMetadata ? 260 : 200;
  }

  const initialWidth = showMetadata ? 188 : 140;
  const decrementPerColumn = showMetadata ? 14 : 12;
  const minimumWidth = showMetadata ? 92 : 60;

  return Math.max(
    minimumWidth,
    initialWidth - (safeRequestedColumns - 2) * decrementPerColumn
  );
}

function parseViewMode(value: string | null | undefined): GalleryViewMode {
  return value === "map" ? "map" : "grid";
}

function parseMapProjection(value: string | null | undefined): GalleryMapProjection {
  return value === "globe" ? "globe" : "mercator";
}

function formatTakenAt(value: number): string {
  return new Date(value * 1000).toLocaleString();
}

function fileName(path: string): string {
  return storeEntryName(path, false);
}

function parentPrefix(path: string): string {
  return parentStorePrefix(path);
}

function projectGpsToWorldMap(latitude: number, longitude: number): { x: number; y: number } {
  const clampedLatitude = Math.max(-85, Math.min(85, latitude));
  const wrappedLongitude = ((((longitude + 180) % 360) + 360) % 360) - 180;

  return {
    x: Math.max(0.028, Math.min(0.972, (wrappedLongitude + 180) / 360)),
    y: Math.max(0.04, Math.min(0.96, (90 - clampedLatitude) / 180))
  };
}
