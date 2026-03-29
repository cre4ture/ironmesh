import { Alert, Badge, Button, Card, Center, Group, Loader, Stack, Text } from "@mantine/core";
import { IconMapPin } from "@tabler/icons-react";
import maplibregl, { type LngLatLike, type StyleSpecification } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { createDbWorker, type WorkerHttpvfs } from "sql.js-httpvfs";
import { useEffect, useRef, useState, type ReactNode } from "react";

const MBTILES_PROTOCOL = "ironmesh-mbtiles";
const SQLJS_WORKER_URL = new URL(
  "sql.js-httpvfs/dist/sqlite.worker.js",
  import.meta.url
).toString();
const SQLJS_WASM_URL = new URL("sql.js-httpvfs/dist/sql-wasm.wasm", import.meta.url).toString();
const TRANSPARENT_PNG_BYTES = base64ToUint8Array(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0N8AAAAASUVORK5CYII="
);

type GalleryBasemapMapEntry = {
  path: string;
  entry_type: string;
  media?: {
    gps?: {
      latitude: number;
      longitude: number;
    } | null;
  } | null;
};

type GalleryBasemapPreviewRequest = {
  url: string;
  headers?: Record<string, string>;
};

type GalleryBasemapBaseConfig = {
  id: string;
  modeLabel?: string;
  attribution?: string;
  label?: string;
};

export type GalleryRasterBasemapConfig = GalleryBasemapBaseConfig & {
  kind: "raster";
  logicalFileUrl: string;
  metadataUrl?: string;
  tileUrlTemplate?: string;
};

export type GalleryVectorBasemapConfig = GalleryBasemapBaseConfig & {
  kind: "vector";
  metadataUrl: string;
  vectorTileUrlTemplate: string;
  glyphsUrlTemplate: string;
};

export type GalleryHybridBasemapConfig = GalleryBasemapBaseConfig & {
  kind: "hybrid";
  rasterMetadataUrl: string;
  rasterTileUrlTemplate: string;
  vectorMetadataUrl: string;
  vectorTileUrlTemplate: string;
  glyphsUrlTemplate: string;
};

export type GalleryBasemapConfig =
  | GalleryRasterBasemapConfig
  | GalleryVectorBasemapConfig
  | GalleryHybridBasemapConfig;
export type GalleryMapProjection = "mercator" | "globe";

type GalleryBasemapMapProps = {
  basemap: GalleryBasemapConfig;
  projection: GalleryMapProjection;
  entries: GalleryBasemapMapEntry[];
  hiddenOnMapCount: number;
  isFullscreen: boolean;
  selectedPath: string | null;
  getMarkerRequest: (entry: GalleryBasemapMapEntry) => GalleryBasemapPreviewRequest | null;
  onSelectPath: (path: string) => void;
  onToggleFullscreen: () => void;
  fallback: ReactNode;
};

type MbtilesSource = {
  worker: WorkerHttpvfs;
  metadata: MbtilesMetadata;
};

type MbtilesMetadata = {
  attribution?: string;
  format?: string;
  id?: string;
  minzoom?: number;
  maxzoom?: number;
  name?: string;
  version?: string;
  center?: [number, number, number?];
};

type TileImagePayload = {
  bytes: Uint8Array;
  mimeType: string;
};

type TileCoordinates = {
  zoomLevel: number;
  tileColumn: number;
  xyzTileRow: number;
  tmsTileRow: number;
};

type MapCameraState = {
  center: [number, number];
  zoom: number;
  bearing: number;
  pitch: number;
};

type LoadedBasemapStyle = {
  style: StyleSpecification;
  viewMetadata: MbtilesMetadata;
};

const mbtilesSourceCache = new Map<string, Promise<MbtilesSource>>();
const mbtilesConfigRegistry = new Map<string, GalleryRasterBasemapConfig>();
let mbtilesProtocolRegistered = false;

export function GalleryBasemapMap({
  basemap,
  projection,
  entries,
  hiddenOnMapCount,
  isFullscreen,
  selectedPath,
  getMarkerRequest,
  onSelectPath,
  onToggleFullscreen,
  fallback
}: GalleryBasemapMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const markerOverlayRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const cameraStateRef = useRef<MapCameraState | null>(null);
  const [mapReady, setMapReady] = useState(false);
  const [mapError, setMapError] = useState<string | null>(null);
  const [viewportVersion, setViewportVersion] = useState(0);
  const [fitSignature, setFitSignature] = useState("");
  const serverRasterBasemap = isServerRasterBasemap(basemap) ? basemap : null;
  const localRasterBasemap = isLocalRasterBasemap(basemap) ? basemap : null;
  const usesRasterServerTiles = serverRasterBasemap !== null;
  const usesLocalRasterMbtiles = localRasterBasemap !== null;
  const localRasterSourceId = localRasterBasemap
    ? sourceIdForLogicalFile(localRasterBasemap.logicalFileUrl)
    : null;
  const entrySignature = entries
    .map((entry) => {
      const gps = entry.media?.gps;
      return `${entry.path}:${gps?.latitude ?? ""}:${gps?.longitude ?? ""}`;
    })
    .join("|");

  useEffect(() => {
    let cancelled = false;
    let map: maplibregl.Map | null = null;

    setMapReady(false);
    setMapError(null);

    async function start() {
      try {
        const { style, viewMetadata } = await loadBasemapStyle(
          basemap,
          projection,
          serverRasterBasemap,
          localRasterBasemap,
          localRasterSourceId
        );
        if (cancelled || !containerRef.current) {
          return;
        }

        if (localRasterBasemap && localRasterSourceId) {
          mbtilesConfigRegistry.set(localRasterSourceId, localRasterBasemap);
          ensureMbtilesProtocolRegistered();
        }
        const preservedCamera = cameraStateRef.current;
        map = new maplibregl.Map({
          container: containerRef.current,
          style,
          center: preservedCamera
            ? ([preservedCamera.center[0], preservedCamera.center[1]] as LngLatLike)
            : viewMetadata.center
              ? ([viewMetadata.center[0], viewMetadata.center[1]] as LngLatLike)
              : ([0, 20] as LngLatLike),
          zoom: preservedCamera?.zoom ?? viewMetadata.center?.[2] ?? 1.2,
          bearing: preservedCamera?.bearing ?? 0,
          pitch: preservedCamera?.pitch ?? 0
        });

        const bumpViewport = () => {
          if (map) {
            const nextCamera = trySnapshotMapCamera(map);
            if (nextCamera) {
              cameraStateRef.current = nextCamera;
            }
          }
          setViewportVersion((current) => current + 1);
        };
        let ready = false;
        const markReady = () => {
          if (cancelled || ready || !map) {
            return;
          }
          if (!currentMapProjectionType(map)) {
            return;
          }
          ready = true;
          setMapReady(true);
          bumpViewport();
        };
        map.on("styledata", () => {
          if (cancelled) {
            return;
          }
          markReady();
        });
        map.on("load", markReady);
        map.on("move", bumpViewport);
        map.on("zoom", bumpViewport);
        map.on("resize", bumpViewport);
        map.on("projectiontransition", bumpViewport);
        mapRef.current = map;
        if (map.isStyleLoaded()) {
          markReady();
        }
      } catch (error) {
        if (!cancelled) {
          setMapError(error instanceof Error ? error.message : "Failed to load self-hosted basemap");
        }
      }
    }

    void start();

    return () => {
      cancelled = true;
      if (localRasterBasemap && localRasterSourceId) {
        mbtilesConfigRegistry.delete(localRasterSourceId);
      }
      if (map) {
        const nextCamera = trySnapshotMapCamera(map);
        if (nextCamera) {
          cameraStateRef.current = nextCamera;
        }
        map.remove();
      }
      mapRef.current = null;
    };
  }, [
    basemap.attribution,
    basemap.label,
    basemap.kind,
    usesRasterServerTiles,
    usesLocalRasterMbtiles,
    serverRasterBasemap,
    localRasterBasemap,
    localRasterSourceId,
    basemap.kind === "raster" ? basemap.logicalFileUrl : null,
    basemap.kind === "raster" ? basemap.metadataUrl ?? null : null,
    basemap.kind === "raster" ? basemap.tileUrlTemplate ?? null : null,
    basemap.kind === "vector" ? basemap.metadataUrl : null,
    basemap.kind === "vector" ? basemap.vectorTileUrlTemplate : null,
    basemap.kind === "vector" ? basemap.glyphsUrlTemplate : null,
    basemap.kind === "hybrid" ? basemap.rasterMetadataUrl : null,
    basemap.kind === "hybrid" ? basemap.rasterTileUrlTemplate : null,
    basemap.kind === "hybrid" ? basemap.vectorMetadataUrl : null,
    basemap.kind === "hybrid" ? basemap.vectorTileUrlTemplate : null,
    basemap.kind === "hybrid" ? basemap.glyphsUrlTemplate : null
  ]);

  useEffect(() => {
    const map = mapRef.current;
    if (!mapReady || !map) {
      return;
    }

    const currentProjection = currentMapProjectionType(map);
    if (!currentProjection || currentProjection === projection) {
      return;
    }

    const currentCamera = trySnapshotMapCamera(map);
    if (!currentCamera) {
      return;
    }
    cameraStateRef.current = currentCamera;
    map.setProjection({ type: projection });
    map.jumpTo(currentCamera);
    setViewportVersion((current) => current + 1);
  }, [mapReady, projection]);

  useEffect(() => {
    const map = mapRef.current;
    if (!mapReady || !map || entries.length === 0) {
      return;
    }

    if (fitSignature === entrySignature) {
      return;
    }

    const bounds = new maplibregl.LngLatBounds();
    for (const entry of entries) {
      const gps = entry.media?.gps;
      if (!gps) {
        continue;
      }
      bounds.extend([gps.longitude, gps.latitude]);
    }

    if (!bounds.isEmpty()) {
      map.fitBounds(bounds, {
        padding: 72,
        maxZoom: 11,
        duration: 0
      });
      setFitSignature(entrySignature);
    }
  }, [entries, entrySignature, fitSignature, mapReady]);

  useEffect(() => {
    const markerOverlay = markerOverlayRef.current;
    const map = mapRef.current;
    if (!markerOverlay || !map) {
      return;
    }
    const mapCanvasContainer = map.getCanvasContainer();

    function handleMarkerWheel(event: WheelEvent) {
      event.preventDefault();
      event.stopPropagation();
      mapCanvasContainer.dispatchEvent(
        new WheelEvent("wheel", {
          bubbles: true,
          cancelable: true,
          deltaMode: event.deltaMode,
          deltaX: event.deltaX,
          deltaY: event.deltaY,
          deltaZ: event.deltaZ,
          clientX: event.clientX,
          clientY: event.clientY,
          screenX: event.screenX,
          screenY: event.screenY,
          ctrlKey: event.ctrlKey,
          shiftKey: event.shiftKey,
          altKey: event.altKey,
          metaKey: event.metaKey
        })
      );
    }

    markerOverlay.addEventListener("wheel", handleMarkerWheel, { passive: false });
    return () => markerOverlay.removeEventListener("wheel", handleMarkerWheel);
  }, [mapReady]);

  useEffect(() => {
    const map = mapRef.current;
    if (!map || typeof window === "undefined") {
      return;
    }

    const frameId = window.requestAnimationFrame(() => {
      map.resize();
    });

    return () => window.cancelAnimationFrame(frameId);
  }, [isFullscreen]);

  if (mapError) {
    if (isFullscreen) {
      return <>{fallback}</>;
    }

    return (
      <Stack gap="md">
        <Alert color="yellow">
          Self-hosted basemap unavailable. Falling back to the built-in atlas view.
        </Alert>
        {fallback}
      </Stack>
    );
  }

  const map = mapRef.current;
  const mapWidth = map?.getContainer().clientWidth ?? 0;
  const mapHeight = map?.getContainer().clientHeight ?? 0;
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
        background: "#0b2433"
      }}
    >
      <div
        ref={containerRef}
        style={{
          position: "absolute",
          inset: 0
        }}
      />

      {!mapReady ? (
        <Center
          style={{
            position: "absolute",
            inset: 0,
            background: "rgba(8, 24, 35, 0.48)",
            backdropFilter: "blur(2px)"
          }}
        >
          <Stack gap="xs" align="center">
            <Loader color="white" />
            <Text c="white" size="sm">
              Loading self-hosted basemap
            </Text>
          </Stack>
        </Center>
      ) : null}

      {mapReady && map ? (
        <div
          ref={markerOverlayRef}
          style={{
            position: "absolute",
            inset: 0,
            pointerEvents: "none"
          }}
        >
          {entries.map((entry) => {
            const gps = entry.media?.gps;
            if (!gps) {
              return null;
            }

            const projected = map.project([gps.longitude, gps.latitude]);
            if (
              projected.x < -64 ||
              projected.y < -64 ||
              projected.x > mapWidth + 64 ||
              projected.y > mapHeight + 64
            ) {
              return null;
            }

            return (
              <GalleryBasemapMarker
                key={entry.path}
                entry={entry}
                request={getMarkerRequest(entry)}
                left={projected.x}
                top={projected.y}
                selected={selectedPath === entry.path}
                onClick={() => onSelectPath(entry.path)}
              />
            );
          })}
        </div>
      ) : null}

      {!isFullscreen ? (
        <div
          style={{
            position: "absolute",
            left: 12,
            top: 12,
            display: "flex",
            gap: 8
          }}
        >
          <Badge color="grape" variant="filled">
            {entries.length} markers
          </Badge>
          {hiddenOnMapCount > 0 ? (
            <Badge color="dark" variant="filled">
              {hiddenOnMapCount} without GPS
            </Badge>
          ) : null}
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
          <Group justify="space-between" align="flex-start" gap="sm">
            <div>
              <Text fw={700}>Geo-tagged world map</Text>
              <Text size="sm" c="dimmed">
                {basemap.label
                  ? `Using ${basemap.label} from your self-hosted basemap dataset.`
                  : "Using your self-hosted basemap dataset."}
              </Text>
            </div>
            <Button variant="default" onClick={onToggleFullscreen}>
              Fullscreen map
            </Button>
          </Group>
        </div>

        {mapViewport}
      </Stack>
    </Card>
  );
}

type GalleryBasemapMarkerProps = {
  entry: GalleryBasemapMapEntry;
  request: GalleryBasemapPreviewRequest | null;
  left: number;
  top: number;
  selected: boolean;
  onClick: () => void;
};

function GalleryBasemapMarker({
  entry,
  request,
  left,
  top,
  selected,
  onClick
}: GalleryBasemapMarkerProps) {
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
        left,
        top,
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
        cursor: "pointer",
        pointerEvents: "auto"
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

function isServerRasterBasemap(basemap: GalleryBasemapConfig): basemap is GalleryRasterBasemapConfig {
  return basemap.kind === "raster" && Boolean(basemap.metadataUrl && basemap.tileUrlTemplate);
}

function isLocalRasterBasemap(basemap: GalleryBasemapConfig): basemap is GalleryRasterBasemapConfig {
  return basemap.kind === "raster" && !isServerRasterBasemap(basemap);
}

async function loadBasemapStyle(
  basemap: GalleryBasemapConfig,
  projection: GalleryMapProjection,
  serverRasterBasemap: GalleryRasterBasemapConfig | null,
  localRasterBasemap: GalleryRasterBasemapConfig | null,
  localRasterSourceId: string | null
): Promise<LoadedBasemapStyle> {
  if (basemap.kind === "vector") {
    const metadata = await fetchMbtilesMetadata(basemap.metadataUrl);
    return {
      style: buildVectorStyle(basemap, metadata, projection),
      viewMetadata: metadata
    };
  }

  if (basemap.kind === "hybrid") {
    const [rasterMetadata, vectorMetadata] = await Promise.all([
      fetchMbtilesMetadata(basemap.rasterMetadataUrl),
      fetchMbtilesMetadata(basemap.vectorMetadataUrl)
    ]);
    return {
      style: buildHybridStyle(basemap, rasterMetadata, vectorMetadata, projection),
      viewMetadata: rasterMetadata.center ? rasterMetadata : vectorMetadata
    };
  }

  if (serverRasterBasemap) {
    const metadata = await fetchMbtilesMetadata(serverRasterBasemap.metadataUrl);
    return {
      style: buildRasterStyle(
        serverRasterBasemap.tileUrlTemplate!,
        metadata,
        serverRasterBasemap,
        projection
      ),
      viewMetadata: metadata
    };
  }

  if (!localRasterBasemap || !localRasterSourceId) {
    throw new Error("missing self-hosted raster basemap source id");
  }

  const metadata = (await loadMbtilesSource(localRasterSourceId, localRasterBasemap)).metadata;
  return {
    style: buildRasterStyle(
      `${MBTILES_PROTOCOL}://${localRasterSourceId}/{z}/{x}/{y}`,
      metadata,
      localRasterBasemap,
      projection
    ),
    viewMetadata: metadata
  };
}

function buildRasterStyle(
  tileUrlTemplate: string,
  metadata: MbtilesMetadata,
  basemap: GalleryRasterBasemapConfig,
  projection: GalleryMapProjection
): StyleSpecification {
  const absoluteTileUrlTemplate = absolutizeStyleUrl(tileUrlTemplate);
  return {
    version: 8,
    projection: { type: projection },
    sources: {
      basemap: {
        type: "raster",
        tiles: [absoluteTileUrlTemplate],
        tileSize: 256,
        attribution: basemap.attribution ?? metadata.attribution ?? "",
        minzoom: metadata.minzoom ?? 0,
        maxzoom: metadata.maxzoom ?? 18
      }
    },
    layers: [
      {
        id: "basemap",
        type: "raster",
        source: "basemap"
      }
    ]
  };
}

function buildVectorStyle(
  basemap: GalleryVectorBasemapConfig,
  metadata: MbtilesMetadata,
  projection: GalleryMapProjection
): StyleSpecification {
  const absoluteTileUrlTemplate = absolutizeStyleUrl(basemap.vectorTileUrlTemplate);
  const absoluteGlyphsUrlTemplate = absolutizeStyleUrl(basemap.glyphsUrlTemplate);
  return {
    version: 8,
    projection: { type: projection },
    glyphs: absoluteGlyphsUrlTemplate,
    sources: {
      basemap: {
        type: "vector",
        tiles: [absoluteTileUrlTemplate],
        attribution: basemap.attribution ?? metadata.attribution ?? "",
        minzoom: metadata.minzoom ?? 0,
        maxzoom: metadata.maxzoom ?? 14
      }
    },
    layers: [
      {
        id: "background",
        type: "background",
        paint: {
          "background-color": "#f4f1ea"
        }
      },
      {
        id: "landcover",
        type: "fill",
        source: "basemap",
        "source-layer": "landcover",
        paint: {
          "fill-color": "#dfe8d2",
          "fill-opacity": 0.85
        }
      },
      {
        id: "landuse",
        type: "fill",
        source: "basemap",
        "source-layer": "landuse",
        paint: {
          "fill-color": "#ebe7da",
          "fill-opacity": 0.72
        }
      },
      {
        id: "water",
        type: "fill",
        source: "basemap",
        "source-layer": "water",
        paint: {
          "fill-color": "#8cbdd9"
        }
      },
      {
        id: "waterway",
        type: "line",
        source: "basemap",
        "source-layer": "waterway",
        paint: {
          "line-color": "#6ea9cf",
          "line-width": [
            "interpolate",
            ["linear"],
            ["zoom"],
            4,
            0.4,
            10,
            1.4,
            14,
            2.4
          ]
        }
      },
      {
        id: "roads",
        type: "line",
        source: "basemap",
        "source-layer": "transportation",
        paint: {
          "line-color": "#ffffff",
          "line-width": [
            "interpolate",
            ["linear"],
            ["zoom"],
            5,
            0.4,
            10,
            1.3,
            14,
            3.2
          ]
        }
      },
      {
        id: "buildings",
        type: "fill",
        source: "basemap",
        "source-layer": "building",
        minzoom: 12,
        paint: {
          "fill-color": "#d9d2c3",
          "fill-opacity": 0.75
        }
      },
      {
        id: "boundaries",
        type: "line",
        source: "basemap",
        "source-layer": "boundary",
        paint: {
          "line-color": "#8c7f73",
          "line-dasharray": [2, 2],
          "line-width": [
            "interpolate",
            ["linear"],
            ["zoom"],
            2,
            0.4,
            6,
            0.8,
            10,
            1.4
          ]
        }
      },
      {
        id: "water-labels",
        type: "symbol",
        source: "basemap",
        "source-layer": "water_name",
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            3,
            10,
            8,
            12,
            12,
            14
          ]
        },
        paint: {
          "text-color": "#4f7b95",
          "text-halo-color": "rgba(255,255,255,0.9)",
          "text-halo-width": 1
        }
      },
      {
        id: "place-country-labels",
        type: "symbol",
        source: "basemap",
        "source-layer": "place",
        filter: ["==", ["get", "class"], "country"],
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-letter-spacing": 0.08,
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            1,
            11,
            4,
            15,
            8,
            18
          ]
        },
        paint: {
          "text-color": "#5b5248",
          "text-halo-color": "rgba(255,255,255,0.92)",
          "text-halo-width": 1.2
        }
      },
      {
        id: "place-region-labels",
        type: "symbol",
        source: "basemap",
        "source-layer": "place",
        filter: [
          "match",
          ["get", "class"],
          ["state", "province", "region"],
          true,
          false
        ],
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            3,
            10,
            6,
            12,
            10,
            14
          ]
        },
        paint: {
          "text-color": "#6b6257",
          "text-halo-color": "rgba(255,255,255,0.92)",
          "text-halo-width": 1.1
        }
      },
      {
        id: "place-city-labels",
        type: "symbol",
        source: "basemap",
        "source-layer": "place",
        filter: [
          "match",
          ["get", "class"],
          ["city", "town", "village"],
          true,
          false
        ],
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            4,
            10,
            8,
            12,
            11,
            15
          ]
        },
        paint: {
          "text-color": "#2f2a25",
          "text-halo-color": "rgba(255,255,255,0.96)",
          "text-halo-width": 1.25
        }
      }
    ]
  } as StyleSpecification;
}

function buildHybridStyle(
  basemap: GalleryHybridBasemapConfig,
  rasterMetadata: MbtilesMetadata,
  vectorMetadata: MbtilesMetadata,
  projection: GalleryMapProjection
): StyleSpecification {
  const absoluteRasterTileUrlTemplate = absolutizeStyleUrl(basemap.rasterTileUrlTemplate);
  const absoluteVectorTileUrlTemplate = absolutizeStyleUrl(basemap.vectorTileUrlTemplate);
  const absoluteGlyphsUrlTemplate = absolutizeStyleUrl(basemap.glyphsUrlTemplate);

  return {
    version: 8,
    projection: { type: projection },
    glyphs: absoluteGlyphsUrlTemplate,
    sources: {
      satellite: {
        type: "raster",
        tiles: [absoluteRasterTileUrlTemplate],
        tileSize: 256,
        attribution: basemap.attribution ?? rasterMetadata.attribution ?? vectorMetadata.attribution ?? "",
        minzoom: rasterMetadata.minzoom ?? 0,
        maxzoom: rasterMetadata.maxzoom ?? 18
      },
      overlay: {
        type: "vector",
        tiles: [absoluteVectorTileUrlTemplate],
        attribution: "",
        minzoom: vectorMetadata.minzoom ?? 0,
        maxzoom: vectorMetadata.maxzoom ?? 14
      }
    },
    layers: [
      {
        id: "satellite-base",
        type: "raster",
        source: "satellite"
      },
      {
        id: "hybrid-boundaries",
        type: "line",
        source: "overlay",
        "source-layer": "boundary",
        paint: {
          "line-color": "#f6e8bb",
          "line-opacity": [
            "interpolate",
            ["linear"],
            ["zoom"],
            1,
            0.42,
            6,
            0.58,
            10,
            0.74
          ],
          "line-dasharray": [3, 2],
          "line-width": [
            "interpolate",
            ["linear"],
            ["zoom"],
            1,
            0.5,
            5,
            0.8,
            9,
            1.4,
            13,
            2.1
          ]
        }
      },
      {
        id: "hybrid-country-labels",
        type: "symbol",
        source: "overlay",
        "source-layer": "place",
        filter: ["==", ["get", "class"], "country"],
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-letter-spacing": 0.1,
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            1,
            10,
            4,
            14,
            7,
            17
          ]
        },
        paint: {
          "text-color": "#fff6dd",
          "text-halo-color": "rgba(12, 17, 24, 0.88)",
          "text-halo-width": 1.4
        }
      },
      {
        id: "hybrid-region-labels",
        type: "symbol",
        source: "overlay",
        "source-layer": "place",
        minzoom: 3,
        filter: [
          "match",
          ["get", "class"],
          ["state", "province", "region"],
          true,
          false
        ],
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            3,
            9,
            6,
            11,
            10,
            13
          ]
        },
        paint: {
          "text-color": "#f8f1de",
          "text-halo-color": "rgba(10, 14, 20, 0.86)",
          "text-halo-width": 1.25
        }
      },
      {
        id: "hybrid-city-labels",
        type: "symbol",
        source: "overlay",
        "source-layer": "place",
        minzoom: 5,
        filter: [
          "match",
          ["get", "class"],
          ["city", "town"],
          true,
          false
        ],
        layout: {
          "text-field": nameExpression(),
          "text-font": ["Noto Sans Regular"],
          "text-size": [
            "interpolate",
            ["linear"],
            ["zoom"],
            5,
            10,
            8,
            12,
            11,
            14
          ]
        },
        paint: {
          "text-color": "#ffffff",
          "text-halo-color": "rgba(8, 12, 18, 0.9)",
          "text-halo-width": 1.35
        }
      }
    ]
  } as StyleSpecification;
}

function nameExpression(): unknown[] {
  return ["coalesce", ["get", "name:latin"], ["get", "name_en"], ["get", "name"]];
}

function currentMapProjectionType(map: maplibregl.Map): GalleryMapProjection | null {
  try {
    const projection = map.getProjection();
    if (!projection || typeof projection.type !== "string") {
      return null;
    }
    return projection.type === "mercator" || projection.type === "globe" ? projection.type : null;
  } catch {
    return null;
  }
}

function trySnapshotMapCamera(map: maplibregl.Map): MapCameraState | null {
  try {
    return snapshotMapCamera(map);
  } catch {
    return null;
  }
}

function snapshotMapCamera(map: maplibregl.Map): MapCameraState {
  const center = map.getCenter();
  return {
    center: [center.lng, center.lat],
    zoom: map.getZoom(),
    bearing: map.getBearing(),
    pitch: map.getPitch()
  };
}

function absolutizeStyleUrl(urlValue: string): string {
  if (/^[a-z][a-z0-9+.-]*:/i.test(urlValue)) {
    return urlValue;
  }

  if (typeof window === "undefined") {
    return urlValue;
  }

  const tokenMatches = [...urlValue.matchAll(/\{[^}]+\}/g)];
  let normalizedUrl = urlValue;
  const placeholderMap = new Map<string, string>();

  for (const [index, match] of tokenMatches.entries()) {
    const token = match[0];
    const placeholder = `__ironmesh_style_token_${index}__`;
    normalizedUrl = normalizedUrl.replace(token, placeholder);
    placeholderMap.set(placeholder, token);
  }

  let absoluteUrl = new URL(normalizedUrl, window.location.href).toString();
  for (const [placeholder, token] of placeholderMap) {
    absoluteUrl = absoluteUrl.replace(placeholder, token);
  }

  return absoluteUrl;
}

function ensureMbtilesProtocolRegistered() {
  if (mbtilesProtocolRegistered) {
    return;
  }

  maplibregl.addProtocol(MBTILES_PROTOCOL, async (request, abortController) => {
    const sourceId = parseProtocolSourceId(request.url);
    const coordinates = parseProtocolTileCoordinates(request.url);
    const config = mbtilesConfigRegistry.get(sourceId);
    if (!config || !coordinates) {
      return {
        data: await decodeTileImage(
          {
            bytes: copyToUint8Array(TRANSPARENT_PNG_BYTES),
            mimeType: "image/png"
          },
          abortController.signal
        )
      };
    }

    const source = await loadMbtilesSource(sourceId, config);
    const tileData = await queryMbtilesTile(
      source,
      coordinates.z,
      coordinates.x,
      coordinates.y,
      abortController.signal
    );
    return { data: tileData };
  });

  mbtilesProtocolRegistered = true;
}

async function loadMbtilesSource(
  sourceId: string,
  basemap: GalleryRasterBasemapConfig
): Promise<MbtilesSource> {
  let existing = mbtilesSourceCache.get(sourceId);
  if (!existing) {
    existing = createMbtilesSource(basemap);
    mbtilesSourceCache.set(sourceId, existing);
  }
  return existing;
}

async function createMbtilesSource(basemap: GalleryRasterBasemapConfig): Promise<MbtilesSource> {
  const pageSize = await detectSqlitePageSize(basemap.logicalFileUrl);
  const worker = await createDbWorker(
    [
      {
        from: "inline",
        config: {
          serverMode: "full",
          requestChunkSize: pageSize,
          url: basemap.logicalFileUrl
        }
      }
    ],
    SQLJS_WORKER_URL,
    SQLJS_WASM_URL
  );

  const metadataRows = (await worker.db.query(
    "select name, value from metadata"
  )) as Array<{ name: string; value: string }>;

  return {
    worker,
    metadata: metadataFromRows(metadataRows)
  };
}

async function fetchMbtilesMetadata(metadataUrl: string | undefined): Promise<MbtilesMetadata> {
  if (!metadataUrl) {
    throw new Error("missing self-hosted basemap metadata URL");
  }

  const response = await fetch(metadataUrl, {
    credentials: "same-origin"
  });
  if (!response.ok) {
    throw new Error(`failed to load self-hosted basemap metadata: HTTP ${response.status}`);
  }

  const payload = (await response.json()) as Partial<{
    attribution: string;
    center: [number, number, number?];
    format: string;
    id: string;
    minzoom: number;
    maxzoom: number;
    name: string;
    version: string;
  }>;
  return {
    attribution: payload.attribution,
    center: payload.center,
    format: payload.format,
    id: payload.id,
    minzoom: payload.minzoom,
    maxzoom: payload.maxzoom,
    name: payload.name,
    version: payload.version
  };
}

async function detectSqlitePageSize(url: string): Promise<number> {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: {
      Range: "bytes=0-99"
    }
  });
  if (!(response.status === 200 || response.status === 206)) {
    throw new Error(`failed to inspect self-hosted basemap header: HTTP ${response.status}`);
  }

  const buffer = new Uint8Array(await response.arrayBuffer());
  if (buffer.length < 18) {
    throw new Error("self-hosted basemap header response is too small");
  }

  const signature = new TextDecoder().decode(buffer.slice(0, 16));
  if (signature !== "SQLite format 3\u0000") {
    throw new Error("self-hosted basemap is not a SQLite/MBTiles file");
  }

  const raw = (buffer[16] << 8) | buffer[17];
  if (raw === 1) {
    return 65536;
  }
  return raw > 0 ? raw : 4096;
}

async function queryMbtilesTile(
  source: MbtilesSource,
  zoomLevel: number,
  tileColumn: number,
  xyzTileRow: number,
  abortSignal?: AbortSignal
): Promise<HTMLImageElement | ImageBitmap> {
  const coordinates = normalizeTileCoordinates(zoomLevel, tileColumn, xyzTileRow);
  // sql.js-httpvfs parameter binding behaves inconsistently for this large MBTiles file.
  // Use a fully validated literal query for the hot tile lookup path instead.
  const rows = (await source.worker.db.query(
    buildTileLookupSql(coordinates)
  )) as Array<{ tile_data?: Uint8Array | ArrayLike<number> | ArrayBufferLike }>;
  const payload = payloadFromTileRow(rows[0]?.tile_data, source.metadata.format);

  return decodeTileImage(payload, abortSignal);
}

function normalizeTileCoordinates(
  zoomLevel: number,
  tileColumn: number,
  xyzTileRow: number
): TileCoordinates {
  if (
    !Number.isInteger(zoomLevel) ||
    !Number.isInteger(tileColumn) ||
    !Number.isInteger(xyzTileRow)
  ) {
    throw new Error("Invalid tile coordinates for self-hosted basemap");
  }

  return {
    zoomLevel,
    tileColumn,
    xyzTileRow,
    tmsTileRow: (1 << zoomLevel) - 1 - xyzTileRow
  };
}

function buildTileLookupSql(coordinates: TileCoordinates): string {
  return `select tile_data as tile_data from tiles where zoom_level = ${coordinates.zoomLevel} and tile_column = ${coordinates.tileColumn} and tile_row = ${coordinates.tmsTileRow} limit 1`;
}

function payloadFromTileRow(
  tileData: Uint8Array | ArrayLike<number> | ArrayBufferLike | undefined,
  declaredFormat?: string
): TileImagePayload {
  if (!tileData) {
    return {
      bytes: copyToUint8Array(TRANSPARENT_PNG_BYTES),
      mimeType: "image/png"
    };
  }

  const normalized =
    tileData instanceof Uint8Array ? tileData : new Uint8Array(tileData as ArrayLike<number>);
  const bytes = copyToUint8Array(normalized);
  return {
    bytes,
    mimeType: inferTileMimeType(bytes, declaredFormat)
  };
}

function metadataFromRows(rows: Array<{ name: string; value: string }>): MbtilesMetadata {
  const metadata = Object.fromEntries(rows.map((row) => [row.name, row.value]));
  return {
    attribution: metadata.attribution,
    format: metadata.format,
    minzoom: parseOptionalNumber(metadata.minzoom),
    maxzoom: parseOptionalNumber(metadata.maxzoom),
    center: parseCenter(metadata.center)
  };
}

function parseOptionalNumber(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseCenter(value: string | undefined): [number, number, number?] | undefined {
  if (!value) {
    return undefined;
  }

  const parts = value
    .split(",")
    .map((part) => Number(part.trim()))
    .filter((part) => Number.isFinite(part));
  if (parts.length < 2) {
    return undefined;
  }

  return [parts[0] ?? 0, parts[1] ?? 0, parts[2]];
}

function parseProtocolSourceId(urlValue: string): string {
  const url = new URL(urlValue);
  return url.hostname;
}

function parseProtocolTileCoordinates(urlValue: string): { z: number; x: number; y: number } | null {
  const url = new URL(urlValue);
  const [zRaw, xRaw, yRaw] = url.pathname.replace(/^\/+/, "").split("/");
  const z = Number(zRaw);
  const x = Number(xRaw);
  const y = Number(yRaw);
  if (!Number.isInteger(z) || !Number.isInteger(x) || !Number.isInteger(y)) {
    return null;
  }
  return { z, x, y };
}

function sourceIdForLogicalFile(url: string): string {
  let hash = 2166136261;
  for (let index = 0; index < url.length; index += 1) {
    hash ^= url.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `source-${Math.abs(hash >>> 0).toString(36)}`;
}

function copyToUint8Array(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

function inferTileMimeType(bytes: Uint8Array, declaredFormat?: string): string {
  const normalizedDeclared = normalizeTileFormat(declaredFormat);
  if (normalizedDeclared) {
    return normalizedDeclared;
  }

  if (
    bytes.byteLength >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return "image/png";
  }

  if (bytes.byteLength >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }

  if (
    bytes.byteLength >= 12 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x49 &&
    bytes[2] === 0x46 &&
    bytes[3] === 0x46 &&
    bytes[8] === 0x57 &&
    bytes[9] === 0x45 &&
    bytes[10] === 0x42 &&
    bytes[11] === 0x50
  ) {
    return "image/webp";
  }

  return "image/png";
}

function normalizeTileFormat(format: string | undefined): string | null {
  if (!format) {
    return null;
  }

  switch (format.trim().toLowerCase()) {
    case "jpg":
    case "jpeg":
      return "image/jpeg";
    case "png":
      return "image/png";
    case "webp":
      return "image/webp";
    default:
      return null;
  }
}

async function decodeTileImage(
  payload: TileImagePayload,
  abortSignal?: AbortSignal
): Promise<HTMLImageElement | ImageBitmap> {
  const blobBytes = copyToUint8Array(payload.bytes);
  const blobBuffer = new ArrayBuffer(blobBytes.byteLength);
  new Uint8Array(blobBuffer).set(blobBytes);
  const blob = new Blob([blobBuffer], { type: payload.mimeType });

  if (typeof createImageBitmap === "function") {
    try {
      return await decodeTileImageBitmap(blob, abortSignal);
    } catch {
      // Some JPEG tiles decode successfully via <img> even when createImageBitmap rejects.
      // Fall through to the HTMLImageElement path before surfacing an error.
    }
  }

  return decodeTileImageElement(blob, payload.mimeType, abortSignal);
}

async function decodeTileImageBitmap(
  blob: Blob,
  abortSignal?: AbortSignal
): Promise<ImageBitmap> {
  if (abortSignal?.aborted) {
    throw new DOMException("The operation was aborted.", "AbortError");
  }

  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(blob);
  } catch (error) {
    throw new Error(
      error instanceof Error ? error.message : "ImageBitmap decode failed"
    );
  }
  if (abortSignal?.aborted) {
    bitmap.close();
    throw new DOMException("The operation was aborted.", "AbortError");
  }
  return bitmap;
}

function decodeTileImageElement(
  blob: Blob,
  mimeType: string,
  abortSignal?: AbortSignal
): Promise<HTMLImageElement | ImageBitmap> {
  return new Promise((resolve, reject) => {
    const objectUrl = URL.createObjectURL(blob);
    const image = new Image();
    let settled = false;

    const cleanup = () => {
      image.onload = null;
      image.onerror = null;
      abortSignal?.removeEventListener("abort", handleAbort);
    };

    const finish = (callback: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };

    const handleAbort = () => {
      finish(() => {
        URL.revokeObjectURL(objectUrl);
        reject(new DOMException("The operation was aborted.", "AbortError"));
      });
    };

    image.onload = () => {
      finish(() => {
        void promoteDecodedImage(image, objectUrl)
          .then(resolve)
          .catch(() => {
            image.width = image.naturalWidth;
            image.height = image.naturalHeight;
            resolve(image);
          });
      });
    };
    image.onerror = () => {
      finish(() => {
        URL.revokeObjectURL(objectUrl);
        reject(new Error(`Failed to decode basemap tile as ${mimeType}`));
      });
    };

    if (abortSignal?.aborted) {
      handleAbort();
      return;
    }

    abortSignal?.addEventListener("abort", handleAbort, { once: true });
    image.src = objectUrl;
  });
}

async function promoteDecodedImage(
  image: HTMLImageElement,
  objectUrl: string
): Promise<ImageBitmap> {
  const canvas = document.createElement("canvas");
  canvas.width = image.naturalWidth;
  canvas.height = image.naturalHeight;
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("2d canvas context unavailable");
  }

  context.drawImage(image, 0, 0);

  if (typeof createImageBitmap !== "function") {
    throw new Error("ImageBitmap creation unavailable");
  }

  const bitmap = await createImageBitmap(canvas);
  URL.revokeObjectURL(objectUrl);
  return bitmap;
}

function useResolvedImageRequest(
  request: GalleryBasemapPreviewRequest | null | undefined
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

function requestSignature(request: GalleryBasemapPreviewRequest | null | undefined): string {
  if (!request) {
    return "";
  }

  const headers = JSON.stringify(
    Object.entries(request.headers ?? {}).sort(([left], [right]) => left.localeCompare(right))
  );
  return `${request.url}::${headers}`;
}

function base64ToUint8Array(value: string): Uint8Array {
  const bytes = atob(value);
  const result = new Uint8Array(bytes.length);
  for (let index = 0; index < bytes.length; index += 1) {
    result[index] = bytes.charCodeAt(index);
  }
  return result;
}
