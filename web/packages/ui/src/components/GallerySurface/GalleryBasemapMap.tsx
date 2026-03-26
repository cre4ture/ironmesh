import { Alert, Badge, Card, Center, Loader, Stack, Text } from "@mantine/core";
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

export type GalleryBasemapConfig = {
  logicalFileUrl: string;
  attribution?: string;
  label?: string;
};

type GalleryBasemapMapProps = {
  basemap: GalleryBasemapConfig;
  entries: GalleryBasemapMapEntry[];
  hiddenOnMapCount: number;
  selectedPath: string | null;
  getMarkerRequest: (entry: GalleryBasemapMapEntry) => GalleryBasemapPreviewRequest;
  onSelectPath: (path: string) => void;
  fallback: ReactNode;
};

type MbtilesSource = {
  worker: WorkerHttpvfs;
  metadata: MbtilesMetadata;
};

type MbtilesMetadata = {
  attribution?: string;
  minzoom?: number;
  maxzoom?: number;
  center?: [number, number, number?];
};

const mbtilesSourceCache = new Map<string, Promise<MbtilesSource>>();
const mbtilesConfigRegistry = new Map<string, GalleryBasemapConfig>();
let mbtilesProtocolRegistered = false;

export function GalleryBasemapMap({
  basemap,
  entries,
  hiddenOnMapCount,
  selectedPath,
  getMarkerRequest,
  onSelectPath,
  fallback
}: GalleryBasemapMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const [mapReady, setMapReady] = useState(false);
  const [mapError, setMapError] = useState<string | null>(null);
  const [viewportVersion, setViewportVersion] = useState(0);
  const [fitSignature, setFitSignature] = useState("");
  const sourceId = sourceIdForLogicalFile(basemap.logicalFileUrl);
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
    mbtilesConfigRegistry.set(sourceId, basemap);
    ensureMbtilesProtocolRegistered();

    async function start() {
      try {
        const source = await loadMbtilesSource(sourceId, basemap);
        if (cancelled || !containerRef.current) {
          return;
        }

        map = new maplibregl.Map({
          container: containerRef.current,
          style: buildRasterStyle(sourceId, source.metadata, basemap),
          center: source.metadata.center
            ? ([source.metadata.center[0], source.metadata.center[1]] as LngLatLike)
            : ([0, 20] as LngLatLike),
          zoom: source.metadata.center?.[2] ?? 1.2
        });

        const bumpViewport = () => setViewportVersion((current) => current + 1);
        let ready = false;
        const markReady = () => {
          if (cancelled || ready) {
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
        mapRef.current = map;
        markReady();
      } catch (error) {
        if (!cancelled) {
          setMapError(error instanceof Error ? error.message : "Failed to load self-hosted basemap");
        }
      }
    }

    void start();

    return () => {
      cancelled = true;
      setFitSignature("");
      if (map) {
        map.remove();
      }
      mapRef.current = null;
    };
  }, [basemap.attribution, basemap.logicalFileUrl, basemap.label, sourceId]);

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

  if (mapError) {
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

  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="md">
        <div>
          <Text fw={700}>Geo-tagged world map</Text>
          <Text size="sm" c="dimmed">
            {basemap.label
              ? `Using ${basemap.label} from your self-hosted basemap dataset.`
              : "Using your self-hosted basemap dataset."}
          </Text>
        </div>

        <div
          aria-label="Geotagged gallery map"
          style={{
            position: "relative",
            aspectRatio: "16 / 9",
            overflow: "hidden",
            borderRadius: "calc(var(--mantine-radius-md) - 2px)",
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
                    key={`${entry.path}:${viewportVersion}`}
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
        </div>
      </Stack>
    </Card>
  );
}

type GalleryBasemapMarkerProps = {
  entry: GalleryBasemapMapEntry;
  request: GalleryBasemapPreviewRequest;
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

function buildRasterStyle(
  sourceId: string,
  metadata: MbtilesMetadata,
  basemap: GalleryBasemapConfig
): StyleSpecification {
  return {
    version: 8,
    glyphs: "",
    sources: {
      basemap: {
        type: "raster",
        tiles: [`${MBTILES_PROTOCOL}://${sourceId}/{z}/{x}/{y}`],
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

function ensureMbtilesProtocolRegistered() {
  if (mbtilesProtocolRegistered) {
    return;
  }

  maplibregl.addProtocol(MBTILES_PROTOCOL, async (request) => {
    const sourceId = parseProtocolSourceId(request.url);
    const coordinates = parseProtocolTileCoordinates(request.url);
    const config = mbtilesConfigRegistry.get(sourceId);
    if (!config || !coordinates) {
      return { data: copyToArrayBuffer(TRANSPARENT_PNG_BYTES) };
    }

    const source = await loadMbtilesSource(sourceId, config);
    const tileData = await queryMbtilesTile(source, coordinates.z, coordinates.x, coordinates.y);
    return { data: tileData };
  });

  mbtilesProtocolRegistered = true;
}

async function loadMbtilesSource(
  sourceId: string,
  basemap: GalleryBasemapConfig
): Promise<MbtilesSource> {
  let existing = mbtilesSourceCache.get(sourceId);
  if (!existing) {
    existing = createMbtilesSource(basemap);
    mbtilesSourceCache.set(sourceId, existing);
  }
  return existing;
}

async function createMbtilesSource(basemap: GalleryBasemapConfig): Promise<MbtilesSource> {
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
  xyzTileRow: number
): Promise<ArrayBuffer> {
  const tmsTileRow = (1 << zoomLevel) - 1 - xyzTileRow;
  const rows = (await source.worker.db.query(
    "select tile_data as tile_data from tiles where zoom_level = ? and tile_column = ? and tile_row = ? limit 1",
    zoomLevel,
    tileColumn,
    tmsTileRow
  )) as Array<{ tile_data?: Uint8Array | ArrayLike<number> | ArrayBufferLike }>;
  const tileData = rows[0]?.tile_data;
  if (!tileData) {
    return copyToArrayBuffer(TRANSPARENT_PNG_BYTES);
  }
  const normalized =
    tileData instanceof Uint8Array ? tileData : new Uint8Array(tileData as ArrayLike<number>);
  return copyToArrayBuffer(normalized);
}

function metadataFromRows(rows: Array<{ name: string; value: string }>): MbtilesMetadata {
  const metadata = Object.fromEntries(rows.map((row) => [row.name, row.value]));
  return {
    attribution: metadata.attribution,
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

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
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
