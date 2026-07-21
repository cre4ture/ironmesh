import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { cargoDebugBinaryPath } from "./cargo-target.mjs";

const repoRoot = resolve(process.cwd(), "..");
const binaryPath = cargoDebugBinaryPath(repoRoot, "ironmesh");
const webUiPort = 18081;
const upstreamPort = 18082;
const upstreamOrigin = `http://127.0.0.1:${upstreamPort}`;
const mapManifestKey = "sys/maps/runtime-gallery.mbtiles.manifest.json";
const mapPartKey = "sys/maps/runtime-gallery.mbtiles.part-000000";
const mapPartBody = readFileSync(resolve(process.cwd(), "tests", "fixtures", "smoke.mbtiles"));
const tinyPngBody = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9WlH7u8AAAAASUVORK5CYII=",
  "base64"
);

const mapManifest = {
  manifest_version: 1,
  type: "split_logical_file",
  logical_format: "mbtiles",
  logical_key: "sys/maps/runtime-gallery.mbtiles",
  logical_size_bytes: mapPartBody.length,
  parts_count: 1,
  parts: [
    {
      part_id: "part-000000",
      key: mapPartKey,
      offset_bytes: 0,
      size_bytes: mapPartBody.length
    }
  ]
};

const mapConfiguration = {
  stored: true,
  configuration: {
    version: 1,
    active_variant_id: "natural-earth-globe",
    variants: [
      {
        id: "natural-earth-globe",
        label: "Natural Earth Globe",
        mode_label: "Globe",
        description: "Small global overview map.",
        attribution: "Made with Natural Earth.",
        kind: "raster",
        style: "raster",
        enabled: true,
        raster_manifest_key: mapManifestKey
      },
      {
        id: "natural-earth-labels",
        label: "Natural Earth Globe + labels",
        mode_label: "Labels",
        description: "Natural Earth base map with country, city, and border labels.",
        attribution: "Made with Natural Earth.",
        kind: "raster",
        style: "raster",
        enabled: true,
        raster_manifest_key: mapManifestKey
      },
      {
        id: "openmaptiles-street",
        label: "OpenMapTiles Street",
        mode_label: "Street",
        description: "Detailed global OpenMapTiles street map.",
        attribution: "Map data © OpenStreetMap contributors.",
        kind: "raster",
        style: "raster",
        enabled: true,
        raster_manifest_key: mapManifestKey
      }
    ]
  }
};

const galleryIndex = {
  prefix: "",
  depth: 4,
  entry_count: 1,
  total_entry_count: 1,
  offset: 0,
  limit: 24,
  has_more: false,
  media_summary: {
    ready_count: 1,
    pending_count: 0,
    incomplete_count: 0,
    image_count: 1,
    video_count: 0,
    geotagged_count: 1
  },
  entries: [
    {
      path: "gallery/runtime-map.png",
      entry_type: "key",
      version: "runtime-map-001",
      content_hash: "runtime-map-hash",
      size_bytes: 68,
      modified_at_unix: 1712345678,
      media: {
        status: "ready",
        content_fingerprint: "runtime-map-fingerprint",
        media_type: "image",
        mime_type: "image/png",
        width: 1,
        height: 1,
        taken_at_unix: 1712345678,
        gps: {
          latitude: 47.3769,
          longitude: 8.5417
        },
        thumbnail: {
          url: "/media/thumbnail?key=gallery%2Fruntime-map.png",
          profile: "grid",
          width: 1,
          height: 1,
          format: "png",
          size_bytes: 68
        }
      }
    }
  ]
};

function json(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  });
  response.end(JSON.stringify(body));
}

function binary(response, status, body, contentType) {
  response.writeHead(status, {
    "content-type": contentType,
    "content-length": String(body.length),
    "accept-ranges": "bytes"
  });
  response.end(body);
}

function rangeBinary(request, response, body, contentType) {
  const range = request.headers.range;
  if (!range) {
    if (request.method === "HEAD") {
      response.writeHead(200, {
        "content-type": contentType,
        "content-length": String(body.length),
        "accept-ranges": "bytes"
      });
      response.end();
      return;
    }
    binary(response, 200, body, contentType);
    return;
  }

  const match = /^bytes=(\d+)-(\d+)?$/i.exec(range);
  const start = Number(match?.[1] ?? "-1");
  const end = Math.min(Number(match?.[2] ?? String(body.length - 1)), body.length - 1);
  if (!match || start < 0 || start > end) {
    response.writeHead(416, {
      "accept-ranges": "bytes",
      "content-range": `bytes */${body.length}`
    });
    response.end();
    return;
  }

  const selected = body.subarray(start, end + 1);
  response.writeHead(206, {
    "content-type": contentType,
    "content-length": String(selected.length),
    "content-range": `bytes ${start}-${end}/${body.length}`,
    "accept-ranges": "bytes"
  });
  response.end(request.method === "HEAD" ? undefined : selected);
}

function upstreamRequest(request, response) {
  const url = new URL(request.url ?? "/", upstreamOrigin);
  if (request.method === "GET" && url.pathname === "/api/v1/maps/config") {
    json(response, 200, mapConfiguration);
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/snapshots") {
    json(response, 200, []);
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/store/index") {
    json(response, 200, galleryIndex);
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/v1/media/thumbnail") {
    binary(response, 200, tinyPngBody, "image/png");
    return;
  }
  if (
    (request.method === "GET" || request.method === "HEAD") &&
    url.pathname.startsWith("/api/v1/store/")
  ) {
    const key = decodeURIComponent(url.pathname.slice("/api/v1/store/".length));
    if (key === mapManifestKey) {
      const body = Buffer.from(JSON.stringify(mapManifest));
      binary(response, 200, body, "application/json; charset=utf-8");
      return;
    }
    if (key === mapPartKey) {
      rangeBinary(request, response, mapPartBody, "application/octet-stream");
      return;
    }
  }

  json(response, 404, { message: `runtime fixture has no route for ${request.method} ${url.pathname}` });
}

const upstream = createServer(upstreamRequest);
let clientProcess;
let shuttingDown = false;

function finish(exitCode) {
  upstream.close(() => process.exit(exitCode));
}

function stop(signal) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  if (clientProcess && !clientProcess.killed) {
    clientProcess.once("exit", () => finish(0));
    clientProcess.kill(signal);
    return;
  }
  finish(0);
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => stop(signal));
}

upstream.listen(upstreamPort, "127.0.0.1", () => {
  clientProcess = spawn(
    binaryPath,
    [
      "--server-base-url",
      upstreamOrigin,
      "serve-web",
      "--bind",
      `127.0.0.1:${webUiPort}`
    ],
    {
      cwd: repoRoot,
      env: {
        ...process.env,
        RUST_LOG: process.env.RUST_LOG ?? "info"
      },
      stdio: "inherit"
    }
  );

  clientProcess.on("exit", (code, signal) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    finish(signal ? 1 : (code ?? 1));
  });
  clientProcess.on("error", (error) => {
    if (shuttingDown) {
      return;
    }
    console.error(`failed to start client runtime: ${error.message}`);
    shuttingDown = true;
    finish(1);
  });
});
