import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { expect, test, type Page, type Route } from "@playwright/test";

const API_V1_PREFIX = "/api/v1";

function apiV1(path: string): string {
  return `${API_V1_PREFIX}${path}`;
}

test("client-ui smoke flow renders and performs core operations", async ({ page }) => {
  test.setTimeout(45_000);
  const uploadMetrics = await installClientUiMocks(page);
  const pageErrors: string[] = [];

  page.on("pageerror", (error) => {
    pageErrors.push(error.message);
  });

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("banner").getByText("cli-client-web", { exact: true })).toBeVisible();
  await expect(page.getByText("Transport-aware", { exact: true })).toBeVisible();
  await expect(page.getByText("Version info", { exact: true })).toBeVisible();
  await expect(page.getByText(/UI build:\s*0\.1\.0 \(/)).toBeVisible();
  await expect(page.getByText("Backend build: 0.1.0 (v0.1.0-3-gmocked)")).toBeVisible();
  await expect(page.getByText("Active route")).toBeVisible();
  await expect(page.getByText("Direct", { exact: true })).toBeVisible();
  await expect(page.getByText("node-alpha", { exact: true })).toBeVisible();
  await expect(page.getByText("https://node-alpha.local", { exact: true })).toBeVisible();

  await page.getByText("Store", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Store" })).toBeVisible();
  await page.getByRole("button", { name: "Upload text object" }).click();
  await expect(page.getByText('"key": "docs/readme.txt"')).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles([
    {
      name: "alpha.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.alloc(40, 0x61)
    },
    {
      name: "beta.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.alloc(32, 0x62)
    }
  ]);
  await page.getByRole("button", { name: "Add files to queue" }).click();
  await expect(page.getByText("images/alpha.bin", { exact: true })).toBeVisible();
  await expect(page.getByText("images/beta.bin", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /Uploads 0\/2|Uploads 1\/2|Uploads 2\/2/ })).toBeVisible();
  await expect(page.getByText(/Starting|Uploading/).first()).toBeVisible();
  await page
    .getByRole("row", { name: /alpha\.bin/ })
    .getByRole("button", { name: "Cancel" })
    .click();
  await expect(page.getByRole("row", { name: /alpha\.bin/ })).toContainText("Canceled");
  await page.locator('input[type="file"]').setInputFiles({
    name: "gamma.bin",
    mimeType: "application/octet-stream",
    buffer: Buffer.alloc(16, 0x63)
  });
  await expect(page.getByRole("button", { name: "Add files to queue" })).toBeEnabled();
  await page.getByRole("button", { name: "Add files to queue" }).click();
  await expect(page.getByText("images/gamma.bin", { exact: true })).toBeVisible();
  await page.getByText("Cluster", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Cluster" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Uploads \d\/3/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Uploads 2\/3.*1 canceled/ })).toBeVisible();
  await page.getByRole("button", { name: /Uploads 2\/3.*1 canceled/ }).click();
  await expect(page.getByRole("heading", { name: "Store" })).toBeVisible();
  await expect(page.getByText('"operation": "binary-upload-queue"')).toBeVisible();
  await expect(page.getByText('"active_concurrency": 2')).toBeVisible();
  await expect(page.getByText('"completed_files": 2')).toBeVisible();
  await expect(page.getByText('"canceled_files": 1')).toBeVisible();
  expect(uploadMetrics.maxConcurrentUploadIds()).toBeGreaterThan(1);
  expect(uploadMetrics.deletedUploadSessionIds()).toContain("upload-1");
  await page.getByRole("button", { name: "Download text object" }).click();
  await expect(page.getByLabel("Downloaded payload")).toHaveValue("hello from the mocked store");

  await page.getByText("Explorer", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Explorer" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: /Size/ })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: /Modified/ })).toBeVisible();
  await expect(page.getByRole("cell", { name: "docs/readme.txt" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "23 B" })).toBeVisible();
  await page.getByRole("button", { name: "Read" }).first().click();
  await expect(page.getByText("hello from the mocked store")).toBeVisible();
  const explorerDownload = page.waitForEvent("download");
  await page.getByRole("row", { name: /docs\/readme\.txt/ }).getByRole("button", { name: "Download" }).click();
  expect((await explorerDownload).suggestedFilename()).toBe("mock.bin");
  await page.getByRole("row", { name: /^docs\/\s+prefix/i }).getByRole("button", { name: "Open" }).click();
  await expect(page.getByRole("cell", { name: "readme.txt" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "nested/" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "docs/" })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: "gallery/" })).toHaveCount(0);
  await page.getByLabel("New folder name").fill("scratch");
  await page.getByRole("button", { name: "New folder" }).click();
  await expect(page.getByRole("cell", { name: "scratch/" })).toBeVisible();
  await page.locator('[data-explorer-upload-input="true"]').setInputFiles([
    {
      name: "quick-a.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.alloc(24, 0x71)
    },
    {
      name: "quick-b.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.alloc(12, 0x72)
    }
  ]);
  await expect(page.getByRole("heading", { name: "Store" })).toBeVisible();
  await expect(page.getByText("docs/quick-a.bin", { exact: true })).toBeVisible();
  await expect(page.getByText("docs/quick-b.bin", { exact: true })).toBeVisible();
  await page.getByText("Explorer", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Explorer" })).toBeVisible();
  await page.getByRole("row", { name: /^docs\/\s+prefix/i }).getByRole("button", { name: "Open" }).click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("row", { name: /scratch\/\s+prefix/i }).getByRole("button", { name: "Delete" }).click();
  await expect(page.getByRole("cell", { name: "scratch/" })).toHaveCount(0);
  page.once("dialog", (dialog) => dialog.accept("quick-c.bin"));
  await page.getByRole("row", { name: /quick-b\.bin/ }).getByRole("button", { name: "Rename" }).click();
  await expect(page.getByRole("cell", { name: "quick-c.bin" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "quick-b.bin" })).toHaveCount(0);
  await page.getByLabel("Key").fill("docs/readme.txt");
  await page.getByRole("button", { name: "Load versions" }).click();
  await expect(page.getByRole("cell", { name: "version-001" })).toBeVisible();

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();
  await expect(page.getByText("gallery/cat.png", { exact: true })).toBeVisible();
  await expect(page.getByText("gallery/clip.mp4", { exact: true })).toBeVisible();
  await expect(page.getByText("3 items")).toBeVisible();
  await expect(page.getByText("1 movie")).toBeVisible();
  const thumbnailsPerRowInput = page.getByLabel("Thumbnails per row");
  await thumbnailsPerRowInput.fill("8");
  await thumbnailsPerRowInput.blur();
  await expect(thumbnailsPerRowInput).toHaveValue("8");
  await page.getByText("clip.mp4", { exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.locator("video")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByText("Cluster", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Cluster" })).toBeVisible();
  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByLabel("Thumbnails per row")).toHaveValue("8");
  await page.reload();
  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByLabel("Thumbnails per row")).toHaveValue("8");
  await page.getByRole("button", { name: "Map" }).click();
  await expect(
    page.getByText("Using MapTiler Satellite 2017-11-02 Planet from your self-hosted basemap dataset.")
  ).toBeVisible();
  await expect(page.getByText("Self-hosted basemap unavailable")).toHaveCount(0);
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("2 markers")).toBeVisible();
  await page.getByRole("button", { name: "Fullscreen map" }).click();
  await expect(page.getByRole("button", { name: "Exit fullscreen map" })).toHaveCount(0);
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await page.getByRole("button", { name: "Open map marker for gallery/cat.png" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("Loading original image")).toBeVisible();
  await expect(page.getByText("Loading original image")).toHaveCount(0);
  await page.getByRole("button", { name: "Next item" }).click();
  await expect(page.getByRole("dialog").getByText("gallery/clip.mp4", { exact: true })).toBeVisible();
  await expect(page.locator("video")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.goBack();
  await expect(page.getByRole("button", { name: "Fullscreen map" })).toBeVisible();
  const prefixInput = page.getByLabel("Prefix");
  await page.getByRole("button", { name: "docs/", exact: true }).click();
  await expect(prefixInput).toHaveValue("docs/");
  await expect(page.getByRole("button", { name: "nested/", exact: true })).toBeVisible();
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await page.getByRole("button", { name: "nested/", exact: true }).click();
  await expect(prefixInput).toHaveValue("docs/nested/");
  await page.getByRole("button", { name: "Up one level" }).click();
  await expect(prefixInput).toHaveValue("docs/");
  await page.getByRole("button", { name: "Up one level" }).click();
  await expect(prefixInput).toHaveValue("");
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("2 markers")).toBeVisible();
  await page.getByRole("button", { name: "media/", exact: true }).click();
  await expect(prefixInput).toHaveValue("media/");
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("2 markers")).toBeVisible();
  await page.getByRole("button", { name: "Up one level" }).click();
  await expect(prefixInput).toHaveValue("");
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(pageErrors).toEqual([]);
  await page.getByRole("button", { name: "Grid" }).click();
  await page.getByLabel("Prefix").fill("docs/");
  await page.getByRole("button", { name: "Load" }).click();
  await expect(page.getByText("nested/", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Up one level")).toBeVisible();
  await expect(page.getByText("No media objects in view")).toHaveCount(0);
  await page.getByText("Up one level").click();
  await expect(page.getByText("gallery/cat.png", { exact: true })).toBeVisible();

  await page.getByText("Cluster", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Cluster" })).toBeVisible();
  await expect(page.getByText("Under replicated")).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"node_id": "node-alpha"' })).toBeVisible();
  await expect(page.getByText('"under_replicated": 1')).toBeVisible();

  const requestedPaths = uploadMetrics.requestedPaths();
  expect(requestedPaths).toEqual(
    expect.arrayContaining([
      apiV1("/ping"),
      apiV1("/health"),
      apiV1("/cluster/status"),
      apiV1("/rendezvous"),
      apiV1("/store/list"),
      apiV1("/store/uploads/start")
    ])
  );
  expect(requestedPaths.some((path) => path.startsWith(apiV1("/store/stream-binary")))).toBe(true);
  expect(requestedPaths.some((path) => path.startsWith(apiV1("/maps/")))).toBe(true);
  expect(requestedPaths).not.toContain("/api/ping");
  expect(requestedPaths).not.toContain("/api/health");
  expect(requestedPaths).not.toContain("/api/cluster/status");
  expect(requestedPaths).not.toContain("/api/store/list");
  expect(requestedPaths).not.toContain("/api/maps/logical-file");
});

test("client-ui gallery grid keeps multiple columns on narrow viewports", async ({ page }) => {
  test.setTimeout(45_000);

  await installClientUiMocks(page);
  await page.goto("/");
  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });

  const thumbnailsPerRowInput = page.getByLabel("Thumbnails per row");
  await thumbnailsPerRowInput.fill("8");
  await thumbnailsPerRowInput.blur();
  await expect(thumbnailsPerRowInput).toHaveValue("8");

  const galleryGrid = page.locator('[data-gallery-grid="true"]');
  await expect(galleryGrid).toBeVisible();
  await expect
    .poll(async () =>
      page.locator('[data-gallery-card="true"]').evaluateAll((nodes) => {
        if (nodes.length === 0) {
          return 0;
        }

        const firstRowTop = Math.round(nodes[0]!.getBoundingClientRect().top);
        return nodes.filter(
          (node) => Math.abs(Math.round(node.getBoundingClientRect().top) - firstRowTop) <= 1
        ).length;
      })
    )
    .toBeGreaterThanOrEqual(2);

  const gap = await galleryGrid.evaluate((node) => Number.parseFloat(getComputedStyle(node).gap));
  expect(gap).toBeLessThanOrEqual(10);

  const metadataToggle = page.getByLabel("Show metadata");
  await expect(metadataToggle).toBeChecked();
  await page.locator("label").filter({ hasText: "Show metadata" }).click();
  await expect(metadataToggle).not.toBeChecked();
  await expect(page.locator('[data-gallery-card-metadata="true"]')).toHaveCount(0);

  const collapsedGap = await galleryGrid.evaluate((node) =>
    Number.parseFloat(getComputedStyle(node).gap)
  );
  expect(collapsedGap).toBe(0);

  const previewHeightDelta = await page
    .locator('[data-gallery-card="true"]')
    .first()
    .evaluate((card) => {
      const aspectRatio = card.querySelector(".mantine-AspectRatio-root");
      if (!aspectRatio) {
        return null;
      }

      return Math.abs(
        card.getBoundingClientRect().height - aspectRatio.getBoundingClientRect().height
      );
    });
  expect(previewHeightDelta).not.toBeNull();
  expect(previewHeightDelta ?? Number.POSITIVE_INFINITY).toBeLessThanOrEqual(1);

  const borderWidth = await page
    .locator('[data-gallery-card="true"]')
    .first()
    .evaluate((node) => Number.parseFloat(getComputedStyle(node).borderTopWidth));
  expect(borderWidth).toBe(0);

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.reload();
  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByLabel("Show metadata")).not.toBeChecked();
  await expect(page.locator('[data-gallery-card-metadata="true"]')).toHaveCount(0);
});

test("client-ui desktop navigation can collapse and scroll on short viewports", async ({ page }) => {
  test.setTimeout(45_000);

  await installClientUiMocks(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  const desktopSidebarToggle = page.getByRole("button", { name: "Toggle navigation sidebar" });
  const primaryNavigation = page.getByLabel("Primary navigation");
  await expect(desktopSidebarToggle).toBeVisible();
  await expect(primaryNavigation).toBeVisible();

  await page.setViewportSize({ width: 1280, height: 320 });
  const navbarScrollViewport = page.locator(".shell-navbar .mantine-ScrollArea-viewport");
  await expect(navbarScrollViewport).toBeVisible();
  const navbarScrollTop = await navbarScrollViewport.evaluate((node) => {
    node.scrollTop = 999;
    return node.scrollTop;
  });
  expect(navbarScrollTop).toBeGreaterThan(0);
  const navbarRightBeforeCollapse = await primaryNavigation.evaluate(
    (node) => node.getBoundingClientRect().right
  );
  expect(navbarRightBeforeCollapse).toBeGreaterThan(0);

  await desktopSidebarToggle.click();
  await expect
    .poll(async () => primaryNavigation.evaluate((node) => node.getBoundingClientRect().right))
    .toBeLessThanOrEqual(0);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await desktopSidebarToggle.click();
  await expect
    .poll(async () => primaryNavigation.evaluate((node) => node.getBoundingClientRect().right))
    .toBeGreaterThan(0);
  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();
});

async function installClientUiMocks(page: Page) {
  const imageBody = tinyPngBuffer();
  const movieBody = Buffer.from("mock-movie-payload");
  const logicalMapBody = readFileSync("tests/fixtures/smoke.mbtiles");
  const emptyVectorTileBody = gzipSync(Buffer.alloc(0));
  const glyphRangeBody = Buffer.alloc(0);
  let uploadSessionStartCount = 0;
  const uploadSizes = new Map<string, number>();
  const uploadKeys = new Map<string, string>();
  let maxConcurrentUploadIds = 0;
  const activeUploadIds = new Set<string>();
  const deletedUploadSessionIds = new Set<string>();
  const requestedPaths = new Set<string>();
  const storeEntries = createMockStoreEntries();

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const { pathname, searchParams } = url;
    const method = route.request().method();
    requestedPaths.add(pathname);

    if (pathname === apiV1("/ping") && method === "GET") {
      return json(route, {
        ok: true,
        service: "cli-client-web",
        backend_version: "0.1.0",
        backend_revision: "v0.1.0-3-gmocked"
      });
    }

    if (pathname === apiV1("/health") && method === "GET") {
      return json(route, { mode: "cluster", status: "ok" });
    }

    if (pathname === apiV1("/cluster/status") && method === "GET") {
      return json(route, {
        local_node_id: "node-alpha",
        total_nodes: 2,
        online_nodes: 2,
        offline_nodes: 0,
        policy: {
          replication_factor: 2
        }
      });
    }

    if (pathname === apiV1("/rendezvous") && method === "GET") {
      return json(route, {
        available: true,
        editable: true,
        transport_mode: "direct",
        relay_mode: "preferred",
        configured_urls: ["https://rendezvous-a.local:9443"],
        direct_url: "https://node-alpha.local",
        direct_target_node_id: "node-alpha",
        active_url: null,
        active_target_node_id: null,
        mtls_required: true,
        persistence_source: "bootstrap_file",
        last_probe_error: null,
        endpoint_statuses: [
          {
            url: "https://rendezvous-a.local:9443",
            status: "connected",
            last_attempt_unix: 1_712_345_600,
            last_success_unix: 1_712_345_600,
            consecutive_failures: 0,
            last_error: null,
            active: false
          }
        ]
      });
    }

    if (pathname === apiV1("/store/put") && method === "POST") {
      const body = route.request().postDataJSON() as { key: string; value: string };
      if (body.key.endsWith("/")) {
        upsertMockFolderEntry(storeEntries, body.key);
      }
      return json(route, {
        key: body.key,
        size_bytes: body.value.length
      });
    }

    if (pathname === apiV1("/store/get") && method === "GET") {
      if (searchParams.get("preview_bytes")) {
        expect(searchParams.get("preview_bytes")).toBe("1024");
        return json(route, {
          key: searchParams.get("key"),
          value: "hello from the mocked store",
          version: searchParams.get("version"),
          snapshot: searchParams.get("snapshot"),
          truncated: false,
          total_size_bytes: 27,
          preview_size_bytes: 27
        });
      }
      return json(route, {
        key: searchParams.get("key"),
        value: "hello from the mocked store",
        version: searchParams.get("version"),
        snapshot: searchParams.get("snapshot")
      });
    }

    if (pathname === apiV1("/store/delete") && method === "DELETE") {
      deleteMockStorePath(storeEntries, searchParams.get("key") ?? "");
      return json(route, {
        key: searchParams.get("key"),
        deleted: true
      });
    }

    if (pathname === apiV1("/store/rename") && method === "POST") {
      const body = route.request().postDataJSON() as {
        from_path: string;
        to_path: string;
      };
      renameMockStorePath(storeEntries, body.from_path, body.to_path);
      return json(route, {
        from_path: body.from_path,
        to_path: body.to_path,
        renamed: true
      });
    }

    if (pathname === apiV1("/maps/logical-file")) {
      const rangeHeader = route.request().headers().range;
      const commonHeaders = {
        "accept-ranges": "bytes",
        "content-type": "application/octet-stream",
        etag: "\"client-ui-smoke-mbtiles\""
      };

      if (method === "HEAD") {
        await route.fulfill({
          status: 200,
          headers: {
            ...commonHeaders,
            "content-length": String(logicalMapBody.length)
          }
        });
        return;
      }

      if (method === "GET") {
        if (!rangeHeader) {
          await route.fulfill({
            status: 200,
            headers: {
              ...commonHeaders,
              "content-length": String(logicalMapBody.length)
            },
            body: logicalMapBody
          });
          return;
        }

        const match = /^bytes=(\d+)-(\d+)?$/i.exec(rangeHeader);
        expect(match).not.toBeNull();
        const start = Number(match?.[1] ?? "0");
        const inclusiveEnd = Math.min(
          Number(match?.[2] ?? String(logicalMapBody.length - 1)),
          logicalMapBody.length - 1
        );
        const sliced = logicalMapBody.subarray(start, inclusiveEnd + 1);
        await route.fulfill({
          status: 206,
          headers: {
            ...commonHeaders,
            "content-length": String(sliced.length),
            "content-range": `bytes ${start}-${inclusiveEnd}/${logicalMapBody.length}`
          },
          body: sliced
        });
        return;
      }
    }

    if (pathname === apiV1("/maps/mbtiles-metadata") && method === "GET") {
      return json(route, {
        attribution: "Imagery Copyright MapTiler 2017. Data Copyright OpenStreetMap contributors.",
        center: [0, 20, 1],
        format: "png",
        minzoom: 0,
        maxzoom: 2
      });
    }

    if (pathname.startsWith(apiV1("/maps/tiles/")) && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "image/png",
          "cache-control": "public, max-age=3600"
        },
        body: imageBody
      });
      return;
    }

    if (pathname.startsWith(apiV1("/maps/vector-tiles/")) && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/vnd.mapbox-vector-tile",
          "content-encoding": "gzip",
          "cache-control": "public, max-age=3600"
        },
        body: emptyVectorTileBody
      });
      return;
    }

    if (pathname.startsWith(apiV1("/maps/fonts/")) && method === "GET") {
      await route.fulfill({
        status: 200,
        headers: {
          "content-type": "application/x-protobuf",
          "cache-control": "public, max-age=3600"
        },
        body: glyphRangeBody
      });
      return;
    }

    if (pathname === apiV1("/store/list") && method === "GET") {
      expect(searchParams.get("view")).toBe("tree");
      const prefix = searchParams.get("prefix") ?? "";
      return json(route, {
        prefix,
        depth: Number(searchParams.get("depth") ?? "1"),
        entry_count: storeEntries.length,
        entries: storeEntries
      });
    }

    if (pathname === apiV1("/media/thumbnail") && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "image/png",
        body: imageBody
      });
      return;
    }

    if (pathname === apiV1("/snapshots") && method === "GET") {
      return json(route, [{ id: "snapshot-001" }]);
    }

    if (pathname === apiV1("/versions") && method === "GET") {
      return json(route, {
        key: searchParams.get("key"),
        versions: [{ version_id: "version-001" }, { version_id: "version-000" }]
      });
    }

    if (pathname === apiV1("/cluster/nodes") && method === "GET") {
      return json(route, [
        { node_id: "node-alpha", status: "online" },
        { node_id: "node-beta", status: "online" }
      ]);
    }

    if (pathname === apiV1("/cluster/replication/plan") && method === "GET") {
      return json(route, {
        under_replicated: 1,
        over_replicated: 0,
        items: [{ key: "docs/readme.txt" }]
      });
    }

    if (pathname === apiV1("/store/uploads/start") && method === "POST") {
      uploadSessionStartCount += 1;
      const body = route.request().postDataJSON() as {
        key: string;
        total_size_bytes: number;
      };
      const uploadId = `upload-${uploadSessionStartCount}`;
      uploadSizes.set(uploadId, body.total_size_bytes);
      uploadKeys.set(uploadId, body.key);
      return json(route, {
        upload_id: uploadId,
        key: body.key,
        total_size_bytes: body.total_size_bytes,
        chunk_size_bytes: 4,
        chunk_count: Math.ceil(body.total_size_bytes / 4),
        received_indexes: [],
        completed: false
      });
    }

    if (/^\/api\/v1\/store\/uploads\/[^/]+\/chunk\/\d+$/.test(pathname) && method === "PUT") {
      const uploadId = pathname.split("/")[5] ?? "upload-unknown";
      const index = Number(pathname.split("/").pop() ?? "0");
      activeUploadIds.add(uploadId);
      maxConcurrentUploadIds = Math.max(maxConcurrentUploadIds, activeUploadIds.size);
      try {
        await new Promise((resolve) => setTimeout(resolve, 75));
        await json(route, {
          stored: true,
          received_index: index
        });
      } catch {
        return;
      } finally {
        activeUploadIds.delete(uploadId);
      }
      return;
    }

    if (/^\/api\/v1\/store\/uploads\/[^/]+\/complete$/.test(pathname) && method === "POST") {
      const uploadId = pathname.split("/")[5] ?? "upload-unknown";
      const key = uploadKeys.get(uploadId) ?? `uploads/${uploadId}.bin`;
      const totalSizeBytes = uploadSizes.get(uploadId) ?? 21;
      upsertMockBinaryEntry(storeEntries, key, totalSizeBytes);
      return json(route, {
        snapshot_id: "snapshot-001",
        version_id: "version-002",
        manifest_hash: "manifest-upload",
        state: "ready",
        new_chunks: Math.ceil(totalSizeBytes / 4),
        dedup_reused_chunks: 0,
        created_new_version: true,
        total_size_bytes: totalSizeBytes
      });
    }

    if (/^\/api\/v1\/store\/uploads\/[^/]+$/.test(pathname) && method === "DELETE") {
      deletedUploadSessionIds.add(pathname.split("/")[5] ?? "upload-unknown");
      await route.fulfill({
        status: 204
      });
      return;
    }

    if (pathname === apiV1("/store/stream-binary") && method === "GET") {
      if (
        searchParams.get("key") === "gallery/cat.png" ||
        searchParams.get("key") === "gallery/dog.jpg"
      ) {
        await new Promise((resolve) => setTimeout(resolve, 250));
        await route.fulfill({
          status: 200,
          contentType: "image/png",
          body: imageBody
        });
        return;
      }
      if (searchParams.get("key") === "gallery/clip.mp4") {
        await route.fulfill({
          status: 200,
          contentType: "video/mp4",
          headers: {
            "accept-ranges": "bytes",
            "content-disposition": 'inline; filename="clip.mp4"'
          },
          body: movieBody
        });
        return;
      }
    }

    if (pathname === apiV1("/store/get-binary") && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/octet-stream",
        headers: {
          "content-disposition": "attachment; filename=\"mock.bin\""
        },
        body: "mock-binary"
      });
      return;
    }

    return route.continue();
  });

  return {
    maxConcurrentUploadIds: () => maxConcurrentUploadIds,
    deletedUploadSessionIds: () => Array.from(deletedUploadSessionIds),
    requestedPaths: () => Array.from(requestedPaths)
  };
}

async function json(route: Route, payload: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(payload)
  });
}

type MockStoreEntry = {
  path: string;
  entry_type: "prefix" | "key";
  size_bytes?: number;
  modified_at_unix?: number;
  media?: Record<string, unknown>;
};

function createMockStoreEntries(): MockStoreEntry[] {
  return [
    { path: "docs/", entry_type: "prefix" },
    {
      path: "docs/readme.txt",
      entry_type: "key",
      size_bytes: 23,
      modified_at_unix: 1_712_345_600
    },
    { path: "docs/nested/", entry_type: "prefix" },
    { path: "media/", entry_type: "prefix" },
    {
      path: "gallery/cat.png",
      entry_type: "key",
      size_bytes: 3_145_728,
      modified_at_unix: 1_712_345_678,
      media: {
        status: "ready",
        content_fingerprint: "fingerprint-cat",
        media_type: "image",
        mime_type: "image/png",
        width: 1024,
        height: 768,
        taken_at_unix: 1712345678,
        gps: {
          latitude: 47.3769,
          longitude: 8.5417
        },
        thumbnail: {
          url: "/media/thumbnail?key=gallery%2Fcat.png",
          profile: "grid",
          width: 256,
          height: 192,
          format: "jpeg",
          size_bytes: 1234
        }
      }
    },
    {
      path: "gallery/dog.jpg",
      entry_type: "key",
      size_bytes: 2_048,
      modified_at_unix: 1_712_300_000,
      media: {
        status: "pending",
        content_fingerprint: "fingerprint-dog",
        media_type: "image",
        mime_type: "image/jpeg",
        gps: {
          latitude: 40.7128,
          longitude: -74.006
        },
        thumbnail: {
          url: "/media/thumbnail?key=gallery%2Fdog.jpg",
          profile: "grid",
          width: 256,
          height: 256,
          format: "jpeg",
          size_bytes: 0
        }
      }
    },
    {
      path: "gallery/clip.mp4",
      entry_type: "key",
      size_bytes: 48_000_000,
      modified_at_unix: 1_712_250_000,
      media: {
        status: "ready",
        content_fingerprint: "fingerprint-clip",
        media_type: "video",
        mime_type: "video/mp4",
        width: 1920,
        height: 1080
      }
    }
  ];
}

function upsertMockFolderEntry(entries: MockStoreEntry[], key: string) {
  const normalized = normalizeMockFolderKey(key);
  if (!normalized) {
    return;
  }
  const existing = entries.find((entry) => entry.path === normalized);
  if (existing) {
    existing.entry_type = "prefix";
    return;
  }
  entries.push({
    path: normalized,
    entry_type: "prefix"
  });
}

function upsertMockBinaryEntry(entries: MockStoreEntry[], key: string, sizeBytes: number) {
  const normalized = key.trim();
  if (!normalized) {
    return;
  }
  const existing = entries.find((entry) => entry.path === normalized);
  if (existing) {
    existing.entry_type = "key";
    existing.size_bytes = sizeBytes;
    existing.modified_at_unix = 1_712_345_900;
    delete existing.media;
    return;
  }
  entries.push({
    path: normalized,
    entry_type: "key",
    size_bytes: sizeBytes,
    modified_at_unix: 1_712_345_900
  });
}

function deleteMockStorePath(entries: MockStoreEntry[], key: string) {
  const normalized = key.trim();
  if (!normalized) {
    return;
  }
  if (normalized.endsWith("/")) {
    const survivors = entries.filter((entry) => !entry.path.startsWith(normalized));
    entries.splice(0, entries.length, ...survivors);
    return;
  }
  const survivors = entries.filter((entry) => entry.path !== normalized);
  entries.splice(0, entries.length, ...survivors);
}

function renameMockStorePath(entries: MockStoreEntry[], fromPath: string, toPath: string) {
  const normalizedFrom = fromPath.trim();
  const normalizedTo = toPath.trim();
  if (!normalizedFrom || !normalizedTo) {
    return;
  }

  const entry = entries.find((candidate) => candidate.path === normalizedFrom);
  if (entry) {
    entry.path = normalizedTo;
  }
}

function normalizeMockFolderKey(key: string): string {
  const normalized = key
    .split("/")
    .map((segment) => segment.trim())
    .filter(Boolean)
    .join("/");
  return normalized ? `${normalized}/` : "";
}

function tinyPngBuffer(): Buffer {
  return Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0N8AAAAASUVORK5CYII=",
    "base64"
  );
}
