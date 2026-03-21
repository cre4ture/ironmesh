import { expect, test, type Page, type Route } from "@playwright/test";

test("client-ui smoke flow renders and performs core operations", async ({ page }) => {
  await installClientUiMocks(page);

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("banner").getByText("cli-client-web", { exact: true })).toBeVisible();
  await expect(page.getByText("Transport-aware", { exact: true })).toBeVisible();

  await page.getByText("Store", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Store" })).toBeVisible();
  await page.getByRole("button", { name: "Upload text object" }).click();
  await expect(page.getByText('"key": "docs/readme.txt"')).toBeVisible();
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
  await page.getByLabel("Key").fill("docs/readme.txt");
  await page.getByRole("button", { name: "Load versions" }).click();
  await expect(page.getByRole("cell", { name: "version-001" })).toBeVisible();

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();
  await expect(page.getByText("gallery/cat.png", { exact: true })).toBeVisible();
  await expect(page.getByText("2 images")).toBeVisible();
  const thumbnailsPerRowInput = page.getByRole("textbox", { name: "Thumbnails per row" });
  await thumbnailsPerRowInput.click();
  await page.getByRole("option", { name: "4 per row" }).click();
  await expect(thumbnailsPerRowInput).toHaveValue("4 per row");

  await page.getByText("Cluster", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Cluster" })).toBeVisible();
  await expect(page.getByText("Under replicated")).toBeVisible();
  await expect(page.getByText('"node-alpha"')).toBeVisible();
  await expect(page.getByText('"under_replicated": 1')).toBeVisible();
});

async function installClientUiMocks(page: Page) {
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const { pathname, searchParams } = url;
    const method = route.request().method();

    if (pathname === "/api/ping" && method === "GET") {
      return json(route, { ok: true, service: "cli-client-web" });
    }

    if (pathname === "/api/health" && method === "GET") {
      return json(route, { mode: "local_edge", status: "ok" });
    }

    if (pathname === "/api/cluster/status" && method === "GET") {
      return json(route, {
        total_nodes: 2,
        online_nodes: 2,
        offline_nodes: 0,
        policy: {
          replication_factor: 2
        }
      });
    }

    if (pathname === "/api/store/put" && method === "POST") {
      const body = route.request().postDataJSON() as { key: string; value: string };
      return json(route, {
        key: body.key,
        size_bytes: body.value.length
      });
    }

    if (pathname === "/api/store/get" && method === "GET") {
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

    if (pathname === "/api/store/delete" && method === "DELETE") {
      return json(route, {
        key: searchParams.get("key"),
        deleted: true
      });
    }

    if (pathname === "/api/store/list" && method === "GET") {
      expect(searchParams.get("view")).toBe("tree");
      const prefix = searchParams.get("prefix") ?? "";
      if (prefix === "docs/") {
        return json(route, {
          prefix,
          depth: Number(searchParams.get("depth") ?? "1"),
          entry_count: 4,
          entries: [
            { path: "docs/", entry_type: "prefix" },
            {
              path: "docs/readme.txt",
              entry_type: "key",
              size_bytes: 23,
              modified_at_unix: 1_712_345_600
            },
            { path: "docs/nested/", entry_type: "prefix" },
            { path: "gallery/", entry_type: "prefix" }
          ]
        });
      }
      return json(route, {
        prefix,
        depth: Number(searchParams.get("depth") ?? "1"),
        entry_count: 5,
        entries: [
          { path: "docs/", entry_type: "prefix" },
          {
            path: "docs/readme.txt",
            entry_type: "key",
            size_bytes: 23,
            modified_at_unix: 1_712_345_600
          },
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
              thumbnail: {
                url: "/media/thumbnail?key=gallery%2Fdog.jpg",
                profile: "grid",
                width: 256,
                height: 256,
                format: "jpeg",
                size_bytes: 0
              }
            }
          }
        ]
      });
    }

    if (pathname === "/media/thumbnail" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "image/jpeg",
        body: Buffer.from([255, 216, 255, 217])
      });
      return;
    }

    if (pathname === "/api/snapshots" && method === "GET") {
      return json(route, [{ id: "snapshot-001" }]);
    }

    if (pathname === "/api/versions" && method === "GET") {
      return json(route, {
        key: searchParams.get("key"),
        versions: [{ version_id: "version-001" }, { version_id: "version-000" }]
      });
    }

    if (pathname === "/api/cluster/nodes" && method === "GET") {
      return json(route, [
        { node_id: "node-alpha", status: "online" },
        { node_id: "node-beta", status: "online" }
      ]);
    }

    if (pathname === "/api/cluster/replication/plan" && method === "GET") {
      return json(route, {
        under_replicated: 1,
        over_replicated: 0,
        items: [{ key: "docs/readme.txt" }]
      });
    }

    if (pathname === "/api/store/put-binary" && method === "POST") {
      return json(route, {
        key: searchParams.get("key"),
        size_bytes: 1234,
        upload_mode: "direct"
      });
    }

    if (pathname === "/api/store/get-binary" && method === "GET") {
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
}

async function json(route: Route, payload: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(payload)
  });
}
