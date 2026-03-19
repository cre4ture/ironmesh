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
  await expect(page.getByRole("cell", { name: "docs/readme.txt" })).toBeVisible();
  await page.getByRole("button", { name: "Read" }).first().click();
  await expect(page.getByText("hello from the mocked store")).toBeVisible();
  await page.getByLabel("Key").fill("docs/readme.txt");
  await page.getByRole("button", { name: "Load versions" }).click();
  await expect(page.getByRole("cell", { name: "version-001" })).toBeVisible();

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
      return json(route, {
        entries: [
          { path: "docs/readme.txt", entry_type: "key" },
          { path: "media/", entry_type: "prefix" }
        ]
      });
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
