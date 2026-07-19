import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { expect, test, type Page, type Route } from "@playwright/test";

const API_V1_PREFIX = "/api/v1";

function apiV1(path: string): string {
  return `${API_V1_PREFIX}${path}`;
}

test("server-admin runtime smoke flow renders and navigates", async ({ page }) => {
  const mockState = await installServerAdminMocks(page);

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
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
  await desktopSidebarToggle.click();
  await expect
    .poll(async () => primaryNavigation.evaluate((node) => node.getBoundingClientRect().right))
    .toBeLessThanOrEqual(0);
  await desktopSidebarToggle.click();
  await expect
    .poll(async () => primaryNavigation.evaluate((node) => node.getBoundingClientRect().right))
    .toBeGreaterThan(0);
  await page.setViewportSize({ width: 1280, height: 800 });
  await expect(page.getByText("Version info", { exact: true })).toBeVisible();
  await expect(page.getByText(/UI build:\s*\S+\s+\(.+\)/)).toBeVisible();
  await expect(page.getByText("Backend build: 0.1.0 (v0.1.0-5-gmocked)")).toBeVisible();
  await expect(page.getByText("0 discovered")).toBeVisible();
  await expect(page.getByText("This node", { exact: true })).toBeVisible();
  await expect(page.getByText("Rendezvous participation", { exact: true })).toBeVisible();
  await expect(page.getByText("Storage stats", { exact: true })).toBeVisible();
  await expect(page.getByText(/live rendezvous registration details here\./i)).toBeVisible();

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  // Storage stats require admin auth — verify chart content is visible after login
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Collected at (UTC)" })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Storage used (bytes)" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom in on storage history chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom out of storage history chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset storage history chart zoom" })).toBeVisible();
  await expect(page.getByRole("button", { name: "30d", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "All", exact: true })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Chunk Store" })).toBeVisible();
  await expect(page.getByText("Latest snapshot ID:")).toBeVisible();
  await expect(page.getByText("Snapshot logical size:")).toBeVisible();
  await expect(page.getByRole("cell", { name: "node-alpha", exact: true }).first()).toBeVisible();
  await expect(page.locator("td").filter({ hasText: /logical/ }).first()).toBeVisible();
  await expect(page.getByRole("code").filter({ hasText: "https://node-alpha.local" })).toBeVisible();
  await expect(
    page
      .getByRole("paragraph")
      .filter({ hasText: "Embedded listener: https://embedded-rendezvous.local:9443" })
      .getByRole("code")
  ).toBeVisible();

  await page
    .getByLabel("Primary navigation")
    .locator("a, button")
    .filter({ hasText: "Metadata" })
    .first()
    .click();
  await expect(page.getByRole("heading", { name: "Metadata" })).toBeVisible();
  await expect(page.getByText("Metadata Space History", { exact: true })).toBeVisible();
  await expect(page.getByText("Metadata DB Logical Distribution", { exact: true })).toBeVisible();
  await expect(page.getByText("Current Breakdown Details", { exact: true })).toBeVisible();
  await expect(page.getByText("Latest Snapshot Context", { exact: true })).toBeVisible();
  await expect(
    page
      .locator('svg[aria-label="Metadata space history chart"] text')
      .filter({ hasText: "Collected at (UTC)" })
  ).toBeVisible();
  await expect(
    page
      .locator('svg[aria-label="Metadata space history chart"] text')
      .filter({ hasText: "Metadata used (bytes)" })
  ).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom in on metadata history chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom out of metadata history chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset metadata history chart zoom" })).toBeVisible();
  await expect(page.getByText("SQLite metadata DB", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Manifest store", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Media cache", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Analyze metadata DB" })).toBeVisible();
  await page.getByRole("button", { name: "Analyze metadata DB" }).click();
  await expect(page.getByText("version_indexes", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("Tracked Value Bytes", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Refresh analysis" })).toBeVisible();

  await page.getByText("Repair", { exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "Replication progress" })).toBeVisible();
  await expect(page.getByText("photos/cover.jpg", { exact: true })).toBeVisible();
  await expect(page.getByText("1 / 2 desired nodes currently present", { exact: true })).toBeVisible();
  await expect(page.getByText("under replicated", { exact: true })).toBeVisible();
  await expect(page.getByText("Live progress log", { exact: true })).toBeVisible();
  await expect(page.getByText("downloading replica chunk from source node")).toBeVisible();
  await page.getByRole("button", { name: "Run data scrub on this node" }).click();
  await expect
    .poll(() => mockState.scrubTriggerScopes())
    .toContain("local");

  await page.getByText("Provisioning", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Provisioning" })).toBeVisible();
  await expect(
    page.getByText("For a smartphone, use the bootstrap claim from this page when available, or scan the QR code below.")
  ).toBeVisible();
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();
  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();
  await expect(page.getByAltText("Client bootstrap QR code")).toBeVisible();

  await page.getByLabel("Node join request JSON").fill(
    JSON.stringify({
      version: 1,
      node_id: "node-beta",
      cluster_id: "cluster-alpha"
    })
  );
  await page.getByRole("button", { name: "Issue enrollment package" }).click();
  await expect(page.getByText("internal_tls_material")).toBeVisible();

  await page.getByText("Credentials", { exact: true }).click();
  await expect(page.getByRole("cell", { name: "client-credential-a", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Revoke" }).first().click();
  await page.getByLabel("Revocation reason").fill("manual smoke revocation");
  await page.getByRole("button", { name: "Revoke credential" }).click();
  await expect(page.getByText("manual smoke revocation")).toBeVisible();

  await page.getByText("S3", { exact: true }).click();
  await expect(page.getByText("Listener and replication status", { exact: true })).toBeVisible();
  await expect(page.getByText("Bucket mappings", { exact: true })).toBeVisible();
  await expect(page.getByText("Access keys", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Gateway command")).toHaveValue(
    /serve-s3 --bind 127\.0\.0\.1:9000/
  );
  await expect(page.getByText("media.example", { exact: true })).toBeVisible();
  await page.getByLabel("Bucket name").fill("archive.example");
  await page.getByLabel("Root prefix").fill("s3/archive.example/");
  await page.getByRole("button", { name: "Create bucket" }).click();
  await expect(page.getByText("archive.example", { exact: true })).toBeVisible();
  await page.getByLabel("Description").fill("build pipeline writer");
  await page.getByLabel("Bucket scope").fill("archive.example");
  await page.getByLabel("Prefix scope").fill("tenant/media/inbox/");
  await page.getByLabel("Write").check();
  await page.getByRole("button", { name: "Create access key" }).click();
  await expect(page.getByText("New S3 access key issued", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Access key ID")).toHaveValue("IMS3TEST0002");
  await expect(page.getByLabel("Secret access key")).toHaveValue("im_secret_2");
  await page.getByRole("button", { name: "Hide secret" }).click();
  const newAccessKeyRow = page.getByRole("row", { name: /IMS3TEST0002/ });
  await expect(newAccessKeyRow).toContainText("build pipeline writer");
  await expect(newAccessKeyRow).toContainText("write");
  page.once("dialog", (dialog) => {
    void dialog.accept();
  });
  await newAccessKeyRow.getByRole("button", { name: "Revoke" }).click();
  await expect(newAccessKeyRow).toContainText("revoked");

  await page.getByText("Connections", { exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "Transport" })).toBeVisible();
  await expect(page.getByText("via relay-alpha.local:9443", { exact: true })).toBeVisible();
  await expect(page.getByText("Rendezvous registration state", { exact: true })).toBeVisible();
  await expect(page.getByText("Server node connections", { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "node-beta", exact: true })).toBeVisible();
  await expect(page.getByText("rendezvous relay", { exact: true })).toBeVisible();
  await expect(page.getByText("Software version: 1.0.31", { exact: true })).toBeVisible();
  await expect(page.getByText("Software version: 1.0.30", { exact: true })).toBeVisible();

  await page.getByText("Certificates", { exact: true }).click();
  await expect(page.getByText("Fingerprint: internal-cert-fingerprint", { exact: true })).toBeVisible();

  await page.getByText("Logs", { exact: true }).click();
  await expect(page.getByText("Recent server logs", { exact: true })).toBeVisible();
  await expect(page.getByText("2023-11-14T22:13:20.000Z INFO runtime ready")).toBeVisible();
  await expect(page.getByText("runtime ready")).toBeVisible();
  await expect(page.getByText("replication audit healthy")).toBeVisible();

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByText("gallery/cat.png", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open Natural Earth" })).toHaveAttribute(
    "href",
    "https://www.naturalearthdata.com/"
  );
  await expect(page.getByText("2 photos", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Map" }).click();
  await expect(
    page.getByText("Using Natural Earth Globe from your self-hosted basemap dataset.")
  ).toBeVisible();
  await expect(page.getByText("Self-hosted basemap unavailable")).toHaveCount(0);
  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("2 markers")).toBeVisible();
  await page.getByRole("button", { name: "Open map marker for gallery/cat.png" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByText("Loading original image")).toBeVisible();
  await expect(page.getByText("Loading original image")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "gallery/cat.png", exact: true })).toHaveAttribute(
    "aria-current",
    "true"
  );
  await page.getByRole("button", { name: "Next item" }).click();
  await expect(page.getByRole("button", { name: "gallery/dog.jpg", exact: true })).toHaveAttribute(
    "aria-current",
    "true"
  );
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Open map marker for gallery/cat.png" }).click();
  const galleryDialog = page.getByRole("dialog");
  await expect(galleryDialog.getByRole("button", { name: "Version history" })).toBeVisible();
  await galleryDialog.getByRole("button", { name: "Version history" }).click();
  await expect(page.getByLabel("Key")).toHaveValue("gallery/cat.png");
  page.once("dialog", (dialog) => {
    void dialog.accept("restored/gallery-cat-from-gallery.png");
  });
  await page
    .getByRole("row", { name: /version-cat-000/ })
    .getByRole("button", { name: "Restore" })
    .click();
  await expect
    .poll(() =>
      mockState.restoredVersions().some(
        (entry) =>
          entry.key === "gallery/cat.png" &&
          entry.versionId === "version-cat-000" &&
          entry.targetPath === "restored/gallery-cat-from-gallery.png"
      )
    )
    .toBe(true);
  await expect(page.getByText('Restored version "version-cat-000" to "restored/gallery-cat-from-gallery.png".')).toBeVisible();
  const galleryVersionThumbnail = page.getByRole("button", {
    name: "Thumbnail for version version-cat-001"
  });
  await expect(galleryVersionThumbnail).toBeVisible();
  await galleryVersionThumbnail.click();
  await page.keyboard.press("Escape");
  await expect(
    page.getByRole("button", { name: "gallery/cat.png version-cat-001", exact: true })
  ).toHaveAttribute("aria-current", "true");
  await page.keyboard.press("Escape");

  await expect(page.getByLabel("Primary navigation").getByText("Setup", { exact: true })).toHaveCount(0);

  await page.getByText("Control Plane", { exact: true }).click();
  await expect(page.getByText("Advertised direct node URLs")).toBeVisible();
  await page
    .getByRole("textbox", { name: "Additional public API URLs" })
    .fill("https://edge-a.local:8443\nhttps://edge-b.local:8443");
  await page
    .getByRole("textbox", { name: "Additional peer API URLs" })
    .fill("https://edge-a.local:18443\nhttps://edge-b.local:18443");
  await page.getByRole("button", { name: "Save direct node URLs" }).click();
  await expect(page.locator("pre").filter({ hasText: "edge-b.local:18443" }).first()).toBeVisible();
  await expect(page.getByText("https://embedded-rendezvous.local:9443", { exact: true })).toBeVisible();
  await page
    .getByRole("textbox", { name: "Editable operator-managed URLs" })
    .fill("https://rendezvous-a.local:9443\nhttps://rendezvous-b.local:9443");
  await page.getByRole("button", { name: "Save rendezvous URLs" }).click();
  await expect(page.locator("pre").filter({ hasText: "rendezvous-b.local:9443" }).first()).toBeVisible();

  await page.getByLabel("Standalone ironmesh-rendezvous-service").click();
  await expect(page.getByRole("textbox", { name: "Target node ID" })).toHaveCount(1);
  await expect(page.getByText("No target node ID is needed for the standalone service package.")).toBeVisible();
  await page.getByLabel("Passphrase").first().fill("rendezvous-passphrase");
  await page.getByRole("button", { name: "Export standalone rendezvous package" }).click();
  await expect(page.getByText("https://node-beta.local/rendezvous")).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"deployment_target": "standalone_service"' })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"includes_cluster_ca_cert": true' })).toBeVisible();

  const rendezvousPackageJson = JSON.stringify({
    version: 1,
    cluster_id: "cluster-alpha",
    source_node_id: "node-alpha",
    public_url: "https://node-beta.local/rendezvous",
    deployment_target: "standalone_service",
    includes_cluster_ca_cert: true
  });
  await page.getByLabel("Rendezvous failover package JSON").fill(rendezvousPackageJson);
  await page.getByLabel("Passphrase").nth(1).fill("rendezvous-passphrase");
  await page.getByRole("button", { name: "Import rendezvous failover package" }).click();
  await expect(page.getByText("does not target an embedded node")).toBeVisible();

  const embeddedRendezvousPackageJson = JSON.stringify({
    version: 1,
    cluster_id: "cluster-alpha",
    source_node_id: "node-alpha",
    target_node_id: "node-beta",
    public_url: "https://node-beta.local/rendezvous",
    deployment_target: "embedded_node",
    includes_cluster_ca_cert: true
  });
  await page.getByLabel("Rendezvous failover package JSON").fill(embeddedRendezvousPackageJson);
  await page.getByRole("button", { name: "Import rendezvous failover package" }).click();
  await expect(page.getByText("tls/rendezvous.key")).toBeVisible();

  await page.getByRole("textbox", { name: "Target node ID" }).fill("node-beta");
  await page.getByLabel("Passphrase").nth(2).fill("promotion-passphrase");
  await page.getByRole("button", { name: "Export promotion package" }).click();
  await expect(page.getByText("signer_backup")).toBeVisible();

  const packageJson = JSON.stringify({
    signer_backup: { version: 1, from: "node-alpha" },
    rendezvous_failover: { version: 1, to: "node-beta" }
  });
  await page.getByLabel("Promotion package JSON").fill(packageJson);
  await page.getByLabel("Passphrase").nth(3).fill("promotion-passphrase");
  await page.getByRole("button", { name: "Import promotion package" }).click();
  await expect(page.getByText("tls/cluster-ca.pem")).toBeVisible();

  const requestedPaths = mockState.requestedPaths();
  expect(requestedPaths).toEqual(
    expect.arrayContaining([
      apiV1("/auth/admin/session"),
      apiV1("/auth/admin/login"),
      apiV1("/auth/store/index"),
      apiV1("/cluster/status"),
      apiV1("/health"),
      apiV1("/storage/stats/current"),
      apiV1("/auth/bootstrap-claims/issue"),
      apiV1("/auth/rendezvous-config"),
      apiV1("/auth/client-connections"),
      apiV1("/auth/s3/status"),
      apiV1("/auth/s3/buckets"),
      apiV1("/auth/s3/access-keys")
    ])
  );
  expect(
    requestedPaths.some((path) => path.startsWith(apiV1("/auth/managed-rendezvous/failover/export")))
  ).toBe(true);
  expect(requestedPaths.some((path) => path.startsWith(apiV1("/auth/media/thumbnail")))).toBe(true);
  expect(requestedPaths.some((path) => path.startsWith(apiV1("/maps/")))).toBe(true);
  expect(requestedPaths).not.toContain("/auth/admin/session");
  expect(requestedPaths).not.toContain("/auth/store/index");
  expect(requestedPaths).not.toContain("/cluster/status");
  expect(requestedPaths).not.toContain("/health");
  expect(requestedPaths).not.toContain("/storage/stats/current");
  expect(requestedPaths).not.toContain("/auth/bootstrap-claims/issue");
});

test("server-admin explorer restores snapshot entries", async ({ page }) => {
  const mockState = await installServerAdminMocks(page);

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Explorer", { exact: true }).click();
  await expect(page.getByRole("button", { name: "Refresh snapshots" })).toBeVisible();

  await page.getByRole("textbox", { name: "Snapshot" }).click();
  await page.getByRole("option", { name: "snapshot-admin-001" }).click();
  await page.getByRole("button", { name: "Load entries" }).click();

  page.once("dialog", (dialog) => dialog.accept("restored/readme-restored.txt"));
  await page
    .getByRole("row", { name: /docs\/readme\.txt/ })
    .getByRole("button", { name: "Restore..." })
    .click();

  await expect.poll(() => mockState.requestedPaths().includes(apiV1("/auth/store/restore"))).toBe(
    true
  );

  await page.getByRole("textbox", { name: "Snapshot" }).click();
  await page.getByRole("option", { name: "Current data" }).click();
  await page.getByRole("button", { name: "Load entries" }).click();
  await expect(page.getByRole("cell", { name: "restored/readme-restored.txt" })).toBeVisible();
});

test("server-admin validates and saves storage-pool configuration with Cockpit guidance", async ({ page }) => {
  const mockState = await installServerAdminMocks(page, { cockpitStatus: "optional" });

  await page.goto("/");
  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page
    .getByLabel("Primary navigation")
    .locator("a, button")
    .filter({ hasText: "Metadata" })
    .first()
    .click();
  const configuration = page.getByLabel("Storage-pool JSON");
  await expect(configuration).toHaveValue(/"id": "primary"/);

  await configuration.fill("{");
  await page.getByRole("button", { name: "Validate configuration" }).click();
  await expect(page.getByText("Invalid JSON", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Reset to running configuration" }).click();
  await expect(configuration).toHaveValue(/"id": "primary"/);

  await configuration.fill(
    JSON.stringify({
      version: 1,
      paths: [
        {
          id: "rejected",
          path: "/srv/ironmesh/primary",
          state: "active",
          weight: 1,
          reserve_bytes: 0
        }
      ]
    })
  );
  await page.getByRole("button", { name: "Validate configuration" }).click();
  await expect(page.getByText(/mocked storage-pool validation failure/)).toBeVisible();

  const nextConfig = {
    version: 1,
    paths: [
      {
        id: "primary",
        path: "/srv/ironmesh/primary",
        state: "active",
        weight: 1,
        reserve_bytes: 0
      },
      {
        id: "secondary",
        path: "/mnt/storage/ironmesh",
        state: "active",
        weight: 2,
        reserve_bytes: 4096
      }
    ]
  };
  await configuration.fill(JSON.stringify(nextConfig));
  await page.getByRole("button", { name: "Validate configuration" }).click();
  await expect(page.getByText("Configuration is valid", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save configuration" }).click();
  await expect(page.getByText("Configuration saved — restart required", { exact: true })).toBeVisible();
  await expect.poll(() => mockState.storagePoolSaveRequests()).toEqual([nextConfig]);

  await page.getByText("Dependencies", { exact: true }).click();
  await expect(page.getByText("Optional host administration tooling unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("Cockpit host administration", { exact: true })).toBeVisible();
  await expect(page.getByText("optional", { exact: true })).toBeVisible();
});

test("server-admin Dependencies reports a detected Cockpit installation", async ({ page }) => {
  await installServerAdminMocks(page, { cockpitStatus: "ready" });

  await page.goto("/");
  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Dependencies", { exact: true }).click();
  await expect(page.getByText("Optional host administration tooling unavailable", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Cockpit web service found at /usr/lib/cockpit/cockpit-ws")).toBeVisible();
  await expect(page.getByText("ready", { exact: true })).toBeVisible();
});

test("server-admin explorer loads version history with thumbnails", async ({ page }) => {
  const mockState = await installServerAdminMocks(page);

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Explorer", { exact: true }).click();
  await page
    .getByRole("row", { name: /gallery\/cat\.png/ })
    .getByRole("button", { name: "History" })
    .click();

  await expect(page.getByLabel("Key")).toHaveValue("gallery/cat.png");
  const versionHistoryTable = page.getByRole("table").nth(1);
  await expect(versionHistoryTable.getByRole("cell", { name: "version-cat-001" })).toBeVisible();
  await expect(versionHistoryTable.getByRole("row", { name: /version-cat-001/ })).toContainText("3.0 MB");
  await expect(
    versionHistoryTable.getByRole("row", { name: /version-cat-001/ }).getByRole("button", { name: "Restore" })
  ).toHaveCount(0);
  page.once("dialog", (dialog) => {
    void dialog.accept("restored/gallery-cat-copy.png");
  });
  await versionHistoryTable
    .getByRole("row", { name: /version-cat-000/ })
    .getByRole("button", { name: "Restore" })
    .click();
  await expect
    .poll(() => mockState.requestedPaths().includes(apiV1("/auth/versions/gallery%2Fcat.png/restore/version-cat-000")))
    .toBe(true);
  await expect
    .poll(() =>
      mockState.restoredVersions().some(
        (entry) =>
          entry.key === "gallery/cat.png" &&
          entry.versionId === "version-cat-000" &&
          entry.targetPath === "restored/gallery-cat-copy.png"
      )
    )
    .toBe(true);
  await expect(page.getByText('"target_path": "restored/gallery-cat-copy.png"')).toBeVisible();
  await expect
    .poll(() => mockState.requestedPaths().includes(apiV1("/auth/versions/gallery%2Fcat.png")))
    .toBe(true);

  await page.keyboard.press("Escape");
  await page.getByText("Show thumbnails", { exact: true }).click();
  await page.getByRole("button", { name: "Version history" }).click();
  await expect(page.getByRole("button", { name: "Thumbnail for gallery/cat.png" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Thumbnail for version version-cat-001" })).toBeVisible();
  await page.getByRole("button", { name: "Thumbnail for version version-cat-001" }).click();
  await expect(page.getByLabel("Media viewer thumbnails")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "gallery/cat.png version-cat-001", exact: true })
  ).toHaveAttribute("aria-current", "true");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Next item" }).click();
  await expect(
    page.getByRole("button", { name: "gallery/cat.png version-cat-000", exact: true })
  ).toHaveAttribute("aria-current", "true");
  await expect.poll(() => mockState.requestedPaths().includes(apiV1("/auth/media/thumbnail"))).toBe(
    true
  );
});

test("server-admin provisioning can target a selected rendezvous service", async ({ page }) => {
  await installServerAdminMocks(page);

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByLabel("Primary rendezvous service").selectOption("https://rendezvous-a.local:9443/");
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.locator("pre").filter({ hasText: '"r": [' })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"https://rendezvous-a.local:9443/"' })).toBeVisible();
  await expect(page.getByText("Request failed", { exact: true })).toHaveCount(0);
});

test("server-admin provisioning forces a bright theme while the QR is visible and restores it after navigation", async ({ page }) => {
  await page.addInitScript(() => {
    window.localStorage.setItem("ironmesh-color-scheme", "dark");
  });
  await installServerAdminMocks(page);

  await page.goto("/");
  await expect(page.locator(":root")).toHaveAttribute("data-mantine-color-scheme", "dark");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();
  await expect(page.locator(":root")).toHaveAttribute("data-mantine-color-scheme", "light", {
    timeout: 15000
  });

  await page.getByText("Dashboard", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.locator(":root")).toHaveAttribute("data-mantine-color-scheme", "dark");
});

test("server-admin provisioning can copy and download the issued bootstrap claim", async ({ page }) => {
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await installServerAdminMocks(page);

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();

  const copyBootstrapClaimButton = page.getByRole("button", {
    name: "Copy bootstrap claim to clipboard"
  });
  const downloadBootstrapClaimButton = page.getByRole("button", {
    name: "Download bootstrap claim"
  });
  const downloadBootstrapBundleButton = page.getByRole("button", {
    name: "Download bootstrap bundle"
  });

  await expect(copyBootstrapClaimButton).toBeDisabled();
  await expect(downloadBootstrapClaimButton).toBeDisabled();
  await expect(downloadBootstrapBundleButton).toBeDisabled();

  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();
  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();

  await expect(copyBootstrapClaimButton).toBeEnabled();
  await expect(downloadBootstrapClaimButton).toBeEnabled();
  await expect(downloadBootstrapBundleButton).toBeEnabled();

  await copyBootstrapClaimButton.click();
  await expect
    .poll(async () => page.evaluate(() => navigator.clipboard.readText()))
    .toContain('"k": "im-claim-example"');

  const claimDownloadPromise = page.waitForEvent("download");
  await downloadBootstrapClaimButton.click();
  const claimDownload = await claimDownloadPromise;
  expect(claimDownload.suggestedFilename()).toBe("ironmesh-client-bootstrap-claim-cluster-alpha.json");

  const bundleDownloadPromise = page.waitForEvent("download");
  await downloadBootstrapBundleButton.click();
  const bundleDownload = await bundleDownloadPromise;
  expect(bundleDownload.suggestedFilename()).toBe("ironmesh-client-bootstrap-cluster-alpha.json");
});

test("server-admin gallery derives child folders from nested media entries", async ({ page }) => {
  await installServerAdminMocks(page, {
    galleryEntries: [
      {
        path: "cameras/vm1.4/",
        entry_type: "prefix"
      },
      {
        path: "cameras/vm1.4/front.jpg",
        entry_type: "key",
        media: {
          status: "ready",
          content_fingerprint: "fingerprint-vm14-front",
          media_type: "image",
          mime_type: "image/jpeg"
        }
      },
      {
        path: "cameras/oppo-uli/front.jpg",
        entry_type: "key",
        media: {
          status: "ready",
          content_fingerprint: "fingerprint-oppo-front",
          media_type: "image",
          mime_type: "image/jpeg"
        }
      }
    ]
  });

  await page.goto("/");
  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();

  await page.getByLabel("Prefix").fill("cameras/");
  await page.getByRole("button", { name: "Load" }).click();

  await expect(page.getByText("vm1.4/", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("oppo-uli/", { exact: true }).first()).toBeVisible();
});

test("server-admin gallery retries missing video poster extraction from the fullscreen view", async ({ page }) => {
  const mockState = await installServerAdminMocks(page, {
    galleryEntries: [
      {
        path: "gallery/clip.mp4",
        entry_type: "key",
        media: {
          status: "failed",
          content_fingerprint: "fingerprint-clip",
          media_type: "video",
          mime_type: "video/mp4",
          width: 1920,
          height: 1080,
          error: "Poster extraction failed on this node."
        }
      }
    ]
  });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();
  await page.getByText("gallery/clip.mp4", { exact: true }).click();

  const dialog = page.getByRole("dialog");
  const retryButton = dialog.getByRole("button", {
    name: "Retry metadata and poster extraction"
  });

  await expect(dialog.getByText("Poster thumbnail unavailable", { exact: true })).toBeVisible();
  await expect(dialog.getByText("Poster extraction failed on this node.", { exact: true })).toBeVisible();
  await expect(retryButton).toBeVisible();

  await retryButton.click();

  await expect(retryButton).toHaveCount(0);
  await expect(dialog.getByText("Poster thumbnail unavailable", { exact: true })).toHaveCount(0);
  await expect(dialog.getByText("Poster extraction failed on this node.", { exact: true })).toHaveCount(0);
  await expect.poll(() => mockState.requestedPaths().includes(apiV1("/auth/media/cache/retry"))).toBe(
    true
  );
});

test("server-admin gallery clusters nearby map markers", async ({ page }) => {
  await installServerAdminMocks(page, {
    galleryEntries: createClusteredAdminGalleryEntries(12)
  });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();
  await page.getByRole("button", { name: "Map" }).click();

  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("12 markers", { exact: true })).toBeVisible();
  await expect(page.getByText("1 visible clusters", { exact: true })).toBeVisible();

  const clusterButton = page.getByRole("button", {
    name: "Open map cluster with 12 items"
  });
  await expect(clusterButton).toBeVisible();
  await clusterButton.click();

  await expect(page.getByRole("dialog").getByText("12 items in map cluster", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "gallery/cluster-03.png", exact: true }).click();

  await expect(
    page.getByRole("dialog").getByText("12 items in map cluster", { exact: true })
  ).toHaveCount(0);
  await expect(
    page.getByRole("dialog").getByRole("button", { name: "gallery/cluster-03.png", exact: true })
  ).toBeVisible();
});

test("server-admin gallery only auto-zooms spread map clusters on ctrl-click", async ({ page }) => {
  await installServerAdminMocks(page, {
    galleryEntries: createGeoSpreadClusteredAdminGalleryEntries(12)
  });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gallery" })).toBeVisible();
  await page.getByRole("button", { name: "Map" }).click();

  await expect(page.locator('[aria-label="Geotagged gallery map"]')).toBeVisible();
  await expect(page.getByText("12 markers", { exact: true })).toBeVisible();
  await expect(page.getByText("1 visible clusters", { exact: true })).toBeVisible();

  const clusterButton = page.getByRole("button", {
    name: "Open map cluster with 12 items"
  });
  const clusterDialogTitle = page
    .getByRole("dialog")
    .getByText("12 items in map cluster", { exact: true });

  await expect(clusterButton).toBeVisible();
  await clusterButton.click();
  await expect(clusterDialogTitle).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(clusterDialogTitle).toHaveCount(0);

  await clusterButton.click({ modifiers: ["Control"] });
  await expect(clusterDialogTitle).toHaveCount(0);
  await expect(page.getByText("1 visible clusters", { exact: true })).toHaveCount(0);
});

test("server-admin provisioning falls back to the full bootstrap bundle when claim issuance returns 502", async ({ page }) => {
  await installServerAdminMocks(page, { bootstrapClaimMode: "bad_gateway" });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.getByText("Compact claim issuance is temporarily unavailable on this node, so the page fell back to a full bootstrap QR.")).toBeVisible();
  await expect(page.getByText("Scan the full bootstrap bundle with the ironmesh Android app")).toBeVisible();
  await expect(page.getByAltText("Client bootstrap QR code")).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"relay_mode": "relay-preferred"' })).toBeVisible();
  await expect(page.getByText("Request failed", { exact: true })).toHaveCount(0);
});

test("server-admin provisioning does not fall back when a specific rendezvous service is selected", async ({ page }) => {
  await installServerAdminMocks(page, { bootstrapClaimMode: "bad_gateway" });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByLabel("Primary rendezvous service").selectOption("https://rendezvous-a.local:9443/");
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();

  await expect(page.getByText("Request failed", { exact: true })).toBeVisible();
  await expect(page.getByText("Compact claim issuance is temporarily unavailable on this node, so the page fell back to a full bootstrap QR.")).toHaveCount(0);
});

test("server-admin runtime ignores auth-protected setup probes", async ({ page }) => {
  await installServerAdminMocks(page, { setupProbeStatus: 401 });

  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Setup probe warning", { exact: true })).toHaveCount(0);

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await expect(page.getByText("Setup probe warning", { exact: true })).toHaveCount(0);
  await page.keyboard.press("Escape");

  await expect(page.getByLabel("Primary navigation").getByText("Setup", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Setup endpoint error", { exact: true })).toHaveCount(0);
});

test("server-admin login ignores stale unauthenticated session probes", async ({ page }) => {
  await installServerAdminMocks(page, {
    delayedInitialUnauthenticatedSessionMs: 250
  });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await expect(page.getByText("not authenticated", { exact: true })).toHaveCount(0);
});

test("server-admin waits for session confirmation before protected dashboard fetches", async ({ page }) => {
  await installServerAdminMocks(page, {
    postLoginUnauthenticatedSessionResponses: 2,
    protectDashboardAdminRoutesUntilSessionConfirmed: true
  });

  await page.goto("/");

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill("hunter2-harder");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("signed in", { exact: true })).toBeVisible();
  await expect(page.getByText("Failed to load dashboard", { exact: true })).toHaveCount(0);
});

async function installServerAdminMocks(
  page: Page,
  options?: {
    setupMode?: boolean;
    bootstrapClaimMode?: "success" | "bad_gateway";
    setupProbeStatus?: 401 | 403 | 404;
    delayedInitialUnauthenticatedSessionMs?: number;
    postLoginUnauthenticatedSessionResponses?: number;
    protectDashboardAdminRoutesUntilSessionConfirmed?: boolean;
    galleryEntries?: AdminMockStoreEntry[];
    cockpitStatus?: "ready" | "optional";
  }
) {
  const imageBody = tinyPngBuffer();
  const logicalMapBody = readFileSync("tests/fixtures/smoke.mbtiles");
  const emptyVectorTileBody = gzipSync(Buffer.alloc(0));
  const glyphRangeBody = Buffer.alloc(0);
  let authenticated = false;
  let sessionConfirmed = false;
  let sessionStatusRequestCount = 0;
  let remainingPostLoginUnauthenticatedSessionResponses =
    options?.postLoginUnauthenticatedSessionResponses ?? 0;
  const revokedDeviceIds = new Set<string>();
  let s3LocalGeneration = 7;
  const s3Buckets = [
    {
      bucket_name: "media.example",
      root_prefix: "s3/media.example/",
      versioning_status: "enabled",
      read_only: false,
      created_at_unix: 1_900_000_020,
      updated_at_unix: 1_900_000_040,
      created_by: "admin-user",
      deleted_at_unix: null
    }
  ];
  const s3AccessKeys = [
    {
      access_key_id: "IMS3TEST0001",
      description: "gallery reader",
      bucket_scope: ["media.example"],
      prefix_scope: ["gallery/"],
      allow_list: true,
      allow_read: true,
      allow_write: false,
      allow_delete: false,
      allow_manage: false,
      created_at_unix: 1_900_000_050,
      updated_at_unix: 1_900_000_060,
      last_used_at_unix: 1_900_000_180,
      revoked_at_unix: null,
      secret_fingerprint: "fp-gallery-reader"
    }
  ];
  let nextS3AccessKeySuffix = 2;
  const bootstrapBundle = {
    cluster_id: "cluster-alpha",
    relay_mode: "relay-preferred",
    rendezvous_mtls_required: true,
    rendezvous_urls: ["https://node-alpha.local/rendezvous"],
    direct_endpoints: [
      {
        url: "https://node-alpha.local",
        usage: "public_api",
        node_id: "node-alpha"
      }
    ],
    trust_roots: {
      cluster_ca_pem: "-----BEGIN CERTIFICATE-----\\ncluster\\n-----END CERTIFICATE-----"
    }
  };
  let directEndpointsConfig = {
    effective_public_urls: ["https://node-alpha.local", "https://edge.example:8443"],
    editable_public_urls: ["https://edge.example:8443"],
    primary_public_url: "https://node-alpha.local",
    effective_peer_urls: ["https://node-alpha.local:18080", "https://edge.example:18443"],
    editable_peer_urls: ["https://edge.example:18443"],
    primary_peer_url: "https://node-alpha.local:18080",
    persistence_source: "node_enrollment",
    persisted: true
  };
  let rendezvousConfig = {
    effective_urls: ["https://embedded-rendezvous.local:9443", "https://rendezvous-a.local:9443"],
    editable_urls: ["https://rendezvous-a.local:9443"],
    managed_embedded_url: "https://embedded-rendezvous.local:9443",
    registration_enabled: true,
    registration_interval_secs: 30,
    disconnected_retry_interval_secs: 5,
    endpoint_registrations: [
      {
        url: "https://embedded-rendezvous.local:9443",
        status: "connected",
        last_attempt_unix: 1_900_000_000,
        last_success_unix: 1_900_000_000,
        consecutive_failures: 0,
        last_error: null,
        software_version: "1.0.31"
      },
      {
        url: "https://rendezvous-a.local:9443",
        status: "connected",
        last_attempt_unix: 1_900_000_010,
        last_success_unix: 1_900_000_010,
        consecutive_failures: 0,
        last_error: null,
        software_version: "1.0.30"
      }
    ],
    mtls_required: true,
    persistence_source: "node_enrollment",
    persisted: true
  };
  const galleryEntries = options?.galleryEntries ?? createDefaultAdminGalleryEntries();
  let storagePoolConfig: StoragePoolMockConfig = {
    version: 1,
    paths: [
      {
        id: "primary",
        path: "/srv/ironmesh/primary",
        state: "active",
        weight: 1,
        reserve_bytes: 0
      }
    ]
  };
  const storagePoolSaveRequests: StoragePoolMockConfig[] = [];
  const requestedPaths = new Set<string>();
  const scrubTriggerScopes = new Set<string>();
  const restoredVersions: Array<{ key: string; versionId: string; targetPath: string }> = [];
  const currentVersionByKey = new Map<string, string>([["gallery/cat.png", "version-cat-001"]]);
  const metadataDbLogicalDistribution = {
    backend: "sqlite",
    generated_at_unix: 1_900_000_121,
    total_row_count: 203,
    total_tracked_value_bytes: 3_447_552,
    tables: [
      {
        table: "version_indexes",
        row_count: 42,
        tracked_value_bytes: 1_640_448,
        average_tracked_value_bytes: 39_058,
        tracked_columns: ["object_id", "index_json"]
      },
      {
        table: "snapshots",
        row_count: 9,
        tracked_value_bytes: 962_560,
        average_tracked_value_bytes: 106_951,
        tracked_columns: ["snapshot_id", "snapshot_json"]
      },
      {
        table: "data_change_events",
        row_count: 88,
        tracked_value_bytes: 442_368,
        average_tracked_value_bytes: 5_027,
        tracked_columns: [
          "event_id",
          "action",
          "path",
          "from_path",
          "to_path",
          "actor_kind",
          "actor_id",
          "actor_label",
          "actor_credential_fingerprint",
          "event_json"
        ]
      },
      {
        table: "current_objects",
        row_count: 42,
        tracked_value_bytes: 155_648,
        average_tracked_value_bytes: 3_706,
        tracked_columns: ["key", "manifest_hash", "object_id"]
      },
      {
        table: "admin_audit_events",
        row_count: 12,
        tracked_value_bytes: 139_264,
        average_tracked_value_bytes: 11_605,
        tracked_columns: ["event_id", "event_json"]
      },
      {
        table: "storage_stats_history",
        row_count: 10,
        tracked_value_bytes: 107_264,
        average_tracked_value_bytes: 10_726,
        tracked_columns: ["sample_json"]
      }
    ]
  };
  let metadataDbLogicalDistributionPhase: "idle" | "running" | "ready" = "idle";

  function buildS3Status() {
    return {
      listener_enabled: true,
      public_url: "https://node-alpha.local:9443",
      tls_enabled: true,
      gateway_command_hint:
        "ironmesh --bootstrap-file <bootstrap.json> --client-identity-file <identity.json> serve-s3 --bind 127.0.0.1:9000",
      local_generation: s3LocalGeneration,
      last_applied_at_unix: 1_900_000_210,
      last_source_node_id: "node-beta",
      last_error: null,
      bucket_count: s3Buckets.length,
      access_key_count: s3AccessKeys.length
    };
  }

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const { pathname, searchParams } = url;
    const method = route.request().method();
    requestedPaths.add(pathname);

    if (pathname === apiV1("/auth/admin/session") && method === "GET") {
      let sessionAuthenticated = authenticated;
      if (sessionAuthenticated && remainingPostLoginUnauthenticatedSessionResponses > 0) {
        remainingPostLoginUnauthenticatedSessionResponses -= 1;
        sessionAuthenticated = false;
      }
      if (sessionAuthenticated) {
        sessionConfirmed = true;
      }
      const shouldDelayInitialUnauthenticatedSession =
        sessionStatusRequestCount === 0 &&
        !sessionAuthenticated &&
        (options?.delayedInitialUnauthenticatedSessionMs ?? 0) > 0;
      sessionStatusRequestCount += 1;
      if (shouldDelayInitialUnauthenticatedSession) {
        await new Promise((resolve) =>
          setTimeout(resolve, options?.delayedInitialUnauthenticatedSessionMs ?? 0)
        );
      }
      return json(route, {
        login_required: true,
        authenticated: sessionAuthenticated,
        session_expires_at_unix: sessionAuthenticated ? 1_900_000_000 : null,
        token_override_enabled: true
      });
    }

    if (pathname === apiV1("/auth/admin/login") && method === "POST") {
      authenticated = true;
      sessionConfirmed = false;
      remainingPostLoginUnauthenticatedSessionResponses =
        options?.postLoginUnauthenticatedSessionResponses ?? 0;
      return json(route, { status: "ok" });
    }

    if (pathname === apiV1("/auth/admin/logout") && method === "POST") {
      authenticated = false;
      sessionConfirmed = false;
      remainingPostLoginUnauthenticatedSessionResponses = 0;
      return json(route, { status: "ok" });
    }

    if (pathname === apiV1("/auth/host/dependencies") && method === "GET") {
      const cockpitReady = options?.cockpitStatus === "ready";
      return json(route, {
        host_os: "linux",
        generated_at_unix: 1_900_000_333,
        checks: [
          {
            id: "image-thumbnails",
            feature: "Image thumbnails and metadata",
            status: "builtin",
            summary: "Ready without extra host packages",
            detail: "Built into the test node.",
            configured_path: null,
            resolved_path: null,
            install_hint: null
          },
          {
            id: "cockpit",
            feature: "Cockpit host administration",
            status: cockpitReady ? "ready" : "optional",
            summary: cockpitReady
              ? "Cockpit web service found at /usr/lib/cockpit/cockpit-ws"
              : "Cockpit web service was not found on this host",
            detail: "Cockpit remains separately authenticated from IronMesh.",
            configured_path: null,
            resolved_path: cockpitReady ? "/usr/lib/cockpit/cockpit-ws" : null,
            install_hint: cockpitReady ? null : "Install Cockpit with the host package manager."
          }
        ]
      });
    }

    if (pathname === apiV1("/auth/storage/pool") && method === "GET") {
      return json(route, storagePoolStatus(storagePoolConfig));
    }

    if (pathname === apiV1("/auth/storage/pool/config/validate") && method === "POST") {
      const config = route.request().postDataJSON() as StoragePoolMockConfig;
      if (config.paths.some((path) => path.id === "rejected")) {
        await route.fulfill({
          status: 400,
          contentType: "application/json; charset=utf-8",
          body: JSON.stringify({ error: "mocked storage-pool validation failure" })
        });
        return;
      }
      return json(route, {
        config_path: "/var/lib/ironmesh/state/storage-pool.json",
        restart_required: true
      });
    }

    if (pathname === apiV1("/auth/storage/pool/config") && method === "PUT") {
      const config = route.request().postDataJSON() as StoragePoolMockConfig;
      storagePoolSaveRequests.push(config);
      storagePoolConfig = config;
      return json(route, {
        config_path: "/var/lib/ironmesh/state/storage-pool.json",
        restart_required: true
      });
    }

    if (pathname === apiV1("/auth/store/snapshots") && method === "GET") {
      return json(route, [{ id: "snapshot-admin-001" }]);
    }

    if (pathname === apiV1("/auth/store/index") && method === "GET") {
      expect(searchParams.get("view")).toBe("tree");
      return json(route, buildAdminStoreIndexResponse(galleryEntries, searchParams));
    }

    if (pathname === apiV1("/auth/client-connections") && method === "GET") {
      return json(route, {
        summary: {
          total: 3,
          http_requests: 1,
          direct_transport: 1,
          relay_transport: 1
        },
        entries: [
          {
            connection_id: "relay-relay-session-1",
            device_id: "device-relay-1",
            label: "Relay Client",
            credential_fingerprint: "cred-relay-1",
            connection_name: "client/relay",
            transport: "relay_transport",
            connected_at_unix: 1_900_000_220,
            last_activity_at_unix: 1_900_000_225,
            method: null,
            path: null,
            session_id: "relay-session-1",
            rendezvous_url: "https://relay-alpha.local:9443/rendezvous"
          },
          {
            connection_id: "direct-direct-session-1",
            device_id: "device-direct-1",
            label: "Direct Client",
            credential_fingerprint: "cred-direct-1",
            connection_name: "client/direct",
            transport: "direct_transport",
            connected_at_unix: 1_900_000_210,
            last_activity_at_unix: 1_900_000_215,
            method: null,
            path: null,
            session_id: "direct-session-1",
            rendezvous_url: null
          },
          {
            connection_id: "http-http-request-1",
            device_id: "device-http-1",
            label: "HTTP Client",
            credential_fingerprint: "cred-http-1",
            connection_name: "client/http",
            transport: "http_request",
            connected_at_unix: 1_900_000_200,
            last_activity_at_unix: 1_900_000_205,
            method: "GET",
            path: "/api/v1/store/index",
            session_id: null,
            rendezvous_url: null
          }
        ],
        next_cursor: null
      });
    }

    if (pathname.startsWith(apiV1("/auth/versions/")) && method === "GET") {
      const key = decodeURIComponent(pathname.slice(`${apiV1("/auth/versions/")}`.length));
      return json(route, buildAdminVersionGraphResponse(key, currentVersionByKey.get(key) ?? null));
    }

    if (
      pathname.startsWith(`${apiV1("/auth/versions")}/`) &&
      pathname.includes("/restore/") &&
      method === "POST"
    ) {
      const versionPrefix = `${apiV1("/auth/versions")}/`;
      const [encodedKey, encodedVersionId] = pathname.slice(versionPrefix.length).split("/restore/");
      const key = decodeURIComponent(encodedKey ?? "");
      const versionId = decodeURIComponent(encodedVersionId ?? "");
      const body = route.request().postDataJSON() as {
        to_path: string;
        overwrite?: boolean;
      };
      restoredVersions.push({ key, versionId, targetPath: body.to_path });
      await route.fulfill({ status: 204, body: "" });
      return;
    }

    if (pathname === apiV1("/auth/store/restore") && method === "POST") {
      const body = route.request().postDataJSON() as {
        snapshot: string;
        from_path: string;
        to_path: string;
        recursive?: boolean;
      };
      const restoredCount = restoreAdminMockStorePath(
        galleryEntries,
        body.from_path,
        body.to_path,
        body.recursive === true
      );
      return json(route, {
        snapshot: body.snapshot,
        source_path: body.from_path,
        target_path: body.to_path,
        recursive: body.recursive === true,
        restored_count: restoredCount
      });
    }

    if (pathname === apiV1("/auth/media/cache/retry") && method === "POST") {
      const key = searchParams.get("key");
      const targetEntry = key
        ? galleryEntries.find((entry) => entry.entry_type === "key" && entry.path === key)
        : null;

      if (!targetEntry) {
        await route.fulfill({
          status: 404,
          contentType: "application/json; charset=utf-8",
          body: JSON.stringify({ error: "gallery entry not found" })
        });
        return;
      }

      const updatedMedia = buildRetriedAdminMedia(targetEntry, imageBody.length);
      targetEntry.media = updatedMedia;
      return json(route, updatedMedia);
    }

    if (pathname === apiV1("/auth/media/thumbnail") && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "image/png",
        body: imageBody
      });
      return;
    }

    if (pathname.startsWith(apiV1("/auth/store/")) && method === "GET") {
      if (pathname === apiV1("/auth/store/gallery%2Fcat.png")) {
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      await route.fulfill({
        status: 200,
        contentType: "image/png",
        body: imageBody
      });
      return;
    }

    if (pathname === apiV1("/maps/logical-file")) {
      const rangeHeader = route.request().headers().range;
      const commonHeaders = {
        "accept-ranges": "bytes",
        "content-type": "application/octet-stream",
        etag: "\"server-admin-smoke-mbtiles\""
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

    if (pathname === apiV1("/auth/maps/config") && method === "GET") {
      return json(route, {
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
              raster_manifest_key: "sys/maps/natural-earth-globe.mbtiles.manifest.json"
            }
          ]
        }
      });
    }

    if (pathname === apiV1("/maps/mbtiles-metadata") && method === "GET") {
      return json(route, {
        attribution: "Made with Natural Earth.",
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

    if (pathname === apiV1("/cluster/status") && method === "GET") {
      if (options?.protectDashboardAdminRoutesUntilSessionConfirmed && !sessionConfirmed) {
        await route.fulfill({ status: 401 });
        return;
      }
      return json(route, {
        local_node_id: "node-alpha",
        total_nodes: 2,
        online_nodes: 2,
        offline_nodes: 0,
        policy: {
          replication_factor: 2,
          min_distinct_labels: {},
          accepted_over_replication_items: 0
        }
      });
    }

    if (pathname === apiV1("/cluster/nodes") && method === "GET") {
      if (options?.protectDashboardAdminRoutesUntilSessionConfirmed && !sessionConfirmed) {
        await route.fulfill({ status: 401 });
        return;
      }
      return json(route, [
        {
          node_id: "node-alpha",
          reachability: {
            public_api_url: "https://node-alpha.local",
            peer_api_url: "https://node-alpha-peer.local",
            relay_required: false
          },
          capabilities: {
            public_api: true,
            peer_api: true,
            relay_tunnel: true
          },
          labels: {
            region: "lab"
          },
          capacity_bytes: 2_000_000_000,
          free_bytes: 1_250_000_000,
          storage_stats: {
            collected_at_unix: 1_900_000_100,
            latest_snapshot_id: "snapshot-node-alpha",
            latest_snapshot_created_at_unix: 1_900_000_090,
            latest_snapshot_object_count: 12,
            chunk_store_bytes: 1_024,
            manifest_store_bytes: 256,
            metadata_db_bytes: 512,
            media_cache_bytes: 256,
            latest_snapshot_logical_bytes: 8_192,
            latest_snapshot_unique_chunk_bytes: 4_096
          },
          last_heartbeat_unix: 1_900_000_000,
          status: "online"
        },
        {
          node_id: "node-beta",
          reachability: {
            public_api_url: null,
            peer_api_url: null,
            relay_required: true
          },
          capabilities: {
            public_api: true,
            peer_api: true,
            relay_tunnel: true
          },
          labels: {
            region: "lab"
          },
          capacity_bytes: 2_500_000_000,
          free_bytes: 1_500_000_000,
          storage_stats: {
            collected_at_unix: 1_900_000_110,
            latest_snapshot_id: "snapshot-node-beta",
            latest_snapshot_created_at_unix: 1_900_000_095,
            latest_snapshot_object_count: 14,
            chunk_store_bytes: 2_048,
            manifest_store_bytes: 512,
            metadata_db_bytes: 1_024,
            media_cache_bytes: 512,
            latest_snapshot_logical_bytes: 16_384,
            latest_snapshot_unique_chunk_bytes: 12_288
          },
          last_heartbeat_unix: 1_900_000_010,
          status: "online"
        }
      ]);
    }

    if (pathname === apiV1("/auth/repair/activity") && method === "GET") {
      return json(route, {
        state: "running",
        startup_status: "completed",
        active_runs: [
          {
            run_id: "repair-run-live-001",
            scope: "local",
            trigger: "background_audit",
            started_at_unix: 1_900_000_001,
            last_log_at_unix: 1_900_000_009,
            live_log_truncated: false,
            live_log: [
              {
                captured_at_unix: 1_900_000_002,
                report_node_id: "node-alpha",
                event: "repair_run_started",
                detail: "starting replication repair run",
                context: {
                  plan_item_count: 1,
                  max_transfers: 32
                }
              },
              {
                captured_at_unix: 1_900_000_006,
                report_node_id: "node-alpha",
                event: "pull_chunk_progress",
                detail: "downloading replica chunk from source node",
                key: "photos/cover.jpg",
                source_node_id: "node-beta",
                target_node_id: "node-alpha",
                context: {
                  chunk_index: 1,
                  chunk_count: 3,
                  chunk_hash: "chunk-cover-001"
                }
              },
              {
                captured_at_unix: 1_900_000_009,
                report_node_id: "node-alpha",
                event: "target_manifest_push_started",
                detail: "pushing replica manifest to target node",
                key: "photos/cover.jpg",
                source_node_id: "node-alpha",
                target_node_id: "node-beta"
              }
            ]
          }
        ],
        latest_run: {
          run_id: "repair-run-finished-001",
          reporting_node_id: "node-alpha",
          scope: "cluster",
          trigger: "manual_request",
          status: "completed",
          started_at_unix: 1_899_999_900,
          finished_at_unix: 1_899_999_960,
          duration_ms: 60_000,
          plan_summary: {
            generated_at_unix: 1_899_999_899,
            under_replicated: 1,
            over_replicated: 0,
            cleanup_deferred_items: 0,
            cleanup_deferred_extra_nodes: 0,
            item_count: 1
          },
          summary: {
            attempted_transfers: 1,
            successful_transfers: 1,
            failed_transfers: 0,
            skipped_items: 0,
            skipped_backoff: 0,
            skipped_max_retries: 0,
            skipped_detail_count: 0,
            nodes_contacted: 2,
            failed_nodes: 0,
            last_error: null
          }
        }
      });
    }

    if (pathname === apiV1("/auth/repair/history") && method === "GET") {
      return json(route, {
        retention_secs: 2_592_000,
        runs: [
          {
            run_id: "repair-run-finished-001",
            reporting_node_id: "node-alpha",
            scope: "cluster",
            trigger: "manual_request",
            status: "completed",
            started_at_unix: 1_899_999_900,
            finished_at_unix: 1_899_999_960,
            duration_ms: 60_000,
            plan_summary: {
              generated_at_unix: 1_899_999_899,
              under_replicated: 1,
              over_replicated: 0,
              cleanup_deferred_items: 0,
              cleanup_deferred_extra_nodes: 0,
              item_count: 1
            },
            summary: {
              attempted_transfers: 1,
              successful_transfers: 1,
              failed_transfers: 0,
              skipped_items: 0,
              skipped_backoff: 0,
              skipped_max_retries: 0,
              skipped_detail_count: 0,
              nodes_contacted: 2,
              failed_nodes: 0,
              last_error: null
            },
            report: {
              detailed_log: [
                {
                  captured_at_unix: 1_899_999_900,
                  report_node_id: "node-alpha",
                  event: "repair_run_started",
                  detail: "starting replication repair run"
                }
              ]
            }
          }
        ]
      });
    }

    if (pathname === apiV1("/auth/repair/actions") && method === "GET") {
      return json(route, {
        actions: [
          {
            id: "legacy_rename_logical_paths",
            label: "Rename legacy logical paths",
            description: "Rewrite legacy logical paths to the current layout.",
            dry_run_supported: true,
            destructive: false
          },
          {
            id: "cleanup_delete_recreate_loop_metadata",
            label: "Clean duplicate delete/recreate loop metadata",
            description: "Collapse provably redundant delete/recreate loop lineages.",
            dry_run_supported: true,
            destructive: true
          },
          {
            id: "compact_snapshot_history",
            label: "Compact snapshot history",
            description:
              "Remove redundant snapshot checkpoints while preserving per-path retouch boundaries, with a 2-hour batch window.",
            dry_run_supported: true,
            destructive: true
          }
        ]
      });
    }

    if (pathname === apiV1("/auth/scrub/cluster") && method === "GET") {
      return json(route, {
        nodes: [
          {
            node_id: "node-alpha",
            state: "idle",
            enabled: true,
            interval_secs: 604800,
            retention_secs: 31104000,
            active_runs: [],
            latest_run: {
              run_id: "scrub-run-001",
              reporting_node_id: "node-alpha",
              trigger: "scheduled",
              status: "clean",
              started_at_unix: 1_899_999_000,
              finished_at_unix: 1_899_999_120,
              duration_ms: 120_000,
              summary: {
                current_keys_scanned: 12,
                version_indexes_scanned: 12,
                version_records_scanned: 12,
                manifests_scanned: 12,
                chunks_scanned: 24,
                bytes_scanned: 4096,
                issue_count: 0,
                sampled_issue_count: 0,
                issue_sample_truncated: false,
                issues: []
              },
              last_error: null
            }
          }
        ],
        skipped_nodes: [],
        runs: [
          {
            run_id: "scrub-run-001",
            reporting_node_id: "node-alpha",
            trigger: "scheduled",
            status: "clean",
            started_at_unix: 1_899_999_000,
            finished_at_unix: 1_899_999_120,
            duration_ms: 120_000,
            summary: {
              current_keys_scanned: 12,
              version_indexes_scanned: 12,
              version_records_scanned: 12,
              manifests_scanned: 12,
              chunks_scanned: 24,
              bytes_scanned: 4096,
              issue_count: 0,
              sampled_issue_count: 0,
              issue_sample_truncated: false,
              issues: []
            },
            last_error: null
          }
        ]
      });
    }

    if (pathname === apiV1("/auth/scrub/run") && method === "POST") {
      const scope = searchParams.get("scope") ?? "cluster";
      scrubTriggerScopes.add(scope);
      return json(route, {
        scope,
        nodes_contacted: scope === "local" ? 1 : 2,
        failed_nodes: 0,
        node_results: [
          {
            node_id: "node-alpha",
            started: true,
            active_run: {
              run_id: "scrub-run-live-001",
              trigger: "manual_request",
              started_at_unix: 1_900_000_200
            },
            error: null
          }
        ]
      });
    }

    if (pathname === apiV1("/cluster/replication/plan") && method === "GET") {
      if (options?.protectDashboardAdminRoutesUntilSessionConfirmed && !sessionConfirmed) {
        await route.fulfill({ status: 401 });
        return;
      }
      return json(route, {
        generated_at_unix: 1_900_000_005,
        under_replicated: 1,
        over_replicated: 0,
        cleanup_deferred_items: 0,
        cleanup_deferred_extra_nodes: 0,
        items: [
          {
            key: "photos/cover.jpg",
            desired_nodes: ["node-alpha", "node-beta"],
            current_nodes: ["node-alpha"],
            missing_nodes: ["node-beta"],
            extra_nodes: [],
            cleanup_option: "none",
            deferred_extra_nodes: 0
          }
        ]
      });
    }

    if (pathname === apiV1("/cluster/replication/repair") && method === "POST") {
      return json(route, {
        status: "repair-triggered",
        repaired_items: 1
      });
    }

    if (pathname === "/logs" && method === "GET") {
      return json(route, {
        entries: [
          {
            captured_at_unix: 1_700_000_000,
            line: "INFO runtime ready"
          },
          {
            captured_at_unix: 1_700_000_002,
            line: "INFO replication audit healthy"
          }
        ]
      });
    }

    if (pathname === apiV1("/health") && method === "GET") {
      return json(route, {
        node_id: "node-alpha",
        role: "server-node",
        online: true,
        version: "0.1.0",
        revision: "v0.1.0-5-gmocked"
      });
    }

    if (pathname === apiV1("/storage/stats/current") && method === "GET") {
      return json(route, {
        sample: {
          collected_at_unix: 1_900_000_120,
          latest_snapshot_id: "snapshot-9",
          latest_snapshot_created_at_unix: 1_900_000_100,
          latest_snapshot_object_count: 42,
          chunk_store_bytes: 1_234_000_000,
          manifest_store_bytes: 12_000_000,
          metadata_db_bytes: 4_000_000,
          media_cache_bytes: 8_000_000,
          latest_snapshot_logical_bytes: 2_468_000_000,
          latest_snapshot_unique_chunk_bytes: 1_100_000_000
        },
        collecting: false,
        last_attempt_unix: 1_900_000_120,
        last_success_unix: 1_900_000_120,
        last_error: null
      });
    }

    if (pathname === apiV1("/storage/stats/history") && method === "GET") {
      expect(searchParams.get("max_points")).toBe("360");
      expect(searchParams.get("since_unix")).not.toBeNull();
      return json(route, [
        {
          collected_at_unix: 1_900_000_120,
          latest_snapshot_id: "snapshot-9",
          latest_snapshot_created_at_unix: 1_900_000_100,
          latest_snapshot_object_count: 42,
          chunk_store_bytes: 1_234_000_000,
          manifest_store_bytes: 12_000_000,
          metadata_db_bytes: 4_000_000,
          media_cache_bytes: 8_000_000,
          latest_snapshot_logical_bytes: 2_468_000_000,
          latest_snapshot_unique_chunk_bytes: 1_100_000_000
        },
        {
          collected_at_unix: 1_900_000_060,
          latest_snapshot_id: "snapshot-8",
          latest_snapshot_created_at_unix: 1_900_000_040,
          latest_snapshot_object_count: 40,
          chunk_store_bytes: 1_190_000_000,
          manifest_store_bytes: 11_500_000,
          metadata_db_bytes: 3_900_000,
          media_cache_bytes: 7_500_000,
          latest_snapshot_logical_bytes: 2_310_000_000,
          latest_snapshot_unique_chunk_bytes: 1_070_000_000
        },
        {
          collected_at_unix: 1_900_000_000,
          latest_snapshot_id: "snapshot-7",
          latest_snapshot_created_at_unix: 1_899_999_980,
          latest_snapshot_object_count: 38,
          chunk_store_bytes: 1_120_000_000,
          manifest_store_bytes: 11_200_000,
          metadata_db_bytes: 3_800_000,
          media_cache_bytes: 7_200_000,
          latest_snapshot_logical_bytes: 2_210_000_000,
          latest_snapshot_unique_chunk_bytes: 1_020_000_000
        }
      ]);
    }

    if (pathname === apiV1("/auth/storage/stats/metadata-db/logical") && method === "GET") {
      if (metadataDbLogicalDistributionPhase === "running") {
        metadataDbLogicalDistributionPhase = "ready";
        return json(route, {
          state: "running",
          backend: "sqlite",
          started_at_unix: 1_900_000_118,
          finished_at_unix: null,
          last_error: null,
          progress: {
            completed_tables: 12,
            total_tables: 20,
            current_table: "data_change_events"
          },
          distribution: null
        });
      }

      return json(route, {
        state: "idle",
        backend: "sqlite",
        started_at_unix: metadataDbLogicalDistributionPhase === "ready" ? 1_900_000_118 : null,
        finished_at_unix: metadataDbLogicalDistributionPhase === "ready" ? 1_900_000_121 : null,
        last_error: null,
        progress: null,
        distribution:
          metadataDbLogicalDistributionPhase === "ready"
            ? metadataDbLogicalDistribution
            : null
      });
    }

    if (pathname === apiV1("/auth/storage/stats/metadata-db/logical") && method === "POST") {
      metadataDbLogicalDistributionPhase = "running";
      return json(route, {
        started: true,
        status: {
          state: "running",
          backend: "sqlite",
          started_at_unix: 1_900_000_118,
          finished_at_unix: null,
          last_error: null,
          progress: {
            completed_tables: 0,
            total_tables: 20,
            current_table: null
          },
          distribution: null
        }
      });
    }

    if (pathname === "/setup/status" && method === "GET" && options?.setupMode) {
      return json(route, {
        state: "pending_join",
        data_dir: "/tmp/ironmesh-node-beta",
        bind_addr: "0.0.0.0:8443",
        bootstrap_tls_cert_path: "/tmp/bootstrap.pem",
        bootstrap_tls_fingerprint: "setup-fingerprint",
        cluster_id: null,
        node_id: "node-beta",
        pending_join_request: {
          version: 1,
          node_id: "node-beta",
          cluster_id: "cluster-alpha"
        }
      });
    }

    if (pathname === "/setup/status" && method === "GET") {
      const status = options?.setupProbeStatus ?? 404;
      if (status === 404) {
        await route.fulfill({
          status,
          contentType: "application/json; charset=utf-8",
          body: JSON.stringify({ error: "setup mode not active" })
        });
        return;
      }

      await route.fulfill({ status });
      return;
    }

    if (pathname === "/setup/start-cluster" && method === "POST") {
      return json(route, {
        status: "transitioning_to_online",
        cluster_id: "cluster-new",
        node_id: "node-new",
        public_url: "https://node-new.local",
        restart_required: false
      });
    }

    if (pathname === "/setup/join/request" && method === "POST") {
      return json(route, {
        version: 1,
        node_id: "node-beta",
        cluster_id: "cluster-alpha"
      });
    }

    if (pathname === "/setup/join/import" && method === "POST") {
      return json(route, {
        status: "transitioning_to_online",
        cluster_id: "cluster-alpha",
        node_id: "node-beta",
        public_url: "https://node-beta.local",
        restart_required: false
      });
    }

    if (pathname === apiV1("/auth/bootstrap-claims/issue") && method === "POST") {
      const body = route.request().postDataJSON() as { preferred_rendezvous_url?: string | null };
      if (options?.bootstrapClaimMode === "bad_gateway") {
        await route.fulfill({
          status: 502
        });
        return;
      }

      return json(route, {
        bootstrap_bundle: bootstrapBundle,
        bootstrap_claim: {
          v: 1,
          c: "cluster-alpha",
          n: "node-alpha",
          r: [
            typeof body.preferred_rendezvous_url === "string" && body.preferred_rendezvous_url.trim().length > 0
              ? new URL(body.preferred_rendezvous_url).toString()
              : "https://node-alpha.local/rendezvous"
          ],
          t: "TUlJQy4uLg",
          k: "im-claim-example"
        }
      });
    }

    if (pathname === apiV1("/auth/bootstrap-bundles/issue") && method === "POST") {
      return json(route, bootstrapBundle);
    }

    if (pathname === apiV1("/auth/node-join-requests/issue-enrollment") && method === "POST") {
      return json(route, {
        bootstrap: {
          cluster_id: "cluster-alpha"
        },
        public_tls_material: {
          cert_pem: "public-cert"
        },
        internal_tls_material: {
          cert_pem: "internal-cert"
        }
      });
    }

    if (pathname === apiV1("/auth/client-credentials") && method === "GET") {
      return json(route, buildCredentialList(revokedDeviceIds));
    }

    if (pathname === apiV1("/auth/bootstrap-claims") && method === "GET") {
      return json(route, buildBootstrapClaimList());
    }

    if (pathname === apiV1("/auth/s3/status") && method === "GET") {
      return json(route, buildS3Status());
    }

    if (pathname === apiV1("/auth/s3/buckets") && method === "GET") {
      return json(route, s3Buckets);
    }

    if (pathname === apiV1("/auth/s3/buckets") && method === "POST") {
      const body = route.request().postDataJSON() as {
        bucket_name: string;
        root_prefix?: string | null;
        versioning_status?: "disabled" | "enabled" | null;
        read_only?: boolean;
      };
      const bucket = {
        bucket_name: body.bucket_name,
        root_prefix: body.root_prefix?.trim() || `s3/${body.bucket_name}/`,
        versioning_status: body.versioning_status ?? "disabled",
        read_only: body.read_only === true,
        created_at_unix: 1_900_000_220,
        updated_at_unix: 1_900_000_220,
        created_by: "admin-user",
        deleted_at_unix: null
      };
      s3Buckets.push(bucket);
      s3LocalGeneration += 1;
      return json(route, bucket);
    }

    if (pathname.startsWith(`${apiV1("/auth/s3/buckets")}/`) && method === "DELETE") {
      const bucketName = decodeURIComponent(pathname.split("/").pop() ?? "");
      const bucketIndex = s3Buckets.findIndex((bucket) => bucket.bucket_name === bucketName);
      if (bucketIndex >= 0) {
        s3Buckets.splice(bucketIndex, 1);
        s3LocalGeneration += 1;
      }
      return json(route, { status: "deleted" });
    }

    if (pathname === apiV1("/auth/s3/access-keys") && method === "GET") {
      return json(route, s3AccessKeys);
    }

    if (pathname === apiV1("/auth/s3/access-keys") && method === "POST") {
      const body = route.request().postDataJSON() as {
        description?: string | null;
        bucket_scope?: string[];
        prefix_scope?: string[];
        allow_list?: boolean;
        allow_read?: boolean;
        allow_write?: boolean;
        allow_delete?: boolean;
        allow_manage?: boolean;
      };
      const accessKeyId = `IMS3TEST${String(nextS3AccessKeySuffix).padStart(4, "0")}`;
      const secretAccessKey = `im_secret_${nextS3AccessKeySuffix}`;
      nextS3AccessKeySuffix += 1;
      const view = {
        access_key_id: accessKeyId,
        description: body.description?.trim() || null,
        bucket_scope: body.bucket_scope ?? [],
        prefix_scope: body.prefix_scope ?? [],
        allow_list: body.allow_list !== false,
        allow_read: body.allow_read !== false,
        allow_write: body.allow_write === true,
        allow_delete: body.allow_delete === true,
        allow_manage: body.allow_manage === true,
        created_at_unix: 1_900_000_230,
        updated_at_unix: 1_900_000_230,
        last_used_at_unix: null,
        revoked_at_unix: null,
        secret_fingerprint: `fp-${accessKeyId.toLowerCase()}`
      };
      s3AccessKeys.push(view);
      s3LocalGeneration += 1;
      return json(route, {
        access_key_id: accessKeyId,
        secret_access_key: secretAccessKey,
        view
      });
    }

    if (
      pathname.startsWith(`${apiV1("/auth/s3/access-keys")}/`) &&
      pathname.endsWith("/revoke") &&
      method === "POST"
    ) {
      const accessKeyId = decodeURIComponent(
        pathname
          .slice(`${apiV1("/auth/s3/access-keys")}/`.length)
          .replace(/\/revoke$/, "")
      );
      const accessKey = s3AccessKeys.find((entry) => entry.access_key_id === accessKeyId);
      if (accessKey) {
        accessKey.revoked_at_unix = 1_900_000_240;
        accessKey.updated_at_unix = 1_900_000_240;
        s3LocalGeneration += 1;
      }
      return json(route, { status: "revoked" });
    }

    if (pathname === apiV1("/auth/rendezvous-config") && method === "GET") {
      if (options?.protectDashboardAdminRoutesUntilSessionConfirmed && !sessionConfirmed) {
        await route.fulfill({ status: 401 });
        return;
      }
      return json(route, rendezvousConfig);
    }

    if (pathname === apiV1("/auth/direct-endpoints-config") && method === "GET") {
      if (options?.protectDashboardAdminRoutesUntilSessionConfirmed && !sessionConfirmed) {
        await route.fulfill({ status: 401 });
        return;
      }
      return json(route, directEndpointsConfig);
    }

    if (pathname === apiV1("/auth/direct-endpoints-config") && method === "PUT") {
      const body = route.request().postDataJSON() as {
        public_urls?: string[];
        peer_urls?: string[];
      };
      directEndpointsConfig = {
        ...directEndpointsConfig,
        editable_public_urls: body.public_urls ?? [],
        effective_public_urls: [
          "https://node-alpha.local",
          ...(body.public_urls ?? [])
        ],
        editable_peer_urls: body.peer_urls ?? [],
        effective_peer_urls: [
          "https://node-alpha.local:18080",
          ...(body.peer_urls ?? [])
        ]
      };
      return json(route, directEndpointsConfig);
    }

    if (pathname === apiV1("/auth/rendezvous-config") && method === "PUT") {
      const body = route.request().postDataJSON() as { editable_urls?: string[] };
      rendezvousConfig = {
        ...rendezvousConfig,
        editable_urls: body.editable_urls ?? [],
        effective_urls: [
          "https://embedded-rendezvous.local:9443",
          ...(body.editable_urls ?? [])
        ]
      };
      return json(route, rendezvousConfig);
    }

    if (pathname.startsWith(apiV1("/auth/client-credentials/")) && method === "DELETE") {
      revokedDeviceIds.add(decodeURIComponent(pathname.split("/").pop() ?? ""));
      return json(route, { status: "revoked" });
    }

    if (pathname === apiV1("/auth/node-certificates/status") && method === "GET") {
      return json(route, {
        public_tls: {
          name: "public",
          configured: true,
          cert_path: "tls/public.pem",
          metadata_path: "tls/public.meta.json",
          issued_at_unix: 1_900_000_000,
          renew_after_unix: 1_900_100_000,
          expires_at_unix: 1_900_200_000,
          seconds_until_expiry: 200_000,
          certificate_fingerprint: "public-cert-fingerprint",
          metadata_matches_certificate: true,
          state: "healthy"
        },
        internal_tls: {
          name: "internal",
          configured: true,
          cert_path: "tls/internal.pem",
          metadata_path: "tls/internal.meta.json",
          issued_at_unix: 1_900_000_000,
          renew_after_unix: 1_900_100_000,
          expires_at_unix: 1_900_200_000,
          seconds_until_expiry: 200_000,
          certificate_fingerprint: "internal-cert-fingerprint",
          metadata_matches_certificate: true,
          state: "healthy"
        },
        auto_renew: {
          enabled: true,
          enrollment_path: "node-enrollment.json",
          issuer_url: "https://node-alpha.local",
          check_interval_secs: 300,
          last_attempt_unix: 1_900_000_050,
          last_success_unix: 1_900_000_040,
          last_error: null,
          restart_required: false
        }
      });
    }

    if (pathname === apiV1("/auth/managed-control-plane/promotion/export") && method === "POST") {
      return json(route, {
        signer_backup: {
          version: 1,
          from: "node-alpha"
        },
        rendezvous_failover: {
          version: 1,
          to: "node-beta"
        }
      });
    }

    if (pathname === apiV1("/auth/managed-rendezvous/failover/export") && method === "POST") {
      const body = route.request().postDataJSON() as {
        deployment_target?: "embedded_node" | "standalone_service";
        target_node_id?: string | null;
      };
      if (
        body.deployment_target === "standalone_service" &&
        body.target_node_id !== undefined &&
        body.target_node_id !== null &&
        body.target_node_id !== ""
      ) {
        return route.fulfill({
          status: 400,
          contentType: "application/json",
          body: JSON.stringify({ error: "standalone exports should not send target_node_id" })
        });
      }
      return json(route, {
        version: 1,
        cluster_id: "cluster-alpha",
        source_node_id: "node-alpha",
        ...(body.deployment_target === "standalone_service"
          ? {}
          : { target_node_id: "node-beta" }),
        public_url: "https://node-beta.local/rendezvous",
        deployment_target: body.deployment_target ?? "embedded_node",
        includes_cluster_ca_cert: true
      });
    }

    if (pathname === apiV1("/auth/managed-rendezvous/failover/import") && method === "POST") {
      const body = route.request().postDataJSON() as {
        package?: {
          target_node_id?: string;
        };
      };
      if (!body.package?.target_node_id) {
        return route.fulfill({
          status: 400,
          contentType: "application/json",
          body: JSON.stringify({
            error: "managed rendezvous failover package does not target an embedded node"
          })
        });
      }
      return json(route, {
        status: "imported",
        cluster_id: "cluster-alpha",
        source_node_id: "node-alpha",
        target_node_id: "node-beta",
        public_url: "https://node-beta.local/rendezvous",
        restart_required: true,
        cert_path: "tls/rendezvous.pem",
        key_path: "tls/rendezvous.key"
      });
    }

    if (pathname === apiV1("/auth/managed-control-plane/promotion/import") && method === "POST") {
      return json(route, {
        status: "imported",
        cluster_id: "cluster-alpha",
        source_node_id: "node-alpha",
        target_node_id: "node-beta",
        public_url: "https://node-beta.local/rendezvous",
        restart_required: true,
        signer_ca_cert_path: "tls/cluster-ca.pem",
        rendezvous_cert_path: "tls/rendezvous.pem",
        rendezvous_key_path: "tls/rendezvous.key"
      });
    }

    return route.continue();
  });

  return {
    requestedPaths: () => Array.from(requestedPaths),
    scrubTriggerScopes: () => Array.from(scrubTriggerScopes),
    restoredVersions: () => restoredVersions.slice(),
    storagePoolSaveRequests: () => storagePoolSaveRequests.slice()
  };
}

type StoragePoolMockConfig = {
  version: number;
  paths: Array<{
    id: string;
    path: string;
    state: "active" | "draining" | "disabled";
    weight: number;
    reserve_bytes: number;
  }>;
};

function storagePoolStatus(config: StoragePoolMockConfig) {
  return {
    config_path: "/var/lib/ironmesh/state/storage-pool.json",
    config,
    paths: config.paths.map((path) => ({
      id: path.id,
      path: path.path,
      state: path.state,
      available: true,
      capacity_bytes: 2_000_000_000,
      free_bytes: 1_500_000_000,
      chunk_store_bytes: 1024,
      manifest_store_bytes: 256,
      last_error: null
    }))
  };
}

type AdminMockStoreEntry = {
  path: string;
  entry_type: "prefix" | "key";
  media?: Record<string, unknown>;
};

function buildAdminStoreIndexResponse(
  entries: AdminMockStoreEntry[],
  searchParams: URLSearchParams
) {
  const prefix = searchParams.get("prefix") ?? "";
  const depth = Number(searchParams.get("depth") ?? "1");
  const mediaFilter = searchParams.get("media_filter");

  if (!mediaFilter) {
    return {
      prefix,
      depth,
      entry_count: entries.length,
      entries
    };
  }

  const filteredEntries = entries.filter((entry) => matchesAdminMediaFilter(entry, mediaFilter));
  const totalEntryCount = filteredEntries.length;
  const offset = Math.max(0, Number(searchParams.get("offset") ?? "0") || 0);
  const limitParam = searchParams.get("limit");
  const limit = limitParam ? Math.max(1, Number(limitParam) || 1) : null;
  const pagedEntries =
    typeof limit === "number"
      ? filteredEntries.slice(offset, offset + limit)
      : filteredEntries.slice(offset);

  return {
    prefix,
    depth,
    entry_count: pagedEntries.length,
    total_entry_count: totalEntryCount,
    offset,
    limit,
    has_more: offset + pagedEntries.length < totalEntryCount,
    media_summary: summarizeAdminMediaEntries(filteredEntries),
    entries: pagedEntries
  };
}

function buildAdminVersionGraphResponse(key: string, preferredHeadVersionId: string | null) {
  if (key === "gallery/cat.png") {
    return {
      key,
      preferred_head_version_id: preferredHeadVersionId,
      versions: [
        {
          version_id: "version-cat-001",
          entry_type: "key",
          size_bytes: 3_145_728,
          modified_at_unix: 1_712_345_678,
          created_at_unix: 1_712_345_678,
          media: {
            status: "ready",
            media_type: "image",
            mime_type: "image/png",
            thumbnail: {
              url: `${apiV1("/auth/media/thumbnail")}?key=gallery%2Fcat.png&version=version-cat-001`,
              profile: "grid",
              width: 256,
              height: 192,
              format: "jpeg",
              size_bytes: 1234
            }
          }
        },
        {
          version_id: "version-cat-000",
          entry_type: "key",
          size_bytes: 3_145_728,
          modified_at_unix: 1_712_300_000,
          created_at_unix: 1_712_300_000,
          media: {
            status: "ready",
            media_type: "image",
            mime_type: "image/png",
            thumbnail: {
              url: `${apiV1("/auth/media/thumbnail")}?key=gallery%2Fcat.png&version=version-cat-000`,
              profile: "grid",
              width: 256,
              height: 192,
              format: "jpeg",
              size_bytes: 1234
            }
          }
        }
      ]
    };
  }

  return {
    key,
    preferred_head_version_id: preferredHeadVersionId,
    versions: [
      {
        version_id: "version-001",
        entry_type: "key",
        size_bytes: 23,
        modified_at_unix: 1_712_345_600,
        created_at_unix: 1_712_345_600
      },
      {
        version_id: "version-000",
        entry_type: "key",
        size_bytes: 21,
        modified_at_unix: 1_712_300_000,
        created_at_unix: 1_712_300_000
      }
    ]
  };
}

function matchesAdminMediaFilter(entry: AdminMockStoreEntry, mediaFilter: string): boolean {
  const media = entry.media;
  if (!media) {
    return false;
  }

  if (mediaFilter === "all") {
    return true;
  }

  return media.media_type === mediaFilter;
}

function summarizeAdminMediaEntries(entries: AdminMockStoreEntry[]) {
  return entries.reduce(
    (summary, entry) => {
      const media = entry.media;
      if (!media) {
        return summary;
      }

      if (media.status === "ready") {
        summary.ready_count += 1;
      } else if (media.status === "pending") {
        summary.pending_count += 1;
      } else {
        summary.incomplete_count += 1;
      }

      if (media.media_type === "image") {
        summary.image_count += 1;
      }
      if (media.media_type === "video") {
        summary.video_count += 1;
      }
      if (media.gps) {
        summary.geotagged_count += 1;
      }

      return summary;
    },
    {
      ready_count: 0,
      pending_count: 0,
      incomplete_count: 0,
      image_count: 0,
      video_count: 0,
      geotagged_count: 0
    }
  );
}

function buildRetriedAdminMedia(
  entry: AdminMockStoreEntry,
  thumbnailSizeBytes: number
): Record<string, unknown> {
  const existingMedia = entry.media ?? {};
  const mediaType =
    typeof existingMedia.media_type === "string"
      ? existingMedia.media_type
      : entry.path.toLowerCase().endsWith(".mp4")
        ? "video"
        : "image";
  const mimeType =
    typeof existingMedia.mime_type === "string"
      ? existingMedia.mime_type
      : mediaType === "video"
        ? "video/mp4"
        : "image/png";

  return {
    ...existingMedia,
    status: "ready",
    media_type: mediaType,
    mime_type: mimeType,
    error: null,
    thumbnail: {
      url: `${apiV1("/auth/media/thumbnail")}?key=${encodeURIComponent(entry.path)}`,
      profile: "grid",
      width: 256,
      height: mediaType === "video" ? 144 : 192,
      format: "jpeg",
      size_bytes: thumbnailSizeBytes
    }
  };
}

function restoreAdminMockStorePath(
  entries: AdminMockStoreEntry[],
  fromPath: string,
  toPath: string,
  recursive: boolean
): number {
  const normalizedFrom = fromPath.trim();
  const normalizedTo = toPath.trim();
  if (!normalizedFrom || !normalizedTo) {
    return 0;
  }

  const sourceEntries = recursive || normalizedFrom.endsWith("/")
    ? entries.filter(
        (entry) => entry.path === normalizedFrom || entry.path.startsWith(normalizedFrom)
      )
    : entries.filter((entry) => entry.path === normalizedFrom);

  for (const sourceEntry of sourceEntries) {
    const nextPath =
      sourceEntry.path === normalizedFrom
        ? normalizedTo
        : `${normalizedTo}${sourceEntry.path.slice(normalizedFrom.length)}`;
    const nextEntry: AdminMockStoreEntry = {
      ...sourceEntry,
      path: nextPath,
      media: sourceEntry.media ? { ...sourceEntry.media } : undefined
    };
    const existingEntry = entries.find((entry) => entry.path === nextPath);
    if (existingEntry) {
      existingEntry.entry_type = nextEntry.entry_type;
      existingEntry.media = nextEntry.media;
      continue;
    }
    entries.push(nextEntry);
  }

  return sourceEntries.length;
}

function createDefaultAdminGalleryEntries(): AdminMockStoreEntry[] {
  return [
    { path: "docs/readme.txt", entry_type: "key" },
    { path: "media/", entry_type: "prefix" },
    {
      path: "gallery/cat.png",
      entry_type: "key",
      media: {
        status: "ready",
        content_fingerprint: "fingerprint-cat",
        media_type: "image",
        mime_type: "image/png",
        width: 1024,
        height: 768,
        taken_at_unix: 1_712_345_678,
        gps: {
          latitude: 47.3769,
          longitude: 8.5417
        },
        thumbnail: {
          url: "/api/v1/auth/media/thumbnail?key=gallery%2Fcat.png",
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
          url: "/api/v1/auth/media/thumbnail?key=gallery%2Fdog.jpg",
          profile: "grid",
          width: 256,
          height: 256,
          format: "jpeg",
          size_bytes: 0
        }
      }
    }
  ];
}

function createClusteredAdminGalleryEntries(count: number): AdminMockStoreEntry[] {
  return Array.from({ length: count }, (_, index) => {
    const path = `gallery/cluster-${String(index + 1).padStart(2, "0")}.png`;
    return {
      path,
      entry_type: "key",
      media: {
        status: "ready",
        content_fingerprint: `fingerprint-cluster-${index + 1}`,
        media_type: "image",
        mime_type: "image/png",
        width: 1024,
        height: 768,
        taken_at_unix: 1_712_345_678 + index,
        gps: {
          latitude: 47.3769,
          longitude: 8.5417
        },
        thumbnail: {
          url: `${apiV1("/auth/media/thumbnail")}?key=${encodeURIComponent(path)}`,
          profile: "grid",
          width: 256,
          height: 192,
          format: "jpeg",
          size_bytes: 1234
        }
      }
    };
  });
}

function createGeoSpreadClusteredAdminGalleryEntries(count: number): AdminMockStoreEntry[] {
  const centerOffset = (count - 1) / 2;

  return Array.from({ length: count }, (_, index) => {
    const path = `gallery/spread-cluster-${String(index + 1).padStart(2, "0")}.png`;
    const offset = (index - centerOffset) * 0.0003;

    return {
      path,
      entry_type: "key",
      media: {
        status: "ready",
        content_fingerprint: `fingerprint-spread-cluster-${index + 1}`,
        media_type: "image",
        mime_type: "image/png",
        width: 1024,
        height: 768,
        taken_at_unix: 1_712_445_678 + index,
        gps: {
          latitude: 47.3769 + offset,
          longitude: 8.5417 + offset * 0.8
        },
        thumbnail: {
          url: `${apiV1("/auth/media/thumbnail")}?key=${encodeURIComponent(path)}`,
          profile: "grid",
          width: 256,
          height: 192,
          format: "jpeg",
          size_bytes: 1234
        }
      }
    };
  });
}

function buildCredentialList(revokedDeviceIds: Set<string>) {
  return [
    {
      device_id: "client-credential-a",
      label: "Pixel test phone",
      public_key_fingerprint: "pk-client-credential-a",
      credential_fingerprint: "cred-client-credential-a",
      created_at_unix: 1_900_000_001,
      revocation_reason: revokedDeviceIds.has("client-credential-a") ? "manual smoke revocation" : null,
      revoked_by_actor: revokedDeviceIds.has("client-credential-a") ? "admin" : null,
      revoked_by_source_node: revokedDeviceIds.has("client-credential-a") ? "node-alpha" : null,
      revoked_at_unix: revokedDeviceIds.has("client-credential-a") ? 1_900_000_100 : null
    },
    {
      device_id: "client-credential-b",
      label: "Desktop sync client",
      public_key_fingerprint: "pk-client-credential-b",
      credential_fingerprint: "cred-client-credential-b",
      created_at_unix: 1_900_000_002,
      revocation_reason: null,
      revoked_by_actor: null,
      revoked_by_source_node: null,
      revoked_at_unix: null
    }
  ];
}

function buildBootstrapClaimList() {
  return [
    {
      claim_id: "claim-001",
      claim_fingerprint: "claim-fingerprint-001",
      label: "MacBook Pro",
      target_node_id: "node-alpha",
      rendezvous_urls: ["https://node-alpha.local/rendezvous"],
      created_at_unix: 1_900_000_000,
      expires_at_unix: 1_900_000_300,
      used_at_unix: null,
      consumed_by_device_id: null,
      status: "pending"
    }
  ];
}

async function json(route: Route, payload: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json; charset=utf-8",
    body: JSON.stringify(payload)
  });
}

function tinyPngBuffer(): Buffer {
  return Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0N8AAAAASUVORK5CYII=",
    "base64"
  );
}
