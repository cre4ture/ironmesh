import { expect, test } from "@playwright/test";

const PLAYWRIGHT_RUNTIME_ADMIN_PASSWORD = "playwright-runtime-password";

test("server-admin is served by a real server-node runtime", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Version info", { exact: true })).toBeVisible();
  await expect(page.getByText(/UI build:\s*\S+\s+\(.+\)/)).toBeVisible();
  await expect(page.getByText(/Backend build:\s*\S+\s+\(.+\)/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "ironmesh Server Node" })).toHaveCount(0);
  await expect(page.getByText("Server Admin", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin password").fill(PLAYWRIGHT_RUNTIME_ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("server-admin-session-badge")).toHaveText("signed in", { timeout: 60_000 });
  await page.keyboard.press("Escape");

  await expect(page.getByTestId("dashboard-cluster-nodes-card")).toContainText("1 / 1", { timeout: 60_000 });
  await expect(page.getByText("This node", { exact: true })).toBeVisible();
  await expect(page.getByText("Rendezvous participation", { exact: true })).toBeVisible();
  await expect(page.getByText("Storage stats", { exact: true })).toBeVisible();
  await expect(page.getByText("Process resource usage", { exact: true })).toBeVisible();
  await expect(page.getByText("Peak Temperature", { exact: true })).toBeVisible();
  await expect(page.getByText("Temperature sensors", { exact: true })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Collected at (UTC)" })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Storage used (bytes)" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom in on storage history chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom out of storage history chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset storage history chart zoom" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom in on temperature chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Zoom out of temperature chart" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset temperature chart zoom" })).toBeVisible();
  await expect(page.getByRole("button", { name: "30d", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "All", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "0 B", exact: true })).toHaveCount(0);

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

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();
  await expect(page.locator("pre").filter({ hasText: '"cluster_id"' })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"direct_endpoints"' })).toBeVisible();
  await expect(
    page
      .getByAltText("Client bootstrap QR code")
      .or(page.getByText("Bootstrap QR fallback", { exact: true }))
  ).toBeVisible();

  await page.getByText("Logs", { exact: true }).click();
  await expect(page.getByText("Recent server logs", { exact: true })).toBeVisible();
  await expect(page.getByText("Failed to load logs", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("log")).toContainText(/T\d{2}:\d{2}:\d{2}\.000Z|no logs yet/, {
    timeout: 60_000
  });

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByText(/No (image|media) objects in view/)).toBeVisible();

  await page.getByText("S3", { exact: true }).click();
  await expect(page.getByText("Listener and replication status", { exact: true })).toBeVisible();
  await expect(page.getByText("Bucket mappings", { exact: true })).toBeVisible();
  await expect(page.getByText("Access keys", { exact: true })).toBeVisible();

  await page.getByText("Certificates", { exact: true }).click();
  await expect(page.getByText("Configured on this node").first()).toBeVisible();
  await expect(page.getByText("Auto renew", { exact: true })).toBeVisible();

  await page.getByText("Control Plane", { exact: true }).click();
  await expect(page.getByText("Advertised direct node URLs")).toBeVisible();
  await page
    .getByRole("textbox", { name: "Additional public API URLs" })
    .fill("https://node.example:8443");
  await page
    .getByRole("textbox", { name: "Additional peer API URLs" })
    .fill("https://node.example:18443");
  await page.getByRole("button", { name: "Save direct node URLs" }).click();
  await expect(page.locator("pre").filter({ hasText: "node.example:18443" }).first()).toBeVisible();
  await expect(page.getByText("Rendezvous service URLs")).toBeVisible();
  await page
    .getByRole("textbox", { name: "Editable operator-managed URLs" })
    .fill("https://rendezvous.example:9443");
  await page.getByRole("button", { name: "Save rendezvous URLs" }).click();
  await expect(page.locator("pre").filter({ hasText: "rendezvous.example:9443" }).first()).toBeVisible();
  await expect(page.getByText("Export rendezvous-only failover package")).toBeVisible();
  await expect(page.getByText("Dedicated standalone ironmesh-rendezvous-service")).toBeVisible();

  await expect(page.getByLabel("Primary navigation").getByText("Setup", { exact: true })).toHaveCount(0);
});
