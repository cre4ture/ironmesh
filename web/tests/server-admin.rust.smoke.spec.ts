import { expect, test } from "@playwright/test";

test("server-admin is served by a real server-node runtime", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Version info", { exact: true })).toBeVisible();
  await expect(page.getByText(/UI build:\s*0\.1\.0 \(/)).toBeVisible();
  await expect(page.getByText(/Backend build:\s*0\.1\.0 \(/)).toBeVisible();
  await expect(page.getByRole("heading", { name: "ironmesh Server Node" })).toHaveCount(0);
  await expect(page.getByText("Server Admin", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin token override").fill("playwright-admin-token");
  await page.keyboard.press("Escape");

  await expect(page.getByText("1 / 1", { exact: true })).toBeVisible();
  await expect(page.getByText("This node", { exact: true })).toBeVisible();
  await expect(page.getByText("Rendezvous participation", { exact: true })).toBeVisible();
  await expect(page.getByText("Storage stats", { exact: true })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Collected at (UTC)" })).toBeVisible();
  await expect(page.locator('svg[aria-label="Storage stats history chart"] text').filter({ hasText: "Storage used (bytes)" })).toBeVisible();
  await expect(page.getByRole("button", { name: "30d", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "All", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "0 B", exact: true })).toHaveCount(0);

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
  await expect(page.getByText("server node listening")).toBeVisible();

  await page.getByText("Gallery", { exact: true }).click();
  await expect(page.getByText(/No (image|media) objects in view/)).toBeVisible();

  await page.getByText("Certificates", { exact: true }).click();
  await expect(page.getByText("Not configured on this node")).toHaveCount(1);
  await expect(page.getByText("Auto renew", { exact: true })).toBeVisible();

  await page.getByText("Control Plane", { exact: true }).click();
  await expect(page.getByText("Rendezvous service URLs")).toBeVisible();
  await page
    .getByRole("textbox", { name: "Editable operator-managed URLs" })
    .fill("https://rendezvous.example:9443");
  await page.getByRole("button", { name: "Save rendezvous URLs" }).click();
  await expect(page.locator("pre").filter({ hasText: "rendezvous.example:9443" }).first()).toBeVisible();
  await expect(page.getByText("Export rendezvous-only failover package")).toBeVisible();
  await expect(page.getByText("Dedicated standalone rendezvous-service")).toBeVisible();

  await page.getByText("Setup", { exact: true }).click();
  await expect(page.getByText("Bootstrap setup APIs are not active on this node")).toBeVisible();
});
