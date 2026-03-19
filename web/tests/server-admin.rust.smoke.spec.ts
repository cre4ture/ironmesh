import { expect, test } from "@playwright/test";

test("server-admin is served by a real server-node runtime", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "ironmesh Server Node" })).toHaveCount(0);
  await expect(page.getByText("Server Admin", { exact: true })).toBeVisible();
  await expect(page.getByText("1 / 1", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Admin Access" }).click();
  await page.getByLabel("Admin token override").fill("playwright-admin-token");
  await page.keyboard.press("Escape");

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByRole("button", { name: "Issue bootstrap bundle" }).click();
  await expect(page.locator("pre").filter({ hasText: '"cluster_id"' })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"direct_endpoints"' })).toBeVisible();

  await page.getByText("Logs", { exact: true }).click();
  await expect(page.getByText("server node listening")).toBeVisible();

  await page.getByText("Certificates", { exact: true }).click();
  await expect(page.getByText("Not configured on this node")).toHaveCount(2);
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
