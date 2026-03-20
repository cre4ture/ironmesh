import { expect, test } from "@playwright/test";

test("server-admin setup mode uses the shared React app and transitions to runtime", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Setup" })).toBeVisible();
  await expect(page.getByText("setup mode", { exact: true })).toBeVisible();
  await expect(page.getByText("This is the live first-run bootstrap UI")).toBeVisible();

  await page.getByLabel("Initial admin password").fill("playwright-setup-password");
  await page.getByRole("button", { name: "Start a new cluster" }).click();

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText("signed in", { exact: true })).toBeVisible({ timeout: 60_000 });

  await page.getByText("Provisioning", { exact: true }).click();
  await page.getByRole("button", { name: "Issue bootstrap bundle" }).click();
  await expect(page.locator("pre").filter({ hasText: '"cluster_id"' })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"rendezvous_urls"' })).toBeVisible();
  await expect(page.getByAltText("Client bootstrap bundle QR code")).toBeVisible();
});
