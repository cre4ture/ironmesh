import { expect, test, type Page } from "@playwright/test";

test("server-admin setup mode uses the shared React app and transitions to runtime", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Setup" })).toBeVisible();
  await waitForRouteReady(page, "setup");
  await expect(page.getByText("setup mode", { exact: true })).toBeVisible();
  await expect(page.getByText("This is the live first-run bootstrap UI")).toBeVisible();
  await expect(page.getByLabel("Administrator password for this node")).toBeVisible();
  await expect(
    page.getByText(
      "Set the password used to administer this node after enrollment. It is stored locally and does not need to match other cluster nodes."
    )
  ).toBeVisible();

  await page.getByLabel("Initial admin password").fill("playwright-setup-password");
  await page.getByRole("button", { name: "Start a new cluster" }).click();

  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("server-admin-session-badge")).toHaveText("signed in", {
    timeout: 60_000
  });
  await waitForRouteReady(page, "dashboard");

  await page.getByText("Provisioning", { exact: true }).click();
  await waitForRouteReady(page, "bootstrap");
  await page.getByRole("button", { name: "Issue bootstrap claim" }).click();
  await expect(page.locator("pre").filter({ hasText: '"cluster_id"' })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: '"rendezvous_urls"' })).toBeVisible();
  await expect(page.getByAltText("Client bootstrap QR code")).toBeVisible();
});

async function waitForRouteReady(page: Page, routeId: string) {
  await expect(page.getByTestId(`server-admin-route-${routeId}`)).toBeVisible({ timeout: 60_000 });
}
