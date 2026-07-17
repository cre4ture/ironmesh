import { expect, test } from "@playwright/test";

test("client-ui runtime logs page shows timestamp-prefixed entries", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await page.getByText("Logs", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Logs" })).toBeVisible();
  await expect(page.getByText("Recent client runtime logs", { exact: true })).toBeVisible();
  await expect(page.getByText("Failed to load logs", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("log")).toContainText(/T\d{2}:\d{2}:\d{2}\.000Z/, {
    timeout: 60_000
  });
});
