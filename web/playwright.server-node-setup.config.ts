import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 90_000,
  expect: {
    timeout: 10_000
  },
  use: {
    baseURL: "https://127.0.0.1:18443",
    trace: "retain-on-failure",
    ignoreHTTPSErrors: true
  },
  webServer: {
    command: "node tests/scripts/run-server-node-setup.mjs",
    url: "https://127.0.0.1:18443/health",
    reuseExistingServer: false,
    timeout: 90_000,
    ignoreHTTPSErrors: true
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
