import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 90_000,
  expect: {
    timeout: 15_000
  },
  use: {
    baseURL: "http://127.0.0.1:18081",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "node tests/scripts/run-cli-client-gallery-runtime.mjs",
    url: "http://127.0.0.1:18081/api/v1/ping",
    reuseExistingServer: false,
    timeout: 120_000
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
