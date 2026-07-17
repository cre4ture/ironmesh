import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  expect: {
    timeout: 60_000
  },
  use: {
    baseURL: "http://127.0.0.1:18081",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "node tests/scripts/run-cli-client-runtime.mjs",
    url: "http://127.0.0.1:18081",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
