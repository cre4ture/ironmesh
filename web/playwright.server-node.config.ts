import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 45_000,
  expect: {
    timeout: 5_000
  },
  use: {
    baseURL: "http://127.0.0.1:18181",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "node tests/scripts/run-server-node-runtime.mjs",
    url: "http://127.0.0.1:18181/health",
    reuseExistingServer: false,
    timeout: 60_000
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
