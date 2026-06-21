import { mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const repoRoot = resolve(process.cwd(), "..");
const dataDir = resolve(process.cwd(), "test-results", "server-node-runtime-data");
const binaryPath = resolve(
  repoRoot,
  "target",
  "debug",
  process.platform === "win32" ? "ironmesh-server-node.exe" : "ironmesh-server-node"
);
const publicOrigin = "https://127.0.0.1:18181";
const runtimeAdminPassword = "playwright-runtime-password";
let fatalBootstrapError = false;

rmSync(dataDir, { recursive: true, force: true });
mkdirSync(dataDir, { recursive: true });

const child = spawn(binaryPath, [], {
  cwd: repoRoot,
  env: {
    ...process.env,
    IRONMESH_SERVER_BIND: "127.0.0.1:18181",
    IRONMESH_DATA_DIR: dataDir,
    RUST_LOG: process.env.RUST_LOG ?? "info"
  },
  stdio: "inherit"
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    if (!child.killed) {
      child.kill(signal);
    }
  });
}

child.on("exit", (code, signal) => {
  if (fatalBootstrapError) {
    process.exit(1);
  }

  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});

function delay(timeoutMs) {
  return new Promise((resolve) => {
    setTimeout(resolve, timeoutMs);
  });
}

async function waitForOk(url, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const response = await fetch(url, {
        cache: "no-store"
      });
      if (response.ok) {
        return response;
      }
      lastError = new Error(`unexpected status ${response.status} while waiting for ${url}`);
    } catch (error) {
      lastError = error;
    }

    await delay(500);
  }

  throw lastError ?? new Error(`timed out waiting for ${url}`);
}

async function bootstrapRuntime() {
  await waitForOk(`${publicOrigin}/setup/status`, 60_000);

  const response = await fetch(`${publicOrigin}/setup/start-cluster`, {
    method: "POST",
    cache: "no-store",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      admin_password: runtimeAdminPassword,
      public_origin: publicOrigin
    })
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`failed to start runtime cluster setup: HTTP ${response.status}: ${errorText}`);
  }

  await waitForOk(`${publicOrigin}/api/v1/auth/admin/session`, 60_000);
}

void bootstrapRuntime().catch((error) => {
  fatalBootstrapError = true;
  console.error(error instanceof Error ? error.message : String(error));
  if (!child.killed) {
    child.kill("SIGTERM");
  }
});
