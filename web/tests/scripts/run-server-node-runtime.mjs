import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { request as httpsRequest } from "node:https";

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
const bootstrapTlsCertPath = resolve(dataDir, "managed", "bootstrap-ui", "bootstrap-cert.pem");
const runtimePublicCaPath = resolve(dataDir, "managed", "runtime", "public", "public-ca.pem");
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

async function waitForFile(path, timeoutMs) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (existsSync(path)) {
      return;
    }
    await delay(250);
  }

  throw new Error(`timed out waiting for ${path}`);
}

async function requestText(url, { method = "GET", body, caPath } = {}) {
  const payload = body ? JSON.stringify(body) : null;
  const ca = caPath ? readFileSync(caPath, "utf8") : undefined;

  return await new Promise((resolve, reject) => {
    const request = httpsRequest(
      new URL(url),
      {
        method,
        ca,
        headers: payload
          ? {
              "content-type": "application/json",
              "content-length": String(Buffer.byteLength(payload))
            }
          : undefined
      },
      (response) => {
        const chunks = [];

        response.on("data", (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        response.on("end", () => {
          resolve({
            ok: (response.statusCode ?? 500) >= 200 && (response.statusCode ?? 500) < 300,
            status: response.statusCode ?? 500,
            text: Buffer.concat(chunks).toString("utf8")
          });
        });
      }
    );

    request.on("error", reject);
    if (payload) {
      request.write(payload);
    }
    request.end();
  });
}

async function waitForOk(url, timeoutMs, caPath) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const response = await requestText(url, { caPath });
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
  await waitForFile(bootstrapTlsCertPath, 60_000);
  await waitForOk(`${publicOrigin}/setup/status`, 60_000, bootstrapTlsCertPath);

  const response = await requestText(`${publicOrigin}/setup/start-cluster`, {
    method: "POST",
    caPath: bootstrapTlsCertPath,
    body: {
      admin_password: runtimeAdminPassword,
      public_origin: publicOrigin
    }
  });

  if (!response.ok) {
    throw new Error(
      `failed to start runtime cluster setup: HTTP ${response.status}: ${response.text}`
    );
  }

  await waitForFile(runtimePublicCaPath, 60_000);
  await waitForOk(`${publicOrigin}/api/v1/auth/admin/session`, 60_000, runtimePublicCaPath);
}

void bootstrapRuntime().catch((error) => {
  fatalBootstrapError = true;
  console.error(error instanceof Error ? error.message : String(error));
  if (!child.killed) {
    child.kill("SIGTERM");
  }
});
