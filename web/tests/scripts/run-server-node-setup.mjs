import { mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(process.cwd(), "..");
const dataDir = resolve(process.cwd(), "test-results", "server-node-setup-data");
const binaryPath = resolve(
  repoRoot,
  "target",
  "debug",
  process.platform === "win32" ? "ironmesh-server-node.exe" : "ironmesh-server-node"
);

rmSync(dataDir, { recursive: true, force: true });
mkdirSync(dataDir, { recursive: true });

const child = spawn(binaryPath, [], {
  cwd: repoRoot,
  env: {
    ...process.env,
    IRONMESH_SERVER_BIND: "127.0.0.1:18443",
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
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }

  process.exit(code ?? 0);
});
