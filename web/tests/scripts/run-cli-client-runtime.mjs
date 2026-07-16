import { resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(process.cwd(), "..");
const binaryPath = resolve(
  repoRoot,
  "target",
  "debug",
  process.platform === "win32" ? "ironmesh.exe" : "ironmesh"
);

const child = spawn(binaryPath, ["serve-web", "--bind", "127.0.0.1:18081"], {
  cwd: repoRoot,
  env: {
    ...process.env,
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
