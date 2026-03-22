import react from "@vitejs/plugin-react";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

function resolveWorkspaceVersion(): string {
  const configDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(configDir, "../../../../");
  const cargoTomlPath = path.join(repoRoot, "Cargo.toml");
  const cargoToml = fs.readFileSync(cargoTomlPath, "utf8");
  const workspacePackageMatch = cargoToml.match(
    /\[workspace\.package\][\s\S]*?version\s*=\s*"([^"]+)"/m
  );
  return workspacePackageMatch?.[1] ?? "0.0.0";
}

function resolveWorkspaceRevision(): string {
  const configDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(configDir, "../../../../");
  try {
    return execSync("git describe --tags --always --dirty=-dirty --abbrev=12", {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "unknown";
  }
}

export function makeViteConfig(appName: string) {
  const workspaceVersion = resolveWorkspaceVersion();
  const workspaceRevision = resolveWorkspaceRevision();

  return defineConfig({
    plugins: [react()],
    define: {
      __IRONMESH_UI_VERSION__: JSON.stringify(workspaceVersion),
      __IRONMESH_UI_REVISION__: JSON.stringify(workspaceRevision)
    },
    server: {
      host: "127.0.0.1",
      port: appName === "server-admin" ? 4173 : 4174
    }
  });
}
