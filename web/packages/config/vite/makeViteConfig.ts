import react from "@vitejs/plugin-react";
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

export function makeViteConfig(appName: string) {
  const workspaceVersion = resolveWorkspaceVersion();

  return defineConfig({
    plugins: [react()],
    define: {
      __IRONMESH_UI_VERSION__: JSON.stringify(workspaceVersion)
    },
    server: {
      host: "127.0.0.1",
      port: appName === "server-admin" ? 4173 : 4174
    }
  });
}
