import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

export function cargoDebugBinaryPath(repoRoot, binaryName) {
  const targetDirectory = cargoTargetDirectory(repoRoot);
  return resolve(
    targetDirectory,
    "debug",
    process.platform === "win32" ? `${binaryName}.exe` : binaryName
  );
}

function cargoTargetDirectory(repoRoot) {
  const output = execFileSync(
    "cargo",
    ["metadata", "--format-version", "1", "--no-deps", "--manifest-path", resolve(repoRoot, "Cargo.toml")],
    {
      cwd: repoRoot,
      encoding: "utf8"
    }
  );
  return JSON.parse(output).target_directory;
}
