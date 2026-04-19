import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawn, spawnSync } from "node:child_process";

const repoRoot = resolve(process.cwd(), "..");
const dataDir = resolve(process.cwd(), "test-results", "server-node-runtime-data");
const tlsDir = resolve(dataDir, "tls");
const binaryPath = resolve(
  repoRoot,
  "target",
  "debug",
  process.platform === "win32" ? "ironmesh-server-node.exe" : "ironmesh-server-node"
);

rmSync(dataDir, { recursive: true, force: true });
mkdirSync(dataDir, { recursive: true });
mkdirSync(tlsDir, { recursive: true });

const internalCaCertPath = resolve(tlsDir, "internal-ca.pem");
const internalCaKeyPath = resolve(tlsDir, "internal-ca.key");
const internalCertPath = resolve(tlsDir, "internal-node.pem");
const internalKeyPath = resolve(tlsDir, "internal-node.key");
const internalCsrPath = resolve(tlsDir, "internal-node.csr");
const internalExtPath = resolve(tlsDir, "internal-node.ext");

function runOrThrow(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit"
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} exited with code ${result.status ?? "unknown"}`);
  }
}

writeFileSync(
  internalExtPath,
  [
    "basicConstraints=CA:FALSE",
    "keyUsage=digitalSignature,keyEncipherment",
    "extendedKeyUsage=serverAuth,clientAuth",
    "subjectAltName=IP:127.0.0.1,DNS:localhost"
  ].join("\n")
);

runOrThrow("openssl", ["genrsa", "-out", internalCaKeyPath, "2048"]);
runOrThrow("openssl", [
  "req",
  "-x509",
  "-new",
  "-nodes",
  "-key",
  internalCaKeyPath,
  "-sha256",
  "-days",
  "3650",
  "-out",
  internalCaCertPath,
  "-subj",
  "/CN=ironmesh-playwright-internal-ca"
]);
runOrThrow("openssl", ["genrsa", "-out", internalKeyPath, "2048"]);
runOrThrow("openssl", [
  "req",
  "-new",
  "-key",
  internalKeyPath,
  "-out",
  internalCsrPath,
  "-subj",
  "/CN=ironmesh-playwright-internal-node"
]);
runOrThrow("openssl", [
  "x509",
  "-req",
  "-in",
  internalCsrPath,
  "-CA",
  internalCaCertPath,
  "-CAkey",
  internalCaKeyPath,
  "-CAcreateserial",
  "-out",
  internalCertPath,
  "-days",
  "3650",
  "-sha256",
  "-extfile",
  internalExtPath
]);

const child = spawn(binaryPath, [], {
  cwd: repoRoot,
  env: {
    ...process.env,
    IRONMESH_SERVER_BIND: "127.0.0.1:18181",
    IRONMESH_INTERNAL_BIND: "127.0.0.1:18182",
    IRONMESH_INTERNAL_URL: "https://127.0.0.1:18182",
    IRONMESH_INTERNAL_TLS_CA_CERT: internalCaCertPath,
    IRONMESH_INTERNAL_TLS_CERT: internalCertPath,
    IRONMESH_INTERNAL_TLS_KEY: internalKeyPath,
    IRONMESH_INTERNAL_TLS_CA_KEY: internalCaKeyPath,
    IRONMESH_DATA_DIR: dataDir,
    IRONMESH_ADMIN_TOKEN: "playwright-admin-token",
    IRONMESH_REQUIRE_CLIENT_AUTH: "false",
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
