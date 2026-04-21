<p align="center">
  <img src="docs/assets/ironmesh-logo.svg" alt="ironmesh logo" width="560" />
</p>

# ironmesh

Rust workspace for a distributed file and media storage platform with server, client SDK, CLI + web UI, and mobile app shells.

Ironmesh is building toward a private, self-hosted storage system that makes clustered files, folders, and media feel as approachable as a consumer cloud drive, while keeping deployment, trust, and data ownership in your hands. The project combines secure multi-node storage, offline-friendly sync and conflict handling, and native filesystem access paths so the same data can surface cleanly in web, mobile, and OS file-manager workflows.

Current direction highlights:

- Cluster-aware storage with deterministic placement, asynchronous replication and repair, and a no-loss version model for offline or concurrent edits.
- Native access paths across the web UI, CLI, Android, Linux FUSE, and Windows CFAPI placeholder integration, with on-demand hydration where the platform supports it.
- Secure onboarding and connectivity through guided zero-touch cluster setup, certificate-backed identities, and rendezvous/relay paths for harder network topologies.
- Media-aware browsing with cached thumbnails and metadata designed to support gallery-style experiences without downloading original files first.

Ironmesh draws inspiration from [PicApport](https://www.picapport.de/de/index.php) on the self-hosted media/gallery side and [Syncthing](https://syncthing.net/) on the private, direct-first synchronization side.

## Personal motivation

As a software engineer, I want the same relationship with my computer and my data that a skilled mechanic has with a car: the ability to repair it, understand it, and extend it when needed. That desire does not come from distrust of large cloud providers, just as a mechanic's wish to work on a car does not imply suspicion of major manufacturers. It comes from knowing the craft well enough to want meaningful influence over the systems one depends on.

Ironmesh is also a test of what is now possible for an individual builder. AI coding agents have expanded the practical reach of small teams and solo engineers by an order of magnitude, and part of this project is to explore that shift seriously. Proving that this kind of ambitious, deeply owned software can be built in a new way is not separate from the project's purpose; it is one of its central goals.

## At A Glance

<p align="center">
  <a href="docs/assets/ironmesh-at-a-glance.png">
    <img
      src="docs/assets/ironmesh-at-a-glance.png"
      alt="IronMesh at a glance overview diagram"
      width="1200"
    />
  </a>
</p>

## Workspace layout

- `crates/common` — shared models used by all nodes/apps.
- `crates/client-sdk` — client library with server access + local cache.
- `apps/server-node` — storage server node.
- `apps/cli-client` — Cargo package for the public `ironmesh` CLI and built-in web interface endpoint.
- `apps/android-app` — Android-facing Rust app layer.
- `apps/ios-app` — iOS-facing Rust app layer.

## Quick start

```bash
cd web && pnpm install
cargo check --workspace
cargo run -p server-node
cargo run -p cli-client -- --help
```

The Rust `server-node` build triggers `pnpm build` inside `web/`, so the frontend dependencies must be installed in [`web/package.json`](/home/uli/rust-dev/ironmesh/web/package.json) first. If you accidentally run `pnpm` or `npm` from the repo root, you'll create an unused top-level `node_modules/` that this workspace does not use.

## Justfile commands

Common workflows are available via `just`:

```bash
just check-stable
just clippy-stable
just test-stable
just test-system-nightly
```

Single system-test targeting:

```bash
just test-system-nightly-one tests::autonomous_peer_heartbeat_recovers_after_peer_restart
```

## System-tests toolchain policy (nightly)

`tests/system-tests` uses Cargo binary artifact dependencies to consume the `ironmesh-server-node` and `ironmesh` binaries directly during test runs.

Why this was chosen:

- Avoids nested `cargo build` calls from inside tests.
- Prevents duplicate compilation phases during one test invocation.
- Reduces side effects and timing noise that made integration tests flaky.
- Makes binary provisioning explicit in Cargo dependency resolution.

Current setup:

- Workspace is pinned to nightly via `rust-toolchain.toml`.
- `bindeps` is enabled in `.cargo/config.toml`.
- CI is split to limit nightly blast radius:
	- Stable lanes: root workspace check/clippy/unit tests/coverage.
	- Nightly lane: `system-tests` only (`cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml`).

The `system-tests` crate is intentionally isolated from root workspace membership so stable Cargo can run root workspace jobs without parsing nightly-only `artifact` dependency declarations.

When you need to run `system-tests`, invoke it directly with nightly:

```bash
cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml
```

Note: CI/push hooks may enforce stricter checks across the workspace. If local commits are needed while unrelated lint debt exists in untouched crates, use local-only commits and avoid pushing until lint debt is resolved.

## Local 4-node cluster (manual testing)

Use the helper script to start/stop a 4-node cluster on one machine with isolated data dirs:

```bash
scripts/local-cluster.sh start
scripts/local-cluster.sh status
scripts/local-cluster.sh stop
```

Defaults:

- Base port: `18080` (nodes on `18080..18083`)
- Data + logs + pid files: `data/local-cluster/`

For the newer rendezvous-plus-relay architecture, use the dedicated manual recipe in [docs/manual-rendezvous-relay-test.md](docs/manual-rendezvous-relay-test.md). The helper script does not yet start `ironmesh-rendezvous-service`. For local plain-HTTP rendezvous testing, the manual recipe now sets `IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP=true` explicitly because insecure startup is refused by default.

Optional overrides:

- `IRONMESH_LOCAL_CLUSTER_BASE_PORT`
- `IRONMESH_LOCAL_CLUSTER_DIR`
- `IRONMESH_SERVER_BIN`

## Runtime Env Contract

Treat only a small runtime subset as the first-release env var contract.

- `ironmesh-server-node` supported runtime envs: `IRONMESH_NODE_ENROLLMENT_FILE`, `IRONMESH_NODE_BOOTSTRAP_FILE`, `IRONMESH_NODE_ID`, `IRONMESH_CLUSTER_ID`, `IRONMESH_DATA_DIR`, `IRONMESH_SERVER_BIND`, `IRONMESH_PUBLIC_URL`, `IRONMESH_PUBLIC_TLS_CERT`, `IRONMESH_PUBLIC_TLS_KEY`, `IRONMESH_INTERNAL_BIND`, `IRONMESH_INTERNAL_URL`, `IRONMESH_INTERNAL_TLS_CA_CERT`, `IRONMESH_INTERNAL_TLS_CERT`, `IRONMESH_INTERNAL_TLS_KEY`, `IRONMESH_RENDEZVOUS_URLS`, `IRONMESH_RENDEZVOUS_CA_CERT`, `IRONMESH_RENDEZVOUS_MTLS_REQUIRED`, `IRONMESH_RELAY_MODE`, and `IRONMESH_ADMIN_TOKEN`.
- `ironmesh-rendezvous-service` supported runtime envs: `IRONMESH_RENDEZVOUS_BIND`, `IRONMESH_RENDEZVOUS_PUBLIC_URL`, `IRONMESH_RELAY_PUBLIC_URLS`, `IRONMESH_RENDEZVOUS_CLIENT_CA_CERT`, `IRONMESH_RENDEZVOUS_TLS_CERT`, `IRONMESH_RENDEZVOUS_TLS_KEY`, `IRONMESH_RENDEZVOUS_FAILOVER_PACKAGE`, and `IRONMESH_RENDEZVOUS_FAILOVER_PASSPHRASE`. Standalone failover startup now expects `--bind-addr`, and new failover exports embed the rendezvous client CA so `IRONMESH_RENDEZVOUS_CLIENT_CA_CERT` is only needed for file-based TLS or legacy failover packages.
- Local-dev or helper-only envs are intentionally separate contracts: `IRONMESH_LOCAL_CLUSTER_*`, `IRONMESH_SERVER_BIN`, `IRONMESH_CLI_BIN`, and `IRONMESH_RENDEZVOUS_DEPLOY_*`. `IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP`, `IRONMESH_ALLOW_INSECURE_PUBLIC_HTTP`, and `IRONMESH_ALLOW_UNAUTHENTICATED_CLIENTS` are development-only and should not be treated as production runtime contracts.
- Advanced tuning and debug envs such as `IRONMESH_METADATA_*`, `IRONMESH_AUTONOMOUS_*`, `IRONMESH_REPLICATION_*`, `IRONMESH_REPAIR_*`, `IRONMESH_DATA_SCRUB_*`, `IRONMESH_STORAGE_STATS_*`, `IRONMESH_MAP_*`, and `IRONMESH_TEST_*` are current operational knobs, not frozen compatibility promises for the first release.

## Local git hooks (recommended)

Enable repository-managed hooks once per clone:

```bash
git config core.hooksPath .githooks
```

The `pre-push` hook runs:

```bash
cargo fmt --all -- --check
```

The `pre-commit` hook runs:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

This prevents pushes that would fail the CI rustfmt check.

## Coverage gate

CI enforces a minimum line coverage floor using `cargo-llvm-cov`:

```bash
cargo llvm-cov --workspace --all-features --summary-only \
	--ignore-filename-regex 'apps/(android-app|ios-app|cli-client|web-ui)/|apps/server-node/src/main.rs|crates/common/src/lib.rs|crates/adapter-linux-fuse/' \
	--fail-under-lines 70
```

Notes:

- The excluded files are shell/bootstrap entrypoints and wrapper crates that currently have no direct tests.
- The threshold is intentionally conservative for now and can be raised as targeted tests are added.

## Notes for mobile integration

`android-app` and `ios-app` are Rust-first shells designed to expose the storage SDK and web GUI string payload to native layers. Typical production integration uses:

- Android: JNI/Kotlin bridge (or UniFFI).
- iOS: C-ABI/Swift bridge. The current Apple File Provider plan explicitly prefers a manual C ABI plus `cbindgen` over `UniFFI` for the initial slice.

Those bridges can be added incrementally without changing the workspace topology.

## Storage design

- Persistent storage strategy and requirements are documented in [docs/persistent-storage-strategy.md](docs/persistent-storage-strategy.md).

## Multi-node strategy

- Multi-node requirements, replication strategy, and rollout plan are documented in [docs/multi-node-strategy.md](docs/multi-node-strategy.md).

## Cross-platform filesystem integration strategy

- Cross-platform filesystem integration strategy, requirements, and phased plan are documented in [docs/cross-platform-filesystem-integration-strategy.md](docs/cross-platform-filesystem-integration-strategy.md).
- Windows CFAPI and Linux FUSE adapters now refresh remote namespace changes via server-driven `/store/index/changes/wait` long-poll notifications.
  - Configure `--remote-refresh-interval-ms` (default `3000`) as the fallback polling/retry cadence.
  - The shared `client-sdk` `RemoteSnapshotPoller` waits for server change notifications first, then refreshes snapshots and triggers adapter callbacks with `changed_paths`.
- Directory-marker deletes sent through `client-sdk` now recurse on the server side, so deleting `docs/` removes the full `docs/**` subtree.

## Linux FUSE mount

The Linux entrypoint is `ironmesh-os-integration`. The mountpoint directory must already exist, and in practice it should be empty before mounting.

Direct server mode:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p os-integration -- \
	--server-base-url https://127.0.0.1:18080 \
	--server-ca-pem-file /path/to/ironmesh-public-ca.pem \
	--client-identity-file /path/to/ironmesh-client-identity.json \
  --mountpoint /tmp/ironmesh-mount
```

Notes:

- Regular server-node deployments now expect public TLS. Plain HTTP is only available for explicit local testing with `IRONMESH_ALLOW_INSECURE_PUBLIC_HTTP=true`.
- Live mounts now require client auth when the server protects `/store/*` APIs. In direct mode,
  pass `--client-identity-file`.
- In bootstrap mode, `ironmesh-os-integration` auto-loads a sibling
	`*.client-identity.json` file when present, for example
	`ironmesh-client-bootstrap.client-identity.json` next to
	`ironmesh-client-bootstrap.json`.
- `--remote-refresh-interval-ms` controls fallback polling/retry cadence for namespace updates in live modes.
- Snapshot mode is still available for debugging with `--snapshot-file`.

## Cross-platform status

- Cross-platform filesystem implementation status and platform notes live in [docs/cross-platform-filesystem-integration-strategy.md](docs/cross-platform-filesystem-integration-strategy.md).
- Short coding-session bootstrap context lives in [docs/agent-context.md](docs/agent-context.md).

## CI operations

- CI branch-protection alignment and nightly-lane triage steps are documented in [docs/ci-runbook.md](docs/ci-runbook.md).

## API semantics (current)

The env vars referenced in the tuning subsections below are current operational knobs. They are useful for local operations and controlled deployments, but they are not the first-release compatibility contract unless they are also listed in the runtime env contract section above.

### Versioning and commit

- Writes support `confirmed` and `provisional` version states via `PUT /store/{key}?state=...`.
- Version metadata is available via `GET /versions/{key}`.
- Version commit endpoints:
	- `POST /versions/{key}/commit/{version_id}`
	- `POST /versions/{key}/confirm/{version_id}` (compatibility alias)
- Metadata commit mode is configurable with `IRONMESH_METADATA_COMMIT_MODE`:
	- `local` (default): commit allowed locally.
	- `quorum`: commit requires cluster majority online.

### Read modes

- `GET /store/{key}` defaults to `read_mode=preferred`.
- Explicit read modes:
	- `read_mode=preferred` — deterministic preferred branch head.
	- `read_mode=confirmed_only` — latest **confirmed head** only.
	- `read_mode=provisional_allowed` — latest head regardless of state.
- Additional selectors:
	- `version=<version_id>` for exact historical reads.
	- `snapshot=<snapshot_id>` for snapshot time-travel reads.

### Object index and browsing

- `GET /store/index?prefix=<prefix>&depth=<n>` lists object keys as a virtual directory tree.
- Keys are treated as slash-delimited paths for browsing convenience.
- `depth` controls how many path segments are grouped under `prefix`.

### CLI status and browsing commands

- `ironmesh list --prefix <prefix> --depth <n>`
- `ironmesh health`
- `ironmesh cluster-status`
- `ironmesh nodes`
- `ironmesh replication-plan`
- `ironmesh serve-web` provides an interactive web UI for upload/download, key browsing, health checks, and replication-plan inspection.
	- Web backend routes and static assets are provided by `crates/web-ui-backend`.

### CLI connection flags

- `ironmesh`, `ironmesh-os-integration`, and `ironmesh-folder-agent` should all treat `--server-base-url` as the canonical direct-connection flag.
- `--bootstrap-file` is the canonical bootstrap-driven alternative across those clients.
- `--client-identity-file` and `--server-ca-pem-file` remain the canonical explicit auth and CA override flags for these direct/bootstrap flows, including Windows CFAPI; legacy `--server-ca-cert` is compatibility-only where it is still accepted.
- `ironmesh` still accepts legacy `--server-url` as a compatibility alias, but release-facing docs and automation should move to `--server-base-url`.

### Reconciliation and maintenance

- Cluster node membership endpoints:
	- `GET /cluster/nodes`
	- `PUT /cluster/nodes/{node_id}` with nested `reachability` and optional `capabilities`
	- `DELETE /cluster/nodes/{node_id}` (rejects local node id)

### Autonomous peer heartbeats

- Server nodes send periodic heartbeats to known peers by default.
- Configuration:
	- `IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED` (default: `true`)
	- `IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS` (default: `15`)

### Autonomous replication on write

- Successful `PUT /store/{key}` writes can trigger an immediate asynchronous replication repair pass.
- Configuration:
	- `IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED` (default: `true`)

### Periodic replication audit and repair

- Cluster-mode nodes run a background replication auditor and execute repair passes for under-replicated data by default.
- Configuration:
	- `IRONMESH_REPLICATION_REPAIR_ENABLED` (default: `true`)
	- `IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS` (default: `3600`)
	- `IRONMESH_REPLICATION_REPAIR_BATCH_SIZE` (default: `256`)
	- `IRONMESH_REPLICATION_REPAIR_MAX_RETRIES` (default: `3`)
	- `IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS` (default: `30`)
	- `IRONMESH_REPAIR_BUSY_THROTTLE_ENABLED` (default: `true`)
	- `IRONMESH_REPAIR_BUSY_INFLIGHT_THRESHOLD` (default: `32`)
	- `IRONMESH_REPAIR_BUSY_WAIT_MILLIS` (default: `100`)

### Startup replication repair

- On startup, the server can run a one-shot replication repair pass after a short delay to heal inconsistent states.
- Configuration:
	- `IRONMESH_STARTUP_REPAIR_ENABLED` (default: `true`)
	- `IRONMESH_STARTUP_REPAIR_DELAY_SECS` (default: `5`)

- When busy-throttle is enabled, each repair transfer waits while current in-flight request count is above the configured threshold.

- Rejoin reconciliation endpoints:
	- `GET /cluster/reconcile/export/provisional`
	- `POST /cluster/reconcile/{node_id}`
- Reconciliation is idempotent: repeated imports from the same source key/version are skipped via persisted replay markers.
- Maintenance cleanup endpoint:
	- `POST /maintenance/cleanup?retention_secs=<n>&dry_run=true|false`
	- Cleanup only removes unreferenced manifests/chunks after retention checks.

### Internal replication security

- Internal cluster traffic now uses a dedicated mTLS listener.
- Required server env:
	- `IRONMESH_INTERNAL_BIND`
	- `IRONMESH_INTERNAL_URL`
	- `IRONMESH_INTERNAL_TLS_CA_CERT`
	- `IRONMESH_INTERNAL_TLS_CERT`
	- `IRONMESH_INTERNAL_TLS_KEY`
- Peer node identity is derived from the client certificate SAN:
	- `urn:ironmesh:node:<uuid>`
- This internal listener is used for node-to-node replication, reconcile, and heartbeat traffic.

- Obsolete note: the old internal token lifecycle bullets below are no longer current. Internal node traffic now uses mTLS as described above.

### Client device authentication

- Public client auth is enabled by default.
- Unauthenticated public client APIs are only intended for explicit local testing with `IRONMESH_ALLOW_UNAUTHENTICATED_CLIENTS=true`; this is not part of the first-release runtime contract.
- Admin can issue one-time pairing authorizations:
	- `POST /auth/pairing-tokens/issue`
	- header: `x-ironmesh-admin-token: <admin token>`
- Clients enroll with a pairing token and receive issued credential material:
	- `POST /auth/device/enroll`
- Client-enrollment and bootstrap-claim redemption JSON should use `device_label` as the canonical label field; bare `label` is compatibility-only for older pre-release callers.
- Admin can inspect and revoke enrolled client credentials:
	- `GET /auth/client-credentials`
	- `DELETE /auth/client-credentials/{device_id}?reason=<text>`
- When client auth is enabled, data-plane routes require:
	- signed proof-of-possession request headers derived from the enrolled client identity
	- the issued credential fingerprint bound to that identity

- Historical token lifecycle bullets:
	- `GET /cluster/internal-auth/tokens` — list configured node ids
	- `POST /cluster/internal-auth/tokens/rotate` — set/replace token for a node (`{"node_id":"<uuid>","token":"..."}`)
	- `DELETE /cluster/internal-auth/tokens/{node_id}` — revoke token for a node (local node token revocation is rejected)

- Protected endpoints:
	- `POST /cluster/replication/push/chunk/{hash}`
	- `POST /cluster/replication/push/manifest`
	- `POST /cluster/replication/drop`
