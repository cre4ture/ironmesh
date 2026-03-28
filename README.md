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

## Workspace layout

- `crates/common` — shared models used by all nodes/apps.
- `crates/client-sdk` — client library with server access + local cache.
- `apps/server-node` — storage server node.
- `apps/cli-client` — CLI client and built-in web interface endpoint.
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

`tests/system-tests` uses Cargo binary artifact dependencies to consume `server-node` and `cli-client` binaries directly during test runs.

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

If you must run with stable for local work, use explicit binaries instead of artifact deps:

```bash
cargo build -p server-node -p cli-client
IRONMESH_SERVER_BIN=target/debug/server-node \
IRONMESH_CLI_BIN=target/debug/cli-client \
cargo +stable test -p system-tests
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

For the newer rendezvous-plus-relay architecture, use the dedicated manual recipe in [docs/manual-rendezvous-relay-test.md](docs/manual-rendezvous-relay-test.md). The helper script does not yet start `rendezvous-service`. For local plain-HTTP rendezvous testing, the manual recipe now sets `IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP=true` explicitly because insecure startup is refused by default.

Optional overrides:

- `IRONMESH_LOCAL_CLUSTER_BASE_PORT`
- `IRONMESH_LOCAL_CLUSTER_DIR`
- `IRONMESH_SERVER_BIN`

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
- iOS: C-ABI/Swift bridge (or UniFFI).

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

The Linux entrypoint is `os-integration`. The mountpoint directory must already exist, and in practice it should be empty before mounting.

Direct server mode:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --mountpoint /tmp/ironmesh-mount
```

Embedded local-edge mode:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --local-edge \
  --mountpoint /tmp/ironmesh-mount
```

Notes:

- `--local-edge` starts a persistent local edge node and mounts against it instead of talking to the remote server directly.
- By default, local-edge state is stored under `$XDG_STATE_HOME/ironmesh/os-integration/local-edge/` or `~/.local/state/ironmesh/os-integration/local-edge/`.
- Use `--local-edge-data-dir` to override that storage path explicitly.
- `--remote-refresh-interval-ms` controls fallback polling/retry cadence for namespace updates in live modes.
- Snapshot mode is still available for debugging with `--snapshot-file`.

## Cross-environment handover

- Current implementation status, environment bootstrap steps, and Windows-next development handover are documented in [docs/cross-platform-handover.md](docs/cross-platform-handover.md).

## CI operations

- CI branch-protection alignment and nightly-lane triage steps are documented in [docs/ci-runbook.md](docs/ci-runbook.md).

## API semantics (current)

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

### Startup replication repair

- On startup, the server can run a one-shot replication repair pass after a short delay to heal inconsistent states.
- Configuration:
	- `IRONMESH_REPLICATION_REPAIR_BATCH_SIZE` (default: `256`)
	- `IRONMESH_STARTUP_REPAIR_ENABLED` (default: `true`)
	- `IRONMESH_STARTUP_REPAIR_DELAY_SECS` (default: `5`)
	- `IRONMESH_REPAIR_BUSY_THROTTLE_ENABLED` (default: `false`)
	- `IRONMESH_REPAIR_BUSY_INFLIGHT_THRESHOLD` (default: `32`)
	- `IRONMESH_REPAIR_BUSY_WAIT_MILLIS` (default: `100`)

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

- Public client auth can be enabled with:
	- `IRONMESH_REQUIRE_CLIENT_AUTH=true`
- Admin can issue one-time pairing authorizations:
	- `POST /auth/pairing-tokens/issue`
	- header: `x-ironmesh-admin-token: <admin token>`
- Clients enroll with a pairing token and receive issued credential material:
	- `POST /auth/device/enroll`
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
