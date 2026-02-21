# ironmesh

Rust workspace for a distributed file storage platform with server, client SDK, CLI + web UI, and mobile app shells.

## Workspace layout

- `crates/common` — shared models used by all nodes/apps.
- `crates/client-sdk` — client library with server access + local cache.
- `apps/server-node` — storage server node.
- `apps/cli-client` — CLI client and built-in web interface endpoint.
- `apps/web-ui` — shared HTML UI fragments used by CLI + mobile wrappers.
- `apps/android-app` — Android-facing Rust app layer.
- `apps/ios-app` — iOS-facing Rust app layer.

## Quick start

```bash
cargo check --workspace
cargo run -p server-node
cargo run -p cli-client -- --help
```

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
	--ignore-filename-regex 'apps/(android-app|ios-app|cli-client|web-ui)/|apps/server-node/src/main.rs|crates/common/src/lib.rs' \
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
	- `serve-web` serves static files directly from `apps/web-ui/static/`.

### Reconciliation and maintenance

- Cluster node membership endpoints:
	- `GET /cluster/nodes`
	- `PUT /cluster/nodes/{node_id}`
	- `DELETE /cluster/nodes/{node_id}` (rejects local node id)

### Autonomous peer heartbeats

- Server nodes send periodic heartbeats to known peers by default.
- Configuration:
	- `IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED` (default: `true`)
	- `IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS` (default: `15`)

- Rejoin reconciliation endpoints:
	- `GET /cluster/reconcile/export/provisional`
	- `POST /cluster/reconcile/{node_id}`
- Reconciliation is idempotent: repeated imports from the same source key/version are skipped via persisted replay markers.
- Maintenance cleanup endpoint:
	- `POST /maintenance/cleanup?retention_secs=<n>&dry_run=true|false`
	- Cleanup only removes unreferenced manifests/chunks after retention checks.

### Internal replication security

- Internal replication mutation endpoints can be restricted with:
	- `IRONMESH_INTERNAL_NODE_TOKENS` (per-node token map: `<node_uuid>=<token>,<node_uuid>=<token>,...`).
- When configured, the local server node id must have a token entry in `IRONMESH_INTERNAL_NODE_TOKENS`.
- Duplicate node ids in `IRONMESH_INTERNAL_NODE_TOKENS` are rejected at startup.
- When auth is configured, requests to these endpoints must include headers:
	- `x-ironmesh-internal-token: <token>`
	- `x-ironmesh-node-id: <uuid>` (must be a registered cluster node)
- The token must match the caller node id entry in `IRONMESH_INTERNAL_NODE_TOKENS`.
- Token updates are persisted in node state and take effect without restart.

- Token lifecycle endpoints:
	- `GET /cluster/internal-auth/tokens` — list configured node ids
	- `POST /cluster/internal-auth/tokens/rotate` — set/replace token for a node (`{"node_id":"<uuid>","token":"..."}`)
	- `DELETE /cluster/internal-auth/tokens/{node_id}` — revoke token for a node (local node token revocation is rejected)

- Protected endpoints:
	- `POST /cluster/replication/push/chunk/{hash}`
	- `POST /cluster/replication/push/manifest`
	- `POST /cluster/replication/drop`
