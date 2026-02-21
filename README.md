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

### Reconciliation and maintenance

- Rejoin reconciliation endpoints:
	- `GET /cluster/reconcile/export/provisional`
	- `POST /cluster/reconcile/{node_id}`
- Reconciliation is idempotent: repeated imports from the same source key/version are skipped via persisted replay markers.
- Maintenance cleanup endpoint:
	- `POST /maintenance/cleanup?retention_secs=<n>&dry_run=true|false`
	- Cleanup only removes unreferenced manifests/chunks after retention checks.
