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

## Notes for mobile integration

`android-app` and `ios-app` are Rust-first shells designed to expose the storage SDK and web GUI string payload to native layers. Typical production integration uses:

- Android: JNI/Kotlin bridge (or UniFFI).
- iOS: C-ABI/Swift bridge (or UniFFI).

Those bridges can be added incrementally without changing the workspace topology.

## Storage design

- Persistent storage strategy and requirements are documented in [docs/persistent-storage-strategy.md](docs/persistent-storage-strategy.md).

## Multi-node strategy

- Multi-node requirements, replication strategy, and rollout plan are documented in [docs/multi-node-strategy.md](docs/multi-node-strategy.md).
