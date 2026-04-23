# Agent Working Context (Compressed)

Purpose: fast bootstrap for coding sessions without replaying full tool/chat history.

## Repository snapshot

- Project: `ironmesh` (Rust workspace)
- Primary backend: `apps/server-node`
- Mobile: Android native shell + SAF provider under `apps/android-app`
- Cross-platform filesystem work:
  - Shared planner: `crates/sync-core`
  - Linux adapter: `crates/adapter-linux-fuse`
  - Windows adapter: `crates/adapter-windows-cfapi`

## Toolchain + CI policy

- Workspace toolchain pinned in `rust-toolchain.toml`: `nightly-2026-02-21`
- CI check lanes include:
  - Rust checks/lints/tests
  - Android debug build + artifact (`android-debug-apk`)
  - Linux FUSE mount binary build + artifact (`linux-fuse-mount-binary-ubuntu`)
  - Windows CFAPI compile check lane
- Coverage gate excludes `crates/adapter-linux-fuse/` for current MVP stage.

## Current state (latest implemented)

### Server + data plane

- Replication planner stabilized with low-churn semantics and tolerance controls.
- Upload idempotency behavior improved (unchanged payload can reuse existing version).
- Web/CLI browsing and snapshot/version flows expanded.

### Android

- SAF `DocumentsProvider` implemented and build-compiling.
- Base server URL now persisted via shared preferences and reused by SAF path.
- Android CI build integrated and APK published as artifact.

### Linux FUSE

- `sync-core` provides deterministic reconciliation operations.
- `adapter-linux-fuse` now has:
  - operation mapping tests
  - runtime
  - mount entrypoint via `apps/os-integration`
  - snapshot mode (`--snapshot-file`)
  - live client-rights edge mode (`--server-base-url` or `--bootstrap-file`)
  - durable local mutation queue + cached remote snapshot for offline restart
  - content-hash-based placeholder identity and hydrated-object cache lookups
  - optional persisted hydrated-object cache, with `--offline-object-cache off` support for
    same-device server-node deployments
  - bounded in-memory range chunk cache even when persisted hydrated-object caching is disabled
  - server-driven `/store/index/changes/wait` refresh wakeups with polling fallback
  - recursive directory deletion through the shared `/store/delete` API when deleting directory-marker paths like `dir/`

### Windows CFAPI

- `adapter-windows-cfapi` now has:
  - operation mapping tests aligned with the Linux adapter contract
  - sync-root registration and placeholder creation runtime
  - fetch-data hydration callbacks backed by `server-node`
  - remote namespace refresh driven by server notifications with polling fallback
  - registration helper implementation in `crates/adapter-windows-cfapi/src/register.rs`

## Key files now authoritative

- `crates/sync-core/src/lib.rs`
- `crates/adapter-linux-fuse/src/lib.rs`
- `crates/adapter-linux-fuse/src/mount_main.rs`
- `crates/adapter-windows-cfapi/src/lib.rs`
- `crates/adapter-windows-cfapi/src/runtime.rs`
- `crates/adapter-windows-cfapi/src/register.rs`
- `apps/os-integration/src/main.rs`
- `apps/android-app/app/src/main/java/io/ironmesh/android/ui/MainViewModel.kt`
- `apps/android-app/app/src/main/java/io/ironmesh/android/data/IronmeshPreferences.kt`
- `apps/android-app/app/src/main/java/io/ironmesh/android/saf/IronmeshDocumentsProvider.kt`
- `.github/workflows/check.yml`
- `.github/workflows/coverage.yml`
- `docs/cross-platform-filesystem-integration-strategy.md`
- `docs/apple-filesystem-integration-sketch.md`

## Quick validation commands

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p sync-core
cargo test -p adapter-linux-fuse
cargo check -p adapter-linux-fuse
```

Linux mount smoke tests:

```bash
cargo run -p os-integration -- \
  --snapshot-file /tmp/snapshot.json \
  --mountpoint /tmp/ironmesh-mount

cargo run -p os-integration -- \
  --server-base-url https://127.0.0.1:18080 \
  --server-ca-pem-file /path/to/ironmesh-public-ca.pem \
  --client-identity-file /path/to/ironmesh-client-identity.json \
  --mountpoint /tmp/ironmesh-mount-live

cargo run -p os-integration -- \
  --server-base-url https://127.0.0.1:18080 \
  --server-ca-pem-file /path/to/ironmesh-public-ca.pem \
  --client-identity-file /path/to/ironmesh-client-identity.json \
  --offline-object-cache off \
  --mountpoint /tmp/ironmesh-mount-live
```

## Immediate next objective

- Continue expanding Windows CFAPI and Android alignment from the status and implementation notes in `docs/cross-platform-filesystem-integration-strategy.md`.
- Apple platform planning now lives in `docs/apple-filesystem-integration-sketch.md`:
  - Active track: File Provider on macOS and iOS/iPadOS
  - Initial bridge decision: static library + C ABI via `cbindgen` (not `UniFFI`)
  - Native Apple project files should live in-repo under `apps/apple-*`
  - Default native layout: one in-repo Apple project root with shared code plus macOS/iOS app and File Provider extension targets
  - Fallback only: `folder-agent + Finder Sync`
