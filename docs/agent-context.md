# Agent Working Context (Compressed)

Purpose: fast bootstrap for coding sessions without replaying full tool/chat history.

## Repository snapshot

- Project: `ironmesh` (Rust workspace)
- Primary backend: `apps/server-node`
- Mobile: Android native shell + SAF provider under `apps/android-app`
- Cross-platform filesystem work:
  - Shared planner: `crates/sync-core`
  - Linux adapter: `crates/adapter-linux-fuse`

## Toolchain + CI policy

- Workspace toolchain pinned in `rust-toolchain.toml`: `nightly-2026-02-21`
- CI check lanes include:
  - Rust checks/lints/tests
  - Android debug build + artifact (`android-debug-apk`)
  - Linux FUSE mount binary build + artifact (`linux-fuse-mount-binary-ubuntu`)
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

## Key files now authoritative

- `crates/sync-core/src/lib.rs`
- `crates/adapter-linux-fuse/src/lib.rs`
- `crates/adapter-linux-fuse/src/mount_main.rs`
- `apps/os-integration/src/main.rs`
- `apps/android-app/app/src/main/java/io/ironmesh/android/ui/MainViewModel.kt`
- `apps/android-app/app/src/main/java/io/ironmesh/android/data/IronmeshPreferences.kt`
- `apps/android-app/app/src/main/java/io/ironmesh/android/saf/IronmeshDocumentsProvider.kt`
- `.github/workflows/check.yml`
- `.github/workflows/coverage.yml`
- `docs/cross-platform-filesystem-integration-strategy.md`
- `docs/cross-platform-handover.md`

## Quick validation commands

```bash
cargo check --workspace
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
  --server-base-url http://127.0.0.1:18080 \
  --client-identity-file /path/to/client-identity.json \
  --mountpoint /tmp/ironmesh-mount-live

cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --client-identity-file /path/to/client-identity.json \
  --offline-object-cache off \
  --mountpoint /tmp/ironmesh-mount-live
```

## Immediate next objective

- Implement Windows CFAPI adapter prototype using `sync-core` contracts.
- Continue from handover doc checklist in `docs/cross-platform-handover.md`.
