# Agent Working Context (Compressed)

Purpose: fast bootstrap for coding sessions without replaying full tool/chat history.

## Repository snapshot

- Project: `ironmesh` (Rust workspace)
- Primary backend: `apps/server-node`
- Mobile: Android native shell + SAF provider under `apps/android-app/native`
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
  - feature-gated runtime (`fuse-runtime`)
  - mount binary `adapter-linux-fuse-mount`
  - snapshot mode (`--snapshot-file`)
  - live server mode (`--server-base-url`) with `/store/index` listing + `GET /store/{key}` hydration

## Key files now authoritative

- `crates/sync-core/src/lib.rs`
- `crates/adapter-linux-fuse/src/lib.rs`
- `crates/adapter-linux-fuse/src/bin/mount.rs`
- `apps/android-app/native/app/src/main/java/io/ironmesh/android/ui/MainViewModel.kt`
- `apps/android-app/native/app/src/main/java/io/ironmesh/android/data/IronmeshPreferences.kt`
- `apps/android-app/native/app/src/main/java/io/ironmesh/android/saf/IronmeshDocumentsProvider.kt`
- `.github/workflows/check.yml`
- `.github/workflows/coverage.yml`
- `docs/cross-platform-filesystem-integration-strategy.md`
- `docs/cross-platform-handover.md`

## Quick validation commands

```bash
cargo check --workspace
cargo test -p sync-core
cargo test -p adapter-linux-fuse
cargo check -p adapter-linux-fuse --features fuse-runtime
```

Linux mount smoke tests:

```bash
cargo run -p adapter-linux-fuse --features fuse-runtime --bin adapter-linux-fuse-mount -- \
  --snapshot-file /tmp/snapshot.json \
  --mountpoint /tmp/ironmesh-mount

cargo run -p adapter-linux-fuse --features fuse-runtime --bin adapter-linux-fuse-mount -- \
  --server-base-url http://127.0.0.1:18080 \
  --mountpoint /tmp/ironmesh-mount-live
```

## Immediate next objective

- Implement Windows CFAPI adapter prototype using `sync-core` contracts.
- Continue from handover doc checklist in `docs/cross-platform-handover.md`.
