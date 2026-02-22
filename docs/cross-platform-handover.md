# Cross-platform handover (Windows-ready)

## Purpose

This document is the handover package for continuing cross-platform filesystem integration in a different environment (especially Windows).

## Current implementation state

### Completed

- Shared sync planning core:
  - `crates/sync-core`
  - Deterministic `plan_sync` output with unit tests.
- Linux adapter MVP:
  - `crates/adapter-linux-fuse`
  - Action mapping from `sync-core` operations.
  - Feature-gated FUSE runtime (`fuse-runtime`).
  - Mount CLI binary `adapter-linux-fuse-mount`.
  - Two mount modes:
    - `--snapshot-file`: static snapshot input.
    - `--server-base-url`: live namespace + object hydration from `server-node`.
- Android SAF integration:
  - Provider + API/repository wiring.
  - Persisted base URL shared between app UI and provider.
- CI artifacts:
  - Android debug APK artifact: `android-debug-apk`.
  - Ubuntu FUSE binary artifact: `linux-fuse-mount-binary-ubuntu`.

### Not implemented yet

- Windows Cloud Files API (CFAPI) adapter.
- Linux write path (current runtime is read-only).
- Android Rust-bridge alignment to consume `sync-core` directly.

## Source-of-truth files

- Planner and domain model:
  - `crates/sync-core/src/lib.rs`
- Linux adapter runtime and mount entrypoint:
  - `crates/adapter-linux-fuse/src/lib.rs`
  - `crates/adapter-linux-fuse/src/bin/mount.rs`
- Workflow artifact publishing:
  - `.github/workflows/check.yml`
- Coverage behavior for MVP stage:
  - `.github/workflows/coverage.yml`
- Strategy doc:
  - `docs/cross-platform-filesystem-integration-strategy.md`

## Validation checklist

### Core workspace

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p sync-core
cargo test -p adapter-linux-fuse
cargo check -p adapter-linux-fuse --features fuse-runtime
```

### Linux manual runtime checks

Snapshot mode:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p adapter-linux-fuse --features fuse-runtime --bin adapter-linux-fuse-mount -- \
  --snapshot-file /tmp/snapshot.json \
  --mountpoint /tmp/ironmesh-mount
```

Live server mode:

```bash
mkdir -p /tmp/ironmesh-mount-live
cargo run -p adapter-linux-fuse --features fuse-runtime --bin adapter-linux-fuse-mount -- \
  --server-base-url http://127.0.0.1:18080 \
  --mountpoint /tmp/ironmesh-mount-live
```

Unmount:

```bash
fusermount3 -u /tmp/ironmesh-mount
fusermount3 -u /tmp/ironmesh-mount-live
```

## Windows handover plan (next development environment)

### 1) Environment setup

- Install Rust toolchain (matching workspace policy).
- Install Windows SDK and required build tools for CFAPI integration.
- Keep this repo checked out and run workspace validation commands first.

### 2) New crate layout

Create a dedicated Windows adapter crate:

- Suggested path: `crates/adapter-windows-cfapi`
- Suggested shape:
  - `src/lib.rs`: adapter API + mapping layer from `sync-core` operations.
  - `src/runtime.rs`: CFAPI callbacks and sync-root registration.
  - `src/bin/register.rs` (optional): utility for local registration/bootstrap.

### 3) Reuse contract from `sync-core`

Implement CFAPI behavior by mapping existing operations:

- `EnsurePlaceholder` -> create/update placeholder metadata.
- `Hydrate` -> fulfill on-demand fetch callback.
- `Upload` -> queue upload on commit/close event.
- `Conflict` -> mark conflict state in metadata/status.
- `CreateDirectory` -> materialize logical directory entries.

### 4) MVP scope for Windows

- Read-only hydration path first:
  - Register sync root.
  - Enumerate virtual namespace from `server-node`.
  - Hydrate bytes on file open/read.
- Defer writeback/conflict UI until read path is stable.

### 5) CI follow-up for Windows

- Keep Ubuntu checks as-is.
- Add Windows build/check job for `adapter-windows-cfapi` once crate exists.
- Publish a Windows artifact for test binary if useful.

## Known caveats

- Coverage gate currently excludes `crates/adapter-linux-fuse/` because runtime code is larger than current test surface.
- Linux runtime is intentionally read-only at this stage.
- Live server mode currently maps remote file versions to placeholder synthetic values for planning consistency.

## Suggested first task on Windows

Implement `adapter-windows-cfapi` with:

1. crate skeleton + compile-only CI on Windows,
2. operation mapping tests equivalent to Linux adapter,
3. minimal sync-root registration and read/hydrate callback path.
