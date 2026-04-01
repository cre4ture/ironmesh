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
  - FUSE runtime.
  - User-facing Linux mount entrypoint via `apps/os-integration`.
  - Mount modes:
    - `--snapshot-file`: static snapshot input.
    - `--server-base-url` or `--bootstrap-file`: live client-rights edge mode with durable local
      mutation queue, cached remote snapshot, content-hash-based placeholder identity, and
      optional hydrated-object cache.
- Android SAF integration:
  - Provider + API/repository wiring.
  - Persisted base URL shared between app UI and provider.
- CI artifacts:
  - Android debug APK artifact: `android-debug-apk`.
  - Ubuntu FUSE binary artifact: `linux-fuse-mount-binary-ubuntu`.
- Windows CFAPI adapter MVP foundation:
  - `crates/adapter-windows-cfapi` crate created and wired into workspace.
  - Operation mapping tests equivalent to Linux adapter.
  - Runtime uses CFAPI registration (`CfRegisterSyncRoot`), placeholder creation (`CfCreatePlaceholders`), and fetch-data callback transfer (`CfExecute`).
  - Registration utility binary: `adapter-windows-cfapi-register`.
  - Live server hydration integration via `os-integration serve`:
    - Placeholder materialization from `/store/index`.
    - On-demand hydration from `GET /store/{key}`.
    - Remote namespace refresh loop via server-driven `/store/index/changes/wait` long-poll notifications, with `client-sdk` polling fallback controlled by `--remote-refresh-interval-ms`.
- Linux FUSE live mount now uses the same `client-sdk` remote refresh abstraction, driven by server notifications first and falling back to polling when needed.
  - Shared delete semantics now treat directory-marker deletes such as `docs/` as recursive subtree tombstones on the server side.
  - Windows compile check lane added to CI.

### Not implemented yet

- Android Rust-bridge alignment to consume `sync-core` directly.

## Source-of-truth files

- Planner and domain model:
  - `crates/sync-core/src/lib.rs`
- Linux adapter runtime and mount entrypoint:
  - `crates/adapter-linux-fuse/src/lib.rs`
  - `crates/adapter-linux-fuse/src/mount_main.rs`
  - `apps/os-integration/src/main.rs`
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
cargo check -p adapter-linux-fuse
```

### Linux manual runtime checks

Snapshot mode:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p os-integration -- \
  --snapshot-file /tmp/snapshot.json \
  --mountpoint /tmp/ironmesh-mount
```

Live client-rights edge mode:

```bash
mkdir -p /tmp/ironmesh-mount-live
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --client-identity-file /path/to/client-identity.json \
  --mountpoint /tmp/ironmesh-mount-live
```

Same-device mode with hydrated-object cache disabled:

```bash
mkdir -p /tmp/ironmesh-mount-live
cargo run -p os-integration -- \
  --server-base-url http://127.0.0.1:18080 \
  --client-identity-file /path/to/client-identity.json \
  --offline-object-cache off \
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
- Embedded Linux FUSE `--local-edge` is obsolete and removed; the design-history rationale is kept
  in `docs/client-rights-edge-sync-idea.md`.
- Direct/bootstrap Linux FUSE mounts now own offline restart through a client-rights durable
  mutation queue and cached remote snapshot.
- Live server mode now carries remote `content_hash` through sync planning, placeholder state, and
  cache lookups so hydrated-object reuse is content-addressed rather than path/version-addressed.
- `--offline-object-cache off` disables persisted hydrated-object copies, but the live mount still
  keeps a small in-memory range chunk cache for repeated reads during the current mount session.

## Suggested first task on Windows

Implement `adapter-windows-cfapi` with:

1. crate skeleton + compile-only CI on Windows,
2. operation mapping tests equivalent to Linux adapter,
3. minimal sync-root registration and read/hydrate callback path.

Status: complete.

## Suggested next task on Windows

Expand remote rename/delete parity coverage and then reduce compatibility polling further once mixed-version fallback is no longer required.
