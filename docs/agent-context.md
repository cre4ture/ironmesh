# Agent Working Context (Compressed)

Purpose: fast bootstrap for coding sessions without reloading full chat/tool history.

## Repository Snapshot

- Project: `ironmesh` (Rust workspace)
- Primary backend node: `apps/server-node`
- End-to-end/system tests: `tests/system-tests`
- CI split:
  - Stable lanes for root workspace checks/lints/tests
  - Nightly lane for `tests/system-tests` with `-Z bindeps`

## Toolchain + Build Policy

- Nightly is pinned in `rust-toolchain.toml` (`nightly-2026-02-21`)
- `bindeps` enabled in `.cargo/config.toml`
- `tests/system-tests` is isolated from root workspace membership
- `tests/system-tests/Cargo.lock` is tracked for reproducibility

## Recent Behavior Fixes

### 1) System-test binary provisioning

- Removed nested in-test `cargo build` behavior
- System-tests now use artifact dependencies for binaries
- Binary resolution supports env overrides:
  - `IRONMESH_SERVER_BIN`
  - `IRONMESH_CLI_BIN`

### 2) Heartbeat test stabilization

- Replaced fixed sleeps with polling helper (`wait_for_online_nodes`)
- Added resilience coverage for restart and repeated flap recovery

### 3) Automatic replication after upload

Root cause: replication repair was periodic/audit-driven (long delay), so writes could remain under-replicated.

Implemented:

- On successful `PUT /store/{key}`, server now can trigger immediate async repair pass
- New config flag:
  - `IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED` (default: `true`)
- Existing periodic auditor remains unchanged

Validation added:

- System test `autonomous_replication_after_put_populates_peer_without_manual_repair`

### 4) Low-churn replication planning

Problem:

- Strict desired-vs-current set diff could suggest 3 transfers after a write on non-desired node (RF=3 with 4 nodes), producing temporary overreplication.

Implemented:

- Planner now preserves current replicas while under target and only backfills enough nodes to reach target count.
- Extra replicas are only flagged when current replica count is above target count.

Validation added:

- Unit test `replication_plan_limits_backfill_when_current_replica_not_in_desired_set`
- Unit test `replication_plan_handles_divergent_versions_for_same_key`
- Unit test `list_replication_subjects_includes_all_heads_for_divergent_versions`

### 5) Startup one-shot repair

Implemented:

- Server can run a one-shot replication repair pass shortly after startup.
- Intended to heal inconsistent states after nodes reconnect (useful for tests and local cluster bring-up).

Configuration:

- `IRONMESH_STARTUP_REPAIR_ENABLED` (default: `true`)
- `IRONMESH_STARTUP_REPAIR_DELAY_SECS` (default: `5`)

Validation added:

- Unit test `startup_repair_noop_when_plan_is_empty`
- Unit test `startup_repair_runs_when_gaps_exist`

### 6) Internal replication loop guard

Problem:

- Internal repair transfer used regular `PUT /store/{key}` on target node.
- Autonomous post-write replication treated that as user-originated write and re-triggered repair, creating replication feedback loops and high CPU.

Fix:

- Internal transfer writes now set `internal_replication=1` query flag.
- `put_object` skips autonomous post-write repair trigger when `internal_replication` is set.

Validation added:

- Unit test `autonomous_post_write_replication_trigger_guard_blocks_internal_writes`
- Unit test `internal_replication_put_url_sets_internal_flag`

## Key Files Touched Recently

- `apps/server-node/src/main.rs`
- `tests/system-tests/src/lib.rs`
- `tests/system-tests/Cargo.toml`
- `README.md`
- `docs/ci-runbook.md`
- `justfile`
- `rust-toolchain.toml`
- `.cargo/config.toml`
- `Cargo.toml` (workspace isolation for system-tests)
- `.gitignore` + `tests/system-tests/Cargo.lock`

## Fast Commands

### Targeted nightly system test

```bash
cargo -Z bindeps test --manifest-path tests/system-tests/Cargo.toml tests::autonomous_replication_after_put_populates_peer_without_manual_repair -- --nocapture
```

### Existing replication regression

```bash
cargo -Z bindeps test --manifest-path tests/system-tests/Cargo.toml tests::manual_replication_repair_reduces_missing_plan_items -- --nocapture
```

### Stable workspace health

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Session Efficiency Rules (Preferred)

- Search symbols/strings first, then read minimal line ranges
- Avoid full-file dumps unless editing large blocks
- Run narrow tests first; widen only if needed
- Do not repeat unchanged context in updates

## Update Protocol

When significant decisions/architecture changes happen, append or revise:

1. What changed
2. Why it changed
3. How to validate quickly
4. Which files are now source-of-truth

Keep this file concise and current.
