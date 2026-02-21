# CI runbook

## Required checks (branch protection alignment)

For branch `main`, require these status checks:

- `workspace-check`
- `rustfmt`
- `clippy`
- `unit-tests`
- `coverage`
- `system-tests`

Optional (recommended separately):

- `cargo-audit`
- `cargo-deny`

Why: CI lanes are intentionally split between stable and nightly. Requiring exactly these checks prevents accidental bypass (missing nightly lane) or false blocking (obsolete check names).

## Nightly lane fails, stable lanes pass

This usually means the failure is isolated to `tests/system-tests` and/or nightly `bindeps` behavior.

### 1) Reproduce locally with the same command

```bash
cargo -Z bindeps test --manifest-path tests/system-tests/Cargo.toml
```

For a single test:

```bash
cargo -Z bindeps test --manifest-path tests/system-tests/Cargo.toml --lib -- tests::<name> --exact --nocapture
```

### 2) Verify stable lanes are still healthy

```bash
cargo +stable check --workspace
cargo +stable clippy --workspace --all-targets -- -D warnings
cargo +stable test --workspace
```

### 3) Common root causes

- Nightly toolchain drift (new nightly behavior/regression).
- `bindeps`/artifact path changes.
- Timing-sensitive system test behavior.
- Environment assumptions in system tests (ports, startup timing).

### 4) Fast mitigation options

- Temporarily pin nightly to the last known good date in `rust-toolchain.toml`.
- Re-run failed system test with `--nocapture` and increase polling retries if truly timing-related.
- Keep stable lanes unchanged while fixing only the nightly/system-test path.

### 5) If branch protection blocks urgent merge

- Do **not** remove required checks globally.
- Use a small targeted fix PR for nightly lane only.
- Revert only the offending nightly/system-test change if needed, then follow up with a proper fix.
