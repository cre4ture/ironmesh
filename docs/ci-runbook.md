# CI runbook

## Android release builds on pull requests

Pull requests run the Android debug checks by default. To request the signed
internal release APKs, add the `ci:android-release` label to the pull request.
The label triggers a workflow run immediately and remains effective for later
pushes to the pull request while it is present.

This requires the repository secrets `IRONMESH_ANDROID_INTERNAL_RELEASE_STORE_B64`
and the corresponding release-signing credentials. For pull requests from
forks, GitHub does not expose these secrets to the standard `pull_request`
workflow, so the release legs remain unavailable there by design.

## Required checks (branch protection alignment)

For branch `main`, require these status checks:

- `workspace-check`
- `rustfmt`
- `clippy`
- `unit-tests`
- `ios-build`
- `coverage`
- `system-tests`

Optional (recommended separately):

- `cargo-audit`
- `cargo-deny`

Why: CI lanes are intentionally split between stable and nightly. Requiring exactly these checks prevents accidental bypass (missing nightly lane) or false blocking (obsolete check names).

## Local required-check reproduction

From the repo root, the closest local equivalent to the required branch-protection set is:

```bash
just ci-required
```

That expands to these exact required-check reproductions:

```bash
cargo fmt --all -- --check
cargo +stable check --workspace
cargo +stable clippy --workspace --all-targets -- -D warnings
cargo +stable test --workspace
cargo +stable llvm-cov \
	-p client-sdk \
	-p sync-core \
	-p transport-sdk \
	-p rendezvous-server \
	-p server-node-sdk \
	--lib \
	--all-features \
	--summary-only \
	--ignore-filename-regex 'crates/common/src/lib.rs|crates/client-sdk/src/content_addressed_client_cache.rs|crates/server-node-sdk/src/(embedded_rendezvous|setup|ui\.rs)|crates/server-node-sdk/src/web_maps(\.rs|/)' \
	--fail-under-lines 68
cd web && pnpm test:e2e:client-ui
cd web && pnpm test:e2e:server-admin
cd web && pnpm test:e2e:server-admin-rust
cd web && pnpm test:e2e:server-admin-setup-rust
cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml
```

Pass or fail rule:

- Each command must exit `0`.
- `coverage` must stay at or above the `--fail-under-lines 68` floor.
- `unit-tests` already excludes `tests/system-tests` implicitly because the workspace root excludes that crate; nightly system coverage belongs only to the `system-tests` lane.
- On Linux, `unit-tests` now also covers the packaged config-app handoff regression through `apps/config-app/tests/package_handoff.rs`, because that integration test is part of the normal `cargo test --workspace` run on `ubuntu-latest`.
- The `ios-build` lane is macOS-only. Reproduce it locally with:

```bash
just ci-ios
```

- On macOS, `just ci-required-macos` reproduces the full required set including the iOS lane.

## iOS CI artifacts

The `ios-build` lane runs on `macos-latest` and covers:

- `cargo test -p ios-app`
- `swift test` in `apps/apple-file-provider`
- `xcodebuild test` for the `IronmeshIosProject` scheme on a dynamically selected iPhone simulator, with an explicit boot-and-wait step to avoid flaky first-launch failures on macOS runners
- a `Release` archive for `IronmeshIosApp`

The `IronmeshIosProject` XCTest bundle is intentionally unhosted: it links only the shared Apple modules and no longer depends on launching `IronmeshIosApp` in the simulator.

Artifact behavior:

- When Apple signing secrets are not configured, CI uploads an unsigned `Release` `.xcarchive` for inspection.
- When Apple signing secrets are configured, CI also exports a downloadable `.ipa` for manual device installation with `Release` performance characteristics.

Configure these repository secrets for signed iOS artifacts:

- `IRONMESH_IOS_SIGNING_CERT_B64` — base64-encoded `.p12` signing certificate
- `IRONMESH_IOS_SIGNING_CERT_PASSWORD` — password for that `.p12`
- `IRONMESH_IOS_APP_PROFILE_B64` — base64-encoded provisioning profile for `dev.ironmesh.apple.iosapp`
- `IRONMESH_IOS_EXTENSION_PROFILE_B64` — base64-encoded provisioning profile for `dev.ironmesh.apple.iosapp.fileprovider`

Both provisioning profiles must grant the App Group `group.dev.ironmesh.apple.shared`
and the resolved Keychain Sharing group
`<AppIdentifierPrefix>dev.ironmesh.apple.shared-keychain`. The source entitlement uses
`$(AppIdentifierPrefix)`; Xcode expands that build-setting placeholder to the signing
team/app-identifier prefix in the built plist and entitlement. Regenerate the profiles
after enabling either capability. Any future signed macOS host and extension profiles
must grant the same pair of shared-access entitlements.

Integration note: PR #93 changes the final iOS File Provider bundle identifier from
`dev.ironmesh.apple.iosfileprovider` to `dev.ironmesh.apple.iosapp.fileprovider` and
overlaps `project.yml`, the generated `project.pbxproj`, and this signing setup. After
both changes land, replace the extension profile with one for the nested PR #93 bundle
identifier that grants both shared-access capabilities above. Whichever PR lands second
must reconcile the generated project and preserve `IronmeshSharedAccess.entitlements`
for both the iOS host and extension configurations.

Optional repository variable:

- `IRONMESH_IOS_EXPORT_METHOD` — defaults to `development`; set to `ad-hoc` when you want shareable sideload builds for registered devices.

Useful per-lane shortcuts:

- `just ci-stable`
- `just coverage`
- `just ci-web-smoke`
- `just test-system-nightly`

## Nightly lane fails, stable lanes pass

This usually means the failure is isolated to `tests/system-tests` and/or nightly `bindeps` behavior.

### 1) Reproduce locally with the same command

```bash
cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml
```

For a single test:

```bash
cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml --lib -- tests::<name> --exact --nocapture
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

## Advisory security checks

`cargo-audit` and `cargo-deny` are currently advisory-only for branch protection.

Run them before a release candidate or tag cut:

```bash
cargo audit
cargo deny --exclude system-tests check advisories licenses sources bans
```

Why advisory-only today:

- the protected merge contract is the six required checks above,
- the security workflow runs on push, pull request, schedule, and manual dispatch,
- `deny.toml` already contains one explicit advisory ignore for the optional Turso path, so release sign-off still needs human triage rather than blind pass or fail.

Release rule:

- New `cargo-audit` or `cargo-deny` findings require an explicit release decision in the checklist.
- Existing ignored findings must stay documented in `deny.toml` with a concrete rationale.

## Manual release validation

These are the minimum manual flows that should be exercised before a release candidate is signed off.

### 1. Local 4-node cluster smoke

```bash
scripts/local-cluster.sh start
scripts/local-cluster.sh status
curl --fail --silent --show-error --cacert data/local-cluster/tls/ca.pem https://127.0.0.1:18080/health >/dev/null
scripts/local-cluster.sh stop
```

Pass or fail rule:

- `status` shows all expected nodes as running.
- the HTTPS `/health` check succeeds with the generated local CA.
- `stop` leaves no stray node processes behind.

### 2. Direct client enroll and CRUD smoke

Issue a bootstrap from the local-cluster helper, enroll once, then round-trip one object:

```bash
scripts/local-cluster.sh start
scripts/local-cluster.sh bootstrap manual-cli 600 1 /tmp/ironmesh-client-bootstrap.json
cargo run -p cli-client -- \
	--bootstrap-file /tmp/ironmesh-client-bootstrap.json \
	--client-identity-file /tmp/ironmesh-client-bootstrap.client-identity.json \
	enroll \
	--label manual-cli
cargo run -p cli-client -- \
	--bootstrap-file /tmp/ironmesh-client-bootstrap.json \
	--client-identity-file /tmp/ironmesh-client-bootstrap.client-identity.json \
	put notes/manual.txt "hello manual release"
cargo run -p cli-client -- \
	--bootstrap-file /tmp/ironmesh-client-bootstrap.json \
	--client-identity-file /tmp/ironmesh-client-bootstrap.client-identity.json \
	get notes/manual.txt
scripts/local-cluster.sh stop
```

Pass or fail rule:

- `enroll` writes the client identity file successfully.
- `get notes/manual.txt` returns `hello manual release`.

### 3. Embedded rendezvous relay client path

Run the guide in [docs/manual-rendezvous-relay-test.md](manual-rendezvous-relay-test.md).

Pass or fail rule:

- both nodes complete zero-touch setup,
- one client identity enrolls successfully,
- the relay-forced bootstrap on node B can read the object written through node A.

### 4. Linux FUSE live mount

Reuse the bootstrap issued in the direct-enroll flow:

```bash
mkdir -p /tmp/ironmesh-mount
cargo run -p os-integration -- \
	--bootstrap-file /tmp/ironmesh-client-bootstrap.json \
	--mountpoint /tmp/ironmesh-mount
```

In another shell, verify one existing object is visible and one new write round-trips:

```bash
cat /tmp/ironmesh-mount/notes/manual.txt
printf 'hello from fuse\n' >/tmp/ironmesh-mount/notes/fuse.txt
cargo run -p cli-client -- \
	--bootstrap-file /tmp/ironmesh-client-bootstrap.json \
	--client-identity-file /tmp/ironmesh-client-bootstrap.client-identity.json \
	get notes/fuse.txt
```

Pass or fail rule:

- the mount comes up without authentication errors,
- `/tmp/ironmesh-mount/notes/manual.txt` is readable,
- the CLI read-back returns `hello from fuse`.

### 5. Folder-agent restart or resume

```bash
mkdir -p /tmp/ironmesh-folder-agent-root
cargo run -p ironmesh-folder-agent -- \
	--root-dir /tmp/ironmesh-folder-agent-root \
	--bootstrap-file /tmp/ironmesh-client-bootstrap.json \
	--client-identity-file /tmp/ironmesh-client-bootstrap.client-identity.json \
	--remote-refresh-interval-ms 500 \
	--local-scan-interval-ms 500
```

Stop the agent, make one remote change with the CLI and one local change in the root directory, then restart the same command.

Pass or fail rule:

- a remote file changed while the agent is stopped appears locally after restart,
- a local file created while the agent is stopped uploads after restart,
- no manual state cleanup is needed between runs.

### 6. Packaged Windows sync-root restart

Run the guide in [docs/manual-windows-sync-root-restart-test.md](manual-windows-sync-root-restart-test.md).

Release rule:

- Record one successful packaged Windows run that proves sync-root reconnection after restart or update before release sign-off.
