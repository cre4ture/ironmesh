# First Release Review Checklist

Status: Draft working checklist for a repository-wide release-readiness review.

## Goal

Use this checklist to review the full repository with a first-release mindset. The focus is not just code quality; it is contract stability.

The main contracts to freeze, or deliberately change before release, are:

- server-node to server-node protocol and identity expectations
- server-node to client APIs and SDK behavior
- user-visible executable names and command names
- configuration, state, bootstrap, and client-identity file names and default paths
- packaging, installation, and update behavior
- security, migration, observability, and release gates

Active compatibility shims and aliases should be tracked in [backwards-compatibility-aliases.md](backwards-compatibility-aliases.md) so cleanup decisions can be made entry by entry.

## Review Rules

1. Work in pass order. Do not skip Pass 1.
2. For each pass, capture:
   - confirmed stable contracts
   - findings tagged as `blocker`, `major`, `minor`, or `question`
   - missing tests, docs, or migrations
   - explicit pre-release decisions
3. After Pass 1, do not rename binaries, endpoint paths, env vars, JSON fields, or default file paths without also recording a migration or compatibility note.
4. Any contract that remains intentionally unstable must be labeled as experimental in docs or packaging.
5. If multiple reviewers or AIs split the work, each pass should leave a short evidence log with reviewed paths, findings, and open questions.

## Evidence Template

Use this output shape for each pass:

- Reviewed paths:
- Confirmed stable contracts:
- Findings:
- Missing tests or docs:
- Proposed pre-release actions:
- Deferred post-release items:

## Current Contract Candidates To Freeze Or Deliberately Change

These are the main release-surface candidates already visible in the repo and worth confirming early.

| Surface | Current state to verify | Why it matters |
| --- | --- | --- |
| CLI command name | `apps/cli-client` remains the Cargo package name, while the public binary and command name are `ironmesh` | Cargo/package naming can stay internal, but released executable naming must stay stable |
| Service binary name | `apps/server-node` remains the Cargo package name, while the public binary and command name are `ironmesh-server-node` | Node automation and cluster tooling will depend on it |
| Rendezvous service name | `apps/rendezvous-service` remains the Cargo package name, while the public binary and command name are `ironmesh-rendezvous-service` | Deployment and troubleshooting depend on it |
| Desktop executable set | `ironmesh-config-app`, `ironmesh-background-launcher`, `ironmesh-os-integration`, `ironmesh-folder-agent` are treated as sibling packaged executables | Package layout and launcher behavior become user-visible contracts |
| Filesystem integration naming | `ironmesh-os-integration` is the intended public wrapper while Linux FUSE and Windows CFAPI adapter names remain implementation details underneath it | Keeping one documented entrypoint avoids support and packaging drift |
| Windows startup task ID | `IronmeshBackgroundLauncher` is hard-coded | OS-level registration names are expensive to change later |
| Desktop config path | Windows uses `%LOCALAPPDATA%\Ironmesh\desktop-client-config\instances.json`; Linux uses `$XDG_CONFIG_HOME/ironmesh/desktop-client-config/instances.json` and `$XDG_STATE_HOME/ironmesh/desktop-client-config/last-launch-report.json`, with migration from legacy uppercase XDG roots | Users, scripts, and packaged apps may start depending on these paths |
| Sync-root local state path | Windows CFAPI uses `%LOCALAPPDATA%\Ironmesh\sync-roots\<label-hash>\...` for `connection-bootstrap.json`, `client-identity.json`, and `desktop-status.json` | This becomes a persistence and migration contract |
| Runtime env var naming | Binary runtime envs use `IRONMESH_*`; local helper scripts should keep distinct prefixes such as `IRONMESH_LOCAL_CLUSTER_*` and `IRONMESH_RENDEZVOUS_DEPLOY_*` rather than reusing the runtime `IRONMESH_RENDEZVOUS_*` namespace | This avoids confusing helper automation settings with the actual runtime config contract |
| Direct connection flag naming | User-facing direct client flows should use `--server-base-url` across `ironmesh`, `ironmesh-os-integration`, and `ironmesh-folder-agent`; legacy `ironmesh --server-url` should stay compatibility-only if kept at all | This prevents docs, scripts, and UI-generated command lines from drifting across clients |
| Auth / CA flag naming | `--client-identity-file` and `--server-ca-pem-file` should stay canonical across `ironmesh`, `ironmesh-os-integration`, and `ironmesh-folder-agent`; legacy Windows `--server-ca-cert` should stay compatibility-only if retained | Config-app generated commands, system tests, and platform docs should not drift by OS |
| Folder-agent state root | `sync-agent-core` defaults to `${XDG_STATE_HOME:-$HOME/.local/state}/ironmesh/folder-agent/` and should stay aligned with the Linux persisted-state root family | Consistent Linux XDG roots reduce migration and support complexity |
| Bootstrap and identity file naming | External examples should use `ironmesh-client-bootstrap*.json`; live flows infer sibling `*.client-identity.json` files such as `ironmesh-client-bootstrap.client-identity.json`; Windows sync-root persistence should stay on `connection-bootstrap.json` and `client-identity.json` under `%LOCALAPPDATA%\Ironmesh\sync-roots\...` | This freezes the release-facing handoff names and keeps legacy hidden Windows names out of current docs and packaging |
| Client enrollment JSON naming | Direct enrollment, bootstrap-claim redeem, and SDK enrollment results should use `device_label` as the canonical JSON field; bare `label` should stay compatibility-only if retained | This keeps bootstrap JSON, enrollment APIs, and mobile/bootstrap tooling aligned |
| Managed rendezvous failover package JSON | Export/import packages should keep top-level fields `version`, `cluster_id`, `source_node_id`, `target_node_id`, `exported_at_unix`, `public_url`, `pbkdf2_rounds`, `salt_b64`, `nonce_b64`, and `ciphertext_b64` stable; the encrypted payload should continue carrying the standalone mTLS client CA plus the server cert and key | Failover handoff files become an operator disaster-recovery contract |
| Inter-node identity contract | Peer TLS identity is based on cert SAN values like `urn:ironmesh:node:<uuid>` | This is a core compatibility and security contract |
| HTTP API versioning | Canonical client-facing routes are versioned under `/api/v1`, with temporary legacy aliases retained server-side for compatibility | The release contract now has an explicit version namespace while bundled callers migrate to the canonical paths |
| Client-facing JSON error shape | Current v1 error bodies stay on the top-level `{ "error": "<message>" }` envelope across server-node and bundled web routes | Bundled clients and external tooling need one predictable error body across the `/api/v1` surface |
| Desktop managed JSON schema markers | `instances.json` and `last-launch-report.json` persist top-level `version: 1` and accept missing version from older files | Desktop state needs an explicit migration marker before release |
| Windows package identity | The Store/MSIX strategy doc now treats the reserved Partner Center identity as fixed | Package identity stability affects install/update continuity |

## Suggested Review Split

If multiple reviewers or AIs are involved, use this split after everyone reads Pass 1:

1. Track A: Passes 1 to 3 for binary names, APIs, and protocol contracts.
2. Track B: Passes 4 to 6 for paths, persistence, packaging, and update behavior.
3. Track C: Passes 7 to 10 for security, release gates, docs, and final sign-off.

## Pass 1. Inventory Public Contracts

Primary repo areas:

- [README.md](../README.md)
- [Cargo.toml](../Cargo.toml)
- [apps/cli-client/src/main.rs](../apps/cli-client/src/main.rs)
- [apps/server-node/src/main.rs](../apps/server-node/src/main.rs)
- [apps/rendezvous-service/src/config.rs](../apps/rendezvous-service/src/config.rs)
- [apps/os-integration/src/main.rs](../apps/os-integration/src/main.rs)
- [apps/config-app/src/main.rs](../apps/config-app/src/main.rs)
- [apps/folder-agent/src/main.rs](../apps/folder-agent/src/main.rs)
- [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)

Checklist:

- [x] Build a contract table with package name, built binary name, user-facing command name, documented name, and supported platforms.
- [x] Mark each binary or command as `public stable`, `stable internal`, `experimental`, or `private implementation`.
- [ ] Inventory release-visible env vars and classify which ones are part of the supported contract versus debug-only or internal knobs.
- [ ] Inventory release-visible persisted files and classify which ones are part of the supported contract versus implementation details.
- [x] Record every naming mismatch that could confuse users, packaging, automation, or docs.

Working evidence log:

- Reviewed paths:
   - [README.md](../README.md)
   - [Cargo.toml](../Cargo.toml)
   - [apps/cli-client/Cargo.toml](../apps/cli-client/Cargo.toml)
   - [apps/cli-client/src/main.rs](../apps/cli-client/src/main.rs)
   - [apps/server-node/Cargo.toml](../apps/server-node/Cargo.toml)
   - [apps/server-node/src/main.rs](../apps/server-node/src/main.rs)
   - [apps/rendezvous-service/Cargo.toml](../apps/rendezvous-service/Cargo.toml)
   - [apps/os-integration/Cargo.toml](../apps/os-integration/Cargo.toml)
   - [apps/os-integration/src/main.rs](../apps/os-integration/src/main.rs)
   - [apps/config-app/Cargo.toml](../apps/config-app/Cargo.toml)
   - [apps/config-app/src/main.rs](../apps/config-app/src/main.rs)
   - [apps/background-launcher/Cargo.toml](../apps/background-launcher/Cargo.toml)
   - [apps/background-launcher/src/main.rs](../apps/background-launcher/src/main.rs)
   - [apps/folder-agent/Cargo.toml](../apps/folder-agent/Cargo.toml)
   - [apps/folder-agent/src/main.rs](../apps/folder-agent/src/main.rs)
   - [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)
- Confirmed stable contracts:

   | Cargo package | Built binary name | User-facing command name | Documented name | Supported platforms | Initial classification |
   | --- | --- | --- | --- | --- | --- |
   | `cli-client` | `ironmesh` | `ironmesh` | `ironmesh` | Cross-platform Rust CLI | `public stable` |
   | `server-node` | `ironmesh-server-node` | `ironmesh-server-node` | `ironmesh-server-node` | Cross-platform Rust service | `public stable` |
   | `rendezvous-service` | `ironmesh-rendezvous-service` | `ironmesh-rendezvous-service` | `ironmesh-rendezvous-service` | Cross-platform Rust service | `public stable` |
   | `os-integration` | `ironmesh-os-integration` | `ironmesh-os-integration` | `ironmesh-os-integration` | Windows CFAPI and Linux FUSE | `public stable` |
   | `ironmesh-config-app` | `ironmesh-config-app` | `ironmesh-config-app` | `ironmesh-config-app` | Linux and Windows packaged desktop builds | `public stable` |
   | `ironmesh-background-launcher` | `ironmesh-background-launcher` | `ironmesh-background-launcher` | packaged background launcher helper | Linux and Windows packaged desktop builds | `stable internal` |
   | `ironmesh-folder-agent` | `ironmesh-folder-agent` | `ironmesh-folder-agent` | packaged folder sync agent | Linux and Windows packaged desktop builds | `stable internal` |
- Findings:
   - `major`: [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs) was still resolving the sibling packaged executable as `os-integration`; this pass updates it to `ironmesh-os-integration` so packaged launch behavior matches the actual binary contract already enforced by the app package and tests.
   - `minor`: the package-name versus command-name split is intentional for `cli-client`, `server-node`, `rendezvous-service`, and `os-integration`; support docs should keep spelling out that `cargo run -p ...` uses Cargo package names while released binaries use the `ironmesh-*` command names above.
   - `question`: the table above is enough to freeze names and classifications, but Pass 6 still needs to decide the final first-release artifact scope per platform.
- Missing tests or docs:
   - Release-visible env vars still need a single inventory and classification pass.
   - Release-visible persisted files still need a stable-vs-internal matrix.
- Proposed pre-release actions:
   - Keep the table above as the naming source of truth and update it when Pass 6 trims or expands the shipped artifact set.
   - Keep adding explicit package-name versus binary-name notes anywhere user docs show `cargo run -p ...` examples.
- Deferred post-release items:
   - Remove internal helper binaries from top-level user docs if packaging eventually hides them completely behind the config app.

Exit criteria:

- [ ] A reviewer can answer "what names and paths are safe for users and scripts to depend on?" without reading the source again.

## Pass 2. Review Server-Node To Server-Node Compatibility

Primary repo areas:

- [crates/server-node-sdk](../crates/server-node-sdk)
- [crates/transport-sdk](../crates/transport-sdk)
- [crates/rendezvous-server](../crates/rendezvous-server)
- [crates/common](../crates/common)
- [docs/security-architecture.md](security-architecture.md)
- [docs/node-certificate-renewal-model-decision.md](node-certificate-renewal-model-decision.md)
- [docs/peer-identity-reachability-proposal.md](peer-identity-reachability-proposal.md)

Checklist:

- [ ] Inventory inter-node HTTP routes, payloads, query parameters, and headers that participate in replication, reconcile, heartbeat, enrollment, repair, or failover.
- [ ] Verify that authenticated peer identity comes from TLS material rather than caller-controlled request fields.
- [ ] Review bootstrap, certificate renewal, membership checks, and failover package handling for backward and forward compatibility risk.
- [ ] Review rendezvous and relay dependencies that affect inter-node behavior, especially where bootstrap metadata and runtime identity have to stay aligned.
- [ ] Decide which inter-node routes, payload fields, and identity assumptions are part of the first release contract and which are still allowed to move.

Exit criteria:

- [ ] There is a written inter-node contract list plus an explicit list of anything still experimental.

## Pass 3. Review Client-Facing API And SDK Stability

Primary repo areas:

- [crates/client-sdk](../crates/client-sdk)
- [crates/common](../crates/common)
- [crates/server-node-sdk](../crates/server-node-sdk)
- [crates/web-ui-backend](../crates/web-ui-backend)
- [README.md](../README.md)
- [docs/manual-rendezvous-relay-test.md](manual-rendezvous-relay-test.md)

Checklist:

- [ ] Inventory client-facing HTTP routes, query parameters, auth requirements, and error-response shapes.
- [x] Review `ConnectionBootstrap`, client enrollment, bootstrap-claim redemption, direct-vs-relay target selection, and client identity loading.
- [ ] Decide whether `web-ui-backend` routes are part of the stable release surface or only internal to bundled tools.
- [x] Confirm the canonical `/api/v1` client-facing route set, and list any legacy unversioned aliases that remain temporarily supported for compatibility.
- [x] Freeze the first-release JSON error envelope on top-level `{ "error": string }` across the `/api/v1` surface unless a richer typed error contract lands before release.
- [ ] Map every stable client-facing route and payload to existing automated tests or create missing-test follow-ups.

Working evidence log:

- Reviewed paths:
   - [crates/client-sdk/src/ironmesh_client.rs](../crates/client-sdk/src/ironmesh_client.rs)
   - [crates/client-sdk/src/remote_sync.rs](../crates/client-sdk/src/remote_sync.rs)
   - [crates/server-node-sdk/src/lib.rs](../crates/server-node-sdk/src/lib.rs)
   - [crates/server-node-sdk/src/web_maps.rs](../crates/server-node-sdk/src/web_maps.rs)
   - [crates/web-ui-backend/src/lib.rs](../crates/web-ui-backend/src/lib.rs)
   - [web/tests/client-ui.smoke.spec.ts](../web/tests/client-ui.smoke.spec.ts)
   - [web/tests/server-admin.smoke.spec.ts](../web/tests/server-admin.smoke.spec.ts)
   - [docs/backwards-compatibility-aliases.md](backwards-compatibility-aliases.md)
- Confirmed stable contracts:
   - `client-sdk`, `server-node-sdk`, and `web-ui-backend` now use `/api/v1` as the canonical client-facing prefix, and bootstrap direct-target probes use `/api/v1/health`.
   - Legacy unversioned client-facing aliases remain server-side only as temporary compatibility shims and are now recorded in [backwards-compatibility-aliases.md](backwards-compatibility-aliases.md).
   - Representative server-node and bundled-web error helpers now pin the top-level public JSON envelope to `{ "error": string }`, and the smoke suites assert canonical `/api/v1` URLs instead of legacy unversioned paths.
- Findings:
   - `question`: whether bundled `web-ui-backend` routes should be documented as part of the public stable surface or treated as bundled-tool internal routes is still undecided.
   - `minor`: the route and payload contract is better pinned than before, but the stable-route inventory is still distributed across source and tests rather than one explicit contract list.
- Missing tests or docs:
   - A single route catalog that maps each stable client-facing endpoint and payload to Rust or smoke-test coverage is still missing.
- Proposed pre-release actions:
   - Write the explicit stable-route catalog and decide whether `web-ui-backend` stays internal or joins the public first-release API surface.
   - Keep legacy aliases documented in [backwards-compatibility-aliases.md](backwards-compatibility-aliases.md) until external callers are known to be off them.
- Deferred post-release items:
   - Remove temporary unversioned aliases once the compatibility window closes.

Exit criteria:

- [ ] Stable client-facing contracts are explicitly listed, and internal or experimental routes are clearly excluded.

## Pass 4. Review Executable Names, Command Names, And Install Layout

Primary repo areas:

- [apps/cli-client/src/main.rs](../apps/cli-client/src/main.rs)
- [apps/os-integration/src/main.rs](../apps/os-integration/src/main.rs)
- [crates/adapter-linux-fuse/src/mount_main.rs](../crates/adapter-linux-fuse/src/mount_main.rs)
- [crates/adapter-windows-cfapi/src/cli.rs](../crates/adapter-windows-cfapi/src/cli.rs)
- [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)
- [README.md](../README.md)

Checklist:

- [ ] Confirm the final user-visible binary and command names for all shipped artifacts.
- [ ] Resolve the `cli-client` package name versus `ironmesh` command-name split in docs, packaging, and support language.
- [ ] Decide whether `os-integration` is the only supported user-facing entrypoint for filesystem integration, with adapter-specific names treated as implementation details.
- [ ] Review all code that assumes packaged sibling executables live under one package root.
- [ ] Review OS-level names that become hard to change later, including startup-task IDs and package-root assumptions.

Exit criteria:

- [ ] Docs, tests, packaging, and code agree on what a user or automation system is expected to run.

## Pass 5. Review Config, State, Naming, And Migration Behavior

Primary repo areas:

- [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)
- [crates/adapter-windows-cfapi/src/local_state.rs](../crates/adapter-windows-cfapi/src/local_state.rs)
- [crates/adapter-windows-cfapi/src/auth.rs](../crates/adapter-windows-cfapi/src/auth.rs)
- [crates/adapter-linux-fuse/src/mount_main.rs](../crates/adapter-linux-fuse/src/mount_main.rs)
- [crates/sync-agent-core/src/folder_agent_state.rs](../crates/sync-agent-core/src/folder_agent_state.rs)
- [docs/windows-msix-release-update-strategy.md](windows-msix-release-update-strategy.md)
- [docs/cross-platform-filesystem-integration-strategy.md](cross-platform-filesystem-integration-strategy.md)

Checklist:

- [x] Enumerate stable or semi-stable persisted files by platform, including `instances.json`, `last-launch-report.json`, `connection-bootstrap.json`, `client-identity.json`, `desktop-status.json`, GNOME status JSON, and the folder-agent SQLite files.
- [x] Decide whether path-root casing differences such as `Ironmesh` versus `ironmesh` are intentional release contracts or inconsistencies to fix before release.
- [x] Review migration behavior for legacy paths such as `windows-client-config` and older bootstrap or identity-file discovery names.
- [x] Review JSON and SQLite format stability, including whether explicit schema or format version markers are needed before release.
- [x] Keep stable JSON stores on explicit format markers; `instances.json` and `last-launch-report.json` currently use `version: 1` with compatibility for missing legacy versions.
- [x] Confirm compatibility behavior for SQLite stores that now persist explicit schema markers, including legacy databases that predate the marker rows.
- [x] Verify deterministic path derivation where state directories are keyed by sync-root path hashing or other derived labels.

Working evidence log:

- Reviewed paths:
   - [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)
   - [crates/adapter-windows-cfapi/src/local_state.rs](../crates/adapter-windows-cfapi/src/local_state.rs)
   - [crates/adapter-windows-cfapi/src/auth.rs](../crates/adapter-windows-cfapi/src/auth.rs)
   - [crates/adapter-linux-fuse/src/mount_main.rs](../crates/adapter-linux-fuse/src/mount_main.rs)
   - [crates/desktop-status/src/gnome.rs](../crates/desktop-status/src/gnome.rs)
   - [crates/sync-agent-core/src/folder_agent_state.rs](../crates/sync-agent-core/src/folder_agent_state.rs)
   - [crates/client-sdk/src/content_addressed_client_cache.rs](../crates/client-sdk/src/content_addressed_client_cache.rs)
   - [crates/server-node-sdk/src/storage/sqlite_impl.rs](../crates/server-node-sdk/src/storage/sqlite_impl.rs)
   - [docs/backwards-compatibility-aliases.md](backwards-compatibility-aliases.md)
   - [docs/cross-platform-filesystem-integration-strategy.md](cross-platform-filesystem-integration-strategy.md)
   - [docs/windows-msix-release-update-strategy.md](windows-msix-release-update-strategy.md)
- Confirmed stable contracts:
   - `instances.json` and `last-launch-report.json` now persist top-level `version: 1` and accept missing version in legacy files.
   - The client content cache and server metadata SQLite stores now persist explicit `schema_version` markers and treat missing legacy marker rows as current while rejecting future versions.
   - Desktop config roots remain `%LOCALAPPDATA%\Ironmesh\desktop-client-config\...` on Windows and XDG `ironmesh/...` roots on Linux; that casing split is now treated as an intentional OS-specific release contract, with migration from older legacy roots still in place.

  | Platform | Path / file family | Classification | Format / derivation | Compatibility / migration notes |
  | --- | --- | --- | --- | --- |
  | Windows | `%LOCALAPPDATA%\Ironmesh\desktop-client-config\instances.json` | `public stable` | JSON with top-level `version: 1` | Migrates from `%LOCALAPPDATA%\Ironmesh\windows-client-config\instances.json` |
  | Windows | `%LOCALAPPDATA%\Ironmesh\desktop-client-config\last-launch-report.json` | `stable internal` | JSON with top-level `version: 1` | Migrates from `%LOCALAPPDATA%\Ironmesh\windows-client-config\last-launch-report.json` |
  | Windows | `%LOCALAPPDATA%\Ironmesh\sync-roots\<sanitized-leaf>-<blake3(normalized-sync-root)>\{connection-bootstrap.json, client-identity.json, desktop-status.json}` | `semi-stable` | Directory label is deterministic from the normalized sync-root path plus the leaf name | Current release-facing persisted sync-root state; preferred names are `connection-bootstrap.json` and `client-identity.json` |
  | Windows | hidden `*.ironmesh-connection.json` and `*.ironmesh-client-identity.json` discovery names | `legacy/internal` | Legacy hidden filenames | Keep out of release-facing docs; use only as compatibility readers if still needed |
  | Windows | `%LOCALAPPDATA%\Ironmesh\thumbnail-cache` and `%LOCALAPPDATA%\Ironmesh\thumbnail-provider.log` | `stable internal` | Packaged runtime cache and diagnostics | Explicitly documented as out-of-package mutable state in the Windows MSIX strategy |
  | Linux | `${XDG_CONFIG_HOME:-$HOME/.config}/ironmesh/desktop-client-config/instances.json` | `public stable` | JSON with top-level `version: 1` | Lower-case XDG root is intentional on Linux |
  | Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/ironmesh/desktop-client-config/last-launch-report.json` | `stable internal` | JSON with top-level `version: 1` | Lower-case XDG root is intentional on Linux |
  | Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/ironmesh/os-integration/client-rights-edge/<sanitized-scope>/state/{pending-mutations.json, remote-snapshot.json}` plus sibling `staged/`, `upload-state/`, and `object-cache/` | `semi-stable root, private internal contents` | Root is derived from direct URL or bootstrap path, prefix, and mountpoint; contents are implementation detail | `--client-edge-state-dir` overrides the default root |
  | Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/ironmesh/os-integration/downloads/<blake3(scope)>/` | `private implementation` | Deterministic blake3 hash of connection target, prefix, and mountpoint | Download staging only |
  | Linux | `${XDG_RUNTIME_DIR}/ironmesh/gnome-status.json` | `semi-stable` | Desktop-status JSON document | `--gnome-status-file` overrides the default runtime path |
  | Linux | `${XDG_STATE_HOME:-$HOME/.local/state}/ironmesh/folder-agent/profiles/<scope_fingerprint>/{baseline.sqlite, modification-log.sqlite}` | `semi-stable` | SQLite baseline plus modification log under a domain-separated BLAKE3 digest of identity root, scope prefix, and connection target | Legacy pre-release `DefaultHasher` profile directories migrate forward on open and rewrite persisted scope-fingerprint metadata |
- Findings:
   - `resolved`: [crates/sync-agent-core/src/folder_agent_state.rs](../crates/sync-agent-core/src/folder_agent_state.rs) now derives `profiles/<scope_fingerprint>/` with an explicit domain-separated BLAKE3 digest and migrates legacy `DefaultHasher` profile directories plus stored SQLite `scope_fingerprint` metadata on open.
   - `minor`: the Windows sync-root state family is on current release-facing names (`connection-bootstrap.json`, `client-identity.json`, `desktop-status.json`), but legacy hidden `.ironmesh-*` discovery names still exist in implementation and should remain compatibility-only.
- Missing tests or docs:
   - No additional persisted-path gaps were found in this pass beyond broader release-review work.
- Proposed pre-release actions:
   - Keep the Windows `Ironmesh` root and Linux `ironmesh` XDG roots as intentional OS-specific contracts, and keep [backwards-compatibility-aliases.md](backwards-compatibility-aliases.md) as the cleanup ledger for retained legacy readers.
- Deferred post-release items:
   - Remove missing-version compatibility paths only after the supported upgrade window no longer requires reading pre-marker files or databases.
   - Remove legacy hidden Windows bootstrap and identity discovery names once the compatibility window closes.

Exit criteria:

- [x] There is a platform-by-platform compatibility matrix for persisted files and migrations.

## Pass 6. Review Packaging, Distribution, And Update Behavior

Primary repo areas:

- [docs/windows-msix-release-update-strategy.md](windows-msix-release-update-strategy.md)
- [windows/thumbnail-provider](../windows/thumbnail-provider)
- [apps/config-app](../apps/config-app)
- [apps/background-launcher](../apps/background-launcher)
- [apps/os-integration](../apps/os-integration)
- [apps/folder-agent](../apps/folder-agent)

Checklist:

- [x] Confirm the first-release artifact list per platform and label anything not ready as out of scope or experimental.
- [x] Verify the Windows package identity, packaged executable set, and rule that mutable state must stay outside the package.
- [x] Review update-time behavior for anything that uses the package root, sync-root registration, shell extensions, or background startup.
- [x] Review Linux packaging and install assumptions, including mountpoint prerequisites and optional GNOME integration.
- [x] Explicitly decide whether mobile shells are part of the first release or only present as workspace code.

Working evidence log:

- Reviewed paths:
   - [docs/windows-msix-release-update-strategy.md](windows-msix-release-update-strategy.md)
   - [docs/ubuntu-ppa-packaging.md](ubuntu-ppa-packaging.md)
   - [debian/README.source](../debian/README.source)
   - [debian/control](../debian/control)
   - [debian/rules](../debian/rules)
   - [debian/ironmesh-server-node.service](../debian/ironmesh-server-node.service)
   - [debian/ironmesh-rendezvous-service.service](../debian/ironmesh-rendezvous-service.service)
   - [debian/ironmesh-server-node.env](../debian/ironmesh-server-node.env)
   - [debian/ironmesh-rendezvous-service.env](../debian/ironmesh-rendezvous-service.env)
   - [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)
   - [apps/background-launcher/src/main.rs](../apps/background-launcher/src/main.rs)
   - [crates/adapter-linux-fuse/src/gnome.rs](../crates/adapter-linux-fuse/src/gnome.rs)
   - [apps/folder-agent/src/gnome.rs](../apps/folder-agent/src/gnome.rs)
   - [crates/desktop-status/src/gnome.rs](../crates/desktop-status/src/gnome.rs)
- First-release artifact and update decisions:

  | Platform | Artifact / install channel | Classification | Update path | Notes |
  | --- | --- | --- | --- | --- |
  | Windows | Store-submitted `.msixupload` / MSIX package | `public stable` | Microsoft Store | Package identity is fixed; installed package root is ephemeral; mutable runtime state must stay outside the package |
  | Ubuntu Linux | Launchpad PPA packages `ironmesh-client`, `ironmesh-server-node`, and `ironmesh-rendezvous-service` | `public stable` | `apt upgrade`, Update Manager, or unattended-upgrades | No custom self-updater; Launchpad builds per-series binaries from the Debian source package |
  | Android and iOS shells | Workspace code only | `out of scope for first release` | n/a | No first-release packaging or update channel is defined yet |
- Confirmed packaging and update behavior:
   - Windows first release stays on Microsoft Store delivery; direct sideload packaging remains a development-only path.
   - Ubuntu first release should use a Launchpad PPA as the supported install and update channel. Users add the PPA once, install the package they need with `apt`, and receive updates through normal Ubuntu package management rather than an Ironmesh self-updater.
   - `ironmesh-client` installs the public `ironmesh` CLI and the packaged helpers `ironmesh-config-app`, `ironmesh-folder-agent`, `ironmesh-os-integration`, and `ironmesh-background-launcher` under one package root, with `/usr/bin` symlinks for the documented commands.
   - Linux background launching resolves sibling binaries from `current_exe().parent()`, so keeping the client helpers together under one package root is part of the update contract for `apt`-delivered upgrades.
   - Linux mutable client state stays under XDG `Ironmesh` roots, while server and rendezvous packages keep operator-edited config in `/etc/ironmesh/*.env` and runtime state in systemd `StateDirectory` roots under `/var/lib`; package upgrades should not rewrite those paths.
   - Debian packaging installs but does not auto-enable or auto-start `ironmesh-server-node.service` or `ironmesh-rendezvous-service.service`; operators must fill in the matching env file and run `systemctl enable --now ...` explicitly.
   - The client package ships GNOME extension assets, but GNOME Shell integration remains optional and per-user. The package does not auto-enable the extension; `ironmesh-os-integration gnome install-extension` or `ironmesh-folder-agent gnome install-extension` still performs the user install step.
   - Linux `Run Enabled Services` works from the config app, but login autostart is not wired yet, so Linux background behavior is intentionally below Windows startup-task parity for the first release.
- Findings:
   - `decision`: [docs/ubuntu-ppa-packaging.md](ubuntu-ppa-packaging.md) should treat Launchpad PPA plus `apt` as the supported Ubuntu install and update contract for the first release; no custom in-app updater is needed on Ubuntu.
   - `minor`: [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs) still reports that Linux login autostart is not configured, so release docs must describe Linux background relaunch as manual-on-demand rather than automatic at sign-in.
   - `minor`: [crates/desktop-status/src/gnome.rs](../crates/desktop-status/src/gnome.rs) installs the GNOME extension into `~/.local/share/gnome-shell/extensions/...`, which keeps the extension per-user and update-safe but means the Debian package alone does not finish desktop integration.
- Missing tests or docs:
   - Validate the real `add-apt-repository` plus `apt install` and `apt upgrade` flow against a fresh supported Ubuntu series once the production PPA name exists.
- Proposed pre-release actions:
   - Keep Launchpad PPA as the Ubuntu consumer channel and document the final end-user install and update commands with the real PPA name.
   - Keep Linux service enablement and GNOME extension enablement as explicit opt-in steps unless a deliberate packaging hook is added later.
- Deferred post-release items:
   - Add Linux login autostart only after the XDG autostart behavior is intentionally designed and tested.

Exit criteria:

- [x] Artifact and update behavior are documented without depending on ephemeral install paths or hidden packaging assumptions.

## Pass 7. Review Security, Identity, And Operational Safety

Primary repo areas:

- [docs/security-architecture.md](security-architecture.md)
- [docs/node-certificate-renewal-model-decision.md](node-certificate-renewal-model-decision.md)
- [docs/nat-traversal-rendezvous-strategy.md](nat-traversal-rendezvous-strategy.md)
- [crates/server-node-sdk](../crates/server-node-sdk)
- [crates/transport-sdk](../crates/transport-sdk)
- [apps/rendezvous-service](../apps/rendezvous-service)

Checklist:

- [x] Review TLS and mTLS requirements, plus every plaintext or insecure-dev escape hatch.
- [x] Review admin-token fallback behavior, audit logging, and safe defaults for destructive maintenance actions.
- [x] Review certificate renewal, issuer matching, membership validation, and client-identity handling for release-time robustness.
- [x] Review rendezvous and relay preconditions, especially cases where missing CA material or misaligned bootstrap metadata should fail fast.
- [x] Confirm that logs, status files, and status endpoints are sufficient for release support and incident diagnosis.

Working evidence log:

- Reviewed paths:
   - [docs/security-architecture.md](security-architecture.md)
   - [docs/node-certificate-renewal-model-decision.md](node-certificate-renewal-model-decision.md)
   - [docs/nat-traversal-rendezvous-strategy.md](nat-traversal-rendezvous-strategy.md)
   - [README.md](../README.md)
   - [crates/server-node-sdk/src/lib.rs](../crates/server-node-sdk/src/lib.rs)
   - [crates/server-node-sdk/src/ui.rs](../crates/server-node-sdk/src/ui.rs)
   - [crates/server-node-sdk/src/storage/sqlite_impl.rs](../crates/server-node-sdk/src/storage/sqlite_impl.rs)
   - [crates/server-node-sdk/src/storage/turso_impl.rs](../crates/server-node-sdk/src/storage/turso_impl.rs)
   - [apps/rendezvous-service/src/config.rs](../apps/rendezvous-service/src/config.rs)
   - [apps/rendezvous-service/src/main.rs](../apps/rendezvous-service/src/main.rs)
   - [crates/rendezvous-server/src/lib.rs](../crates/rendezvous-server/src/lib.rs)
   - [crates/rendezvous-server/src/auth.rs](../crates/rendezvous-server/src/auth.rs)
   - [crates/transport-sdk/src/rendezvous.rs](../crates/transport-sdk/src/rendezvous.rs)
- Confirmed security and operational controls:
   - Internal peer traffic is materially stricter than the public listener. `ironmesh-server-node` requires internal TLS material at startup, wraps the internal router with authenticated `InternalCaller` extraction, and only allows node-enrollment auto-renew when the caller cluster ID matches and the caller node ID is still present in cluster membership.
   - `ironmesh-server-node` public startup now mirrors the rendezvous fail-closed model: runtime startup refuses plaintext public HTTP unless `IRONMESH_ALLOW_INSECURE_PUBLIC_HTTP=true` is set explicitly for local development or testing.
   - Standalone `ironmesh-rendezvous-service` already refuses plaintext HTTP by default. It only starts without mTLS when `IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP=true` is set explicitly for local development, and its config validation also rejects partial or inconsistent failover-package TLS inputs.
   - Client bootstrap and rendezvous enrollment flows fail fast when the release-time trust roots are incomplete. In particular, rendezvous client identity issuance aborts when rendezvous mTLS is required but cluster CA or internal CA key material is missing.
   - Admin actions are audit-persisted in both metadata backends through `admin_audit_events`, and destructive operations still require explicit `approve=true` before they can run as non-dry-run requests.
   - Support-facing status surfaces already exist for first release triage: public `/health`, authenticated node-certificate status, scrub and repair activity or history endpoints, and the recent log buffer, which now sits behind client-or-admin authentication on the public router.
- Findings:
   - `blocker`: [crates/server-node-sdk/src/lib.rs](../crates/server-node-sdk/src/lib.rs) only enforces admin authentication when an admin token or password-backed session hash is configured. If neither exists, `authorize_admin_request()` falls through to the dry-run and approval checks and leaves the public admin or maintenance surface reachable without authentication.
   - `resolved`: [crates/server-node-sdk/src/lib.rs](../crates/server-node-sdk/src/lib.rs) now refuses public runtime startup without `IRONMESH_PUBLIC_TLS_CERT` and `IRONMESH_PUBLIC_TLS_KEY` unless `IRONMESH_ALLOW_INSECURE_PUBLIC_HTTP=true` is set explicitly for local development or testing.
   - `resolved`: [crates/server-node-sdk/src/lib.rs](../crates/server-node-sdk/src/lib.rs) now treats unauthenticated client access as an explicit development-only override via `IRONMESH_ALLOW_UNAUTHENTICATED_CLIENTS=true`, and [README.md](../README.md) no longer advertises the old `IRONMESH_REQUIRE_CLIENT_AUTH` knob as part of the supported runtime contract.
   - `resolved`: [crates/server-node-sdk/src/lib.rs](../crates/server-node-sdk/src/lib.rs) no longer leaves `/logs` anonymous on the public router; the route now requires either valid client auth or admin auth, and [web/apps/server-admin/src/pages/LogsPage.tsx](../web/apps/server-admin/src/pages/LogsPage.tsx) forwards the admin token override when present.
- Missing tests or docs:
   - Add fail-closed tests for admin routes when no admin auth is configured.
- Proposed pre-release actions:
   - Fail closed on public admin and maintenance routes unless password-backed admin auth or an explicit emergency token is configured.
   - Keep `IRONMESH_ALLOW_INSECURE_PUBLIC_HTTP` and `IRONMESH_ALLOW_UNAUTHENTICATED_CLIENTS` documented as development-only overrides rather than release-facing runtime contract knobs.

Exit criteria:

- [x] No auth, transport, or destructive-operation blocker is left unclassified.

## Pass 8. Review CI, Tests, And Manual Release Gates

Primary repo areas:

- [README.md](../README.md)
- [justfile](../justfile)
- [docs/ci-runbook.md](ci-runbook.md)
- [tests/system-tests](../tests/system-tests)
- [deny.toml](../deny.toml)

Checklist:

- [ ] Map each stable contract from Passes 1 to 7 to automated tests or explicit manual checks.
- [ ] Confirm the minimum automated gates for release, including formatting, check, clippy, unit tests, coverage, and system tests.
- [ ] Decide whether `cargo-deny` and audit checks are hard release gates or advisory-only checks.
- [ ] Define the minimum manual flows for release validation, such as local cluster start, direct client enroll, rendezvous relay enroll, packaged Windows sync-root restart flow, Linux FUSE mount, and folder-agent restart or resume.
- [ ] Record exact commands and pass or fail criteria for each manual flow.

Exit criteria:

- [ ] Someone other than the original author can run the release gates and decide pass or fail.

## Pass 9. Review Docs, Examples, Scripts, And Shipped Sample Assets

Primary repo areas:

- [README.md](../README.md)
- [docs](.)
- [scripts](../scripts)
- [start_node.sh](../start_node.sh)
- [ironmesh-client-bootstrap.client-identity.json](../ironmesh-client-bootstrap.client-identity.json)
- [ironmesh-client-bootstrap.json](../ironmesh-client-bootstrap.json)

Checklist:

- [ ] Ensure docs consistently use the final executable names, command names, and supported path conventions.
- [ ] Ensure examples and shipped sample assets use supported bootstrap and client-identity naming conventions.
- [ ] Ensure scripts do not bake in obsolete package names or unstable implementation details.
- [ ] Ensure experimental or platform-limited features are labeled accurately.
- [ ] Ensure README and release notes explain what is stable now and what is still expected to evolve.

Exit criteria:

- [ ] A new user can follow the docs without accidentally depending on obsolete names or unsupported paths.

## Pass 10. Final Sign-Off And Backlog Split

Checklist:

- [ ] Create a final `v1` contract list for APIs, binaries, paths, and packaged artifacts.
- [ ] Convert every finding into one of: `fix before release`, `document before release`, or `post-release backlog`.
- [ ] Reject release if any `blocker` lacks either a fix or an explicit signed-off decision.
- [ ] Tag every intentional incompatibility with migration, support, and documentation follow-up.
- [ ] Capture a short go or no-go summary with remaining risk notes.

Exit criteria:

- [ ] There is a clear release decision record and a short list of what the next AI reviewer should work on first.

## Recommended First Work Items

If this checklist is used immediately, the highest-value first steps are:

1. Build the binary and command-name contract table from Pass 1.
2. Build the persisted file and path matrix from Pass 5.
3. Build the client-facing and inter-node API contract lists from Passes 2 and 3.
4. Resolve naming mismatches before wider packaging and documentation cleanup.