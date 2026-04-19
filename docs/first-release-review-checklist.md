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
| CLI command name | `apps/cli-client` builds from the `cli-client` package but exposes the user command name `ironmesh` | Scripts, docs, packaging, and support instructions need one stable name |
| Service binary name | `server-node` is both package name and command name | Node automation and cluster tooling will depend on it |
| Rendezvous service name | `rendezvous-service` is both package name and command name | Deployment and troubleshooting depend on it |
| Desktop executable set | `ironmesh-config-app`, `ironmesh-background-launcher`, `os-integration`, `ironmesh-folder-agent` are treated as sibling packaged executables | Package layout and launcher behavior become user-visible contracts |
| Filesystem integration naming | `os-integration` delegates to `adapter-linux-fuse-mount` on Linux and `adapter-windows-cfapi` on Windows | Decide whether adapter-specific names are public or internal-only |
| Windows startup task ID | `IronmeshBackgroundLauncher` is hard-coded | OS-level registration names are expensive to change later |
| Desktop config path | Windows uses `%LOCALAPPDATA%\Ironmesh\desktop-client-config\instances.json`; Linux uses XDG config for `instances.json` and XDG state for `last-launch-report.json` | Users, scripts, and packaged apps may start depending on these paths |
| Sync-root local state path | Windows CFAPI uses `%LOCALAPPDATA%\Ironmesh\sync-roots\<label-hash>\...` for `connection-bootstrap.json`, `client-identity.json`, and `desktop-status.json` | This becomes a persistence and migration contract |
| Folder-agent state root | `sync-agent-core` defaults to `${XDG_STATE_HOME:-$HOME/.local/state}/ironmesh/folder-agent/` | Note the lowercase `ironmesh` root compared with `Ironmesh` elsewhere |
| Bootstrap and identity file naming | Live flows use sibling `*.client-identity.json` discovery, fallback `ironmesh-client-identity.json`, and some Windows flows also refer to `.ironmesh-client-identity.json` | Naming drift here will break enroll/bootstrap reuse and migration |
| Inter-node identity contract | Peer TLS identity is based on cert SAN values like `urn:ironmesh:node:<uuid>` | This is a core compatibility and security contract |
| HTTP API versioning | Public routes are currently unversioned | Decide whether unversioned routes are acceptable for v1 or need pre-release versioning |
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
- [apps/ironmesh-config-app/src/main.rs](../apps/ironmesh-config-app/src/main.rs)
- [apps/ironmesh-folder-agent/src/main.rs](../apps/ironmesh-folder-agent/src/main.rs)
- [crates/desktop-client-config/src/lib.rs](../crates/desktop-client-config/src/lib.rs)

Checklist:

- [ ] Build a contract table with package name, built binary name, user-facing command name, documented name, and supported platforms.
- [ ] Mark each binary or command as `public stable`, `stable internal`, `experimental`, or `private implementation`.
- [ ] Inventory release-visible env vars and classify which ones are part of the supported contract versus debug-only or internal knobs.
- [ ] Inventory release-visible persisted files and classify which ones are part of the supported contract versus implementation details.
- [ ] Record every naming mismatch that could confuse users, packaging, automation, or docs.

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
- [ ] Review `ConnectionBootstrap`, client enrollment, bootstrap-claim redemption, direct-vs-relay target selection, and client identity loading.
- [ ] Decide whether `web-ui-backend` routes are part of the stable release surface or only internal to bundled tools.
- [ ] Review whether unversioned HTTP routes and JSON payloads are acceptable for the first release or need a versioning story before release.
- [ ] Map every stable client-facing route and payload to existing automated tests or create missing-test follow-ups.

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

- [ ] Enumerate stable or semi-stable persisted files by platform, including `instances.json`, `last-launch-report.json`, `connection-bootstrap.json`, `client-identity.json`, `desktop-status.json`, GNOME status JSON, and the folder-agent SQLite files.
- [ ] Decide whether path-root casing differences such as `Ironmesh` versus `ironmesh` are intentional release contracts or inconsistencies to fix before release.
- [ ] Review migration behavior for legacy paths such as `windows-client-config` and older bootstrap or identity-file discovery names.
- [ ] Review JSON and SQLite format stability, including whether explicit schema or format version markers are needed before release.
- [ ] Verify deterministic path derivation where state directories are keyed by sync-root path hashing or other derived labels.

Exit criteria:

- [ ] There is a platform-by-platform compatibility matrix for persisted files and migrations.

## Pass 6. Review Packaging, Distribution, And Update Behavior

Primary repo areas:

- [docs/windows-msix-release-update-strategy.md](windows-msix-release-update-strategy.md)
- [windows/thumbnail-provider](../windows/thumbnail-provider)
- [apps/ironmesh-config-app](../apps/ironmesh-config-app)
- [apps/ironmesh-background-launcher](../apps/ironmesh-background-launcher)
- [apps/os-integration](../apps/os-integration)
- [apps/ironmesh-folder-agent](../apps/ironmesh-folder-agent)

Checklist:

- [ ] Confirm the first-release artifact list per platform and label anything not ready as out of scope or experimental.
- [ ] Verify the Windows package identity, packaged executable set, and rule that mutable state must stay outside the package.
- [ ] Review update-time behavior for anything that uses the package root, sync-root registration, shell extensions, or background startup.
- [ ] Review Linux packaging and install assumptions, including mountpoint prerequisites and optional GNOME integration.
- [ ] Explicitly decide whether mobile shells are part of the first release or only present as workspace code.

Exit criteria:

- [ ] Artifact and update behavior are documented without depending on ephemeral install paths or hidden packaging assumptions.

## Pass 7. Review Security, Identity, And Operational Safety

Primary repo areas:

- [docs/security-architecture.md](security-architecture.md)
- [docs/node-certificate-renewal-model-decision.md](node-certificate-renewal-model-decision.md)
- [docs/nat-traversal-rendezvous-strategy.md](nat-traversal-rendezvous-strategy.md)
- [crates/server-node-sdk](../crates/server-node-sdk)
- [crates/transport-sdk](../crates/transport-sdk)
- [apps/rendezvous-service](../apps/rendezvous-service)

Checklist:

- [ ] Review TLS and mTLS requirements, plus every plaintext or insecure-dev escape hatch.
- [ ] Review admin-token fallback behavior, audit logging, and safe defaults for destructive maintenance actions.
- [ ] Review certificate renewal, issuer matching, membership validation, and client-identity handling for release-time robustness.
- [ ] Review rendezvous and relay preconditions, especially cases where missing CA material or misaligned bootstrap metadata should fail fast.
- [ ] Confirm that logs, status files, and status endpoints are sufficient for release support and incident diagnosis.

Exit criteria:

- [ ] No auth, transport, or destructive-operation blocker is left unclassified.

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
- [ironmesh-client-bootstrap-cli-client.client-identity.json](../ironmesh-client-bootstrap-cli-client.client-identity.json)
- [ironmesh-client-bootstrap-cli-client.json](../ironmesh-client-bootstrap-cli-client.json)

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