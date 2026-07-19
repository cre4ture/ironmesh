# Apple File Provider

This directory contains IronMesh's native macOS and iOS File Provider apps and replicated
extensions. The iOS app supports multiple independently scoped sync profiles; each profile is a
separate Files domain backed by the shared enrolled device connection.

## Layout

- `Package.swift` - shared Apple models, profile policy, bridge code, and tests.
- `project.yml` - XcodeGen spec for the repo-local macOS and iOS app/extension project.
- `IronmeshAppleFileProvider.xcodeproj` - generated Xcode project for the Apple app slice.
- `Sources/AppleCore` - bridge-facing configuration, sync-profile persistence/policy, remote-change
  journals, domain coordination, and transport-adjacent model types.
- `Sources/AppleFileProviderShared` - File Provider identifier and item-mapping helpers.
- `Sources/IronmeshMacApp` and `Sources/IronmeshIosApp` - native SwiftUI hosts and profile controls.
- `Sources/AppleFileProviderRuntime` - Rust-backed replicated File Provider service, enumerators,
  persistent sync anchors, scope mapping, mutation conflict handling, and network/power gates.
- `Sources/IronmeshMacFileProviderExtension` and `Sources/IronmeshIosFileProviderExtension` -
  replicated File Provider extension principals.
- `Tests/*` - `swift test` coverage for identifier formatting and model normalization, plus a small Xcode project test target.

## Build

- Generate the Xcode project with `xcodegen generate --spec project.yml`.
- Run the shared Swift package tests with `swift test`.
- Use `xcodebuild` against `IronmeshAppleFileProvider.xcodeproj` and the `IronmeshAppleProject` scheme for the four app/extension targets.
- Use the `IronmeshIosProject` scheme with an iOS Simulator destination for the runnable XCTest slice.
- The CI helpers `scripts/resolve-ios-simulator-destination.sh` and `scripts/prepare-ios-simulator.sh` pick a currently available simulator destination and wait for it to become launch-ready before `xcodebuild test`.
- For a local simulator build/install/launch loop, run `scripts/run-ios-simulator-app.sh` or `just ios-app-run`.
- GitHub Actions can also archive the `IronmeshIosApp` Release build and, when Apple signing secrets are configured, export a downloadable `.ipa` for manual device installs.

## iOS sync behavior

- Profiles own their remote prefix, discovery depth, lifecycle, and network/power policy while
  explicitly referencing the shared device connection and Keychain identity.
- iOS pause/resume is a persisted operation gate because iOS does not expose File Provider domain
  disconnect/reconnect. The registered domain and OS-managed queued/materialized data remain intact.
- Remote discovery is driven by File Provider enumeration and explicit working-set signals. A
  persistent generation journal translates full remote snapshots into restart-safe updates and
  deletions without foreground polling. Network/power recovery and a newly materialized conflict
  copy emit best-effort working-set hints; they do not promise immediate remote push delivery.
- Content is materialized on demand. Offline pinning remains the Files app's system-managed
  **Keep Downloaded** action; iOS has no provider-level per-profile eager-retention API.
- File mutations carry File Provider's base version to a server-side preferred-head compare-and-swap.
  Concurrent content edits are preserved under a deterministic visible conflict-copy name. A
  directory deletion is recursive and enabled in Files. A concurrent child mutation may be
  deleted with that subtree, but is recoverable from the durable snapshot/version history; Files
  does not restore it automatically. Namespace-level snapshot CAS is deliberately deferred in
  [#148](https://github.com/cre4ture/ironmesh/issues/148).

See [the multi-profile sync ADR](../../docs/ios-multi-profile-folder-sync-decision.md) for the
architecture, platform compromises, guarantees, and known boundaries.
