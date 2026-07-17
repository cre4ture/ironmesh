# Apple File Provider Scaffold

This directory is the in-repo Apple-side starting point for IronMesh.

## Layout

- `Package.swift` - Swift Package scaffold for shared Apple code and tests.
- `project.yml` - XcodeGen spec for the repo-local macOS and iOS app/extension project.
- `IronmeshAppleFileProvider.xcodeproj` - generated Xcode project for the Apple app slice.
- `Sources/AppleCore` - bridge-facing configuration, protocol, and transport-adjacent model types.
- `Sources/AppleFileProviderShared` - File Provider identifier and item-mapping helpers.
- `Sources/IronmeshMacApp` and `Sources/IronmeshIosApp` - minimal SwiftUI stubs that import the shared package code.
- `Sources/IronmeshMacFileProviderExtension` and `Sources/IronmeshIosFileProviderExtension` - minimal extension principals for the future File Provider implementations.
- `Tests/*` - `swift test` coverage for identifier formatting and model normalization, plus a small Xcode project test target.

## Build

- Generate the Xcode project with `xcodegen generate --spec project.yml`.
- Run the shared Swift package tests with `swift test`.
- Use `xcodebuild` against `IronmeshAppleFileProvider.xcodeproj` and the `IronmeshAppleProject` scheme for the four app/extension targets.
- Use the `IronmeshIosProject` scheme with an iOS Simulator destination for the runnable XCTest slice.
- The CI helpers `scripts/resolve-ios-simulator-destination.sh` and `scripts/prepare-ios-simulator.sh` pick a currently available simulator destination and wait for it to become launch-ready before `xcodebuild test`.
- For a local simulator build/install/launch loop, run `scripts/run-ios-simulator-app.sh` or `just ios-app-run`.
- GitHub Actions can also archive the `IronmeshIosApp` Release build and, when Apple signing secrets are configured, export a downloadable `.ipa` for manual device installs.

## Intended next step

The project now has a concrete native scaffold. The next implementation slice can replace the stub app/extension bodies with the Rust-backed File Provider bridge and domain wiring.
