# Ironmesh Android (initial MVP)

This is a standalone Kotlin Android app scaffold for local testing of `server-node`.

## Features (MVP)

- Set server base URL
- Health check (`GET /health`)
- Replication plan summary (`GET /cluster/replication/plan`)
- Upload/download via Rust `client-sdk` bridge when native library is available
- Fallback HTTP/Retrofit path remains enabled if native bridge is not loaded
- Open the client Web UI in a browser-powered Custom Tab when available, with fallback to an in-app `WebView`
- Configure multiple folder-sync profiles (remote prefix <-> local folder)
- Automatic periodic background folder sync (WorkManager) + manual "Sync Now"
- Optional Rust-backed title latency monitor with configurable period; compact `D` (direct) or `R` (relay) result in the app bar

## Open in Android Studio

Open this folder as a project:

- `apps/android-app`

Android Studio will sync Gradle and let you run the `app` module.

Rust JNI integration is wired into the app Gradle build:

- `preBuild` runs `cargo ndk ... build` for Android ABIs
- generated `.so` files are packaged from the variant-specific
  `app/build/generated/rustJniLibs/debug` or `app/build/generated/rustJniLibs/release` directory
- JNI load name is `android_app` (`System.loadLibrary("android_app")`)

Prerequisites for native bridge builds:

- Rust toolchain installed
- `cargo-ndk` installed (`cargo install cargo-ndk`)
- Android NDK available in the Android SDK setup

## Internal release signing

`assembleRelease` uses a dedicated internal release key when these environment variables are set:

- `IRONMESH_ANDROID_INTERNAL_RELEASE_STORE_FILE`
- `IRONMESH_ANDROID_INTERNAL_RELEASE_STORE_PASSWORD`
- `IRONMESH_ANDROID_INTERNAL_RELEASE_KEY_ALIAS`
- `IRONMESH_ANDROID_INTERNAL_RELEASE_KEY_PASSWORD`

In GitHub Actions, store the keystore itself as base64 in `IRONMESH_ANDROID_INTERNAL_RELEASE_STORE_B64`, decode it to a file, then export `IRONMESH_ANDROID_INTERNAL_RELEASE_STORE_FILE` for Gradle before running `:app:assembleRelease`.

## Local server notes

For Android emulator, use:

- `http://10.0.2.2:18080`

For a physical device, use your host machine LAN IP.

## Cleartext HTTP

The app currently allows cleartext traffic (`usesCleartextTraffic=true`) for local development.

## Rust bridge notes

- JNI bridge class: `io.ironmesh.android.data.RustClientBridge`
- Rust exports implemented in: `apps/android-app/src/lib.rs`
- Current Rust-backed operations in repository:
  - `putObject`, `putObjectBytes`
  - `getObject`, `getObjectBytes` (latest-only path; snapshot/version still uses HTTP fallback)
  - `startWebUi` (starts embedded local web UI server and returns localhost URL)
