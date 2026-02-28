# Ironmesh Android (initial MVP)

This is a standalone Kotlin Android app scaffold for local testing of `server-node`.

## Features (MVP)

- Set server base URL
- Health check (`GET /health`)
- Replication plan summary (`GET /cluster/replication/plan`)
- Upload/download via Rust `client-sdk` bridge when native library is available
- Fallback HTTP/Retrofit path remains enabled if native bridge is not loaded

## Open in Android Studio

Open this folder as a project:

- `apps/android-app`

Android Studio will sync Gradle and let you run the `app` module.

Rust JNI integration is wired into the app Gradle build:

- `preBuild` runs `cargo ndk ... build` for Android ABIs
- generated `.so` files are packaged from `app/build/generated/rustJniLibs`
- JNI load name is `android_app` (`System.loadLibrary("android_app")`)

Prerequisites for native bridge builds:

- Rust toolchain installed
- `cargo-ndk` installed (`cargo install cargo-ndk`)
- Android NDK available in the Android SDK setup

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
