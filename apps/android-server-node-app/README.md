# Ironmesh Android Server Node

This is a standalone Android app that runs the Ironmesh server-node directly on Android.

## What it does

- Starts the managed Ironmesh server-node inside the app process
- Keeps it alive with a foreground service
- Opens the local bootstrap/admin UI inside an embedded `WebView`
- Stores node state under the app's Android `no_backup` directory
- Shows suggested LAN `https://` origins to use during the initial bootstrap flow

## Open in Android Studio

Open this folder as a project:

- `apps/android-server-node-app`

The app uses a Rust JNI bridge:

- Rust crate: `apps/android-server-node-app`
- JNI library name: `android_server_node_app`
- Embedded startup entrypoint: `server_node_sdk::run_embedded_managed`

## Native build prerequisites

- Rust toolchain installed
- `cargo-ndk` installed: `cargo install cargo-ndk`
- Android SDK + NDK installed in Android Studio

Gradle packages the JNI libraries from `app/build/generated/rustJniLibs`.

## Runtime notes

- The Android app binds the public listener to `0.0.0.0:38443`
- The embedded UI opens through `https://127.0.0.1:38443/`
- During first bootstrap, use one of the app's suggested LAN origins like `https://192.168.x.x:38443`
- The embedded `WebView` intentionally accepts the local node's self-signed certificate for the active host
