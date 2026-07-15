#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <platform-name> <configuration>" >&2
    exit 64
fi

PLATFORM_NAME="$1"
CONFIGURATION="$2"
PROJECT_DIR="${PROJECT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
REPO_DIR="$(CDPATH= cd -- "$PROJECT_DIR/../.." && pwd)"

CARGO_BIN_DIR=""
if [ -n "${CARGO_HOME:-}" ] && [ -d "${CARGO_HOME}/bin" ]; then
    CARGO_BIN_DIR="${CARGO_HOME}/bin"
elif [ -n "${HOME:-}" ] && [ -d "${HOME}/.cargo/bin" ]; then
    CARGO_BIN_DIR="${HOME}/.cargo/bin"
fi

PATH_PREFIX="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
if [ -n "$CARGO_BIN_DIR" ]; then
    export PATH="$CARGO_BIN_DIR:$PATH_PREFIX${PATH:+:$PATH}"
else
    export PATH="$PATH_PREFIX${PATH:+:$PATH}"
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found; install Rust and ensure ~/.cargo/bin is available to Xcode builds" >&2
    exit 127
fi

case "$PLATFORM_NAME" in
    macosx)
        RUST_TARGET="aarch64-apple-darwin"
        ARTIFACT_DIR="$PROJECT_DIR/RustArtifacts/macosx"
        export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-14.0}"
        ;;
    iphonesimulator)
        RUST_TARGET="aarch64-apple-ios-sim"
        ARTIFACT_DIR="$PROJECT_DIR/RustArtifacts/iphonesimulator"
        export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
        ;;
    iphoneos)
        RUST_TARGET="aarch64-apple-ios"
        ARTIFACT_DIR="$PROJECT_DIR/RustArtifacts/iphoneos"
        export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-16.0}"
        ;;
    *)
        echo "unsupported Apple platform: $PLATFORM_NAME" >&2
        exit 65
        ;;
esac

PROFILE_DIR="debug"
PROFILE_FLAG=""
if [ "$CONFIGURATION" = "Release" ]; then
    PROFILE_DIR="release"
    PROFILE_FLAG="--release"
fi

LOCK_DIR="$PROJECT_DIR/RustArtifacts/.build-lock-$PLATFORM_NAME"
mkdir -p "$PROJECT_DIR/RustArtifacts"
while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    sleep 1
done
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT HUP INT TERM

rustup target add "$RUST_TARGET" --toolchain nightly-2026-02-17 >/dev/null 2>&1 || true

cd "$REPO_DIR"
cargo build -p ios-app --target "$RUST_TARGET" $PROFILE_FLAG
apps/ios-app/scripts/generate_c_header.sh

mkdir -p "$ARTIFACT_DIR"
TEMP_ARCHIVE="$ARTIFACT_DIR/libios_app.a.tmp.$$"
cp "$REPO_DIR/target/$RUST_TARGET/$PROFILE_DIR/libios_app.a" "$TEMP_ARCHIVE"
mv "$TEMP_ARCHIVE" "$ARTIFACT_DIR/libios_app.a"
