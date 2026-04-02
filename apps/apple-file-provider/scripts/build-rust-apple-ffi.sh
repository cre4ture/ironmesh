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

case "$PLATFORM_NAME" in
    macosx)
        RUST_TARGET="aarch64-apple-darwin"
        ARTIFACT_DIR="$PROJECT_DIR/RustArtifacts/macosx"
        ;;
    iphonesimulator)
        RUST_TARGET="aarch64-apple-ios-sim"
        ARTIFACT_DIR="$PROJECT_DIR/RustArtifacts/iphonesimulator"
        ;;
    iphoneos)
        RUST_TARGET="aarch64-apple-ios"
        ARTIFACT_DIR="$PROJECT_DIR/RustArtifacts/iphoneos"
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

rustup target add "$RUST_TARGET" --toolchain nightly-2026-02-17 >/dev/null 2>&1 || true

cd "$REPO_DIR"
cargo build -p ios-app --target "$RUST_TARGET" $PROFILE_FLAG
apps/ios-app/scripts/generate_c_header.sh

mkdir -p "$ARTIFACT_DIR"
cp "$REPO_DIR/target/$RUST_TARGET/$PROFILE_DIR/libios_app.a" "$ARTIFACT_DIR/libios_app.a"
