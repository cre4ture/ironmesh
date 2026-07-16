#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <project-path> <scheme>" >&2
    exit 64
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
PROJECT_PATH="$1"
SCHEME="$2"
DESTINATION="$("$SCRIPT_DIR/resolve-ios-simulator-destination.sh" "$PROJECT_PATH" "$SCHEME")"
UDID="${DESTINATION##*=}"

if [ "${IRONMESH_IOS_SIMULATOR_RESET:-0}" = "1" ]; then
    xcrun simctl shutdown "$UDID" >/dev/null 2>&1 || true
    xcrun simctl erase "$UDID" >/dev/null 2>&1 || true
fi

xcrun simctl boot "$UDID" >/dev/null 2>&1 || true
xcrun simctl bootstatus "$UDID" -b >&2

if [ -n "${IRONMESH_IOS_SIMULATOR_APP_BUNDLE_ID:-}" ]; then
    xcrun simctl uninstall "$UDID" "$IRONMESH_IOS_SIMULATOR_APP_BUNDLE_ID" >/dev/null 2>&1 || true
fi

printf '%s\n' "$DESTINATION"
