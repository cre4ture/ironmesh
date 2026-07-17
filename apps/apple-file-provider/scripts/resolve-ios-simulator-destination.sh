#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <project-path> <scheme>" >&2
    exit 64
fi

PROJECT_PATH="$1"
SCHEME="$2"

if ! DESTINATIONS="$(xcodebuild -project "$PROJECT_PATH" -scheme "$SCHEME" -showdestinations 2>&1)"; then
    printf '%s\n' "$DESTINATIONS" >&2
    exit 1
fi

extract_destination() {
    PATTERN="$1"
    printf '%s\n' "$DESTINATIONS" \
        | sed -nE "s/^[[:space:]]*\\{ platform:iOS Simulator,.* id:([^,]+),.* name:${PATTERN}[[:space:]]*\\}\$/platform=iOS Simulator,id=\\1/p" \
        | head -n 1
}

DESTINATION="$(extract_destination "iPhone[^}]*")"
if [ -z "$DESTINATION" ]; then
    DESTINATION="$(extract_destination "[^}]*")"
fi

if [ -z "$DESTINATION" ]; then
    echo "failed to resolve an available iOS Simulator destination for scheme $SCHEME" >&2
    printf '%s\n' "$DESTINATIONS" >&2
    exit 69
fi

printf '%s\n' "$DESTINATION"
