#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <github-env-output-file>" >&2
    exit 64
fi

ENV_OUTPUT_FILE="$1"
RUNNER_TEMP_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
PROFILE_DIR="${HOME}/Library/MobileDevice/Provisioning Profiles"
KEYCHAIN_PATH="${RUNNER_TEMP_DIR}/ironmesh-ios-signing.keychain-db"
CERT_PATH="${RUNNER_TEMP_DIR}/ironmesh-ios-signing.p12"
APP_PROFILE_PATH="${RUNNER_TEMP_DIR}/ironmesh-ios-app.mobileprovision"
EXTENSION_PROFILE_PATH="${RUNNER_TEMP_DIR}/ironmesh-ios-extension.mobileprovision"
KEYCHAIN_PASSWORD_FILE="${RUNNER_TEMP_DIR}/ironmesh-ios-signing.password"

require_env() {
    VAR_NAME="$1"
    eval "VAR_VALUE=\${$VAR_NAME:-}"
    if [ -z "$VAR_VALUE" ]; then
        echo "missing required environment variable: $VAR_NAME" >&2
        exit 65
    fi
}

decode_base64() {
    INPUT="$1"
    OUTPUT_PATH="$2"

    if printf '%s' "$INPUT" | base64 --decode >"$OUTPUT_PATH" 2>/dev/null; then
        return 0
    fi

    if printf '%s' "$INPUT" | base64 -d >"$OUTPUT_PATH" 2>/dev/null; then
        return 0
    fi

    if printf '%s' "$INPUT" | base64 -D >"$OUTPUT_PATH" 2>/dev/null; then
        return 0
    fi

    echo "failed decoding base64 payload into $OUTPUT_PATH" >&2
    exit 66
}

append_env() {
    KEY="$1"
    VALUE="$2"
    printf '%s=%s\n' "$KEY" "$VALUE" >>"$ENV_OUTPUT_FILE"
}

plist_value() {
    PLIST_PATH="$1"
    PLIST_KEY="$2"
    /usr/libexec/PlistBuddy -c "Print ${PLIST_KEY}" "$PLIST_PATH"
}

install_profile() {
    LABEL="$1"
    PROFILE_B64="$2"
    RAW_PROFILE_PATH="$3"
    PROFILE_PLIST_PATH="${RAW_PROFILE_PATH}.plist"

    decode_base64 "$PROFILE_B64" "$RAW_PROFILE_PATH"
    security cms -D -i "$RAW_PROFILE_PATH" >"$PROFILE_PLIST_PATH"

    PROFILE_UUID="$(plist_value "$PROFILE_PLIST_PATH" "UUID")"
    PROFILE_TEAM="$(plist_value "$PROFILE_PLIST_PATH" "TeamIdentifier:0")"

    mkdir -p "$PROFILE_DIR"
    cp "$RAW_PROFILE_PATH" "$PROFILE_DIR/${PROFILE_UUID}.mobileprovision"

    append_env "IRONMESH_IOS_${LABEL}_PROFILE_UUID" "$PROFILE_UUID"
    append_env "IRONMESH_IOS_${LABEL}_PROFILE_PATH" "$PROFILE_DIR/${PROFILE_UUID}.mobileprovision"

    printf '%s\n' "$PROFILE_TEAM"
}

require_env "IRONMESH_IOS_SIGNING_CERT_B64"
require_env "IRONMESH_IOS_SIGNING_CERT_PASSWORD"
require_env "IRONMESH_IOS_APP_PROFILE_B64"
require_env "IRONMESH_IOS_EXTENSION_PROFILE_B64"

KEYCHAIN_PASSWORD="$(uuidgen)"
printf '%s' "$KEYCHAIN_PASSWORD" >"$KEYCHAIN_PASSWORD_FILE"

security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1 || true
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

decode_base64 "$IRONMESH_IOS_SIGNING_CERT_B64" "$CERT_PATH"
security import "$CERT_PATH" \
    -k "$KEYCHAIN_PATH" \
    -P "$IRONMESH_IOS_SIGNING_CERT_PASSWORD" \
    -A \
    -t cert \
    -f pkcs12
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

set -- $(security list-keychains -d user | tr -d '"')
security list-keychains -d user -s "$KEYCHAIN_PATH" "$@"
security default-keychain -d user -s "$KEYCHAIN_PATH"

SIGNING_IDENTITY="$(
    security find-identity -v -p codesigning "$KEYCHAIN_PATH" \
        | awk -F'"' '/"/ { print $2; exit }'
)"

if [ -z "$SIGNING_IDENTITY" ]; then
    echo "failed to resolve a codesigning identity from $KEYCHAIN_PATH" >&2
    exit 67
fi

APP_TEAM="$(install_profile "APP" "$IRONMESH_IOS_APP_PROFILE_B64" "$APP_PROFILE_PATH")"
EXTENSION_TEAM="$(install_profile "EXTENSION" "$IRONMESH_IOS_EXTENSION_PROFILE_B64" "$EXTENSION_PROFILE_PATH")"

if [ "$APP_TEAM" != "$EXTENSION_TEAM" ]; then
    echo "iOS app and extension provisioning profiles use different team identifiers" >&2
    exit 68
fi

append_env "IRONMESH_IOS_DEVELOPMENT_TEAM" "$APP_TEAM"
append_env "IRONMESH_IOS_KEYCHAIN_PATH" "$KEYCHAIN_PATH"
append_env "IRONMESH_IOS_KEYCHAIN_PASSWORD_FILE" "$KEYCHAIN_PASSWORD_FILE"
append_env "IRONMESH_IOS_SIGNING_IDENTITY" "$SIGNING_IDENTITY"
