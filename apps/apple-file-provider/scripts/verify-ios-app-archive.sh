#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <archive-path>" >&2
    exit 64
fi

ARCHIVE_PATH="$1"
APP_PATH="$ARCHIVE_PATH/Products/Applications/IronmeshIosApp.app"
EXTENSION_PATH="$APP_PATH/PlugIns/IronmeshIosFileProviderExtension.appex"
EXTENSION_INFO_PLIST="$EXTENSION_PATH/Info.plist"
EXPECTED_EXTENSION_BUNDLE_ID="dev.ironmesh.apple.iosapp.fileprovider"
PLIST_BUDDY="/usr/libexec/PlistBuddy"

fail() {
    echo "iOS archive verification failed: $1" >&2
    exit 1
}

[ -d "$ARCHIVE_PATH" ] || fail "archive not found at $ARCHIVE_PATH"
[ -d "$APP_PATH" ] || fail "app bundle not found at $APP_PATH"
[ -d "$EXTENSION_PATH" ] || fail "File Provider extension not embedded at $EXTENSION_PATH"
[ -f "$EXTENSION_INFO_PLIST" ] || fail "extension Info.plist not found at $EXTENSION_INFO_PLIST"
[ -x "$PLIST_BUDDY" ] || fail "PlistBuddy not found at $PLIST_BUDDY"

EXTENSION_BUNDLE_ID="$($PLIST_BUDDY -c 'Print :CFBundleIdentifier' "$EXTENSION_INFO_PLIST")"
[ "$EXTENSION_BUNDLE_ID" = "$EXPECTED_EXTENSION_BUNDLE_ID" ] ||
    fail "unexpected extension bundle identifier: $EXTENSION_BUNDLE_ID"

EXTENSION_EXECUTABLE="$($PLIST_BUDDY -c 'Print :CFBundleExecutable' "$EXTENSION_INFO_PLIST")"
[ -x "$EXTENSION_PATH/$EXTENSION_EXECUTABLE" ] ||
    fail "extension executable not found at $EXTENSION_PATH/$EXTENSION_EXECUTABLE"

printf 'Verified embedded File Provider extension: %s\n' "$EXTENSION_PATH"
