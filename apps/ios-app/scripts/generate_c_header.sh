#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

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

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "cbindgen is not installed; using checked-in include/ironmesh_ios_app.h" >&2
    exit 0
fi

cd "$ROOT_DIR"
cbindgen --config cbindgen.toml --output include/ironmesh_ios_app.h
