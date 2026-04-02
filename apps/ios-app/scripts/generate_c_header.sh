#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if ! command -v cbindgen >/dev/null 2>&1; then
    echo "cbindgen is not installed; using checked-in include/ironmesh_ios_app.h" >&2
    exit 0
fi

cd "$ROOT_DIR"
cbindgen --config cbindgen.toml --output include/ironmesh_ios_app.h
