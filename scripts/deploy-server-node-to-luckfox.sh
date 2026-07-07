#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEFAULT_HOST="root@192.168.178.132"
DEFAULT_REMOTE_PATH="/userdata/ironmesh-server-node"

HOST="${IRONMESH_LUCKFOX_HOST:-${DEFAULT_HOST}}"
REMOTE_PATH="${IRONMESH_LUCKFOX_REMOTE_PATH:-${DEFAULT_REMOTE_PATH}}"

log() {
  printf '[deploy-server-node-to-luckfox] %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<EOF
Cross-compile ironmesh-server-node and deploy it to a LuckFox PicoKVM (or
similar armv7 hardfloat board) over SSH.

Thin wrapper around scripts/build-server-node-armv7-musl.sh --deploy; see
that script for the actual cross-compile toolchain setup.

Usage:
  ./scripts/deploy-server-node-to-luckfox.sh [--host user@host] [--remote-path path]

Options:
  --host HOST         SSH target. Defaults to ${DEFAULT_HOST}.
  --remote-path PATH  Destination path on the device. Defaults to ${DEFAULT_REMOTE_PATH}.
  -h, --help          Show this help text.

Environment:
  IRONMESH_LUCKFOX_HOST         Default for --host.
  IRONMESH_LUCKFOX_REMOTE_PATH  Default for --remote-path.
EOF
}

while (($# > 0)); do
  case "$1" in
    --host)
      [[ $# -ge 2 ]] || fail "--host requires a value"
      HOST="$2"
      shift 2
      ;;
    --host=*)
      HOST="${1#*=}"
      shift
      ;;
    --remote-path)
      [[ $# -ge 2 ]] || fail "--remote-path requires a value"
      REMOTE_PATH="$2"
      shift 2
      ;;
    --remote-path=*)
      REMOTE_PATH="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

log "building and deploying to ${HOST}:${REMOTE_PATH}"
"${ROOT_DIR}/scripts/build-server-node-armv7-musl.sh" --deploy "${HOST}:${REMOTE_PATH}"

log "marking remote binary executable"
ssh "${HOST}" "chmod +x '${REMOTE_PATH}'"

log "deployed: ${HOST}:${REMOTE_PATH}"
ssh "${HOST}" "'${REMOTE_PATH}' --version"
