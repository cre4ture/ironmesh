#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_ROOT="/usr/lib/ironmesh-client"
PACKAGED_BINARY="${PACKAGE_ROOT}/ironmesh"
PACKAGED_BACKUP="${PACKAGE_ROOT}/ironmesh.packaged-deb"
DEFAULT_PROFILE="release"

PROFILE="${IRONMESH_LOCAL_PROFILE:-${DEFAULT_PROFILE}}"
SKIP_BUILD=0
LOCAL_BINARY=""

usage() {
  cat <<'EOF'
Usage: scripts/use-local-ironmesh.sh [options]

Build the local `ironmesh` CLI and replace the packaged client binary with a
symlink to the local build for testing.

Options:
  --local-binary PATH   Use an existing local binary instead of building.
  --profile NAME        Cargo profile to build. Defaults to `release`.
  --skip-build          Reuse the local binary for the selected profile.
  --help                Show this help.

Environment:
  IRONMESH_LOCAL_PROFILE   Default Cargo profile when --profile is omitted.

Notes:
  The packaged binary is backed up once at:
    /usr/lib/ironmesh-client/ironmesh.packaged-deb

Examples:
  scripts/use-local-ironmesh.sh
  scripts/use-local-ironmesh.sh --profile debug
  scripts/use-local-ironmesh.sh --local-binary /home/me/rust-dev/ironmesh/target/release/ironmesh
EOF
}

log() {
  printf '[use-local-ironmesh] %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --local-binary)
        [[ $# -ge 2 ]] || fail "--local-binary requires a value"
        LOCAL_BINARY="$2"
        shift 2
        ;;
      --local-binary=*)
        LOCAL_BINARY="${1#*=}"
        shift
        ;;
      --profile)
        [[ $# -ge 2 ]] || fail "--profile requires a value"
        PROFILE="$2"
        shift 2
        ;;
      --profile=*)
        PROFILE="${1#*=}"
        shift
        ;;
      --skip-build)
        SKIP_BUILD=1
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done
}

resolve_local_binary() {
  if [[ -n "$LOCAL_BINARY" ]]; then
    [[ -f "$LOCAL_BINARY" ]] || fail "local binary not found: $LOCAL_BINARY"
    [[ -x "$LOCAL_BINARY" ]] || fail "local binary is not executable: $LOCAL_BINARY"
    LOCAL_BINARY="$(cd "$(dirname "$LOCAL_BINARY")" && pwd)/$(basename "$LOCAL_BINARY")"
    return
  fi

  LOCAL_BINARY="${ROOT_DIR}/target/${PROFILE}/ironmesh"
  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "building local ironmesh binary with cargo profile=${PROFILE}"
    cargo build --locked -p cli-client "--profile=${PROFILE}" --manifest-path "${ROOT_DIR}/Cargo.toml"
  fi

  [[ -f "$LOCAL_BINARY" ]] || fail "built binary not found: $LOCAL_BINARY"
  [[ -x "$LOCAL_BINARY" ]] || fail "built binary is not executable: $LOCAL_BINARY"
}

backup_packaged_binary_if_needed() {
  if sudo test -L "$PACKAGED_BINARY"; then
    if sudo test -f "$PACKAGED_BACKUP"; then
      log "packaged backup already exists at ${PACKAGED_BACKUP}"
      return
    fi
    fail "${PACKAGED_BINARY} is already a symlink but no packaged backup exists; restore manually first"
  fi

  if sudo test -f "$PACKAGED_BACKUP"; then
    log "packaged backup already exists at ${PACKAGED_BACKUP}"
    return
  fi

  log "backing up packaged binary to ${PACKAGED_BACKUP}"
  sudo mv "$PACKAGED_BINARY" "$PACKAGED_BACKUP"
}

install_local_symlink() {
  log "linking ${PACKAGED_BINARY} -> ${LOCAL_BINARY}"
  sudo ln -sfn "$LOCAL_BINARY" "$PACKAGED_BINARY"
}

print_result() {
  local resolved_target
  resolved_target="$(readlink -f "$PACKAGED_BINARY")"
  log "active ironmesh target: ${resolved_target}"
  log "package symlink at /usr/bin/ironmesh remains unchanged"
  log "revert with: scripts/restore-packaged-ironmesh.sh"
}

main() {
  parse_args "$@"
  require_command cargo
  require_command sudo
  require_command readlink

  resolve_local_binary
  backup_packaged_binary_if_needed
  install_local_symlink
  print_result
}

main "$@"
