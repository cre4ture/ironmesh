#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_ONLY=false
PRINT_ONLY=false

log() {
  printf '[sync-debian-version] %s\n' "$*"
}

usage() {
  cat <<'EOF'
Align debian/changelog's upstream version with Cargo.toml's workspace version.

Usage:
  ./scripts/sync-debian-version.sh [--check] [--print]

Options:
  --check   Fail if debian/changelog is not aligned; do not edit.
  --print   Print the desired Debian package version; do not edit.
  -h, --help
            Show this help text.

The script reads [workspace.package] version from Cargo.toml and converts Cargo
pre-release syntax to Debian pre-release syntax:

  1.0.0-beta.1 -> 1.0.0~beta.1

It preserves the Debian revision suffix from the current top changelog entry,
for example:

  1.0.0~beta.1-1~repo1~ubuntu24.04.1 -> 1.0.4-1~repo1~ubuntu24.04.1
EOF
}

require_command() {
  local command_name="$1"

  if command -v "${command_name}" >/dev/null 2>&1; then
    return 0
  fi

  printf '%s is required but was not found in PATH\n' "${command_name}" >&2
  exit 1
}

workspace_cargo_version() {
  awk '
    /^\[workspace\.package\]$/ {
      in_workspace_package = 1
      next
    }
    /^\[/ {
      in_workspace_package = 0
    }
    in_workspace_package && $1 == "version" {
      sub(/^[^"]*"/, "")
      sub(/".*$/, "")
      print
      exit
    }
  ' "${ROOT_DIR}/Cargo.toml"
}

cargo_version_to_debian_upstream() {
  local version="$1"
  printf '%s\n' "${version//-/~}"
}

while (($# > 0)); do
  case "$1" in
    --check)
      CHECK_ONLY=true
      shift
      ;;
    --print)
      PRINT_ONLY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_command awk
require_command dpkg-parsechangelog
require_command sed

CARGO_VERSION="$(workspace_cargo_version)"
if [[ -z "${CARGO_VERSION}" ]]; then
  printf 'failed to read [workspace.package] version from Cargo.toml\n' >&2
  exit 1
fi

CURRENT_VERSION="$(cd "${ROOT_DIR}" && dpkg-parsechangelog -SVersion)"
DEBIAN_REVISION=""
if [[ "${CURRENT_VERSION}" == *-* ]]; then
  DEBIAN_REVISION="-${CURRENT_VERSION#*-}"
fi

DESIRED_VERSION="$(cargo_version_to_debian_upstream "${CARGO_VERSION}")${DEBIAN_REVISION}"

if [[ "${PRINT_ONLY}" == true ]]; then
  printf '%s\n' "${DESIRED_VERSION}"
  exit 0
fi

if [[ "${CURRENT_VERSION}" == "${DESIRED_VERSION}" ]]; then
  log "debian/changelog already matches Cargo version ${CARGO_VERSION} (${DESIRED_VERSION})"
  exit 0
fi

if [[ "${CHECK_ONLY}" == true ]]; then
  printf 'debian/changelog version %s does not match Cargo version %s; expected %s\n' \
    "${CURRENT_VERSION}" "${CARGO_VERSION}" "${DESIRED_VERSION}" >&2
  exit 1
fi

sed -i "1s/(${CURRENT_VERSION})/(${DESIRED_VERSION})/" "${ROOT_DIR}/debian/changelog"
log "updated debian/changelog from ${CURRENT_VERSION} to ${DESIRED_VERSION}"
