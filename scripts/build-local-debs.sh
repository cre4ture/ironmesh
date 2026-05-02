#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
RUN_PREPARE=true
RUN_LINTIAN=false
DPKG_BUILD_ARGS=()

log() {
  printf '[build-local-debs] %s\n' "$*"
}

usage() {
  cat <<'EOF'
Build installable local Debian binary packages from the current checkout.

Usage:
  ./scripts/build-local-debs.sh [--no-prepare] [--lintian] [-- <dpkg-buildpackage args>]

Options:
  --no-prepare  Skip ./scripts/prepare-ppa-source.sh.
  --lintian     Run lintian on the generated .changes file after a successful build.
  -h, --help    Show this help text.

Notes:
  - This helper builds local binary packages with dpkg-buildpackage -b -us -uc.
  - It is separate from ./scripts/build-ppa-source.sh, which builds Launchpad/PPA source uploads.
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

check_build_dependencies() {
  local output

  if output="$(cd "${ROOT_DIR}" && dpkg-checkbuilddeps 2>&1)"; then
    return 0
  fi

  printf '%s\n' "${output}" >&2
  printf '\n' >&2
  printf 'Install the Debian build dependencies from %s and rerun.\n' \
    "${ROOT_DIR}/debian/control" >&2
  printf 'If deb-src entries are enabled, you can usually run:\n' >&2
  printf '  cd %q && sudo apt build-dep .\n' "${ROOT_DIR}" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --no-prepare)
      RUN_PREPARE=false
      shift
      ;;
    --lintian)
      RUN_LINTIAN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      DPKG_BUILD_ARGS+=("$@")
      break
      ;;
    *)
      printf 'unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_command dpkg-buildpackage
require_command dpkg-checkbuilddeps
require_command dpkg-parsechangelog
require_command dpkg

if [[ "${RUN_LINTIAN}" == true ]]; then
  require_command lintian
fi

"${ROOT_DIR}/scripts/sync-debian-version.sh"
check_build_dependencies

if [[ "${RUN_PREPARE}" == true ]]; then
  log "preparing vendored crates and prebuilt web assets"
  "${ROOT_DIR}/scripts/prepare-ppa-source.sh"
fi

SOURCE_NAME="$(cd "${ROOT_DIR}" && dpkg-parsechangelog -SSource)"
VERSION="$(cd "${ROOT_DIR}" && dpkg-parsechangelog -SVersion)"
ARCH="$(dpkg --print-architecture)"
CHANGES_PATH="${ARTIFACT_DIR}/${SOURCE_NAME}_${VERSION}_${ARCH}.changes"
BUILDINFO_PATH="${ARTIFACT_DIR}/${SOURCE_NAME}_${VERSION}_${ARCH}.buildinfo"
PACKAGE_PATHS=(
  "${ARTIFACT_DIR}/ironmesh-client_${VERSION}_${ARCH}.deb"
  "${ARTIFACT_DIR}/ironmesh-server-node_${VERSION}_${ARCH}.deb"
  "${ARTIFACT_DIR}/ironmesh-rendezvous-service_${VERSION}_${ARCH}.deb"
)

log "building local Debian binary packages"
(
  cd "${ROOT_DIR}"
  dpkg-buildpackage -b -us -uc "${DPKG_BUILD_ARGS[@]}"
)

for path in "${PACKAGE_PATHS[@]}" "${CHANGES_PATH}" "${BUILDINFO_PATH}"; do
  if [[ ! -f "${path}" ]]; then
    printf 'expected build artifact not found: %s\n' "${path}" >&2
    exit 1
  fi
done

log "built artifacts:"
for path in "${PACKAGE_PATHS[@]}" "${CHANGES_PATH}" "${BUILDINFO_PATH}"; do
  printf '  %s\n' "${path}"
done

printf '\n'
log "install locally with:"
printf '  sudo apt install'
for path in "${PACKAGE_PATHS[@]}"; do
  printf ' %q' "${path}"
done
printf '\n'

if [[ "${RUN_LINTIAN}" == true ]]; then
  printf '\n'
  log "running lintian on ${CHANGES_PATH}"
  lintian "${CHANGES_PATH}"
fi
