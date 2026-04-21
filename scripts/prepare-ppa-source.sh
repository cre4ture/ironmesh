#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREBUILT_WEB_DIR="${ROOT_DIR}/debian/prebuilt-web"
VENDORED_DIR="${ROOT_DIR}/debian/cargo-vendor"
INCLUDE_BINARIES_FILE="${ROOT_DIR}/debian/source/include-binaries"

log() {
  printf '[prepare-ppa-source] %s\n' "$*"
}

copy_dist_dir() {
  local src="$1"
  local dst="$2"

  if [[ ! -f "${src}/index.html" ]]; then
    printf 'missing built web UI at %s\n' "${src}" >&2
    exit 1
  fi

  rm -rf "${dst}"
  mkdir -p "${dst}"
  cp -a "${src}/." "${dst}/"
}

refresh_include_binaries() {
  local tmp_file path rel_path

  tmp_file="$(mktemp)"

  while IFS= read -r -d '' path; do
    if ! grep -Iq . "${path}"; then
      rel_path="${path#${ROOT_DIR}/}"
      printf '%s\n' "${rel_path}" >> "${tmp_file}"
    fi
  done < <(find "${PREBUILT_WEB_DIR}" "${VENDORED_DIR}" -type f -print0)

  sort -u "${tmp_file}" > "${INCLUDE_BINARIES_FILE}"
  rm -f "${tmp_file}"
}

log "preparing generated packaging inputs under debian/"
mkdir -p "${PREBUILT_WEB_DIR}"

if [[ ! -d "${ROOT_DIR}/web/node_modules" ]]; then
  log "web/node_modules missing; running pnpm install"
  pnpm --dir "${ROOT_DIR}/web" install --frozen-lockfile
fi

log "building bundled web applications"
pnpm --dir "${ROOT_DIR}/web" build

log "copying prebuilt server-admin assets"
copy_dist_dir \
  "${ROOT_DIR}/web/apps/server-admin/dist" \
  "${PREBUILT_WEB_DIR}/server-admin"

log "copying prebuilt client-ui assets"
copy_dist_dir \
  "${ROOT_DIR}/web/apps/client-ui/dist" \
  "${PREBUILT_WEB_DIR}/client-ui"

log "vendoring Rust dependencies"
rm -rf "${VENDORED_DIR}"
cargo vendor --locked --versioned-dirs "${VENDORED_DIR}" >/dev/null

log "refreshing debian/source/include-binaries"
refresh_include_binaries

log "prepared debian/prebuilt-web and debian/cargo-vendor"
