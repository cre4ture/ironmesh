#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNING_KEY="${DEBUILD_KEYID:-${DEBSIGN_KEYID:-}}"

log() {
  printf '[build-ppa-source] %s\n' "$*"
}

create_orig_tarball() {
  local source_name version upstream_version orig_name orig_path stage_dir tmp_dir

  source_name="$(dpkg-parsechangelog -SSource)"
  version="$(dpkg-parsechangelog -SVersion)"
  upstream_version="${version%-*}"
  orig_name="${source_name}-${upstream_version}"
  orig_path="${ROOT_DIR}/../${source_name}_${upstream_version}.orig.tar.gz"

  log "creating ${orig_path##*/}"
  rm -f "${orig_path}"

  tmp_dir="$(mktemp -d)"
  stage_dir="${tmp_dir}/${orig_name}"
  mkdir -p "${stage_dir}"
  trap 'rm -rf "${tmp_dir}"' RETURN

  tar \
    --exclude='./.git' \
    --exclude='./debian' \
    --exclude='./target' \
    --exclude='./data' \
    --exclude='./map' \
    --exclude='./target-codex-check' \
    --exclude='./web/node_modules' \
    --exclude='./web/.turbo' \
    --exclude='./web/playwright-report' \
    --exclude='./web/test-results' \
    --exclude='./web/apps/client-ui/dist' \
    --exclude='./web/apps/server-admin/dist' \
    -C "${ROOT_DIR}" \
    -cf - \
    . | tar -C "${stage_dir}" -xf -

  tar -C "${tmp_dir}" -czf "${orig_path}" "${orig_name}"
  log "wrote ${orig_path}"
}

if ! command -v debuild >/dev/null 2>&1; then
  printf 'debuild is required; install devscripts first\n' >&2
  exit 1
fi

"${ROOT_DIR}/scripts/prepare-ppa-source.sh"
create_orig_tarball

cd "${ROOT_DIR}"

if [[ -n "${SIGNING_KEY}" ]]; then
  log "using signing key ${SIGNING_KEY}"
  exec debuild --no-lintian -S -sa -nc "-k${SIGNING_KEY}" "$@"
fi

exec debuild --no-lintian -S -sa -nc "$@"
