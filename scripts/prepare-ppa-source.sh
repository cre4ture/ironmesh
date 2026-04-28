#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREBUILT_WEB_DIR="${ROOT_DIR}/debian/prebuilt-web"
VENDORED_DIR="${ROOT_DIR}/debian/cargo-vendor"
INCLUDE_BINARIES_FILE="${ROOT_DIR}/debian/source/include-binaries"
CARGO_REGISTRY_SRC_ROOT="${CARGO_HOME:-${HOME}/.cargo}/registry/src"

log() {
  printf '[prepare-ppa-source] %s\n' "$*"
}

find_cargo_bin() {
  local candidate

  for candidate in \
    /usr/bin/cargo-1.91 \
    /usr/bin/cargo-1.89 \
    /usr/bin/cargo-1.85; do
    if [[ -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  command -v cargo >/dev/null 2>&1 || {
    printf 'cargo is required but was not found in PATH\n' >&2
    exit 1
  }

  command -v cargo
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

list_vendored_missing_files() {
  node <<'EOF'
const fs = require("fs");
const path = require("path");

const root = process.env.VENDORED_DIR;

for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
  if (!entry.isDirectory()) {
    continue;
  }

  const checksumPath = path.join(root, entry.name, ".cargo-checksum.json");
  if (!fs.existsSync(checksumPath)) {
    continue;
  }

  const checksum = JSON.parse(fs.readFileSync(checksumPath, "utf8"));
  for (const relativePath of Object.keys(checksum.files || {})) {
    const vendoredPath = path.join(root, entry.name, relativePath);
    if (!fs.existsSync(vendoredPath)) {
      process.stdout.write(`${entry.name}\t${relativePath}\n`);
    }
  }
}
EOF
}

repair_vendored_missing_files() {
  local -a missing_entries=()
  local entry crate_dir relative_path source_dir src_path dst_path

  mapfile -t missing_entries < <(VENDORED_DIR="${VENDORED_DIR}" list_vendored_missing_files)

  if ((${#missing_entries[@]} == 0)); then
    return 0
  fi

  if [[ ! -d "${CARGO_REGISTRY_SRC_ROOT}" ]]; then
    printf 'vendored crates are missing checksum-referenced files, but cargo registry cache was not found at %s\n' \
      "${CARGO_REGISTRY_SRC_ROOT}" >&2
    exit 1
  fi

  log "repairing ${#missing_entries[@]} missing checksum-referenced vendored files"

  shopt -s nullglob
  for entry in "${missing_entries[@]}"; do
    IFS=$'\t' read -r crate_dir relative_path <<<"${entry}"
    src_path=""
    for source_dir in "${CARGO_REGISTRY_SRC_ROOT}"/*/"${crate_dir}"; do
      if [[ -f "${source_dir}/${relative_path}" ]]; then
        src_path="${source_dir}/${relative_path}"
        break
      fi
    done

    if [[ -z "${src_path}" ]]; then
      printf 'failed to repair vendored file %s/%s: source file not found under %s\n' \
        "${crate_dir}" "${relative_path}" "${CARGO_REGISTRY_SRC_ROOT}" >&2
      exit 1
    fi

    dst_path="${VENDORED_DIR}/${crate_dir}/${relative_path}"
    mkdir -p "$(dirname "${dst_path}")"
    cp -a "${src_path}" "${dst_path}"
  done
  shopt -u nullglob

  mapfile -t missing_entries < <(VENDORED_DIR="${VENDORED_DIR}" list_vendored_missing_files)
  if ((${#missing_entries[@]} != 0)); then
    printf 'vendored dependency repair left %d checksum-referenced files missing\n' \
      "${#missing_entries[@]}" >&2
    exit 1
  fi
}

CARGO_BIN="$(find_cargo_bin)"

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

log "vendoring Rust dependencies with ${CARGO_BIN}"
rm -rf "${VENDORED_DIR}"
"${CARGO_BIN}" vendor --locked --versioned-dirs "${VENDORED_DIR}" >/dev/null
repair_vendored_missing_files

log "refreshing debian/source/include-binaries"
refresh_include_binaries

log "prepared debian/prebuilt-web and debian/cargo-vendor"
