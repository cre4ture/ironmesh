#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"

REPO_DIR="${APT_REPO_DIR:-${ROOT_DIR}/target/apt-repo}"
SUITE="${APT_REPO_SUITE:-noble}"
CODENAME="${APT_REPO_CODENAME:-${SUITE}}"
COMPONENT="${APT_REPO_COMPONENT:-main}"
DEFAULT_ARCH="${APT_REPO_ARCH:-$(dpkg --print-architecture)}"
ORIGIN="${APT_REPO_ORIGIN:-Ironmesh}"
LABEL="${APT_REPO_LABEL:-Ironmesh}"
DESCRIPTION="${APT_REPO_DESCRIPTION:-Ironmesh Debian package repository}"
SIGNING_KEY="${APT_REPO_SIGN_KEY:-${DEBUILD_KEYID:-${DEBSIGN_KEYID:-}}}"
IMPORT_REMOTE="${APT_REPO_IMPORT_REMOTE:-}"
SIGN_REPO=true
DEB_PATHS=()
REQUESTED_ARCHES=()

log() {
  printf '[build-apt-repository] %s\n' "$*"
}

usage() {
  cat <<'EOF'
Build a simple signed apt repository from locally built Ironmesh .deb packages.

Usage:
  ./scripts/build-apt-repository.sh [options] [--] [package.deb ...]

Options:
  --repo-dir DIR       Output repository directory. Defaults to target/apt-repo.
  --suite NAME         Apt suite/distribution. Defaults to noble.
  --codename NAME      Release codename. Defaults to the suite name.
  --component NAME     Apt component. Defaults to main.
  --arch ARCH          Architecture to update. May be passed more than once.
                       Without explicit package paths, defaults to
                       dpkg --print-architecture.
  --import-remote SRC  Rsync source for the published repository to import
                       before updating it, for example
                       creature@creax.de:/home/creature/html/apt/ironmesh.
  --sign-key KEY       GPG key ID or fingerprint used for Release signing.
  --no-sign            Build repository metadata without signing it.
  -h, --help           Show this help text.

Environment defaults:
  APT_REPO_DIR, APT_REPO_SUITE, APT_REPO_CODENAME, APT_REPO_COMPONENT,
  APT_REPO_ARCH, APT_REPO_ORIGIN, APT_REPO_LABEL, APT_REPO_DESCRIPTION,
  APT_REPO_IMPORT_REMOTE, APT_REPO_SIGN_KEY, DEBUILD_KEYID, DEBSIGN_KEYID.

If no .deb paths are passed, the script expects the current changelog version
artifacts in the parent directory of the checkout. Run
./scripts/build-local-debs.sh first to create them.
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

while (($# > 0)); do
  case "$1" in
    --repo-dir)
      REPO_DIR="$2"
      shift 2
      ;;
    --repo-dir=*)
      REPO_DIR="${1#*=}"
      shift
      ;;
    --suite)
      SUITE="$2"
      shift 2
      ;;
    --suite=*)
      SUITE="${1#*=}"
      shift
      ;;
    --codename)
      CODENAME="$2"
      shift 2
      ;;
    --codename=*)
      CODENAME="${1#*=}"
      shift
      ;;
    --component)
      COMPONENT="$2"
      shift 2
      ;;
    --component=*)
      COMPONENT="${1#*=}"
      shift
      ;;
    --arch)
      REQUESTED_ARCHES+=("$2")
      shift 2
      ;;
    --arch=*)
      REQUESTED_ARCHES+=("${1#*=}")
      shift
      ;;
    --import-remote)
      IMPORT_REMOTE="$2"
      shift 2
      ;;
    --import-remote=*)
      IMPORT_REMOTE="${1#*=}"
      shift
      ;;
    --sign-key)
      SIGNING_KEY="$2"
      shift 2
      ;;
    --sign-key=*)
      SIGNING_KEY="${1#*=}"
      shift
      ;;
    --no-sign)
      SIGN_REPO=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      DEB_PATHS+=("$@")
      break
      ;;
    -*)
      printf 'unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
    *)
      DEB_PATHS+=("$1")
      shift
      ;;
  esac
done

require_command apt-ftparchive
require_command dpkg
require_command dpkg-deb
require_command dpkg-parsechangelog
require_command dpkg-scanpackages
require_command gzip

"${ROOT_DIR}/scripts/sync-debian-version.sh"

if [[ "${SIGN_REPO}" == true ]]; then
  require_command gpg

  if [[ -z "${SIGNING_KEY}" ]]; then
    printf 'set APT_REPO_SIGN_KEY, DEBUILD_KEYID, or DEBSIGN_KEYID; or pass --sign-key\n' >&2
    exit 1
  fi

  if [[ -z "${GPG_TTY:-}" && -t 0 ]]; then
    export GPG_TTY
    GPG_TTY="$(tty)"
  fi
fi

if [[ -z "${REPO_DIR}" || "${REPO_DIR}" == "/" ]]; then
  printf 'refusing unsafe repository directory: %s\n' "${REPO_DIR}" >&2
  exit 1
fi

if [[ -n "${IMPORT_REMOTE}" ]]; then
  require_command rsync
  log "importing existing repository from ${IMPORT_REMOTE}"
  mkdir -p "${REPO_DIR}"
  rsync -a --delete "${IMPORT_REMOTE%/}/" "${REPO_DIR%/}/"
fi

contains_architecture() {
  local architecture="$1"
  local candidate

  for candidate in "${REQUESTED_ARCHES[@]}"; do
    if [[ "${candidate}" == "${architecture}" ]]; then
      return 0
    fi
  done

  return 1
}

add_architecture() {
  local architecture="$1"

  if ! contains_architecture "${architecture}"; then
    REQUESTED_ARCHES+=("${architecture}")
  fi
}

if ((${#DEB_PATHS[@]} == 0)); then
  VERSION="$(cd "${ROOT_DIR}" && dpkg-parsechangelog -SVersion)"
  IMPLICIT_ARCHES=("${REQUESTED_ARCHES[@]}")

  if ((${#IMPLICIT_ARCHES[@]} == 0)); then
    IMPLICIT_ARCHES=("${DEFAULT_ARCH}")
  fi

  REQUESTED_ARCHES=()
  DEB_PATHS=()
  for architecture in "${IMPLICIT_ARCHES[@]}"; do
    add_architecture "${architecture}"
    DEB_PATHS+=(
      "${ARTIFACT_DIR}/ironmesh-client_${VERSION}_${architecture}.deb"
      "${ARTIFACT_DIR}/ironmesh-server-node_${VERSION}_${architecture}.deb"
      "${ARTIFACT_DIR}/ironmesh-rendezvous-service_${VERSION}_${architecture}.deb"
    )
  done
fi

for path in "${DEB_PATHS[@]}"; do
  if [[ ! -f "${path}" ]]; then
    printf 'package not found: %s\n' "${path}" >&2
    printf 'Run ./scripts/build-local-debs.sh first, or pass explicit .deb paths.\n' >&2
    exit 1
  fi
done

for path in "${DEB_PATHS[@]}"; do
  package_architecture="$(dpkg-deb -f "${path}" Architecture)"
  if [[ -z "${package_architecture}" || "${package_architecture}" == "all" ]]; then
    printf 'package architecture must be a concrete architecture, not %s: %s\n' \
      "${package_architecture:-empty}" "${path}" >&2
    exit 1
  fi

  add_architecture "${package_architecture}"
done

if ((${#REQUESTED_ARCHES[@]} == 0)); then
  add_architecture "${DEFAULT_ARCH}"
fi

for architecture in "${REQUESTED_ARCHES[@]}"; do
  if [[ ! "${architecture}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    printf 'invalid Debian architecture: %s\n' "${architecture}" >&2
    exit 1
  fi
done

SUITE_DIR="${REPO_DIR}/dists/${SUITE}"
POOL_DIR="${REPO_DIR}/pool/${COMPONENT}/i/ironmesh"

log "refreshing ${REPO_DIR}"
mkdir -p "${POOL_DIR}"

for architecture in "${REQUESTED_ARCHES[@]}"; do
  rm -f "${POOL_DIR}"/*_"${architecture}".deb
  rm -rf "${SUITE_DIR}/${COMPONENT}/binary-${architecture}"
  mkdir -p "${SUITE_DIR}/${COMPONENT}/binary-${architecture}"
done

log "copying packages"
cp -f "${DEB_PATHS[@]}" "${POOL_DIR}/"

for architecture in "${REQUESTED_ARCHES[@]}"; do
  packages_rel="dists/${SUITE}/${COMPONENT}/binary-${architecture}/Packages"
  log "writing ${packages_rel}"
  (
    cd "${REPO_DIR}"
    dpkg-scanpackages --arch "${architecture}" pool /dev/null > "${packages_rel}"
    gzip -9cn "${packages_rel}" > "${packages_rel}.gz"
  )
done

mapfile -t RELEASE_ARCHES < <(
  find "${SUITE_DIR}/${COMPONENT}" -mindepth 1 -maxdepth 1 -type d -name 'binary-*' -printf '%f\n' \
    | sed 's/^binary-//' \
    | sort -u
)

if ((${#RELEASE_ARCHES[@]} == 0)); then
  printf 'no package architectures found under %s\n' "${SUITE_DIR}/${COMPONENT}" >&2
  exit 1
fi

RELEASE_ARCHITECTURES="${RELEASE_ARCHES[*]}"

log "writing Release metadata"
RELEASE_TMP="$(mktemp)"
trap 'rm -f "${RELEASE_TMP}"' EXIT
apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=${ORIGIN}" \
  -o "APT::FTPArchive::Release::Label=${LABEL}" \
  -o "APT::FTPArchive::Release::Suite=${SUITE}" \
  -o "APT::FTPArchive::Release::Codename=${CODENAME}" \
  -o "APT::FTPArchive::Release::Architectures=${RELEASE_ARCHITECTURES}" \
  -o "APT::FTPArchive::Release::Components=${COMPONENT}" \
  -o "APT::FTPArchive::Release::Description=${DESCRIPTION}" \
  release "${SUITE_DIR}" > "${RELEASE_TMP}"
mv "${RELEASE_TMP}" "${SUITE_DIR}/Release"

if [[ "${SIGN_REPO}" == true ]]; then
  log "exporting public signing key"
  gpg --armor --export "${SIGNING_KEY}" > "${REPO_DIR}/ironmesh-archive-keyring.asc"

  log "signing Release metadata with ${SIGNING_KEY}"
  rm -f "${SUITE_DIR}/InRelease" "${SUITE_DIR}/Release.gpg"
  gpg --yes --local-user "${SIGNING_KEY}" --clearsign --digest-algo SHA256 \
    -o "${SUITE_DIR}/InRelease" "${SUITE_DIR}/Release"
  gpg --yes --local-user "${SIGNING_KEY}" --armor --detach-sign --digest-algo SHA256 \
    -o "${SUITE_DIR}/Release.gpg" "${SUITE_DIR}/Release"
else
  log "leaving repository unsigned"
  rm -f "${SUITE_DIR}/InRelease" "${SUITE_DIR}/Release.gpg"
fi

log "repository ready: ${REPO_DIR}"
