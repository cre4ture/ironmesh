#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$(cd "${ROOT_DIR}/.." && pwd)"

REPO_DIR="${APT_REPO_DIR:-${ROOT_DIR}/target/apt-repo}"
SUITE="${APT_REPO_SUITE:-noble}"
CODENAME="${APT_REPO_CODENAME:-${SUITE}}"
COMPONENT="${APT_REPO_COMPONENT:-main}"
ARCH="${APT_REPO_ARCH:-$(dpkg --print-architecture)}"
ORIGIN="${APT_REPO_ORIGIN:-Ironmesh}"
LABEL="${APT_REPO_LABEL:-Ironmesh}"
DESCRIPTION="${APT_REPO_DESCRIPTION:-Ironmesh Debian package repository}"
SIGNING_KEY="${APT_REPO_SIGN_KEY:-${DEBUILD_KEYID:-${DEBSIGN_KEYID:-}}}"
SIGN_REPO=true
DEB_PATHS=()

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
  --arch ARCH          Binary architecture. Defaults to dpkg --print-architecture.
  --sign-key KEY       GPG key ID or fingerprint used for Release signing.
  --no-sign            Build repository metadata without signing it.
  -h, --help           Show this help text.

Environment defaults:
  APT_REPO_DIR, APT_REPO_SUITE, APT_REPO_CODENAME, APT_REPO_COMPONENT,
  APT_REPO_ARCH, APT_REPO_ORIGIN, APT_REPO_LABEL, APT_REPO_DESCRIPTION,
  APT_REPO_SIGN_KEY, DEBUILD_KEYID, DEBSIGN_KEYID.

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
      ARCH="$2"
      shift 2
      ;;
    --arch=*)
      ARCH="${1#*=}"
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

if ((${#DEB_PATHS[@]} == 0)); then
  VERSION="$(cd "${ROOT_DIR}" && dpkg-parsechangelog -SVersion)"
  DEB_PATHS=(
    "${ARTIFACT_DIR}/ironmesh-client_${VERSION}_${ARCH}.deb"
    "${ARTIFACT_DIR}/ironmesh-server-node_${VERSION}_${ARCH}.deb"
    "${ARTIFACT_DIR}/ironmesh-rendezvous-service_${VERSION}_${ARCH}.deb"
  )
fi

for path in "${DEB_PATHS[@]}"; do
  if [[ ! -f "${path}" ]]; then
    printf 'package not found: %s\n' "${path}" >&2
    printf 'Run ./scripts/build-local-debs.sh first, or pass explicit .deb paths.\n' >&2
    exit 1
  fi
done

PACKAGES_REL="dists/${SUITE}/${COMPONENT}/binary-${ARCH}/Packages"
SUITE_DIR="${REPO_DIR}/dists/${SUITE}"
POOL_DIR="${REPO_DIR}/pool/main/i/ironmesh"

log "refreshing ${REPO_DIR}"
rm -rf \
  "${REPO_DIR}/dists" \
  "${REPO_DIR}/pool" \
  "${REPO_DIR}/ironmesh-archive-keyring.asc"
mkdir -p \
  "${REPO_DIR}/$(dirname "${PACKAGES_REL}")" \
  "${POOL_DIR}"

log "copying packages"
cp -f "${DEB_PATHS[@]}" "${POOL_DIR}/"

log "writing Packages index"
(
  cd "${REPO_DIR}"
  dpkg-scanpackages --arch "${ARCH}" pool /dev/null > "${PACKAGES_REL}"
  gzip -9cn "${PACKAGES_REL}" > "${PACKAGES_REL}.gz"
)

log "writing Release metadata"
RELEASE_TMP="$(mktemp)"
trap 'rm -f "${RELEASE_TMP}"' EXIT
apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=${ORIGIN}" \
  -o "APT::FTPArchive::Release::Label=${LABEL}" \
  -o "APT::FTPArchive::Release::Suite=${SUITE}" \
  -o "APT::FTPArchive::Release::Codename=${CODENAME}" \
  -o "APT::FTPArchive::Release::Architectures=${ARCH}" \
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
fi

log "repository ready: ${REPO_DIR}"
