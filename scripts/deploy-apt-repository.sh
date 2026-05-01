#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO_DIR="${APT_REPO_DIR:-${ROOT_DIR}/target/apt-repo}"
SUITE="${APT_REPO_SUITE:-noble}"
REMOTE="${APT_REPO_REMOTE:-creature@creax.de}"
REMOTE_DIR="${APT_REPO_REMOTE_DIR:-/home/creature/html/apt/ironmesh}"
REMOTE_URL="${APT_REPO_URL:-https://creax.de/apt/ironmesh}"
DRY_RUN=false

log() {
  printf '[deploy-apt-repository] %s\n' "$*"
}

usage() {
  cat <<'EOF'
Deploy the generated Ironmesh apt repository to a static web directory.

Usage:
  ./scripts/deploy-apt-repository.sh [options]

Options:
  --repo-dir DIR     Local repository directory. Defaults to target/apt-repo.
  --suite NAME       Apt suite to sanity-check. Defaults to noble.
  --remote HOST      SSH remote. Defaults to creature@creax.de.
  --remote-dir DIR   Remote web directory. Defaults to /home/creature/html/apt/ironmesh.
  --url URL          Public repository URL printed at the end.
  --dry-run          Show the rsync changes without uploading.
  -h, --help         Show this help text.

Environment defaults:
  APT_REPO_DIR, APT_REPO_SUITE, APT_REPO_REMOTE, APT_REPO_REMOTE_DIR,
  APT_REPO_URL.
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

shell_quote() {
  local value="$1"
  printf "'%s'" "$(printf '%s' "${value}" | sed "s/'/'\\\\''/g")"
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
    --remote)
      REMOTE="$2"
      shift 2
      ;;
    --remote=*)
      REMOTE="${1#*=}"
      shift
      ;;
    --remote-dir)
      REMOTE_DIR="$2"
      shift 2
      ;;
    --remote-dir=*)
      REMOTE_DIR="${1#*=}"
      shift
      ;;
    --url)
      REMOTE_URL="$2"
      shift 2
      ;;
    --url=*)
      REMOTE_URL="${1#*=}"
      shift
      ;;
    --dry-run)
      DRY_RUN=true
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

require_command rsync
require_command sed
require_command ssh

if [[ ! -f "${REPO_DIR}/dists/${SUITE}/InRelease" ]]; then
  printf 'signed apt metadata not found: %s\n' "${REPO_DIR}/dists/${SUITE}/InRelease" >&2
  printf 'Run ./scripts/build-apt-repository.sh with a signing key first.\n' >&2
  exit 1
fi

RSYNC_ARGS=(-av --delete)
if [[ "${DRY_RUN}" == true ]]; then
  RSYNC_ARGS+=(--dry-run)
fi

log "ensuring ${REMOTE}:${REMOTE_DIR} exists"
ssh "${REMOTE}" "mkdir -p $(shell_quote "${REMOTE_DIR}")"

log "syncing ${REPO_DIR}/ to ${REMOTE}:${REMOTE_DIR}/"
rsync "${RSYNC_ARGS[@]}" \
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r \
  "${REPO_DIR%/}/" \
  "${REMOTE}:${REMOTE_DIR%/}/"

if [[ "${DRY_RUN}" == true ]]; then
  log "dry run complete"
else
  log "published ${REMOTE_URL%/}/"
fi
