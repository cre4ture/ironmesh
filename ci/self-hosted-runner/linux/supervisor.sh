#!/usr/bin/env bash
# Host-side supervisor loop for one ephemeral runner slot.
#
# Each iteration:
#   1. mints a fresh, short-lived runner *registration token* using the local
#      `gh` auth (the powerful credential never leaves this host),
#   2. starts a disposable container that registers, runs a single job, exits,
#   3. loops, giving the next job a brand-new clean container.
#
# Usage: supervisor.sh [SLOT_INDEX]
# Reads config.env from the repo's ci/self-hosted-runner/ directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${ROOT_DIR}/config.env"

: "${REPO:?set REPO in config.env}"
: "${RUNNER_LABELS:?set RUNNER_LABELS in config.env}"
: "${IMAGE:?set IMAGE in config.env}"
BACKOFF_SECONDS="${BACKOFF_SECONDS:-10}"
DOCKER_CMD="${DOCKER_CMD:-docker}"

SLOT="${1:-0}"
REPO_URL="https://github.com/${REPO}"

log() { printf '[supervisor slot=%s] %s\n' "${SLOT}" "$*"; }

mint_token() {
    # Repo-scoped registration token, valid ~1h, single use at config time.
    gh api -X POST "repos/${REPO}/actions/runners/registration-token" -q .token
}

log "starting; repo=${REPO} image=${IMAGE}"
while true; do
    if ! TOKEN="$(mint_token)"; then
        log "failed to mint registration token; backing off ${BACKOFF_SECONDS}s"
        sleep "${BACKOFF_SECONDS}"
        continue
    fi

    NAME="ironmesh-$(hostname -s)-${SLOT}-$(date +%s)"
    CONTAINER="ironmesh-runner-${SLOT}"
    log "launching ephemeral runner ${NAME}"

    # --rm: dispose after the single job. No docker socket is mounted (jobs run
    # isolated inside the container, not on the host).
    ${DOCKER_CMD} run --rm \
        --name "${CONTAINER}" \
        --pull never \
        -e REPO_URL="${REPO_URL}" \
        -e RUNNER_TOKEN="${TOKEN}" \
        -e RUNNER_LABELS="${RUNNER_LABELS}" \
        -e RUNNER_NAME="${NAME}" \
        "${IMAGE}" || log "runner container exited non-zero (job failure or restart)"

    log "runner finished; recycling"
    sleep 1
done
