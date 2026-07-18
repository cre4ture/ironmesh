#!/usr/bin/env bash
# Container entrypoint: register one ephemeral runner, run exactly one job,
# then exit so the host supervisor can dispose the container and start a fresh
# one. This is what makes each job land in a clean environment.
#
# Required env:
#   REPO_URL       e.g. https://github.com/cre4ture/ironmesh
#   RUNNER_TOKEN   short-lived registration token (minted on the host)
#   RUNNER_LABELS  comma-separated labels, e.g. self-hosted,Linux,X64,ironmesh-linux
#   RUNNER_NAME    unique name for this ephemeral instance
set -euo pipefail

: "${REPO_URL:?REPO_URL is required}"
: "${RUNNER_TOKEN:?RUNNER_TOKEN is required}"
: "${RUNNER_LABELS:?RUNNER_LABELS is required}"
: "${RUNNER_NAME:?RUNNER_NAME is required}"

cd /opt/actions-runner

# Best-effort deregistration if we are stopped before/after picking up a job.
cleanup() {
    ./config.sh remove --token "${RUNNER_TOKEN}" >/dev/null 2>&1 || true
}
trap 'cleanup; exit 130' INT TERM

./config.sh \
    --unattended \
    --url "${REPO_URL}" \
    --token "${RUNNER_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --labels "${RUNNER_LABELS}" \
    --work "_work" \
    --ephemeral \
    --replace \
    --disableupdate

# --ephemeral makes run.sh exit after a single job; ephemeral runners are also
# auto-removed from the repo by GitHub, so no explicit cleanup is needed here.
exec ./run.sh
