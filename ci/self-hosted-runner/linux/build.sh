#!/usr/bin/env bash
# Build the ephemeral runner image for Linux/x86_64.
# Pins to the latest actions/runner release unless RUNNER_VERSION is given.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${ROOT_DIR}/config.env"
IMAGE="${IMAGE:-ironmesh-runner-linux:latest}"
DOCKER_CMD="${DOCKER_CMD:-docker}"

if [ -z "${RUNNER_VERSION:-}" ]; then
    echo "Resolving latest actions/runner release..."
    RUNNER_VERSION="$(gh api repos/actions/runner/releases/latest -q .tag_name | sed 's/^v//')"
fi
echo "Building ${IMAGE} with runner v${RUNNER_VERSION}"

${DOCKER_CMD} build \
    --build-arg RUNNER_VERSION="${RUNNER_VERSION}" \
    -t "${IMAGE}" \
    "${SCRIPT_DIR}"

echo "Done: ${IMAGE}"
