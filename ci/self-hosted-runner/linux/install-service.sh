#!/usr/bin/env bash
# Install and start the ephemeral runner as systemd *user* services.
# Prereqs (one-time, need root — see ../README.md "Bootstrap"):
#   - user is in the `docker` group (and has re-logged-in since)
#   - loginctl linger enabled for the user (already on for this host)
#   - `gh auth status` is green
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${ROOT_DIR}/config.env"
RUNNER_COUNT="${RUNNER_COUNT:-1}"
DOCKER_CMD="${DOCKER_CMD:-docker}"

# Sanity checks.
${DOCKER_CMD} info >/dev/null 2>&1 || { echo "ERROR: cannot talk to docker via '${DOCKER_CMD}'. See README Bootstrap (docker group or passwordless sudo)."; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "ERROR: gh is not authenticated."; exit 1; }

UNIT_DIR="${HOME}/.config/systemd/user"
mkdir -p "${UNIT_DIR}"
cp "${SCRIPT_DIR}/ironmesh-runner@.service" "${UNIT_DIR}/ironmesh-runner@.service"
systemctl --user daemon-reload

for i in $(seq 0 $((RUNNER_COUNT - 1))); do
    echo "Enabling ironmesh-runner@${i}.service"
    systemctl --user enable --now "ironmesh-runner@${i}.service"
done

echo
echo "Installed ${RUNNER_COUNT} runner slot(s). Status:"
systemctl --user --no-pager status 'ironmesh-runner@*' 2>/dev/null | head -n 40 || true
echo
echo "Verify registration:  gh api repos/${REPO}/actions/runners -q '.runners[].name'"
