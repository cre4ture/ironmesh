#!/usr/bin/env bash
# Stop and remove the ephemeral runner user services and any leftover
# containers. Ephemeral runners deregister themselves from GitHub on exit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=/dev/null
source "${ROOT_DIR}/config.env"
RUNNER_COUNT="${RUNNER_COUNT:-1}"

for i in $(seq 0 $((RUNNER_COUNT - 1))); do
    systemctl --user disable --now "ironmesh-runner@${i}.service" 2>/dev/null || true
    docker rm -f "ironmesh-runner-${i}" 2>/dev/null || true
done

rm -f "${HOME}/.config/systemd/user/ironmesh-runner@.service"
systemctl --user daemon-reload
echo "Removed runner services. Check GitHub for stragglers:"
echo "  gh api repos/${REPO}/actions/runners -q '.runners[].name'"
