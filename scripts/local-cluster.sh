#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_DIR="${IRONMESH_LOCAL_CLUSTER_DIR:-${ROOT_DIR}/data/local-cluster}"
BASE_PORT="${IRONMESH_LOCAL_CLUSTER_BASE_PORT:-18080}"
NODE_COUNT=4
BIN_PATH="${IRONMESH_SERVER_BIN:-${ROOT_DIR}/target/debug/server-node}"

NODE_IDS=(
  "00000000-0000-0000-0000-00000000a001"
  "00000000-0000-0000-0000-00000000a002"
  "00000000-0000-0000-0000-00000000a003"
  "00000000-0000-0000-0000-00000000a004"
)

node_port() {
  local idx="$1"
  echo "$((BASE_PORT + idx - 1))"
}

node_bind() {
  local idx="$1"
  echo "127.0.0.1:$(node_port "$idx")"
}

node_url() {
  local idx="$1"
  echo "http://$(node_bind "$idx")"
}

pid_file() {
  local idx="$1"
  echo "${CLUSTER_DIR}/pids/node${idx}.pid"
}

log_file() {
  local idx="$1"
  echo "${CLUSTER_DIR}/logs/node${idx}.log"
}

data_dir() {
  local idx="$1"
  echo "${CLUSTER_DIR}/node${idx}"
}

ensure_binary() {
  if [[ -x "${BIN_PATH}" ]]; then
    return 0
  fi

  echo "[local-cluster] Building server-node binary..."
  (cd "${ROOT_DIR}" && cargo build -p server-node)
}

wait_for_health() {
  local url="$1"
  local retries=80
  for _ in $(seq 1 "$retries"); do
    if curl -fsS "${url}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  echo "[local-cluster] ERROR: timed out waiting for ${url}/health" >&2
  return 1
}

register_node() {
  local controller_idx="$1"
  local target_idx="$2"

  local controller_url
  controller_url="$(node_url "$controller_idx")"

  local target_id
  target_id="${NODE_IDS[$((target_idx - 1))]}"

  local target_url
  target_url="$(node_url "$target_idx")"

  local payload
  payload=$(cat <<JSON
{
  "public_url": "${target_url}",
  "labels": {
    "region": "local",
    "dc": "local-dc",
    "rack": "rack-${target_idx}"
  },
  "capacity_bytes": 1000000000,
  "free_bytes": 800000000
}
JSON
)

  curl -fsS -X PUT "${controller_url}/cluster/nodes/${target_id}" \
    -H "content-type: application/json" \
    --data "${payload}" >/dev/null
}

register_full_mesh() {
  echo "[local-cluster] Registering all nodes on every node..."
  for controller_idx in $(seq 1 "$NODE_COUNT"); do
    for target_idx in $(seq 1 "$NODE_COUNT"); do
      register_node "$controller_idx" "$target_idx"
    done
  done
}

start_cluster() {
  mkdir -p "${CLUSTER_DIR}/pids" "${CLUSTER_DIR}/logs"
  ensure_binary

  for idx in $(seq 1 "$NODE_COUNT"); do
    local pid_path
    pid_path="$(pid_file "$idx")"

    if [[ -f "${pid_path}" ]]; then
      local existing_pid
      existing_pid="$(cat "${pid_path}")"
      if [[ -n "${existing_pid}" ]] && kill -0 "${existing_pid}" >/dev/null 2>&1; then
        echo "[local-cluster] node${idx} already running with pid ${existing_pid}"
        continue
      fi
      rm -f "${pid_path}"
    fi

    local bind
    bind="$(node_bind "$idx")"

    local url
    url="$(node_url "$idx")"

    local node_id
    node_id="${NODE_IDS[$((idx - 1))]}"

    local ddir
    ddir="$(data_dir "$idx")"
    mkdir -p "${ddir}"

    local logfile
    logfile="$(log_file "$idx")"

    echo "[local-cluster] starting node${idx} on ${bind}"
    IRONMESH_NODE_ID="${node_id}" \
    IRONMESH_SERVER_BIND="${bind}" \
    IRONMESH_PUBLIC_URL="${url}" \
    IRONMESH_DATA_DIR="${ddir}" \
    IRONMESH_REPLICATION_FACTOR=3 \
    "${BIN_PATH}" >"${logfile}" 2>&1 &

    echo "$!" >"${pid_path}"
  done

  for idx in $(seq 1 "$NODE_COUNT"); do
    wait_for_health "$(node_url "$idx")"
  done

  register_full_mesh

  echo "[local-cluster] Cluster is up."
  status_cluster
}

stop_cluster() {
  local had_any=0
  for idx in $(seq 1 "$NODE_COUNT"); do
    local pid_path
    pid_path="$(pid_file "$idx")"

    if [[ ! -f "${pid_path}" ]]; then
      continue
    fi

    had_any=1
    local pid
    pid="$(cat "${pid_path}")"

    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      echo "[local-cluster] stopping node${idx} pid=${pid}"
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" 2>/dev/null || true
    fi

    rm -f "${pid_path}"
  done

  if [[ "${had_any}" -eq 0 ]]; then
    echo "[local-cluster] no running nodes found"
  fi
}

status_cluster() {
  echo "[local-cluster] status"
  for idx in $(seq 1 "$NODE_COUNT"); do
    local pid_path
    pid_path="$(pid_file "$idx")"

    local bind
    bind="$(node_bind "$idx")"

    local health="down"
    if curl -fsS "$(node_url "$idx")/health" >/dev/null 2>&1; then
      health="up"
    fi

    if [[ -f "${pid_path}" ]]; then
      local pid
      pid="$(cat "${pid_path}")"
      if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
        echo "  node${idx}: pid=${pid} bind=${bind} health=${health} data=$(data_dir "$idx")"
      else
        echo "  node${idx}: stale pid file bind=${bind} health=${health}"
      fi
    else
      echo "  node${idx}: not running bind=${bind} health=${health}"
    fi
  done

  echo "  logs: ${CLUSTER_DIR}/logs"
}

clean_cluster() {
  stop_cluster
  rm -rf "${CLUSTER_DIR}"
  echo "[local-cluster] removed ${CLUSTER_DIR}"
}

usage() {
  cat <<EOF
Usage: scripts/local-cluster.sh <start|stop|restart|status|clean>

Environment variables:
  IRONMESH_LOCAL_CLUSTER_DIR        Default: ${ROOT_DIR}/data/local-cluster
  IRONMESH_LOCAL_CLUSTER_BASE_PORT  Default: 18080
  IRONMESH_SERVER_BIN               Default: ${ROOT_DIR}/target/debug/server-node
EOF
}

main() {
  local cmd="${1:-start}"

  case "${cmd}" in
    start)
      start_cluster
      ;;
    stop)
      stop_cluster
      ;;
    restart)
      stop_cluster
      start_cluster
      ;;
    status)
      status_cluster
      ;;
    clean)
      clean_cluster
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
