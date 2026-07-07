#!/usr/bin/env bash

set -euo pipefail

NODE_A_NAME="node-a"
NODE_B_NAME="node-b"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$REPO_ROOT/data/manual-relay-test"
NODE_A_BIND="0.0.0.0:18481"
NODE_B_BIND="0.0.0.0:18482"
NODE_A_URL="https://127.0.0.1:18481"
NODE_B_URL="https://127.0.0.1:18482"
ADMIN_PASSWORD="correct horse battery staple"
SERVER_NODE_BUILT=0
SCREEN_STOP_WAIT_ATTEMPTS=50
SCREEN_STOP_WAIT_INTERVAL_SECONDS=0.1
MEMORY_MAX=""
MEMORY_HIGH=""

usage() {
  cat <<EOF
Usage:
  $0 [start|stop|restart] [--memory-max=SIZE] [--memory-high=SIZE] {$NODE_A_NAME|$NODE_B_NAME}...
  $0 {$NODE_A_NAME|$NODE_B_NAME}...

Examples:
  $0 $NODE_A_NAME
  $0 $NODE_A_NAME $NODE_B_NAME
  $0 start $NODE_B_NAME
  $0 stop $NODE_A_NAME
  $0 restart $NODE_A_NAME $NODE_B_NAME
  $0 start --memory-max=500M $NODE_A_NAME
  $0 start --memory-max=500M --memory-high=400M $NODE_A_NAME

Actions are applied sequentially in the order provided.

--memory-max=SIZE sets a hard memory cap (RSS+cache); the node is OOM-killed
if it's exceeded and reclaim can't bring usage back down.
--memory-high=SIZE sets a soft cap that triggers throttling and proactive
reclaim before --memory-max is reached. Defaults to --memory-max's value if
only --memory-max is given.
Both accept systemd size syntax (e.g. 500M, 1G) and are applied via a
systemd --user scope. Only apply to start/restart.
EOF
}

require_screen() {
  if ! command -v screen >/dev/null 2>&1; then
    echo "screen is required but was not found in PATH" >&2
    exit 1
  fi
}

require_systemd_run() {
  if ! command -v systemd-run >/dev/null 2>&1; then
    echo "--memory-max/--memory-high require systemd-run, which was not found in PATH" >&2
    exit 1
  fi
}

ensure_server_node_built() {
  if [[ "$SERVER_NODE_BUILT" -eq 1 ]]; then
    return 0
  fi

  (cd "$REPO_ROOT" && cargo build --release -p server-node)
  SERVER_NODE_BUILT=1
}

validate_node_name() {
  case "$1" in
    "$NODE_A_NAME"|"$NODE_B_NAME")
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

bind_for_node() {
  case "$1" in
    "$NODE_A_NAME")
      printf '%s' "$NODE_A_BIND"
      ;;
    "$NODE_B_NAME")
      printf '%s' "$NODE_B_BIND"
      ;;
  esac
}

url_for_node() {
  case "$1" in
    "$NODE_A_NAME")
      printf '%s' "$NODE_A_URL"
      ;;
    "$NODE_B_NAME")
      printf '%s' "$NODE_B_URL"
      ;;
  esac
}

data_dir_for_node() {
  printf '%s' "$ROOT/$1"
}

log_file_for_node() {
  printf '%s' "$ROOT/$1.screen.log"
}

session_name_for_node() {
  printf 'ironmesh-%s' "$1"
}

screen_session_exists() {
  local session_name="$1"

  screen -wipe >/dev/null 2>&1 || true
  screen -list | grep -Eq "[[:space:]]*[0-9]+\\.${session_name}[[:space:]]"
}

wait_for_screen_session_exit() {
  local session_name="$1"
  local attempt

  for ((attempt = 0; attempt < SCREEN_STOP_WAIT_ATTEMPTS; attempt++)); do
    if ! screen_session_exists "$session_name"; then
      return 0
    fi

    sleep "$SCREEN_STOP_WAIT_INTERVAL_SECONDS"
  done

  return 1
}

start_node() {
  local node_name="$1"
  local session_name bind_addr url data_dir log_file start_command

  require_screen
  mkdir -p "$ROOT"

  session_name="$(session_name_for_node "$node_name")"
  bind_addr="$(bind_for_node "$node_name")"
  url="$(url_for_node "$node_name")"
  data_dir="$(data_dir_for_node "$node_name")"
  log_file="$(log_file_for_node "$node_name")"

  if screen_session_exists "$session_name"; then
    echo "$node_name is already running in screen session $session_name"
    echo "Attach: screen -r $session_name"
    return 0
  fi

  # build the server-node binary once before the first node start in this invocation
  ensure_server_node_built

  mkdir -p "$data_dir"

  local run_command
  run_command="cargo run --release -p server-node"
  if [[ -n "$MEMORY_MAX" || -n "$MEMORY_HIGH" ]]; then
    require_systemd_run

    local systemd_run_args=(--user --scope --quiet --collect)
    if [[ -n "$MEMORY_MAX" ]]; then
      systemd_run_args+=(-p "MemoryMax=$MEMORY_MAX")
    fi
    if [[ -n "$MEMORY_HIGH" ]]; then
      systemd_run_args+=(-p "MemoryHigh=$MEMORY_HIGH")
    elif [[ -n "$MEMORY_MAX" ]]; then
      systemd_run_args+=(-p "MemoryHigh=$MEMORY_MAX")
    fi

    local systemd_run_args_quoted
    printf -v systemd_run_args_quoted '%q ' "${systemd_run_args[@]}"
    printf -v run_command \
      'systemd-run %s-- %s' \
      "$systemd_run_args_quoted" "$run_command"
  fi

  printf -v start_command \
    'ulimit -n 1024 && cd %q && export IRONMESH_DATA_DIR=%q IRONMESH_SERVER_BIND=%q && %s' \
    "$REPO_ROOT" "$data_dir" "$bind_addr" "$run_command"

  screen -L -Logfile "$log_file" -DdmS "$session_name" bash -lc "$start_command"

  echo "Started $node_name in screen session $session_name"
  echo "URL: $url"
  echo "Data dir: $data_dir"
  echo "Log file: $log_file"
  if [[ -n "$MEMORY_MAX" ]]; then
    echo "Memory max: $MEMORY_MAX"
  fi
  if [[ -n "$MEMORY_HIGH" ]]; then
    echo "Memory high: $MEMORY_HIGH"
  elif [[ -n "$MEMORY_MAX" ]]; then
    echo "Memory high: $MEMORY_MAX (defaulted to memory max)"
  fi
  echo "Attach: screen -r $session_name"
  echo "Stop:   $0 stop $node_name"
  echo "Admin password: $ADMIN_PASSWORD"
}

stop_node() {
  local node_name="$1"
  local session_name

  require_screen
  session_name="$(session_name_for_node "$node_name")"

  if ! screen_session_exists "$session_name"; then
    echo "$node_name is not running in screen session $session_name"
    return 0
  fi

  screen -S "$session_name" -X quit

  if ! wait_for_screen_session_exit "$session_name"; then
    echo "Timed out waiting for $node_name to stop ($session_name)" >&2
    return 1
  fi

  echo "Stopped $node_name ($session_name)"
}

restart_node() {
  local node_name="$1"

  stop_node "$node_name"
  start_node "$node_name"
}

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

ACTION="start"

case "$1" in
  start|stop|restart)
    ACTION="$1"
    shift
    ;;
esac

ARGS=()
for arg in "$@"; do
  case "$arg" in
    --memory-max=*)
      MEMORY_MAX="${arg#--memory-max=}"
      ;;
    --memory-high=*)
      MEMORY_HIGH="${arg#--memory-high=}"
      ;;
    *)
      ARGS+=("$arg")
      ;;
  esac
done
set -- "${ARGS[@]}"

if [[ $# -lt 1 ]]; then
  usage >&2
  exit 1
fi

NODE_NAMES=("$@")

for node_name in "${NODE_NAMES[@]}"; do
  validate_node_name "$node_name"
done

for index in "${!NODE_NAMES[@]}"; do
  node_name="${NODE_NAMES[$index]}"

  if (( ${#NODE_NAMES[@]} > 1 )); then
    echo "[$((index + 1))/${#NODE_NAMES[@]}] $ACTION $node_name"
  fi

  case "$ACTION" in
    start)
      start_node "$node_name"
      ;;
    stop)
      stop_node "$node_name"
      ;;
    restart)
      restart_node "$node_name"
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
done
