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

usage() {
  cat <<EOF
Usage:
  $0 [start|stop|restart] {$NODE_A_NAME|$NODE_B_NAME}
  $0 {$NODE_A_NAME|$NODE_B_NAME}

Examples:
  $0 $NODE_A_NAME
  $0 start $NODE_B_NAME
  $0 stop $NODE_A_NAME
  $0 restart $NODE_B_NAME
EOF
}

require_screen() {
  if ! command -v screen >/dev/null 2>&1; then
    echo "screen is required but was not found in PATH" >&2
    exit 1
  fi
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

  # build the server-node binary to ensure it's available before starting the screen session
  (cd "$REPO_ROOT" && cargo build -p server-node)

  mkdir -p "$data_dir"
  printf -v start_command \
    'cd %q && export IRONMESH_DATA_DIR=%q IRONMESH_SERVER_BIND=%q && cargo run -p server-node' \
    "$REPO_ROOT" "$data_dir" "$bind_addr"

  screen -L -Logfile "$log_file" -DdmS "$session_name" bash -lc "$start_command"

  echo "Started $node_name in screen session $session_name"
  echo "URL: $url"
  echo "Data dir: $data_dir"
  echo "Log file: $log_file"
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
  echo "Stopped $node_name ($session_name)"
}

restart_node() {
  local node_name="$1"

  stop_node "$node_name"
  start_node "$node_name"
}

if [[ $# -eq 1 ]]; then
  ACTION="start"
  NODE_NAME="$1"
elif [[ $# -eq 2 ]]; then
  ACTION="$1"
  NODE_NAME="$2"
else
  usage >&2
  exit 1
fi

validate_node_name "$NODE_NAME"

case "$ACTION" in
  start)
    start_node "$NODE_NAME"
    ;;
  stop)
    stop_node "$NODE_NAME"
    ;;
  restart)
    restart_node "$NODE_NAME"
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac