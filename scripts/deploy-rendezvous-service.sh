#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="rendezvous-service"
BINARY_NAME="ironmesh-rendezvous-service"
MANIFEST_PATH="${ROOT_DIR}/apps/rendezvous-service/Cargo.toml"

TARGET_TRIPLE="${IRONMESH_RENDEZVOUS_TARGET:-x86_64-unknown-linux-musl}"
REMOTE_DIR="${IRONMESH_RENDEZVOUS_REMOTE_DIR:-}"
REMOTE_BINARY="${IRONMESH_RENDEZVOUS_REMOTE_BINARY:-}"
REMOTE_WORKDIR="${IRONMESH_RENDEZVOUS_REMOTE_WORKDIR:-}"
REMOTE_PIDFILE="${IRONMESH_RENDEZVOUS_REMOTE_PIDFILE:-}"
REMOTE_LOGFILE="${IRONMESH_RENDEZVOUS_REMOTE_LOGFILE:-}"
REMOTE_START_CMD="${IRONMESH_RENDEZVOUS_REMOTE_START_CMD:-}"
REMOTE_MATCH_PATTERN="${IRONMESH_RENDEZVOUS_REMOTE_MATCH_PATTERN:-}"
STOP_TIMEOUT_SECS="${IRONMESH_RENDEZVOUS_STOP_TIMEOUT_SECS:-20}"
FORCE_KILL="${IRONMESH_RENDEZVOUS_FORCE_KILL:-true}"
AUTO_ADD_TARGET="${IRONMESH_RENDEZVOUS_AUTO_ADD_TARGET:-true}"

SKIP_BUILD=0
HOSTS_FILE=""
LOCAL_BINARY=""

declare -a REMOTES=()
declare -a SSH_OPTIONS=()
declare -a SCP_OPTIONS=()

usage() {
  cat <<'EOF'
Usage: scripts/deploy-rendezvous-service.sh [options] host1 [host2 ...]

Build the MUSL Linux release binary for the standalone rendezvous-service and
deploy it to each remote over SSH.

Required:
  --remote-dir PATH            Remote directory that holds the binary, pid file,
                               and log file.
  --remote-binary PATH         Full remote binary path. Use this instead of
                               --remote-dir when you need a custom location.

Useful options:
  --remote-workdir PATH        Directory to cd into before restart. Defaults to
                               the remote directory.
  --remote-pidfile PATH        Remote pid file. Defaults to
                               <remote-dir>/rendezvous-service.pid.
  --remote-logfile PATH        Remote log file. Defaults to
                               <remote-dir>/rendezvous-service.log.
  --remote-start-cmd CMD       Command to run on the remote host after upload.
                               Defaults to exec <remote-binary>.
  --remote-match-pattern TEXT  Fixed string used to find an already running
                               process when the pid file is missing. Defaults to
                               the remote binary path.
  --hosts-file PATH            Read remotes from file, one per line. Blank lines
                               and lines starting with # are ignored.
  --target TRIPLE              Rust target triple. Defaults to
                               x86_64-unknown-linux-musl.
  --stop-timeout SECS          Seconds to wait for a graceful stop before a
                               forced kill. Defaults to 20.
  --skip-build                 Reuse an existing local release binary.
  --ssh-option OPT             Extra ssh option token. Repeat as needed.
  --scp-option OPT             Extra scp option token. Repeat as needed.
  --help                       Show this help.

Environment overrides:
  IRONMESH_RENDEZVOUS_REMOTE_DIR
  IRONMESH_RENDEZVOUS_REMOTE_BINARY
  IRONMESH_RENDEZVOUS_REMOTE_WORKDIR
  IRONMESH_RENDEZVOUS_REMOTE_PIDFILE
  IRONMESH_RENDEZVOUS_REMOTE_LOGFILE
  IRONMESH_RENDEZVOUS_REMOTE_START_CMD
  IRONMESH_RENDEZVOUS_REMOTE_MATCH_PATTERN
  IRONMESH_RENDEZVOUS_STOP_TIMEOUT_SECS
  IRONMESH_RENDEZVOUS_FORCE_KILL=true|false
  IRONMESH_RENDEZVOUS_AUTO_ADD_TARGET=true|false
  IRONMESH_RENDEZVOUS_TARGET

Notes:
  The remote start command must launch the service in the foreground. This
  script handles the backgrounding with nohup itself.
  If you provide a custom --remote-start-cmd, make it end in exec <binary> so
  the pid file tracks the service process rather than a wrapper shell.

Example:
  scripts/deploy-rendezvous-service.sh \
    --remote-dir /srv/ironmesh/rendezvous \
    --remote-start-cmd 'source /etc/ironmesh/rendezvous.env && exec ./ironmesh-rendezvous-service' \
    rendezvous-a rendezvous-b
EOF
}

log() {
  printf '[deploy-rendezvous-service] %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

quote_for_sh() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

is_truthy() {
  case "${1,,}" in
    1|true|yes|y)
      return 0
      ;;
    0|false|no|n)
      return 1
      ;;
    *)
      fail "invalid boolean value: $1"
      ;;
  esac
}

require_command() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
}

load_hosts_file() {
  [[ -n "$HOSTS_FILE" ]] || return 0
  [[ -f "$HOSTS_FILE" ]] || fail "hosts file not found: $HOSTS_FILE"

  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(trim_whitespace "$line")"
    [[ -z "$line" ]] && continue
    REMOTES+=("$line")
  done <"$HOSTS_FILE"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --remote-dir)
        [[ $# -ge 2 ]] || fail "--remote-dir requires a value"
        REMOTE_DIR="$2"
        shift 2
        ;;
      --remote-dir=*)
        REMOTE_DIR="${1#*=}"
        shift
        ;;
      --remote-binary)
        [[ $# -ge 2 ]] || fail "--remote-binary requires a value"
        REMOTE_BINARY="$2"
        shift 2
        ;;
      --remote-binary=*)
        REMOTE_BINARY="${1#*=}"
        shift
        ;;
      --remote-workdir)
        [[ $# -ge 2 ]] || fail "--remote-workdir requires a value"
        REMOTE_WORKDIR="$2"
        shift 2
        ;;
      --remote-workdir=*)
        REMOTE_WORKDIR="${1#*=}"
        shift
        ;;
      --remote-pidfile)
        [[ $# -ge 2 ]] || fail "--remote-pidfile requires a value"
        REMOTE_PIDFILE="$2"
        shift 2
        ;;
      --remote-pidfile=*)
        REMOTE_PIDFILE="${1#*=}"
        shift
        ;;
      --remote-logfile)
        [[ $# -ge 2 ]] || fail "--remote-logfile requires a value"
        REMOTE_LOGFILE="$2"
        shift 2
        ;;
      --remote-logfile=*)
        REMOTE_LOGFILE="${1#*=}"
        shift
        ;;
      --remote-start-cmd)
        [[ $# -ge 2 ]] || fail "--remote-start-cmd requires a value"
        REMOTE_START_CMD="$2"
        shift 2
        ;;
      --remote-start-cmd=*)
        REMOTE_START_CMD="${1#*=}"
        shift
        ;;
      --remote-match-pattern)
        [[ $# -ge 2 ]] || fail "--remote-match-pattern requires a value"
        REMOTE_MATCH_PATTERN="$2"
        shift 2
        ;;
      --remote-match-pattern=*)
        REMOTE_MATCH_PATTERN="${1#*=}"
        shift
        ;;
      --hosts-file)
        [[ $# -ge 2 ]] || fail "--hosts-file requires a value"
        HOSTS_FILE="$2"
        shift 2
        ;;
      --hosts-file=*)
        HOSTS_FILE="${1#*=}"
        shift
        ;;
      --target)
        [[ $# -ge 2 ]] || fail "--target requires a value"
        TARGET_TRIPLE="$2"
        shift 2
        ;;
      --target=*)
        TARGET_TRIPLE="${1#*=}"
        shift
        ;;
      --stop-timeout)
        [[ $# -ge 2 ]] || fail "--stop-timeout requires a value"
        STOP_TIMEOUT_SECS="$2"
        shift 2
        ;;
      --stop-timeout=*)
        STOP_TIMEOUT_SECS="${1#*=}"
        shift
        ;;
      --ssh-option)
        [[ $# -ge 2 ]] || fail "--ssh-option requires a value"
        SSH_OPTIONS+=("$2")
        shift 2
        ;;
      --ssh-option=*)
        SSH_OPTIONS+=("${1#*=}")
        shift
        ;;
      --scp-option)
        [[ $# -ge 2 ]] || fail "--scp-option requires a value"
        SCP_OPTIONS+=("$2")
        shift 2
        ;;
      --scp-option=*)
        SCP_OPTIONS+=("${1#*=}")
        shift
        ;;
      --skip-build)
        SKIP_BUILD=1
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      --)
        shift
        while [[ $# -gt 0 ]]; do
          REMOTES+=("$1")
          shift
        done
        ;;
      -*)
        fail "unknown option: $1"
        ;;
      *)
        REMOTES+=("$1")
        shift
        ;;
    esac
  done
}

resolve_remote_layout() {
  if [[ -z "$REMOTE_BINARY" ]]; then
    [[ -n "$REMOTE_DIR" ]] || fail "set --remote-dir or --remote-binary"
    REMOTE_DIR="${REMOTE_DIR%/}"
    REMOTE_BINARY="${REMOTE_DIR}/${BINARY_NAME}"
  fi

  if [[ -z "$REMOTE_DIR" ]]; then
    REMOTE_DIR="$(dirname -- "$REMOTE_BINARY")"
  fi

  [[ "$STOP_TIMEOUT_SECS" =~ ^[0-9]+$ ]] || fail "--stop-timeout must be a non-negative integer"

  if [[ -z "$REMOTE_WORKDIR" ]]; then
    REMOTE_WORKDIR="$REMOTE_DIR"
  fi

  if [[ -z "$REMOTE_PIDFILE" ]]; then
    REMOTE_PIDFILE="${REMOTE_DIR}/${BINARY_NAME}.pid"
  fi

  if [[ -z "$REMOTE_LOGFILE" ]]; then
    REMOTE_LOGFILE="${REMOTE_DIR}/${BINARY_NAME}.log"
  fi

  if [[ -z "$REMOTE_START_CMD" ]]; then
    REMOTE_START_CMD="exec $(quote_for_sh "$REMOTE_BINARY")"
  fi

  if [[ -z "$REMOTE_MATCH_PATTERN" ]]; then
    REMOTE_MATCH_PATTERN="$REMOTE_BINARY"
  fi

  LOCAL_BINARY="${ROOT_DIR}/target/${TARGET_TRIPLE}/release/${BINARY_NAME}"
}

ensure_inputs() {
  [[ ${#REMOTES[@]} -gt 0 ]] || fail "provide at least one remote host or --hosts-file"
  require_command ssh
  require_command scp
}

ensure_target_installed() {
  if rustup target list --installed | grep -Fxq "$TARGET_TRIPLE"; then
    return 0
  fi

  if is_truthy "$AUTO_ADD_TARGET"; then
    log "installing rust target ${TARGET_TRIPLE}"
    rustup target add "$TARGET_TRIPLE"
    return 0
  fi

  fail "rust target ${TARGET_TRIPLE} is not installed"
}

build_binary() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    [[ -x "$LOCAL_BINARY" ]] || fail "local binary not found: $LOCAL_BINARY"
    log "reusing existing ${TARGET_TRIPLE} release binary"
    return 0
  fi

  require_command cargo
  require_command rustup
  ensure_target_installed
  log "building ${PACKAGE_NAME} for ${TARGET_TRIPLE}"
  cargo build --manifest-path "$MANIFEST_PATH" --release --target "$TARGET_TRIPLE"
  [[ -x "$LOCAL_BINARY" ]] || fail "build finished without producing $LOCAL_BINARY"
}

stop_remote_service() {
  local host="$1"
  local remote_dir_q remote_pidfile_q match_pattern_q stop_timeout_q force_kill_q

  remote_dir_q="$(quote_for_sh "$REMOTE_DIR")"
  remote_pidfile_q="$(quote_for_sh "$REMOTE_PIDFILE")"
  match_pattern_q="$(quote_for_sh "$REMOTE_MATCH_PATTERN")"
  stop_timeout_q="$(quote_for_sh "$STOP_TIMEOUT_SECS")"
  force_kill_q="$(quote_for_sh "$FORCE_KILL")"

  log "[$host] stopping existing service"
  ssh "${SSH_OPTIONS[@]}" "$host" \
    "REMOTE_DIR=${remote_dir_q} REMOTE_PIDFILE=${remote_pidfile_q} REMOTE_MATCH_PATTERN=${match_pattern_q} STOP_TIMEOUT_SECS=${stop_timeout_q} FORCE_KILL=${force_kill_q} bash -s" <<'REMOTE'
set -euo pipefail

mkdir -p "$REMOTE_DIR"

declare -A seen_pids=()
declare -a pids=()

record_pid() {
  local candidate="$1"
  [[ "$candidate" =~ ^[0-9]+$ ]] || return 0
  if [[ -z "${seen_pids[$candidate]+x}" ]]; then
    seen_pids["$candidate"]=1
    pids+=("$candidate")
  fi
}

if [[ -f "$REMOTE_PIDFILE" ]]; then
  pid="$(tr -d '[:space:]' <"$REMOTE_PIDFILE" || true)"
  record_pid "$pid"
fi

while IFS= read -r line; do
  [[ "$line" == *"$REMOTE_MATCH_PATTERN"* ]] || continue
  read -r pid _ <<<"$line"
  record_pid "$pid"
done < <(ps -eo pid=,args=)

if [[ ${#pids[@]} -eq 0 ]]; then
  rm -f "$REMOTE_PIDFILE"
  echo "service not running"
  exit 0
fi

for pid in "${pids[@]}"; do
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
  fi
done

deadline=$((SECONDS + STOP_TIMEOUT_SECS))
while :; do
  any_running=0
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" >/dev/null 2>&1; then
      any_running=1
      break
    fi
  done

  if [[ "$any_running" -eq 0 ]]; then
    rm -f "$REMOTE_PIDFILE"
    echo "service stopped"
    exit 0
  fi

  if (( SECONDS >= deadline )); then
    break
  fi

  sleep 1
done

case "${FORCE_KILL,,}" in
  1|true|yes|y)
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    done
    sleep 1
    ;;
  0|false|no|n)
    echo "service did not stop within ${STOP_TIMEOUT_SECS}s" >&2
    exit 1
    ;;
  *)
    echo "invalid FORCE_KILL=${FORCE_KILL}" >&2
    exit 1
    ;;
esac

for pid in "${pids[@]}"; do
  if kill -0 "$pid" >/dev/null 2>&1; then
    echo "process ${pid} refused to stop" >&2
    exit 1
  fi
done

rm -f "$REMOTE_PIDFILE"
echo "service killed after timeout"
REMOTE
}

upload_remote_binary() {
  local host="$1"
  local remote_dir_q remote_tmp remote_tmp_q remote_binary_q remote_target

  remote_tmp="${REMOTE_BINARY}.new.$$"
  remote_dir_q="$(quote_for_sh "$REMOTE_DIR")"
  remote_tmp_q="$(quote_for_sh "$remote_tmp")"
  remote_binary_q="$(quote_for_sh "$REMOTE_BINARY")"
  remote_target="${host}:${remote_tmp}"

  log "[$host] uploading ${BINARY_NAME}"
  ssh "${SSH_OPTIONS[@]}" "$host" \
    "REMOTE_DIR=${remote_dir_q} bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$REMOTE_DIR"
REMOTE

  scp "${SCP_OPTIONS[@]}" "$LOCAL_BINARY" "$remote_target"

  ssh "${SSH_OPTIONS[@]}" "$host" \
    "REMOTE_TMP=${remote_tmp_q} REMOTE_BINARY=${remote_binary_q} bash -s" <<'REMOTE'
set -euo pipefail
chmod 0755 "$REMOTE_TMP"
mv "$REMOTE_TMP" "$REMOTE_BINARY"
REMOTE
}

start_remote_service() {
  local host="$1"
  local remote_dir_q remote_workdir_q remote_pidfile_q remote_logfile_q remote_start_cmd_q

  remote_dir_q="$(quote_for_sh "$REMOTE_DIR")"
  remote_workdir_q="$(quote_for_sh "$REMOTE_WORKDIR")"
  remote_pidfile_q="$(quote_for_sh "$REMOTE_PIDFILE")"
  remote_logfile_q="$(quote_for_sh "$REMOTE_LOGFILE")"
  remote_start_cmd_q="$(quote_for_sh "$REMOTE_START_CMD")"

  log "[$host] starting updated service"
  ssh "${SSH_OPTIONS[@]}" "$host" \
    "REMOTE_DIR=${remote_dir_q} REMOTE_WORKDIR=${remote_workdir_q} REMOTE_PIDFILE=${remote_pidfile_q} REMOTE_LOGFILE=${remote_logfile_q} REMOTE_START_CMD=${remote_start_cmd_q} bash -s" <<'REMOTE'
set -euo pipefail

mkdir -p "$REMOTE_DIR"
mkdir -p "$(dirname "$REMOTE_PIDFILE")"
mkdir -p "$(dirname "$REMOTE_LOGFILE")"
cd "$REMOTE_WORKDIR"

if [[ -f "$REMOTE_PIDFILE" ]]; then
  pid="$(tr -d '[:space:]' <"$REMOTE_PIDFILE" || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    echo "pid file still points to running process ${pid}" >&2
    exit 1
  fi
  rm -f "$REMOTE_PIDFILE"
fi

nohup bash -lc "$REMOTE_START_CMD" >>"$REMOTE_LOGFILE" 2>&1 </dev/null &
pid="$!"
printf '%s\n' "$pid" >"$REMOTE_PIDFILE"

sleep 1
if ! kill -0 "$pid" >/dev/null 2>&1; then
  echo "service exited immediately; check $REMOTE_LOGFILE" >&2
  exit 1
fi

echo "service started pid=${pid}"
REMOTE
}

deploy_host() {
  local host="$1"
  stop_remote_service "$host"
  upload_remote_binary "$host"
  start_remote_service "$host"
}

main() {
  parse_args "$@"
  load_hosts_file
  ensure_inputs
  resolve_remote_layout
  build_binary

  for host in "${REMOTES[@]}"; do
    deploy_host "$host"
  done

  log "deployment completed for ${#REMOTES[@]} remote(s)"
}

main "$@"