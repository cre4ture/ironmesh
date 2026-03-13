#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_DIR="${IRONMESH_LOCAL_CLUSTER_DIR:-${ROOT_DIR}/data/local-cluster}"
BASE_PORT="${IRONMESH_LOCAL_CLUSTER_BASE_PORT:-18080}"
PUBLIC_HOST="${IRONMESH_LOCAL_CLUSTER_PUBLIC_HOST:-127.0.0.1}"
PUBLIC_HOST_ALT_NAMES="${IRONMESH_LOCAL_CLUSTER_PUBLIC_HOST_ALT_NAMES:-}"
NODE_COUNT=4
BIN_PATH="${IRONMESH_SERVER_BIN:-${ROOT_DIR}/target/debug/server-node}"
CLIENT_AUTH_ENABLED="${IRONMESH_LOCAL_CLUSTER_ENABLE_CLIENT_AUTH:-true}"

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
  echo "0.0.0.0:$(node_port "$idx")"
}

node_internal_port() {
  local idx="$1"
  echo "$((BASE_PORT + 10000 + idx - 1))"
}

node_internal_bind() {
  local idx="$1"
  echo "127.0.0.1:$(node_internal_port "$idx")"
}

node_public_host() {
  echo "${PUBLIC_HOST}"
}

node_url() {
  local idx="$1"
  echo "https://$(node_public_host):$(node_port "$idx")"
}

node_internal_url() {
  local idx="$1"
  echo "https://$(node_internal_bind "$idx")"
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

shared_tls_dir() {
  echo "${CLUSTER_DIR}/tls"
}

admin_token_file() {
  echo "${CLUSTER_DIR}/admin-token"
}

ca_cert_file() {
  echo "$(shared_tls_dir)/ca.pem"
}

ca_key_file() {
  echo "$(shared_tls_dir)/ca.key"
}

ca_serial_file() {
  echo "$(shared_tls_dir)/ca.srl"
}

public_cert_file() {
  echo "$(shared_tls_dir)/public.pem"
}

public_key_file() {
  echo "$(shared_tls_dir)/public.key"
}

public_san_file() {
  echo "$(shared_tls_dir)/public-san.txt"
}

node_tls_dir() {
  local idx="$1"
  echo "$(data_dir "$idx")/tls"
}

node_cert_file() {
  local idx="$1"
  echo "$(node_tls_dir "$idx")/node.pem"
}

node_key_file() {
  local idx="$1"
  echo "$(node_tls_dir "$idx")/node.key"
}

admin_token() {
  if [[ -f "$(admin_token_file)" ]]; then
    tr -d '\r\n' <"$(admin_token_file)"
    return 0
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24 | tee "$(admin_token_file)" >/dev/null
  else
    local fallback
    fallback="ironmesh-local-admin-$(date +%s)"
    printf '%s\n' "${fallback}" | tee "$(admin_token_file)" >/dev/null
  fi
  chmod 600 "$(admin_token_file)" 2>/dev/null || true
  tr -d '\r\n' <"$(admin_token_file)"
}

ensure_binary() {
  if [[ -x "${BIN_PATH}" ]]; then
    if [[ "${ROOT_DIR}/Cargo.toml" -ot "${BIN_PATH}" ]] \
      && [[ "${ROOT_DIR}/Cargo.lock" -ot "${BIN_PATH}" ]] \
      && [[ -z "$(find "${ROOT_DIR}/apps" "${ROOT_DIR}/crates" -type f -newer "${BIN_PATH}" -print -quit 2>/dev/null)" ]]; then
      return 0
    fi
  fi

  echo "[local-cluster] Building fresh server-node binary..."
  (cd "${ROOT_DIR}" && cargo build -p server-node)
}

ensure_openssl() {
  if command -v openssl >/dev/null 2>&1; then
    return 0
  fi

  echo "[local-cluster] ERROR: openssl is required to generate internal mTLS certificates" >&2
  return 1
}

is_ip_literal() {
  local value="$1"
  [[ "${value}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

discover_ipv4_hosts() {
  if command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true
  fi

  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true
  fi
}

public_san_values() {
  {
    printf '%s\n' "localhost"
    printf '%s\n' "127.0.0.1"
    printf '%s\n' "$(node_public_host)"
    if [[ -n "${PUBLIC_HOST_ALT_NAMES}" ]]; then
      tr ',' '\n' <<<"${PUBLIC_HOST_ALT_NAMES}"
    fi
    discover_ipv4_hosts
  } | sed '/^$/d' | awk '!seen[$0]++'
}

public_san_entries() {
  while IFS= read -r value; do
    if is_ip_literal "${value}"; then
      printf 'IP:%s\n' "${value}"
    else
      printf 'DNS:%s\n' "${value}"
    fi
  done < <(public_san_values)
}

public_san_config() {
  public_san_entries | tr '\n' ',' | sed 's/,$//'
}

generate_ca() {
  local tls_root
  tls_root="$(shared_tls_dir)"
  mkdir -p "${tls_root}"

  echo "[local-cluster] Generating shared internal CA..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$(ca_key_file)" \
    -out "$(ca_cert_file)" \
    -days 3650 \
    -sha256 \
    -subj "/CN=ironmesh-local-cluster-ca" >/dev/null 2>&1
}

generate_public_cert() {
  local tls_root
  tls_root="$(shared_tls_dir)"
  mkdir -p "${tls_root}"

  local csr_path
  csr_path="${tls_root}/public.csr"

  local ext_path
  ext_path="${tls_root}/openssl-public.cnf"

  local san_line
  san_line="$(public_san_config)"

  cat >"${ext_path}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=${san_line}
EOF

  echo "[local-cluster] Generating shared public HTTPS certificate..."
  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$(public_key_file)" \
    -out "${csr_path}" \
    -subj "/CN=$(node_public_host)" >/dev/null 2>&1

  openssl x509 -req \
    -in "${csr_path}" \
    -CA "$(ca_cert_file)" \
    -CAkey "$(ca_key_file)" \
    -CAcreateserial \
    -CAserial "$(ca_serial_file)" \
    -out "$(public_cert_file)" \
    -days 3650 \
    -sha256 \
    -extfile "${ext_path}" >/dev/null 2>&1

  printf '%s\n' "${san_line}" >"$(public_san_file)"
  rm -f "${csr_path}" "${ext_path}"
}

generate_node_cert() {
  local idx="$1"
  local tls_dir
  tls_dir="$(node_tls_dir "$idx")"
  mkdir -p "${tls_dir}"

  local node_id
  node_id="${NODE_IDS[$((idx - 1))]}"

  local csr_path
  csr_path="${tls_dir}/node.csr"

  local ext_path
  ext_path="${tls_dir}/openssl-node.cnf"

  cat >"${ext_path}" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:${node_id}
EOF

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$(node_key_file "$idx")" \
    -out "${csr_path}" \
    -subj "/CN=ironmesh-node-${node_id}" >/dev/null 2>&1

  openssl x509 -req \
    -in "${csr_path}" \
    -CA "$(ca_cert_file)" \
    -CAkey "$(ca_key_file)" \
    -CAcreateserial \
    -CAserial "$(ca_serial_file)" \
    -out "$(node_cert_file "$idx")" \
    -days 3650 \
    -sha256 \
    -extfile "${ext_path}" >/dev/null 2>&1

  rm -f "${csr_path}" "${ext_path}"
}

ensure_tls_material() {
  ensure_openssl

  if [[ ! -f "$(ca_cert_file)" || ! -f "$(ca_key_file)" ]]; then
    generate_ca
  fi

  local expected_public_san
  expected_public_san="$(public_san_config)"
  if [[ ! -f "$(public_cert_file)" || ! -f "$(public_key_file)" || ! -f "$(public_san_file)" ]] \
    || [[ "$(tr -d '\r\n' <"$(public_san_file)")" != "${expected_public_san}" ]]; then
    generate_public_cert
  fi

  for idx in $(seq 1 "$NODE_COUNT"); do
    if [[ ! -f "$(node_cert_file "$idx")" || ! -f "$(node_key_file "$idx")" ]]; then
      echo "[local-cluster] Generating internal cert for node${idx}..."
      generate_node_cert "$idx"
    fi
  done
}

ensure_admin_token() {
  mkdir -p "${CLUSTER_DIR}"
  if [[ "${CLIENT_AUTH_ENABLED}" == "true" ]]; then
    admin_token >/dev/null
  fi
}

wait_for_health() {
  local url="$1"
  local retries=80
  for _ in $(seq 1 "$retries"); do
    if curl --cacert "$(ca_cert_file)" -fsS "${url}/health" >/dev/null 2>&1; then
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

  local target_internal_url
  target_internal_url="$(node_internal_url "$target_idx")"

  local payload
  payload=$(cat <<JSON
{
  "public_url": "${target_url}",
  "internal_url": "${target_internal_url}",
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

  curl --cacert "$(ca_cert_file)" -fsS -X PUT "${controller_url}/cluster/nodes/${target_id}" \
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

issue_pairing_token() {
  local label="${1:-local-device}"
  local expires_in_secs="${2:-3600}"
  local node_idx="${3:-1}"

  if [[ "${CLIENT_AUTH_ENABLED}" != "true" ]]; then
    echo "[local-cluster] client auth is disabled; no pairing token needed"
    return 0
  fi

  local controller_url
  controller_url="$(node_url "${node_idx}")"

  local payload
  payload=$(cat <<JSON
{
  "label": "${label}",
  "expires_in_secs": ${expires_in_secs}
}
JSON
)

  echo "[local-cluster] issuing pairing token via ${controller_url}"
  curl --cacert "$(ca_cert_file)" -fsS -X POST "${controller_url}/auth/pairing-tokens/issue" \
    -H "content-type: application/json" \
    -H "x-ironmesh-admin-token: $(admin_token)" \
    --data "${payload}"
  echo
}

issue_pairing_token_json() {
  local label="${1:-local-device}"
  local expires_in_secs="${2:-3600}"
  local node_idx="${3:-1}"

  if [[ "${CLIENT_AUTH_ENABLED}" != "true" ]]; then
    echo "[local-cluster] client auth is disabled; no pairing token needed" >&2
    return 1
  fi

  local controller_url
  controller_url="$(node_url "${node_idx}")"

  local payload
  payload=$(cat <<JSON
{
  "label": "${label}",
  "expires_in_secs": ${expires_in_secs}
}
JSON
)

  curl --cacert "$(ca_cert_file)" -fsS -X POST "${controller_url}/auth/pairing-tokens/issue" \
    -H "content-type: application/json" \
    -H "x-ironmesh-admin-token: $(admin_token)" \
    --data "${payload}"
}

bootstrap_bundle_json() {
  local label="${1:-local-device}"
  local expires_in_secs="${2:-3600}"
  local node_idx="${3:-1}"

  if [[ "${CLIENT_AUTH_ENABLED}" != "true" ]]; then
    echo "[local-cluster] client auth is disabled; no bootstrap bundle needed" >&2
    return 1
  fi

  local controller_url
  controller_url="$(node_url "${node_idx}")"

  local payload
  payload=$(cat <<JSON
{
  "label": "${label}",
  "expires_in_secs": ${expires_in_secs}
}
JSON
)

  curl --cacert "$(ca_cert_file)" -fsS -X POST "${controller_url}/auth/bootstrap-bundles/issue" \
    -H "content-type: application/json" \
    -H "x-ironmesh-admin-token: $(admin_token)" \
    --data "${payload}"
}

write_bootstrap_bundle() {
  local label="${1:-local-device}"
  local expires_in_secs="${2:-3600}"
  local node_idx="${3:-1}"
  local output_path="${4:-${CLUSTER_DIR}/bootstrap/${label}.json}"

  mkdir -p "$(dirname "${output_path}")"
  bootstrap_bundle_json "${label}" "${expires_in_secs}" "${node_idx}" >"${output_path}"
  echo "[local-cluster] wrote bootstrap bundle to ${output_path}"
}

print_client_auth_help() {
  if [[ "${CLIENT_AUTH_ENABLED}" != "true" ]]; then
    return 0
  fi

  echo "  client auth: enabled"
  echo "  admin token file: $(admin_token_file)"
  echo "  pairing token helper:"
  echo "    scripts/local-cluster.sh pairing-token [label] [expires_in_secs] [node_idx]"
  echo "  bootstrap bundle helper:"
  echo "    scripts/local-cluster.sh bootstrap [label] [expires_in_secs] [node_idx] [output_file]"
}

start_cluster() {
  mkdir -p "${CLUSTER_DIR}/pids" "${CLUSTER_DIR}/logs"
  ensure_binary
  ensure_tls_material
  ensure_admin_token

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

    local internal_bind
    internal_bind="$(node_internal_bind "$idx")"

    local internal_url
    internal_url="$(node_internal_url "$idx")"

    local node_id
    node_id="${NODE_IDS[$((idx - 1))]}"

    local ddir
    ddir="$(data_dir "$idx")"
    mkdir -p "${ddir}"

    local logfile
    logfile="$(log_file "$idx")"

    echo "[local-cluster] starting node${idx} on ${bind}"
    nohup env \
      IRONMESH_NODE_ID="${node_id}" \
      IRONMESH_SERVER_BIND="${bind}" \
      IRONMESH_PUBLIC_URL="${url}" \
      IRONMESH_PUBLIC_TLS_CERT="$(public_cert_file)" \
      IRONMESH_PUBLIC_TLS_KEY="$(public_key_file)" \
      IRONMESH_PUBLIC_TLS_CA_CERT="$(ca_cert_file)" \
      IRONMESH_INTERNAL_BIND="${internal_bind}" \
      IRONMESH_INTERNAL_URL="${internal_url}" \
      IRONMESH_INTERNAL_TLS_CA_CERT="$(ca_cert_file)" \
      IRONMESH_INTERNAL_TLS_CERT="$(node_cert_file "$idx")" \
      IRONMESH_INTERNAL_TLS_KEY="$(node_key_file "$idx")" \
      IRONMESH_DATA_DIR="${ddir}" \
      IRONMESH_REPLICATION_FACTOR=3 \
      IRONMESH_REQUIRE_CLIENT_AUTH="${CLIENT_AUTH_ENABLED}" \
      IRONMESH_ADMIN_TOKEN="$(admin_token)" \
      "${BIN_PATH}" >"${logfile}" 2>&1 </dev/null &

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

    local internal_bind
    internal_bind="$(node_internal_bind "$idx")"

    local health="down"
    if curl --cacert "$(ca_cert_file)" -fsS "$(node_url "$idx")/health" >/dev/null 2>&1; then
      health="up"
    fi

    if [[ -f "${pid_path}" ]]; then
      local pid
      pid="$(cat "${pid_path}")"
      if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
        echo "  node${idx}: pid=${pid} public=${bind} internal=${internal_bind} health=${health} data=$(data_dir "$idx")"
      else
        echo "  node${idx}: stale pid file public=${bind} internal=${internal_bind} health=${health}"
      fi
    else
      echo "  node${idx}: not running public=${bind} internal=${internal_bind} health=${health}"
    fi
  done

  echo "  logs: ${CLUSTER_DIR}/logs"
  echo "  tls: $(shared_tls_dir)"
  echo "  public ca cert: $(ca_cert_file)"
  echo "  public host: $(node_public_host)"
  print_client_auth_help
}

clean_cluster() {
  stop_cluster
  rm -rf "${CLUSTER_DIR}"
  echo "[local-cluster] removed ${CLUSTER_DIR}"
}

usage() {
  cat <<EOF
Usage: scripts/local-cluster.sh <start|stop|restart|status|clean>

Extra commands:
  pairing-token [label] [expires_in_secs] [node_idx]
  bootstrap [label] [expires_in_secs] [node_idx] [output_file]

Environment variables:
  IRONMESH_LOCAL_CLUSTER_DIR        Default: ${ROOT_DIR}/data/local-cluster
  IRONMESH_LOCAL_CLUSTER_BASE_PORT  Default: 18080
  IRONMESH_LOCAL_CLUSTER_PUBLIC_HOST  Default: 127.0.0.1
  IRONMESH_LOCAL_CLUSTER_PUBLIC_HOST_ALT_NAMES  Optional comma-separated extra DNS/IP SANs
  IRONMESH_SERVER_BIN               Default: ${ROOT_DIR}/target/debug/server-node
  IRONMESH_LOCAL_CLUSTER_ENABLE_CLIENT_AUTH  Default: true

Requirements:
  openssl                         Used to generate local TLS certificates
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
    pairing-token)
      issue_pairing_token "${2:-local-device}" "${3:-3600}" "${4:-1}"
      ;;
    bootstrap)
      write_bootstrap_bundle "${2:-local-device}" "${3:-3600}" "${4:-1}" "${5:-}"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
