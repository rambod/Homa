#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_DIR="${ROOT_DIR}/.homa-devnet"
MODE="${HOMA_DEVNET_MODE:-local}"
COMPOSE_FILE="${DEVNET_DIR}/docker-compose.yml"

node_key() {
  case "$1" in
    1) printf '0101010101010101010101010101010101010101010101010101010101010101' ;;
    2) printf '0202020202020202020202020202020202020202020202020202020202020202' ;;
    3) printf '0303030303030303030303030303030303030303030303030303030303030303' ;;
    *) return 1 ;;
  esac
}

node_rpc_port() {
  printf '%s' "$((8544 + "$1"))"
}

node_tcp_port() {
  printf '%s' "$((6990 + "$1" * 10))"
}

node_quic_port() {
  printf '%s' "$((6991 + "$1" * 10))"
}

write_node_config() {
  local node="$1"
  local node_dir="${DEVNET_DIR}/node-${node}"
  local rpc_port tcp_port quic_port bootstrap key
  rpc_port="$(node_rpc_port "${node}")"
  tcp_port="$(node_tcp_port "${node}")"
  quic_port="$(node_quic_port "${node}")"
  key="$(node_key "${node}")"
  mkdir -p "${node_dir}/state"

  if [[ "${node}" == "1" ]]; then
    bootstrap='[]'
  else
    bootstrap='["/ip4/127.0.0.1/tcp/7000"]'
  fi

  cat > "${node_dir}/node.toml" <<EOF
network = "devnet"
seed_domain = ""
fallback_bootstrap = ${bootstrap}
listen_multiaddrs = ["/ip4/0.0.0.0/tcp/${tcp_port}", "/ip4/0.0.0.0/udp/${quic_port}/quic-v1"]
listen = true
bootstrap = ${node_bootstrap:-false}
strict_bootstrap = false
min_pow_bits = 0
event_loop_tick_ms = 250
slot_duration_ms = 1000
max_block_transactions = 1024
max_pending_blocks = 512
mempool_checkpoint_interval_ms = 10000
index_max_retained_blocks = 100000
rpc_listen_addr = "127.0.0.1:${rpc_port}"
rpc_max_body_bytes = 262144
rpc_rate_limit_per_sec = 100
ws_max_subscriptions_per_conn = 32
strict_recovery = true
repair_index = false
ignore_mempool_checkpoint = false
sync_advertisement_interval_ms = 5000
snapshot_serve_cache_entries = 4
state_directory = "${node_dir}/state"
producer_secret_key_hex = "${key}"
EOF
}

write_docker_config() {
  local node="$1"
  local node_dir="${DEVNET_DIR}/docker/node-${node}"
  local rpc_port tcp_port quic_port bootstrap key
  rpc_port="$(node_rpc_port "${node}")"
  tcp_port="$(node_tcp_port "${node}")"
  quic_port="$(node_quic_port "${node}")"
  key="$(node_key "${node}")"
  mkdir -p "${node_dir}"

  if [[ "${node}" == "1" ]]; then
    bootstrap='[]'
  else
    bootstrap='["/dns4/homa-node-1/tcp/7000"]'
  fi

  cat > "${node_dir}/node.toml" <<EOF
network = "devnet"
seed_domain = ""
fallback_bootstrap = ${bootstrap}
listen_multiaddrs = ["/ip4/0.0.0.0/tcp/7000", "/ip4/0.0.0.0/udp/7001/quic-v1"]
listen = true
bootstrap = true
strict_bootstrap = false
min_pow_bits = 0
event_loop_tick_ms = 250
slot_duration_ms = 1000
max_block_transactions = 1024
max_pending_blocks = 512
mempool_checkpoint_interval_ms = 10000
index_max_retained_blocks = 100000
rpc_listen_addr = "0.0.0.0:8545"
rpc_max_body_bytes = 262144
rpc_rate_limit_per_sec = 100
ws_max_subscriptions_per_conn = 32
strict_recovery = true
repair_index = false
ignore_mempool_checkpoint = false
sync_advertisement_interval_ms = 5000
snapshot_serve_cache_entries = 4
state_directory = "/var/lib/homa"
producer_secret_key_hex = "${key}"
EOF

  printf '%s:%s:%s\n' "${rpc_port}" "${tcp_port}" "${quic_port}"
}

generate() {
  rm -rf "${DEVNET_DIR}"
  mkdir -p "${DEVNET_DIR}/docker"
  for node in 1 2 3; do
    if [[ "${node}" == "1" ]]; then
      node_bootstrap=false write_node_config "${node}"
    else
      node_bootstrap=true write_node_config "${node}"
    fi
  done

  {
    printf 'services:\n'
    for node in 1 2 3; do
      IFS=':' read -r rpc_port tcp_port quic_port < <(write_docker_config "${node}")
      cat <<EOF
  homa-node-${node}:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile
    container_name: homa-node-${node}
    volumes:
      - ./docker/node-${node}/node.toml:/etc/homa/node.toml:ro
      - homa-state-${node}:/var/lib/homa
    ports:
      - "${rpc_port}:8545"
      - "${tcp_port}:7000"
      - "${quic_port}:7001/udp"
EOF
    done
    printf 'volumes:\n'
    for node in 1 2 3; do
      printf '  homa-state-%s:\n' "${node}"
    done
  } > "${COMPOSE_FILE}"

  printf 'generated %s\n' "${DEVNET_DIR}"
}

local_up() {
  generate
  for node in 1 2 3; do
    local log="${DEVNET_DIR}/node-${node}/node.log"
    (
      cd "${ROOT_DIR}"
      cargo run --bin homa-node -- run --config "${DEVNET_DIR}/node-${node}/node.toml"
    >"${log}" 2>&1 &
      printf '%s\n' "$!" > "${DEVNET_DIR}/node-${node}/node.pid"
    )
  done
}

docker_up() {
  generate
  docker compose -f "${COMPOSE_FILE}" up -d --build
}

down() {
  if [[ -f "${COMPOSE_FILE}" ]]; then
    docker compose -f "${COMPOSE_FILE}" down --remove-orphans || true
  fi
  find "${DEVNET_DIR}" -name node.pid -print 2>/dev/null | while read -r pid_file; do
    kill "$(cat "${pid_file}")" 2>/dev/null || true
    rm -f "${pid_file}"
  done
}

status() {
  for node in 1 2 3; do
    local port
    port="$(node_rpc_port "${node}")"
    printf 'node-%s rpc: ' "${node}"
    curl -fsS "http://127.0.0.1:${port}/status" >/dev/null && printf 'ok\n' || printf 'down\n'
  done
}

logs() {
  if [[ "${MODE}" == "docker" ]]; then
    docker compose -f "${COMPOSE_FILE}" logs -f
    return
  fi
  tail -F "${DEVNET_DIR}"/node-*/node.log
}

smoke() {
  status
  for node in 1 2 3; do
    curl -fsS "http://127.0.0.1:$(node_rpc_port "${node}")/status" >/dev/null
  done
  printf 'devnet smoke passed\n'
}

case "${1:-}" in
  generate) generate ;;
  up)
    if [[ "${MODE}" == "docker" ]]; then docker_up; else local_up; fi
    ;;
  down) down ;;
  status) status ;;
  logs) logs ;;
  smoke) smoke ;;
  *)
    printf 'usage: %s generate|up|down|status|logs|smoke\n' "$0" >&2
    printf 'set HOMA_DEVNET_MODE=docker for Docker Compose mode\n' >&2
    exit 2
    ;;
esac
