# Bootstrap Runbook

## Host Setup

1. Provision host and create a dedicated `homa` user/group.
2. Install `homa-node` under `/opt/homa` or `/usr/local/bin`.
3. Create config and state directories:

```bash
install -o homa -g homa -m 0750 -d /etc/homa /var/lib/homa /var/log/homa
```

4. Copy `node.toml` to `/etc/homa/node.toml` and set `state_directory = "/var/lib/homa"`.
5. Configure `rpc_listen_addr`. Use `127.0.0.1:8545` for host-local RPC and `0.0.0.0:8545` only behind explicit firewall/reverse-proxy controls.
6. Configure either DNS seed or fallback bootstrap peers. Bootstrap validation fails if `bootstrap = true` and both are empty.
7. Add producer key only for a validator node with stake in the active validator set.

## Start

```bash
systemctl enable --now homa-node
systemctl status homa-node
```

## Validate

```bash
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"homa_getStatus"}'
```

Check:

- lifecycle is `ready` or `syncing`
- finalized height is non-decreasing
- peer list is non-empty after bootstrap
- logs do not show persistence, index, or mempool recovery failures

## Current Devnet Gap

The checked-in Docker compose file is a scaffold, not a complete production devnet. The roadmap tracks generated per-node configs, stable listen ports, container RPC bind addresses, bootstrap multiaddrs, and producer key generation as required follow-up work.
