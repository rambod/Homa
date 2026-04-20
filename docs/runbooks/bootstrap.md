# Bootstrap Runbook

1. Provision host, install Rust runtime artifacts, create `homa` user.
2. Copy binary to `/opt/homa/homa-node` and config to `/etc/homa/node.toml`.
3. Verify DNS seed/fallback peers and validator key configuration.
4. Start service: `systemctl enable --now homa-node`.
5. Validate RPC health: `curl -s localhost:8545 -d '{"jsonrpc":"2.0","id":1,"method":"homa_getStatus"}'`.
