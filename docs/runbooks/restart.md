# Restart Runbook

1. Announce maintenance window.
2. Restart service: `systemctl restart homa-node`.
3. Confirm lifecycle returns to `ready` via `homa_getStatus`.
4. Validate mempool/index recovery counters from startup logs.
