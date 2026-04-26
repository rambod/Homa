# Restart Runbook

1. Announce maintenance window.
2. Capture pre-restart status:

```bash
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"homa_getStatus"}'
```

3. Restart service:

```bash
systemctl restart homa-node
```

4. Confirm lifecycle returns to `ready` or expected `syncing` state via `homa_getStatus`.
5. Validate startup logs show persistence recovery counters and no strict recovery failures.
6. Confirm finalized height is non-decreasing compared with pre-restart status.
7. Confirm peer count and RPC responsiveness recover.

Rollback is to stop the node and follow `backup_restore.md` if restart exposes state corruption.
