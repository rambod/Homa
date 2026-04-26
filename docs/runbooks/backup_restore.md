# Backup and Restore Runbook

Use this runbook for a node with `state_directory` configured.

Canonical state files:

- `chain_state.snapshot`
- `chain_state.wal`
- `finalized_block.checkpoint`
- `sync_session.checkpoint`
- `mempool.checkpoint.redb`
- `finalized_index.redb`
- `validator.key.hex` if local key rotation tooling was used
- `checkpoint_rotation.submit.json` if a pending checkpoint-rotation artifact exists

## Backup

1. Prefer a clean stop: `systemctl stop homa-node`.
2. Verify the process exited and no writer is holding the state directory.
3. Archive the entire configured state directory:

```bash
tar -C /var/lib -czf homa-state-$(date +%Y%m%d%H%M%S).tar.gz homa
```

4. Record the latest status before/after backup when RPC is available:

```bash
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"homa_getStatus"}'
```

5. Restart the node if this was a planned online backup window: `systemctl start homa-node`.

## Restore

1. Stop node.
2. Move the current state directory aside before copying backup data back into place.
3. Restore the archive to the configured state directory owner/group.
4. Start with default strict recovery first.
5. Verify startup logs show coherent recovery and no finalized/index mismatch.
6. Verify finalized height/hash via RPC.

If strict recovery fails because the finalized index is corrupt but state/checkpoint files are trusted, retry once with `repair_index = true`. If mempool checkpoint recovery is the only failure, retry once with `ignore_mempool_checkpoint = true`.
