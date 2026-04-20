# Backup and Restore Runbook

## Backup
1. Stop node or ensure quiescent window.
2. Archive state directory (`state.snapshot`, sync checkpoint, finalized checkpoint, mempool/index redb files).

## Restore
1. Stop node.
2. Replace state directory with backup files.
3. Start node and verify finalized height/hash via RPC.
