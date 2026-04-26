# Recovery Runbook

Use this when startup fails or a node reports persistence/index/mempool coherence errors.

1. Stop node service.
2. Backup the state directory before modifying config.
3. Run status inventory:

```bash
homa-node validator status --config /etc/homa/node.toml
```

4. Select the least invasive mode:

- Strict: default. Use first for all recovery.
- Index repair: set `repair_index = true` only when finalized state/checkpoint is trusted and the index is corrupt or missing rows.
- Mempool ignore: set `ignore_mempool_checkpoint = true` only when mempool checkpoint ingestion fails and losing pending transactions is acceptable.
- Non-strict recovery: set `strict_recovery = false` only for controlled recovery drills or when an operator has confirmed the mismatch is non-consensus-critical.

5. Start node and watch startup logs for recovery counters:
   - `mempool_recovered`
   - `mempool_dropped_invalid`
   - `mempool_dropped_conflict`
   - `index_rebuild_performed`
   - `index_events_replayed`

6. Verify RPC status and finalized hash/height.
7. Revert temporary recovery flags after a successful recovery restart.
