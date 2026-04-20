# Recovery Runbook

1. Stop node service.
2. Backup state directory.
3. Select mode:
   - strict: default fail-closed.
   - index repair: set `repair_index = true`.
   - mempool ignore: set `ignore_mempool_checkpoint = true`.
4. Start node and verify recovery metrics/logs.
