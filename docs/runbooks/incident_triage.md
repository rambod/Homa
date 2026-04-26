# Incident Triage Runbook

## Capture

1. Save current RPC status:

```bash
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"homa_getStatus"}'
curl -s http://127.0.0.1:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"homa_getPeers"}'
```

2. Capture logs around the incident window.
3. Copy the current `node.toml` and state-directory file listing.

## Classify

- Networking: low/no peers, bootstrap failures, repeated dial or gossip failures.
- Consensus: inbound block rejection spikes, slot misses, unexpected proposer, equivocation, state-root mismatch.
- Sync: sync lag, repeated snapshot import failures, quarantine growth, timeout bursts.
- Storage/recovery: startup failure, missing/corrupt checkpoints, index mismatch, mempool recovery mismatch.
- RPC: rate limiting, body limit errors, slow responses, unavailable `/ws`.

## Mitigate

- Networking: verify fallback peers/DNS seed, firewall, and listen addresses before restart.
- Consensus: preserve logs and payload evidence before changing config.
- Sync: restart once with strict recovery. Do not delete checkpoints unless a backup exists.
- Index-only failure: set `repair_index = true` for one restart, then set it back to false.
- Mempool-only failure: set `ignore_mempool_checkpoint = true` for one restart, then set it back to false.

## Closeout

Record root cause, impact window, finalized height/hash before and after, mitigation used, and follow-up issue/roadmap item.
