# Homa Project Roadmap

**Audit date:** 2026-04-25
**Status:** active pre-alpha, protocol/runtime feature complete in many local paths, not production-ready.

This file is the short current roadmap. `../Homa_Architecture_and_Implementation_Plan.md` remains the long-form phase history and detailed task tracker.

## Current Capability Audit

| Area | Current state | Evidence |
| --- | --- | --- |
| Crypto and addressing | Implemented: Ed25519 keys, network-domain addresses, checksum parsing, signature verification. | `src/crypto/` |
| Transactions | Implemented: signed transfer model, sender public-key authority binding, network-domain signing, bounded decode. | `src/core/transaction.rs` |
| Ledger state | Implemented: account balances/nonces, max supply cap, fee redistribution, deterministic state root. | `src/core/state.rs` |
| Blocks | Implemented: block/header model, transaction root, proposer proof validation, bounded decode. | `src/core/block.rs` |
| Mempool | Implemented: PoW admission, fee/PoW priority, TTL pruning, sender/peer throttles, durable checkpoint recovery. | `src/core/mempool.rs`, `src/core/mempool_checkpoint.rs` |
| Fast sync primitives | Implemented: snapshots, chunking, checkpoint verification, anti-rollback import, runtime assembly/quarantine. | `src/core/sync.rs`, `src/network/sync_runtime.rs` |
| P2P boundary | Implemented: libp2p swarm setup, gossipsub topics, Kademlia bootstrap helpers, sync wire codecs. | `src/network/p2p.rs` |
| Reputation and runtime policy | Implemented: peer scoring, adaptive serve/dial penalties, checkpoint trust-set rotation. | `src/network/reputation.rs`, `src/network/runtime_policy.rs`, `src/network/checkpoint_rotation.rs` |
| Node daemon | Implemented: lifecycle states, pending block finalization, local block production, restart recovery, persistence flush, swarm polling. | `src/node/daemon.rs` |
| RPC/WS | Implemented: JSON-RPC server, request limits, status/block/balance/tx/mempool/peer methods, WS subscriptions. | `src/node/rpc.rs` |
| Persistent indexer | Implemented: finalized block event log, transaction/block/address indexes, rebuild and retention compaction. | `src/core/indexer.rs` |
| Wallet CLI | Implemented: encrypted wallet, nonce state, local PoW, signed tx broadcast over gossipsub. | `src/wallet/cli.rs` |
| Tests and fuzzing | Implemented: unit tests, chaos integration tests, partition chaos fuzzer, three cargo-fuzz targets. | `tests/`, `fuzz/` |
| Deploy and ops docs | Present: Docker/systemd/logrotate and baseline runbooks exist, but devnet config and operational procedures need production hardening and drill validation. | `deploy/`, `docs/runbooks/` |

## Main Gaps

1. **Distributed finality is not complete.** The node can produce, validate, self-finalize, and accept valid inbound blocks, but there is no validator vote/attestation quorum or finality certificate path.
2. **Validator membership is static.** Stake and trusted-checkpoint sets derive from deterministic genesis/bootstrap state. There is no on-chain staking, unbonding, validator activation, or slashing flow.
3. **Sync transport needs full end-to-end orchestration.** The wire codec, scheduler, session manager, and inbound response path exist, but the daemon still needs complete request publication, chunk serving, response publication, and integration tests over real swarms.
4. **Devnet deployment config is not yet reliable.** Current Docker assets reuse one example config, bind RPC to localhost, use random listen ports, and do not generate per-node persistence, producer keys, or bootstrap peer addresses.
5. **Observability is in-process only.** Counters/events exist, but there is no Prometheus/OpenTelemetry endpoint, alert set, dashboard, or production log schema.
6. **Operator procedures need drill validation.** Runbooks now include baseline commands and checks, but production needs exercised rollback criteria, ownership, and failure-mode decision trees.
7. **Security release posture is incomplete.** Release gates exist, but mainnet needs a threat model, external review, longer fuzz/soak runs, reproducible artifacts, genesis ceremony, and key-management policy.

## Priority Backlog

### P0: Production-Critical Protocol Safety

- [ ] Define validator vote and finality certificate structures with network-domain-separated signatures.
- [ ] Add vote gossip topic, vote admission, equivocation evidence, and duplicate vote handling.
- [ ] Require quorum finality certificates before advancing finalized height for network-received blocks.
- [ ] Keep local self-finalization only as a dev/test mode behind explicit config.
- [ ] Add multi-validator tests for normal finality, delayed votes, partitions, equivocation, and invalid certificate rejection.

### P0: Real Multi-Node Devnet

- [ ] Add per-node devnet config generation with unique state directories, producer keys, RPC ports, and bootstrap multiaddrs.
- [ ] Fix container-facing defaults: RPC must bind `0.0.0.0` in Docker/devnet, and P2P listen ports must match exposed ports or be discoverable.
- [ ] Complete sync request/response publication and serving in daemon runtime.
- [ ] Add an end-to-end devnet test that starts 3 nodes, submits a transaction, produces/finalizes blocks, restarts a node, and verifies RPC/indexer recovery.
- [ ] Document a single command for local devnet bring-up, health checks, and teardown.

### P1: Validator and Staking Lifecycle

- [ ] Decide whether staking is represented as dedicated transaction variants or a separate validator operation protocol.
- [ ] Add validator registration, stake increase/decrease, unbonding delay, epoch activation, and validator removal rules.
- [ ] Connect active validator set changes to leader election, checkpoint trust rotation, and RPC status.
- [ ] Add slashing/evidence state for double-signing and invalid finality votes.
- [ ] Replace hardcoded production genesis key material with a dev-only path plus mainnet genesis input/ceremony tooling.

### P1: RPC, Wallet, and Indexer Productization

- [ ] Publish a JSON-RPC/WS method reference with request/response examples and error codes.
- [ ] Add wallet `--rpc-url` submission mode using `homa_sendRawTransaction`, while retaining direct gossip broadcast as an advanced mode.
- [ ] Add RPC methods for address timelines, transaction-by-sender/nonce, block ranges, and node version/build info.
- [ ] Add HTTP/WS integration tests against a real bound RPC server.
- [ ] Add compatibility/versioning rules for API changes.

### P1: Operations and Observability

- [ ] Add metrics export endpoint and define alert rules for sync lag, slot misses, block rejection spikes, RPC rate limits, peer bans, and persistence failures.
- [ ] Drill-validate runbooks for bootstrap, restart, recovery, backup/restore, incident triage, and key rotation, then add expected outputs and rollback criteria.
- [ ] Harden systemd and Docker deployment: config templates, secrets handling, health checks, persistent volumes, and log rotation validation.
- [ ] Add backup restore drill automation against a temporary state directory.
- [ ] Add release artifact build and checksum/signature generation.

### P2: Security, Performance, and Release Readiness

- [ ] Write and review a formal threat model covering consensus, network, wallet, RPC, persistence, and deployment.
- [ ] Increase fuzz duration in CI nightlies and add corpus minimization/coverage reporting.
- [ ] Add property tests for finality, supply conservation, snapshot import, and indexer replay invariants.
- [ ] Run long soak tests with realistic mempool load, node restarts, and network churn.
- [ ] Resolve or explicitly document remaining supply-chain advisories and yanked transitive dependencies.

## Definition of Done for Production Beta

- [ ] A real multi-node devnet can run from clean checkout with one command.
- [ ] Blocks finalize only with validator quorum certificates outside dev mode.
- [ ] Validator set changes are deterministic, delayed by epoch rules, and covered by tests.
- [ ] Node restart, backup/restore, and index/mempool recovery are tested in automation.
- [ ] RPC and wallet flows are documented and covered by integration tests.
- [ ] Operators have actionable runbooks, metrics, alerts, and deployment templates.
- [ ] Full release gate plus longer fuzz/soak jobs pass on release branches.
- [ ] External security review findings are triaged before mainnet genesis.
